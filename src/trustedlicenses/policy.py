"""Policy evaluation: which detected licenses are acceptable, and for which packages.

This is deliberately separate from :mod:`trustedlicenses.detection` -- detection says
what license a package carries, policy says whether that's acceptable for *this*
project. The same detection can pass one project's policy and fail another's.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from importlib.metadata import distributions
from typing import TYPE_CHECKING

from trustedlicenses.detection import DistributionLicence, canonical_name, categories_for, inspect_distribution

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from importlib.metadata import Distribution

# Plain, unmodified strong-copyleft licenses -- no linking exception (unlike LGPL) and
# no conditional compatibility grant (unlike MPL-2.0's GPL-compatibility clause). Used
# only for the generic "your project isn't copyleft, this dependency is" heads-up.
_STRONG_COPYLEFT_IDS = frozenset(
    {"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later"}
)

# GPLv2-only is not, by itself, compatible with GPLv3 (or AGPL-3.0, which incorporates
# GPLv3 terms) -- see the FSF's own GPL compatibility guidance:
# https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility -- "GPLv2 is, by itself,
# not compatible with GPLv3." A package that instead declares "GPL-2.0-or-later"
# grants permission to relicense under GPLv3, so that variant is deliberately excluded
# from this set.
_GPL3_FAMILY_IDS = frozenset({"GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later"})
_GPL2_ONLY_ID = "GPL-2.0-only"

_GPL_FAQ_URL = "https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility"


@dataclass(frozen=True)
class Policy:
    """A project's license policy.

    Attributes:
        allowed_categories: scancode license categories this project accepts (e.g.
            ``Permissive``, ``Public Domain``, ``Copyleft Limited``). A distribution
            passes when at least one of its detected licenses falls into one of these
            categories -- see :func:`evaluate` for why "at least one" rather than
            "none disallowed".
        ignored_packages: Canonical (PEP 503 normalised) names of distributions
            exempted from the check entirely, regardless of what they detect as.
        project_license_keys: SPDX identifiers the consuming project's own declared
            license resolves to (from its ``[project.license]``, per :pep:`639`).
            Empty when the project declares nothing resolvable. Used only for the
            informational compatibility notes in :func:`evaluate` -- never affects
            pass/fail.
        trust_corrected_licenses: Trust *every* free-text correction
            (:attr:`~trustedlicenses.detection.DistributionLicence.suggested`)
            project-wide. Off by default: a project shouldn't start silently passing
            packages it previously flagged just because detection got smarter --
            see :func:`_trusted_suggestion_ids`.
        verified_packages: Canonical package name -> the exact ``(declared statement,
            corrected SPDX id)`` pair a human verified for *that* package. Only
            trusted while the pair still matches what's currently detected -- if the
            package's declared statement ever changes, the pin silently stops
            applying and the package needs re-review, rather than trusting a new,
            unreviewed string under the old id.
        verified_statements: Declared statement text -> the SPDX id a human verified
            it corrects to, for *any* package with that exact statement (e.g. several
            internal packages sharing identical boilerplate). Same re-check-on-change
            property as ``verified_packages``.
    """

    allowed_categories: frozenset[str]
    ignored_packages: frozenset[str] = field(default_factory=frozenset)
    project_license_keys: frozenset[str] = field(default_factory=frozenset)
    trust_corrected_licenses: bool = False
    verified_packages: Mapping[str, tuple[str, str]] = field(default_factory=dict)
    verified_statements: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyResult:
    """The outcome of evaluating a :class:`Policy` against installed distributions.

    Attributes:
        failures: Distributions that detected no license in an allowed category,
            sorted by name.
        checked: How many distributions were evaluated (ignored ones excluded).
        compatibility_notes: Informational (never pass/fail-affecting) notes about a
            *specific, FSF-documented* copyleft compatibility concern between the
            consuming project's own declared license and a dependency's -- see
            :func:`_compatibility_note`. Empty when the project declares no resolvable
            license, or nothing triggered a note. These can fire even for a
            dependency that otherwise *passed* the category check: a category match
            (e.g. both "Copyleft") doesn't guarantee the specific licenses within it
            are compatible with each other.
    """

    failures: tuple[DistributionLicence, ...]
    checked: int
    compatibility_notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        """Whether every checked distribution had an allowed license."""
        return not self.failures


def _is_allowed(detected: DistributionLicence, policy: Policy) -> bool:
    """Whether a detection satisfies a policy's allowed categories.

    Args:
        detected: What was detected for a distribution.
        policy: The policy to check it against.

    Returns:
        Whether at least one detected license is in an allowed category.
    """
    return bool(detected.categories & policy.allowed_categories)


def _trusted_suggestion_ids(detected: DistributionLicence, policy: Policy) -> frozenset[str]:
    """Which of a detection's suggested corrections a policy actually trusts.

    Checked in order: the project-wide flag, then a package-specific pin, then a
    statement-text pin. Both pin types are matched against ``detected.suggested`` as
    it stands *right now* -- not merely looked up by name/text -- so a pin recorded
    for one declared statement silently stops applying the moment that statement
    changes to something new and unreviewed, rather than carrying the old id forward.

    Args:
        detected: What was detected for a distribution, including any suggestions.
        policy: The policy to check trust against.

    Returns:
        The subset of ``detected.suggested``'s ids that are trusted. Empty when
        nothing is.
    """
    if not detected.suggested:
        return frozenset()

    if policy.trust_corrected_licenses:
        return frozenset(spdx_id for _statement, spdx_id in detected.suggested)

    pinned_package = policy.verified_packages.get(detected.name)
    if pinned_package is not None and pinned_package in detected.suggested:
        return frozenset({pinned_package[1]})

    return frozenset(
        spdx_id for statement, spdx_id in detected.suggested if policy.verified_statements.get(statement) == spdx_id
    )


def _effective_result(detected: DistributionLicence, policy: Policy) -> DistributionLicence:
    """Fold a trusted free-text correction into a detection, without mutating it.

    A suggestion only ever fills in a distribution that otherwise resolved to
    nothing at all -- it never overrides an existing declared-metadata or
    license-file match, even a trusted one. Suggestion is a last resort that needs
    explicit trust to count, not a priority-one source the way direct declared
    metadata is.

    Args:
        detected: What was detected for a distribution.
        policy: The policy to check trust against.

    Returns:
        ``detected`` unchanged, unless it has no keys and a trusted suggestion
        exists -- in which case a copy with that suggestion folded into ``keys``,
        ``categories`` and ``source``.
    """
    if detected.keys or not detected.suggested:
        return detected

    trusted_ids = _trusted_suggestion_ids(detected, policy)
    if not trusted_ids:
        return detected

    return replace(
        detected,
        keys=trusted_ids,
        categories=categories_for(trusted_ids),
        source="declared metadata (corrected from free text)",
    )


def _compatibility_note(detected: DistributionLicence, policy: Policy) -> str | None:
    """A narrow, FSF-documented copyleft compatibility note, if one applies.

    Deliberately not a general compatibility engine -- see the research behind this
    (`docs/comparison.md`): category-level ("Copyleft" vs "Copyleft Limited")
    comparisons get real cases wrong (GPLv2-only vs GPLv3 are mutually incompatible
    despite both being "copyleft"; MPL-2.0 has its own conditional GPL-compatibility
    clause). This checks only the small number of pairings the FSF states explicitly
    and unambiguously, using exact SPDX identifiers, and reports them as a note to
    verify -- never a verdict, never something that fails the build.

    Args:
        detected: What was detected for a distribution.
        policy: The policy to check it against -- specifically its
            ``project_license_keys``.

    Returns:
        A one-line note, or ``None`` if nothing applies (including when the project's
        own license isn't known, since a responsible note needs both sides).
    """
    if not policy.project_license_keys:
        return None

    if _GPL2_ONLY_ID in policy.project_license_keys and detected.keys & _GPL3_FAMILY_IDS:
        other = ", ".join(sorted(detected.keys & _GPL3_FAMILY_IDS))
        return (
            f"  {detected.name}: your project is GPL-2.0-only; {detected.name} is {other} -- "
            f"the FSF states GPLv2 is not, by itself, compatible with GPLv3 ({_GPL_FAQ_URL})"
        )
    if _GPL2_ONLY_ID in detected.keys and policy.project_license_keys & _GPL3_FAMILY_IDS:
        return (
            f"  {detected.name}: your project is {', '.join(sorted(policy.project_license_keys & _GPL3_FAMILY_IDS))}; "
            f"{detected.name} is GPL-2.0-only -- the FSF states GPLv2 is not, by itself, "
            f"compatible with GPLv3 ({_GPL_FAQ_URL})"
        )

    if "Copyleft" not in categories_for(policy.project_license_keys) and detected.keys & _STRONG_COPYLEFT_IDS:
        matched = ", ".join(sorted(detected.keys & _STRONG_COPYLEFT_IDS))
        return (
            f"  {detected.name}: detected {matched} (strong copyleft); your project's own declared "
            f"license isn't copyleft -- distributing this combination may require your project to "
            f"also be GPL-compatible, see the FSF's GPL FAQ ({_GPL_FAQ_URL})"
        )

    return None


def detect_all(
    distributions_: Iterable[Distribution] | None = None,
    *,
    exclude: frozenset[str] = frozenset(),
) -> tuple[DistributionLicence, ...]:
    """Detect the license of every distribution, with no policy applied.

    Used both by :func:`evaluate` and for report-only output when no policy is
    configured yet (see :func:`trustedlicenses.cli.main`) -- detection doesn't need a
    policy to run, only to judge.

    Args:
        distributions_: Distributions to inspect. Defaults to every distribution
            installed in the current environment; overridable for testing, or for
            inspecting an arbitrary install location (e.g. an isolated temporary
            directory a candidate package was resolved into).
        exclude: Canonical (PEP 503 normalised) names to skip entirely.

    Returns:
        One :class:`~trustedlicenses.detection.DistributionLicence` per distinct
        (canonical-name-deduped) distribution, sorted by name.
    """
    # distributions() yields one entry per sys.path location a distribution is
    # importable from, so the same package can come back more than once.
    to_inspect: dict[str, Distribution] = {}
    for dist in distributions_ if distributions_ is not None else distributions():
        name = canonical_name(dist.metadata["Name"] or "")
        if not name or name in exclude or name in to_inspect:
            continue
        to_inspect[name] = dist

    # Most packages resolve from declared metadata (microseconds); the minority that
    # fall back to the Rust text matcher can each take tens to hundreds of milliseconds
    # (see `trustedlicenses.rust_matcher.scan_license_text`'s docstring) -- a thread
    # pool actually parallelizes that work, since the matcher releases the GIL for the
    # scan itself, rather than running every package's detection strictly one at a time.
    with ThreadPoolExecutor() as executor:
        results = executor.map(lambda item: inspect_distribution(item[1], name=item[0]), to_inspect.items())
    return tuple(sorted(results, key=lambda result: result.name))


def evaluate(policy: Policy, distributions_: Iterable[Distribution] | None = None) -> PolicyResult:
    """Detect every installed distribution and evaluate it against a policy.

    Args:
        policy: The policy to evaluate against.
        distributions_: Distributions to check. Defaults to every distribution
            installed in the current environment; overridable for testing.

    Returns:
        The distributions that failed the policy, and how many were checked.
    """
    detected = detect_all(distributions_, exclude=policy.ignored_packages)
    return reevaluate(detected, policy)


def reevaluate(detected: Iterable[DistributionLicence], policy: Policy) -> PolicyResult:
    """Evaluate already-detected results against a policy, without re-running detection.

    Split out from :func:`evaluate` so the same detection pass can be judged against
    more than one policy -- in particular, the interactive failure-review wizard
    writing a policy change and then re-checking: re-scanning the whole environment
    again (potentially re-running the Rust text-matcher fallback for every package
    that needs it, tens to hundreds of milliseconds each) would be wasted work to
    apply what's actually a pure policy-level change, not a change in what's
    installed.

    Many distributions concatenate the license texts of their vendored dependencies
    into their own ``LICENSE`` file -- pandas ships BSD-3-Clause alongside the notices
    of everything it vendors, which includes GPL text. Failing on any disallowed
    *match* would reject pandas, which is plainly wrong: the grant pandas makes to us
    is BSD-3-Clause. Requiring a positive allowed match (rather than "no disallowed
    match") still fails a dependency that offers only a disallowed license, or none
    at all.

    Args:
        detected: Previously detected results (e.g. from :func:`detect_all`).
            ``policy.ignored_packages`` is (re-)applied here regardless of whatever
            exclusion `detected` was already computed with, so this is safe to call
            with a policy whose ``ignored_packages`` differs from what produced
            `detected` -- e.g. a package the wizard just added to the ignore list.
        policy: The policy to evaluate against.

    Returns:
        The distributions that failed the policy, and how many were checked.
    """
    results = tuple(
        _effective_result(result, policy) for result in detected if result.name not in policy.ignored_packages
    )
    failures = tuple(result for result in results if not _is_allowed(result, policy))
    # Checked against every result, not just failures: a category match (e.g. both
    # "Copyleft") doesn't guarantee the specific licenses within it are compatible --
    # see _compatibility_note.
    compatibility_notes = tuple(note for result in results if (note := _compatibility_note(result, policy)) is not None)
    return PolicyResult(failures=failures, checked=len(results), compatibility_notes=compatibility_notes)


def format_failure(failure: DistributionLicence) -> str:
    """Render one policy failure as a human-readable line.

    Args:
        failure: The failing distribution.

    Returns:
        A description of what was detected and why it was rejected.
    """
    if not failure.keys:
        detail = "no license detected"
    else:
        detail = (
            f"detected {', '.join(sorted(failure.keys))} "
            f"(categories: {', '.join(sorted(failure.categories)) or 'none'})"
        )
    return f"  {failure.name}: {detail} -- from {failure.source}"


def format_remediation(failure: DistributionLicence) -> str:
    """Suggest a policy change that would let one failure pass.

    Args:
        failure: The failing distribution.

    Returns:
        A one-line suggestion: add the failure's own categories to
        ``allowed-categories``, or its name to ``ignored-packages``. When nothing was
        detected at all but a free-text correction was found, points at trusting that
        instead (interactively, or via policy config) -- see :func:`format_suggestion`.
        When nothing was detected and no correction applies either, points at manual
        verification.
    """
    if not failure.categories:
        if failure.suggested:
            return format_suggestion(failure)
        return (
            f'    -> no license could be detected; verify "{failure.name}" manually, '
            "then add it to ignored-packages if acceptable"
        )
    categories = ", ".join(f'"{category}"' for category in sorted(failure.categories))
    return f'    -> add {categories} to allowed-categories, or "{failure.name}" to ignored-packages, to allow this'


def format_suggestion(failure: DistributionLicence) -> str:
    """Describe an untrusted free-text correction, and how to trust it.

    Args:
        failure: A failing distribution with a non-empty ``suggested``.

    Returns:
        A one-line hint naming what the correction looks like and the three ways to
        trust it -- visible from a plain (non-interactive) report, not just the
        interactive review wizard.
    """
    statement, spdx_id = min(failure.suggested)
    return (
        f'    -> looks like {spdx_id} from its declared metadata ("{statement}"), not trusted by default -- '
        f"review interactively, or add trust-corrected-licenses / verified-packages / "
        f"verified-statements to your policy"
    )
