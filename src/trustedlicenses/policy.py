"""Policy evaluation: which detected licenses are acceptable, and for which packages.

This is deliberately separate from :mod:`trustedlicenses.detection` -- detection says
what license a package carries, policy says whether that's acceptable for *this*
project. The same detection can pass one project's policy and fail another's.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import distributions
from typing import TYPE_CHECKING

from trustedlicenses.detection import DistributionLicence, canonical_name, categories_for, inspect_distribution

if TYPE_CHECKING:
    from collections.abc import Iterable
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
    """

    allowed_categories: frozenset[str]
    ignored_packages: frozenset[str] = field(default_factory=frozenset)
    project_license_keys: frozenset[str] = field(default_factory=frozenset)


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
    results: dict[str, DistributionLicence] = {}
    for dist in distributions_ if distributions_ is not None else distributions():
        name = canonical_name(dist.metadata["Name"] or "")
        if not name or name in exclude or name in results:
            continue
        results[name] = inspect_distribution(dist, name=name)
    return tuple(sorted(results.values(), key=lambda result: result.name))


def evaluate(policy: Policy, distributions_: Iterable[Distribution] | None = None) -> PolicyResult:
    """Evaluate every installed distribution against a policy.

    Many distributions concatenate the license texts of their vendored dependencies
    into their own ``LICENSE`` file -- pandas ships BSD-3-Clause alongside the notices
    of everything it vendors, which includes GPL text. Failing on any disallowed
    *match* would reject pandas, which is plainly wrong: the grant pandas makes to us
    is BSD-3-Clause. Requiring a positive allowed match (rather than "no disallowed
    match") still fails a dependency that offers only a disallowed license, or none
    at all.

    Args:
        policy: The policy to evaluate against.
        distributions_: Distributions to check. Defaults to every distribution
            installed in the current environment; overridable for testing.

    Returns:
        The distributions that failed the policy, and how many were checked.
    """
    results = detect_all(distributions_, exclude=policy.ignored_packages)
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
        detected at all, there's no category to suggest, so this points at manual
        verification instead.
    """
    if not failure.categories:
        return (
            f'    -> no license could be detected; verify "{failure.name}" manually, '
            "then add it to ignored-packages if acceptable"
        )
    categories = ", ".join(f'"{category}"' for category in sorted(failure.categories))
    return f'    -> add {categories} to allowed-categories, or "{failure.name}" to ignored-packages, to allow this'
