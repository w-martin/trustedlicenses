"""Interactive setup: guide a user through configuring a policy, with explanations.

Two independent flows live here:

- :func:`run` -- initial ``allowed-categories`` setup, offered by :mod:`trustedlicenses.cli`
  when no policy is configured yet.
- :func:`review_failures` -- walks through a failing check's failures one at a time,
  offering to add each to ``ignored-packages``, allow its category, or -- for a
  failure with a free-text correction available -- trust that correction (for just
  that package, for that exact declared text everywhere, or project-wide if enough
  failures would *actually pass* once it's enabled). Offered after a failing check
  against an *existing* policy.

Both only run when the session looks interactive (a real terminal attached, ``--quiet``
not passed) -- see :mod:`trustedlicenses.cli`'s ``_should_offer_wizard`` guard. Neither
launches in a non-interactive context (CI, pre-commit, piped input) on its own.

Every prompt is also individually time-boxed (see ``PROMPT_TIMEOUT_SECONDS``): a
``--quiet``-less CI/pre-commit job that somehow still has a real terminal attached
(some runners do) would otherwise hang forever waiting for an answer nobody's there
to give. A timeout aborts either flow the same way a declined one does -- see
:func:`run` and :func:`review_failures`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, TypeVar, cast

import typer

from trustedlicenses.config import CorrectionTrust, add_to_policy, write_policy
from trustedlicenses.detection import categories_for
from trustedlicenses.policy import detect_all, format_failure

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from trustedlicenses.detection import DistributionLicence
    from trustedlicenses.policy import Policy, PolicyResult

# (category, explanation, default answer) -- the vocabulary this project's own docs
# and examples already treat as the common case; the default answers mirror the
# `allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]` example
# used throughout.
_PRIMARY_CATEGORIES: tuple[tuple[str, str, bool], ...] = (
    (
        "Permissive",
        (
            "MIT, BSD, Apache-2.0, ISC, ... -- minimal restrictions: use, modify, and "
            "redistribute freely, usually with just an attribution/copyright notice."
        ),
        True,
    ),
    (
        "Public Domain",
        "CC0, Unlicense, ... -- copyright is waived entirely. No restrictions at all.",
        True,
    ),
    (
        "Copyleft Limited",
        (
            "LGPL, MPL-2.0, ... -- changes to the licensed code itself must be shared "
            "back, but you can still use it inside a project under a different license "
            "(e.g. dynamic linking is fine). Doesn't require your whole project to adopt "
            "the same license."
        ),
        True,
    ),
    (
        "Copyleft",
        (
            "GPL, AGPL, ... -- a much bigger commitment: distributing a work that "
            "includes this code generally requires your entire project to also be "
            "released under a compatible copyleft license."
        ),
        False,
    ),
)

_PRIMARY_CATEGORY_NAMES = frozenset(name for name, _explanation, _default in _PRIMARY_CATEGORIES)

# How long to wait for an answer to any single prompt before giving up. A module
# constant (rather than a CLI flag) deliberately: this is a safety net for a
# misconfigured non-interactive job, not a knob anyone should need to tune.
PROMPT_TIMEOUT_SECONDS = 30.0

# Above this many matches in one category, list a count only -- naming every package
# stops being skimmable.
_NAME_INDIVIDUALLY_UP_TO = 2

_T = TypeVar("_T")


class _PromptTimeoutError(Exception):
    """No answer arrived within ``PROMPT_TIMEOUT_SECONDS``."""


def _with_timeout(func: Callable[..., _T], *args: object, **kwargs: object) -> _T:
    """Run a blocking ``typer.confirm``/``typer.prompt`` call with a timeout.

    The call runs on a daemon thread so a timeout here never blocks process exit --
    if an answer does arrive after the timeout, it's simply discarded (the wizard has
    already moved on to aborting).

    Args:
        func: ``typer.confirm`` or ``typer.prompt``.
        *args: Forwarded to ``func``.
        **kwargs: Forwarded to ``func``.

    Returns:
        Whatever ``func`` returned.

    Raises:
        _PromptTimeoutError: No answer arrived within ``PROMPT_TIMEOUT_SECONDS``.
    """
    done = threading.Event()
    outcome: dict[str, object] = {}

    def _target() -> None:
        try:
            outcome["value"] = func(*args, **kwargs)
        except BaseException as error:  # noqa: BLE001 -- re-raised on the caller's thread below
            outcome["error"] = error
        finally:
            done.set()

    threading.Thread(target=_target, daemon=True).start()
    if not done.wait(timeout=PROMPT_TIMEOUT_SECONDS):
        raise _PromptTimeoutError
    if "error" in outcome:
        raise cast("BaseException", outcome["error"])
    return cast("_T", outcome["value"])


def _confirm(text: str, *, default: bool) -> bool:
    return _with_timeout(typer.confirm, text, default=default)


def _prompt(text: str, *, default: str) -> str:
    return _with_timeout(typer.prompt, text, default=default, show_default=False)


def _category_summary(detected: tuple[DistributionLicence, ...], category: str) -> str:
    """Describe how many detected packages fall into one category, and which.

    Args:
        detected: Every package's detection, from :func:`~trustedlicenses.policy.detect_all`.
        category: The category to summarize, e.g. ``"Copyleft"``.

    Returns:
        ``"(none detected in your environment)"``, ``"(N detected)"``, or --
        specifically for 1 or 2 matches, where naming them is still skimmable --
        ``"(N detected: name (KEYS), ...)"``.
    """
    matches = [result for result in detected if category in result.categories]
    if not matches:
        return "(none detected in your environment)"
    if len(matches) <= _NAME_INDIVIDUALLY_UP_TO:
        named = "; ".join(f"{result.name} ({', '.join(sorted(result.keys)) or 'unknown'})" for result in matches)
        return f"({len(matches)} detected: {named})"
    return f"({len(matches)} detected)"


def run(pyproject_path: Path) -> Path | None:
    """Run the interactive setup wizard, writing a policy file.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml`` -- used to derive
            where a standalone ``trustedlicenses.toml`` would live, and as the file
            edited in place if the user chooses that instead.

    Returns:
        The path written, or ``None`` if nothing was written -- guided setup was
        declined up front, no categories were selected, the final confirmation was
        declined, or no answer arrived within ``PROMPT_TIMEOUT_SECONDS`` for some
        prompt (all treated the same as a declined setup, not a failure: see
        :func:`trustedlicenses.cli.main_command`'s report-only fallback).
    """
    try:
        return _run(pyproject_path)
    except _PromptTimeoutError:
        typer.secho(
            f"\nNo answer received within {PROMPT_TIMEOUT_SECONDS:.0f}s -- aborting setup. "
            "(Running non-interactively? Pass --quiet to skip this wizard entirely.)",
            fg="yellow",
            bold=True,
        )
        return None


def _run(pyproject_path: Path) -> Path | None:
    """The wizard's actual prompt sequence -- see :func:`run` for the timeout wrapper."""
    detected = detect_all()
    with_license = sum(1 for result in detected if result.keys)
    typer.echo(f"Detected licenses for {with_license} of {len(detected)} installed packages.\n")

    if not _confirm("No policy configured yet -- would you like to run the guided setup?", default=True):
        return None
    typer.echo("")

    allowed: list[str] = []
    for category, explanation, default in _PRIMARY_CATEGORIES:
        typer.echo(f"{category}: {explanation}")
        typer.echo(f"  {_category_summary(detected, category)}")
        if _confirm(f"Allow {category} licenses?", default=default):
            allowed.append(category)
        typer.echo("")

    other_categories = sorted(
        {category for result in detected for category in result.categories} - _PRIMARY_CATEGORY_NAMES
    )
    if other_categories:
        typer.echo(f"Also detected in your environment: {', '.join(other_categories)}.")
        extra = _prompt("Allow any of these too? Comma-separated exact names, or Enter to skip", default="")
        allowed.extend(name.strip() for name in extra.split(",") if name.strip())

    if not allowed:
        typer.echo("\nNo categories selected -- nothing to write. Run `trustedlicenses` again when you're ready.")
        return None

    typer.secho(f"\nAllowed categories: {', '.join(allowed)}", fg="green", bold=True)

    if pyproject_path.is_file():
        standalone = _confirm(
            f"\nSave to a separate trustedlicenses.toml instead of adding to {pyproject_path}?", default=False
        )
    else:
        typer.echo(f"\n{pyproject_path} doesn't exist -- writing a separate trustedlicenses.toml.")
        standalone = True

    if not _confirm("\nWrite this configuration?", default=True):
        return None

    written = write_policy(pyproject_path, allowed_categories=allowed, standalone=standalone)
    typer.secho(f"\nWrote policy to {written}.", fg="green", bold=True)
    return written


# Single-letter answers for the per-failure prompt in review_failures -- short enough to
# type without a full menu system, and echoed in the option text itself (e.g. "[i]gnore")
# so nothing needs to be memorized.
_IGNORE_CHOICE = "i"
_ALLOW_CATEGORY_CHOICE = "a"
_BULK_IGNORE_CHOICE = "b"
_VERIFY_PACKAGE_CHOICE = "v"
_TRUST_TEXT_CHOICE = "t"
_CHECK_INDEX_CHOICE = "c"
_SKIP_CHOICE = "s"
_QUIT_CHOICE = "q"

# Below this many failures a free-text correction would resolve, per-case pinning
# (verify/trust choices below) is the expected path; at or above it, offering to
# enable correction project-wide saves repetitive pinning. Matches
# `_NAME_INDIVIDUALLY_UP_TO`'s threshold deliberately -- both are "is this worth
# naming individually, or just a count" judgment calls, and there's no reason for
# them to disagree.
_OFFER_BLANKET_CORRECTION_AT = _NAME_INDIVIDUALLY_UP_TO


@dataclass
class _ReviewDecisions:
    """Decisions accumulated across one `review_failures` walkthrough, written once at the end."""

    ignored: dict[str, str] = field(default_factory=dict)
    allowed_categories: set[str] = field(default_factory=set)
    verified_packages: dict[str, tuple[str, str]] = field(default_factory=dict)
    verified_statements: dict[str, str] = field(default_factory=dict)
    trust_corrected_licenses: bool = False

    def has_decisions(self) -> bool:
        """Whether anything was actually decided -- nothing to write otherwise."""
        return bool(
            self.ignored
            or self.allowed_categories
            or self.verified_packages
            or self.verified_statements
            or self.trust_corrected_licenses
        )


def _today() -> str:
    """Today's date, for the "accepted <date>" reason recorded on a new ignored-packages entry."""
    return datetime.now(UTC).date().isoformat()


def _reason_for(failure: DistributionLicence, today: str) -> str:
    """The reason comment recorded when a failure is accepted into ignored-packages."""
    if failure.keys:
        return f"detected {', '.join(sorted(failure.keys))} -- accepted {today}"
    return f"no license detected -- accepted {today}"


def _primary_suggestion(failure: DistributionLicence) -> tuple[str, str]:
    """The ``(statement, spdx id)`` pair to show/pin for a failure with more than one.

    Multiple declared statements each correcting differently is rare enough (an edge
    case, not a real scenario seen in practice) that a sub-menu to choose between them
    isn't worth it -- the lexicographically first is picked and shown plainly instead.
    """
    return min(failure.suggested)


def _failure_options(failure: DistributionLicence) -> str:
    """The choice menu for one failure, tailored to what's known about it."""
    options = [f"[{_IGNORE_CHOICE}]gnore this package"]
    if failure.categories:
        categories = ", ".join(sorted(failure.categories))
        options.append(f'[{_ALLOW_CATEGORY_CHOICE}]llow "{categories}" (every package in it, not just this one)')
    else:
        options.append(f"[{_BULK_IGNORE_CHOICE}]ulk-ignore every remaining undetectable package")
    if failure.suggested:
        statement, spdx_id = _primary_suggestion(failure)
        options.append(f"[{_VERIFY_PACKAGE_CHOICE}]erify this package as {spdx_id} (re-checked if its text changes)")
        options.append(f'[{_TRUST_TEXT_CHOICE}]rust "{statement}" -> {spdx_id} for any package')
    if not failure.keys:
        options.append(f"[{_CHECK_INDEX_CHOICE}]heck the package index for a version that ships a license")
    options.extend([f"[{_SKIP_CHOICE}]kip", f"[{_QUIT_CHOICE}]uit reviewing"])
    return "  " + "; ".join(options)


def _apply_choice(
    choice: str,
    failure: DistributionLicence,
    today: str,
    decisions: _ReviewDecisions,
) -> tuple[bool, bool]:
    """Apply one prompted choice for a failure, mutating `decisions`.

    Args:
        choice: The raw answer to the per-failure prompt.
        failure: The failure the choice applies to.
        today: Precomputed :func:`_today`, so every reason in one review shares a date.
        decisions: Accumulated decisions so far, mutated in place.

    Returns:
        ``(quit_requested, bulk_ignore_requested)``.
    """
    if choice == _QUIT_CHOICE:
        return True, False
    if choice == _BULK_IGNORE_CHOICE and not failure.categories:
        decisions.ignored[failure.name] = _reason_for(failure, today)
        return False, True

    if choice == _IGNORE_CHOICE:
        decisions.ignored[failure.name] = _reason_for(failure, today)
    elif choice == _ALLOW_CATEGORY_CHOICE and failure.categories:
        decisions.allowed_categories |= failure.categories
    elif choice == _VERIFY_PACKAGE_CHOICE and failure.suggested:
        decisions.verified_packages[failure.name] = _primary_suggestion(failure)
    elif choice == _TRUST_TEXT_CHOICE and failure.suggested:
        statement, spdx_id = _primary_suggestion(failure)
        decisions.verified_statements[statement] = spdx_id
    elif choice != _SKIP_CHOICE:
        typer.secho(f'  "{choice}" isn\'t one of the options above -- skipping {failure.name}.', fg="yellow")
    return False, False


def _summarize_and_write(source: Path, decisions: _ReviewDecisions) -> bool:
    """Show accumulated review decisions, confirm, and write them -- or write nothing."""
    if not decisions.has_decisions():
        typer.echo("\nNothing selected -- nothing to write.")
        return False

    typer.secho("\nAbout to update:", fg="green", bold=True)
    if decisions.trust_corrected_licenses:
        typer.echo("  enable free-text license correction project-wide")
    for category in sorted(decisions.allowed_categories):
        typer.echo(f'  allow category "{category}"')
    for name, reason in sorted(decisions.ignored.items()):
        typer.echo(f"  ignore {name}  # {reason}")
    for name, (statement, spdx_id) in sorted(decisions.verified_packages.items()):
        typer.echo(f'  verify {name} as {spdx_id} (text: "{statement}")')
    for statement, spdx_id in sorted(decisions.verified_statements.items()):
        typer.echo(f'  trust "{statement}" -> {spdx_id} for any package')
    typer.echo(f"\n  -> {source}")

    if not _confirm("\nWrite these changes?", default=True):
        return False

    add_to_policy(
        source,
        ignored_packages=list(decisions.ignored),
        allowed_categories=sorted(decisions.allowed_categories),
        reasons=decisions.ignored,
        trust=CorrectionTrust(
            enabled=decisions.trust_corrected_licenses or None,
            verified_packages=decisions.verified_packages,
            verified_statements=decisions.verified_statements,
        ),
    )
    typer.secho(f"\nUpdated {source}.", fg="green", bold=True)
    return True


def review_failures(source: Path, result: PolicyResult, policy: Policy) -> bool:
    """Interactively review a failed check's failures, offering to fix the policy.

    Args:
        source: The policy file to write any decisions to -- see
            :func:`trustedlicenses.config.policy_source`.
        result: The failed evaluation to review.
        policy: The policy that produced `result` -- needed to tell whether enabling
            free-text correction would actually resolve a given failure (its
            corrected category has to be in `policy.allowed_categories`, not just
            exist), not just whether a correction was found at all.

    Returns:
        Whether anything was written to `source`. ``False`` covers declining up front,
        selecting nothing, declining the final confirmation, and a prompt timing out --
        callers should treat all of these exactly like an unreviewed failure.
    """
    try:
        return _review_failures(source, result, policy)
    except _PromptTimeoutError:
        typer.secho(
            f"\nNo answer received within {PROMPT_TIMEOUT_SECONDS:.0f}s -- stopping the review. "
            "Nothing has been written.",
            fg="yellow",
            bold=True,
        )
        return False


def _would_pass_if_corrected(failure: DistributionLicence, policy: Policy) -> bool:
    """Whether trusting *any* of a failure's suggestions would land it in an allowed category.

    Having a suggestion at all isn't enough -- the corrected id still has to map to a
    category `policy.allowed_categories` actually accepts, exactly like a real
    declared id would have to. Without this check, the blanket-correction offer would
    overcount: a suggestion that corrects to e.g. MPL-2.0 doesn't help a
    Permissive-only policy just because *some* suggestion exists.
    """
    suggested_ids = {spdx_id for _statement, spdx_id in failure.suggested}
    return bool(categories_for(suggested_ids) & policy.allowed_categories)


def _offer_blanket_correction(
    remaining: list[DistributionLicence], decisions: _ReviewDecisions, policy: Policy
) -> list[DistributionLicence]:
    """Offer to enable free-text correction project-wide when enough failures need it.

    Args:
        remaining: Failures not yet reviewed.
        decisions: Mutated in place with ``trust_corrected_licenses = True`` if accepted.
        policy: The policy failures were evaluated against -- see :func:`review_failures`.

    Returns:
        ``remaining`` with the now-resolved failures removed, if accepted; unchanged
        otherwise (declined, or below :data:`_OFFER_BLANKET_CORRECTION_AT`) -- those
        stay in the per-failure walkthrough, each still individually offered the
        narrower verify/trust choices.
    """
    correctable = [failure for failure in remaining if _would_pass_if_corrected(failure, policy)]
    if len(correctable) < _OFFER_BLANKET_CORRECTION_AT:
        return remaining

    if len(correctable) <= _NAME_INDIVIDUALLY_UP_TO:
        named = ", ".join(failure.name for failure in correctable)
    else:
        named = f"{len(correctable)} packages"
    accepted = _confirm(
        f"\n{len(correctable)} failure(s) would resolve if free-text license correction were enabled "
        f"project-wide ({named}). Enable it now?",
        default=False,
    )
    if not accepted:
        return remaining

    decisions.trust_corrected_licenses = True
    return [failure for failure in remaining if failure not in correctable]


def _run_index_check(failure: DistributionLicence, project_dir: Path) -> None:
    """Ask the package index whether a newer release of one failing package ships a license.

    Purely informational -- writes nothing. Confirms the index (and why it was chosen)
    before anything is sent, since guessing wrong could send an internal package's name
    to a public host. Imported lazily: a plain check never loads the network code.

    Args:
        failure: The failing package.
        project_dir: The project directory, where lockfiles and index config live.
    """
    from trustedlicenses import index, index_discovery  # noqa: PLC0415 -- opt-in, keep off the plain-check path

    choice = index_discovery.discover_index(project_dir, failure.name)
    shown = index_discovery.redact_url(choice.url)
    if not _confirm(
        f'\nAsk {shown} (from {choice.origin}) about "{failure.name}"? Only its name is sent.', default=False
    ):
        return
    try:
        audit = index.audit_package(index.HttpClient(), choice.url, failure.name, failure.version)
    except index.IndexQueryError as error:
        typer.secho(f"  {error}", fg="yellow")
        return
    typer.echo(index.format_audit(audit))


def _ask_choice(failure: DistributionLicence, project_dir: Path) -> str:
    """Show one failure's menu and read the answer, re-asking after an informational index check.

    Args:
        failure: The failure being reviewed.
        project_dir: The project directory, for the index check.

    Returns:
        The answer to act on -- never the index-check choice, which is handled here.
    """
    while True:
        typer.echo(f"\n{format_failure(failure)}")
        typer.echo(_failure_options(failure))
        choice = _prompt("  Choice", default=_SKIP_CHOICE).strip().lower()
        if choice != _CHECK_INDEX_CHOICE or failure.keys:
            return choice
        _run_index_check(failure, project_dir)


def _review_failures(source: Path, result: PolicyResult, policy: Policy) -> bool:
    """The review's actual prompt sequence -- see :func:`review_failures` for the timeout wrapper."""
    if not _confirm(f"Review these {len(result.failures)} failing package(s) now?", default=False):
        return False

    decisions = _ReviewDecisions()
    today = _today()
    remaining = _offer_blanket_correction(list(result.failures), decisions, policy)

    bulk_ignore_undetectable = False
    for failure in remaining:
        if bulk_ignore_undetectable and not failure.categories:
            decisions.ignored[failure.name] = _reason_for(failure, today)
            continue

        choice = _ask_choice(failure, source.parent)

        quit_requested, bulk_requested = _apply_choice(choice, failure, today, decisions)
        bulk_ignore_undetectable = bulk_ignore_undetectable or bulk_requested
        if quit_requested:
            break

    return _summarize_and_write(source, decisions)
