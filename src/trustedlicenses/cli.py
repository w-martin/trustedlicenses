"""Command-line entry point: check installed dependency licenses against policy."""

from __future__ import annotations

import sys
import tempfile
from importlib.metadata import distributions
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from trustedlicenses import wizard
from trustedlicenses.config import ConfigError, NoPolicyConfiguredError, load_policy, policy_source
from trustedlicenses.policy import detect_all, evaluate, format_failure, format_remediation, reevaluate
from trustedlicenses.resolve import ResolutionError, resolve_packages

if TYPE_CHECKING:
    from trustedlicenses.policy import Policy, PolicyResult

DOCS_URL = "https://trustedlicenses.readthedocs.io/en/latest/usage/"

app = typer.Typer(
    name="trustedlicenses",
    help=__doc__,
    add_completion=False,
    no_args_is_help=False,
)


def _should_offer_wizard(*, quiet: bool) -> bool:
    """Whether it's safe to launch the interactive setup wizard right now.

    Args:
        quiet: The ``--quiet`` flag -- explicitly opts out, independent of whether a
            real terminal is attached.

    Returns:
        ``False`` when ``--quiet`` was passed, or stdin isn't a real terminal (CI,
        pre-commit, piped input, ...) -- prompting there would hang or misbehave.
    """
    return not quiet and sys.stdin.isatty()


def _print_result(result: PolicyResult) -> None:
    """Print a :class:`~trustedlicenses.policy.PolicyResult` in the shared format.

    Colors (green pass, red fail, yellow caution) are applied when stdout is a real
    terminal, and automatically stripped otherwise (piped, redirected, `NO_COLOR`) --
    handled by Typer/Click, not something this function checks itself.

    Args:
        result: The evaluation to report.
    """
    if result.compatibility_notes:
        typer.secho(
            f"i {len(result.compatibility_notes)} compatibility note(s) -- not a pass/fail result, see below:",
            fg="yellow",
            bold=True,
        )
        for note in result.compatibility_notes:
            typer.echo(note)

    if result.failures:
        typer.secho(
            f"✗ Disallowed or undetectable licenses in {len(result.failures)} of {result.checked} packages:",
            fg="red",
            bold=True,
        )
        for failure in result.failures:
            typer.echo(format_failure(failure))
            typer.echo(format_remediation(failure))
    else:
        typer.secho(f"✓ All {result.checked} packages passed.", fg="green", bold=True)


def _load_or_configure_policy(pyproject: Path, *, quiet: bool) -> Policy | None:
    """Load the policy, offering the interactive wizard if none is configured yet.

    Args:
        pyproject: Path to the ``pyproject.toml`` holding (or that would hold) the
            policy.
        quiet: Whether interactive setup is allowed at all -- see
            :func:`_should_offer_wizard`.

    Returns:
        The loaded policy, or ``None`` when nothing is configured and either
        interactive setup isn't appropriate right now (the caller should fall back
        to its own report-only behavior) or the user declined to write one.

    Raises:
        ConfigError: A config file exists but is genuinely broken (not just
            unconfigured) -- callers should report this and exit, not fall back.
    """
    try:
        return load_policy(pyproject)
    except NoPolicyConfiguredError:
        if not _should_offer_wizard(quiet=quiet):
            return None
        written = wizard.run(pyproject)
        if written is None:
            return None
        typer.echo("")
        return load_policy(pyproject)


def _check_environment(pyproject: Path, *, quiet: bool) -> int:
    """Check every package installed in the current environment against a policy.

    Args:
        pyproject: Path to the ``pyproject.toml`` holding ``[tool.trustedlicenses]``.
        quiet: Never prompt interactively -- see :func:`_should_offer_wizard`.

    Returns:
        ``0`` if every checked package passed (or nothing is configured to check
        against yet), ``1`` otherwise. When the interactive failure-review wizard
        (:func:`trustedlicenses.wizard.review_failures`) writes a policy change, this
        reflects the *re-evaluated* result against the updated policy, not the
        original failing one.
    """
    try:
        policy = _load_or_configure_policy(pyproject, quiet=quiet)
    except ConfigError as error:
        typer.secho(f"trustedlicenses: {error}", fg="red", bold=True)
        return 1

    if policy is None:
        typer.secho(f"i {pyproject} has no policy configured yet -- showing detected licenses only.", dim=True)
        for detected in detect_all():
            categories = ", ".join(sorted(detected.categories)) or "none"
            typer.echo(f"  {detected.name}: {', '.join(sorted(detected.keys)) or 'no license detected'} ({categories})")
        typer.echo(
            f"\nAdd a policy to start enforcing this (re-run without --quiet in a terminal for guided setup). "
            f"See {DOCS_URL} for the full guide."
        )
        return 0

    typer.echo("Checking dependency licenses...")
    # Detection kept separate from evaluate() here (rather than one evaluate() call)
    # so a wizard-driven policy change below can be re-checked via reevaluate() alone
    # -- reusing this same scan -- instead of re-scanning the whole environment (which
    # can mean re-running the Rust text-matcher fallback for every package that needs
    # it) just to apply what's actually a pure policy-level change.
    detected = detect_all(exclude=policy.ignored_packages)
    result = reevaluate(detected, policy)
    _print_result(result)

    if result.failures and _should_offer_wizard(quiet=quiet):
        typer.echo("")
        if wizard.review_failures(policy_source(pyproject), result, policy):
            typer.echo("\nRe-checking against the updated policy...")
            policy = load_policy(pyproject)
            result = reevaluate(detected, policy)
            _print_result(result)

    return 0 if not result.failures else 1


def _check_new_packages(pyproject: Path, packages: list[str], *, quiet: bool) -> int:
    """Check whether adding package(s) -- and their transitive dependencies -- would pass policy.

    Resolves ``packages`` into an isolated temporary directory (see
    :mod:`trustedlicenses.resolve`), independent of whatever installer the current
    project actually uses, then evaluates every resolved distribution against the
    current project's policy. Nothing is installed into the real environment.

    Args:
        pyproject: Path to the ``pyproject.toml`` holding ``[tool.trustedlicenses]``.
        packages: Package requirement strings to check, e.g. ``["requests"]``.
        quiet: Never prompt interactively -- see :func:`_should_offer_wizard`.

    Returns:
        ``0`` if the candidate package(s) and every transitive dependency would
        pass, ``1`` otherwise (including if resolution itself failed, or no policy
        is configured to check against).
    """
    try:
        policy = _load_or_configure_policy(pyproject, quiet=quiet)
    except ConfigError as error:
        typer.secho(f"trustedlicenses: {error}", fg="red", bold=True)
        return 1

    if policy is None:
        typer.secho(
            f"trustedlicenses: no policy configured yet -- add one first (see {DOCS_URL}, or re-run without "
            f"--quiet in a terminal for guided setup) so there's something to check {', '.join(packages)} against.",
            fg="red",
            bold=True,
        )
        return 1

    typer.echo(f"Resolving {', '.join(packages)} and its transitive dependencies...")
    with tempfile.TemporaryDirectory(prefix="trustedlicenses-check-") as target:
        try:
            resolve_packages(packages, Path(target))
        except ResolutionError as error:
            typer.secho(f"trustedlicenses: {error}", fg="red", bold=True)
            return 1

        # Distribution objects read their metadata/license files from `target` lazily,
        # so evaluation has to happen before the temporary directory is cleaned up.
        resolved = list(distributions(path=[target]))
        typer.echo(f"Checking {len(resolved)} package(s) (requested plus transitive dependencies)...")
        result = evaluate(policy, distributions_=resolved)
        _print_result(result)
        return 0 if not result.failures else 1


@app.callback(invoke_without_command=True)
def main_command(
    ctx: typer.Context,
    pyproject: Path = typer.Option(
        Path("pyproject.toml"), "--pyproject", help="Path to the pyproject.toml holding [tool.trustedlicenses]."
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help=(
            "Never prompt interactively; fall back to report-only mode when no policy is configured. "
            "Recommended for CI/CD and pre-commit hooks."
        ),
    ),
) -> None:
    """Check installed dependency licenses against policy."""
    ctx.obj = {"pyproject": pyproject, "quiet": quiet}
    if ctx.invoked_subcommand is None:
        raise typer.Exit(code=_check_environment(pyproject, quiet=quiet))


@app.command()
def check(
    ctx: typer.Context,
    packages: list[str] = typer.Argument(..., help="Package requirement(s) to check, e.g. requests 'django>=5,<6'"),
) -> None:
    """Check whether package(s) could be added without a license problem, before adding them."""
    raise typer.Exit(code=_check_new_packages(ctx.obj["pyproject"], packages, quiet=ctx.obj["quiet"]))
