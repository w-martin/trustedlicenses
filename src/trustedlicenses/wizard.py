"""Interactive setup: guide a user through configuring a policy, with explanations.

Run by :mod:`trustedlicenses.cli` when no policy is configured yet and the session
looks interactive (a real terminal attached, ``--quiet`` not passed) -- see that
module for the guard that decides whether to offer this at all. Never launches in a
non-interactive context (CI, pre-commit, piped input) on its own.

Every prompt is also individually time-boxed (see ``PROMPT_TIMEOUT_SECONDS``): a
``--quiet``-less CI/pre-commit job that somehow still has a real terminal attached
(some runners do) would otherwise hang forever waiting for an answer nobody's there
to give. A timeout aborts the wizard the same way a declined setup does -- see
:func:`run`.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, TypeVar, cast

import typer

from trustedlicenses.config import write_policy
from trustedlicenses.policy import detect_all

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from trustedlicenses.detection import DistributionLicence

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
