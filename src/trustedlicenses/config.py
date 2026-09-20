"""Load a :class:`~trustedlicenses.policy.Policy` from a project's config.

A project opts in one of two ways:

1. A ``[tool.trustedlicenses]`` table in ``pyproject.toml``:

   ```toml
   [tool.trustedlicenses]
   allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
   ignored-packages = ["mypy-extensions"]
   ```

2. A standalone ``trustedlicenses.toml`` next to it, with the same keys at the file's
   root (no ``[tool.trustedlicenses]`` wrapper needed) -- the same convention
   ``ruff.toml`` uses relative to ``[tool.ruff]``. When both exist, the standalone
   file wins.

``allowed-categories`` is required and has no default: a project should state its
policy explicitly rather than inherit an assumption about what it's willing to accept.
Neither of these is written automatically -- see :func:`write_policy` for the
interactive setup that does, driven by :mod:`trustedlicenses.wizard`.

The project's own declared ``[project.license]`` (per :pep:`639`) is also read, when
``pyproject.toml`` exists, to power the narrow compatibility notes described in
:func:`trustedlicenses.policy.evaluate` -- entirely optional, and never required, and
independent of which file the policy itself came from.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from trustedlicenses.detection import canonical_name, resolve_license_expression

if TYPE_CHECKING:
    from collections.abc import Mapping, MutableMapping, Sequence
from trustedlicenses.policy import Policy

CONFIG_SECTION = ("tool", "trustedlicenses")
STANDALONE_FILENAME = "trustedlicenses.toml"
DOCS_URL = "https://trustedlicenses.readthedocs.io/en/latest/usage/"


def _project_license_keys(document: dict[str, Any]) -> frozenset[str]:
    """Resolve the project's own declared license, if any, to SPDX identifiers.

    Args:
        document: The parsed ``pyproject.toml`` (empty if it doesn't exist).

    Returns:
        SPDX identifiers the project's own ``[project.license]`` (:pep:`639` string
        form) or ``License ::`` classifiers resolve to. Empty when the project
        declares nothing resolvable -- including the pre-PEP-639
        ``license = {text = "..."}``/``{file = "..."}`` table forms, which this
        deliberately doesn't try to parse further than a bare ``text`` value.
    """
    project = document.get("project")
    if not isinstance(project, dict):
        return frozenset()

    license_field = project.get("license")
    statements = []
    if isinstance(license_field, str):
        statements.append(license_field)
    elif isinstance(license_field, dict) and isinstance(license_field.get("text"), str):
        statements.append(license_field["text"])
    statements.extend(
        classifier for classifier in project.get("classifiers", []) if str(classifier).startswith("License ::")
    )

    keys: set[str] = set()
    for statement in statements:
        keys |= resolve_license_expression(statement)
    return frozenset(keys)


class ConfigError(Exception):
    """A config file misconfigures ``trustedlicenses``."""


class NoPolicyConfiguredError(ConfigError):
    """Neither a ``trustedlicenses.toml`` nor a ``[tool.trustedlicenses]`` table exists yet.

    Distinct from :class:`ConfigError`: this isn't a *broken* config, it's simply an
    unconfigured project. Callers (see :func:`trustedlicenses.cli.main`) catch this
    separately to offer the interactive setup wizard, or fall back to a report-only
    mode.
    """


def policy_source(pyproject_path: Path | str) -> Path:
    """The file that currently holds (or would hold) the policy for a project.

    Mirrors the "standalone wins" rule :func:`load_policy` applies when both a
    standalone ``trustedlicenses.toml`` and a ``[tool.trustedlicenses]`` table exist.
    Unlike :func:`load_policy`, this doesn't validate or even read either file -- it
    just says which one is authoritative, for callers (e.g. the interactive
    failure-review wizard in :mod:`trustedlicenses.wizard`) that need to know which
    physical file to write additions back to.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml``.

    Returns:
        The sibling ``trustedlicenses.toml`` if it exists, otherwise ``pyproject_path``
        itself.
    """
    path = Path(pyproject_path)
    standalone_path = path.parent / STANDALONE_FILENAME
    return standalone_path if standalone_path.is_file() else path


def load_policy(pyproject_path: Path | str = Path("pyproject.toml")) -> Policy:
    """Load a policy from a project's config.

    Args:
        pyproject_path: Path to the ``pyproject.toml`` to read. Defaults to
            ``pyproject.toml`` in the current working directory. A sibling
            ``trustedlicenses.toml`` in the same directory, if present, is checked
            first -- see the module docstring.

    Returns:
        The configured policy.

    Raises:
        NoPolicyConfiguredError: Neither config file exists yet -- the project hasn't
            opted in.
        ConfigError: A config file exists but has no non-empty ``allowed-categories``.
    """
    path = Path(pyproject_path)
    standalone_path = path.parent / STANDALONE_FILENAME
    source = policy_source(path)

    document: dict[str, Any] = {}
    if path.is_file():
        with path.open("rb") as handle:
            document = tomllib.load(handle)

    if source == standalone_path:
        with source.open("rb") as handle:
            section = tomllib.load(handle)
        section_source = standalone_path
    else:
        section = document
        for key in CONFIG_SECTION:
            if not isinstance(section, dict) or key not in section:
                message = (
                    f"Neither {standalone_path} nor a [tool.trustedlicenses] table in {path} exists yet. "
                    f"Add one to enable enforcement, e.g.:\n\n"
                    '  [tool.trustedlicenses]\n  allowed-categories = ["Permissive", "Public Domain", '
                    '"Copyleft Limited"]\n\n'
                    f"See {DOCS_URL} for the full guide, or run `trustedlicenses` interactively to set "
                    f"this up with guided prompts."
                )
                raise NoPolicyConfiguredError(message)
            section = section[key]
        section_source = path

    allowed_categories = section.get("allowed-categories")
    if not allowed_categories:
        message = (
            f"{section_source} needs a non-empty allowed-categories list, e.g.:\n\n"
            '  allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]\n\n'
            f"See {DOCS_URL} for the full category vocabulary."
        )
        raise ConfigError(message)

    ignored_packages = section.get("ignored-packages", [])
    return Policy(
        allowed_categories=frozenset(allowed_categories),
        ignored_packages=frozenset(canonical_name(name) for name in ignored_packages),
        project_license_keys=_project_license_keys(document),
        trust_corrected_licenses=bool(section.get("trust-corrected-licenses", False)),
        verified_packages=_verified_packages(section, section_source),
        verified_statements=_verified_statements(section, section_source),
    )


def _verified_packages(section: dict[str, Any], source: Path) -> dict[str, tuple[str, str]]:
    """Parse ``verified-packages`` into ``{canonical name: (statement, spdx id)}``.

    Args:
        section: The parsed policy table.
        source: The file it came from, for a clear error message.

    Returns:
        Empty when the key is absent -- this is an optional, wizard-populated table.

    Raises:
        ConfigError: The key exists but an entry is malformed.
    """
    raw = section.get("verified-packages", {})
    if not isinstance(raw, dict):
        message = f"{source}: verified-packages must be a table of package name -> {{ statement, spdx-id }}."
        raise ConfigError(message)
    result: dict[str, tuple[str, str]] = {}
    for name, entry in raw.items():
        if not isinstance(entry, dict) or "statement" not in entry or "spdx-id" not in entry:
            message = f'{source}: verified-packages.{name} needs both "statement" and "spdx-id".'
            raise ConfigError(message)
        result[canonical_name(name)] = (entry["statement"], entry["spdx-id"])
    return result


def _verified_statements(section: dict[str, Any], source: Path) -> dict[str, str]:
    """Parse ``verified-statements`` into ``{statement text: spdx id}``.

    Args:
        section: The parsed policy table.
        source: The file it came from, for a clear error message.

    Returns:
        Empty when the key is absent -- this is an optional, wizard-populated table.

    Raises:
        ConfigError: The key exists but isn't a table.
    """
    raw = section.get("verified-statements", {})
    if not isinstance(raw, dict):
        message = f"{source}: verified-statements must be a table of statement text -> spdx id."
        raise ConfigError(message)
    return dict(raw)


def write_policy(
    pyproject_path: Path | str,
    *,
    allowed_categories: Sequence[str],
    ignored_packages: Sequence[str] = (),
    standalone: bool,
) -> Path:
    """Write a policy to disk, for the interactive setup wizard.

    Args:
        pyproject_path: Path to the project's ``pyproject.toml`` (used to derive
            where a standalone file would live, and edited in place when
            ``standalone`` is ``False``).
        allowed_categories: Categories to write into ``allowed-categories``.
        ignored_packages: Package names to write into ``ignored-packages``, if any.
        standalone: Write a sibling ``trustedlicenses.toml`` instead of editing
            ``pyproject.toml``. Required (not auto-detected) when ``pyproject.toml``
            doesn't exist, since there's nothing to edit in that case.

    Returns:
        The path actually written.

    Raises:
        ConfigError: ``standalone`` is ``False`` but ``pyproject_path`` doesn't exist
            -- there's no file to add a ``[tool.trustedlicenses]`` table to.
    """
    path = Path(pyproject_path)
    allowed = list(allowed_categories)
    ignored = list(ignored_packages)

    if standalone:
        target = path.parent / STANDALONE_FILENAME
        document = tomlkit.document()
        document.add("allowed-categories", allowed)
        if ignored:
            document.add("ignored-packages", ignored)
        target.write_text(tomlkit.dumps(document))
        return target

    if not path.is_file():
        message = f"{path} doesn't exist -- can't add a [tool.trustedlicenses] table to a file that isn't there."
        raise ConfigError(message)

    document = tomlkit.parse(path.read_text())
    tool_table = document.setdefault("tool", tomlkit.table(is_super_table=True))
    section = tomlkit.table()
    section.add("allowed-categories", allowed)
    if ignored:
        section.add("ignored-packages", ignored)
    tool_table["trustedlicenses"] = section
    path.write_text(tomlkit.dumps(document))
    return path


def _policy_table(document: tomlkit.TOMLDocument, path: Path) -> MutableMapping[str, Any]:
    """Locate the table holding policy keys within an already-parsed policy document.

    Args:
        document: The parsed policy file.
        path: The file it was parsed from -- used only to tell a standalone
            ``trustedlicenses.toml`` (keys at the document root) apart from a
            ``pyproject.toml`` (keys nested under ``[tool.trustedlicenses]``).

    Returns:
        The table ``allowed-categories``/``ignored-packages`` live directly under.
    """
    if path.name == STANDALONE_FILENAME:
        return document
    table: MutableMapping[str, Any] = document
    for key in CONFIG_SECTION:
        table = table[key]
    return table


def _extend_unique(section: MutableMapping[str, Any], key: str, values: Sequence[str]) -> None:
    """Append values to ``section[key]`` (creating it as a fresh array if absent).

    Args:
        section: The policy table to modify in place.
        key: The array key to extend, e.g. ``"allowed-categories"``.
        values: Values to add. Ones already present (by exact string match) are left
            alone -- not duplicated.
    """
    existing = section.get(key)
    if existing is None:
        section[key] = list(values)
        return
    current = set(existing)
    for value in values:
        if value not in current:
            existing.append(value)
            current.add(value)


def _extend_ignored_packages(
    section: MutableMapping[str, Any], names: Sequence[str], reasons: Mapping[str, str]
) -> None:
    """Append new ``ignored-packages`` entries, each with an inline comment when a reason is given.

    Args:
        section: The policy table to modify in place.
        names: Package names to add. Ones already present (by canonical/PEP-503 name)
            are left alone -- not duplicated, not re-commented.
        reasons: Package name -> one-line reason for accepting it, recorded as a
            trailing comment on that entry. A name absent here gets no comment.
    """
    existing = section.get("ignored-packages")
    current = {canonical_name(name) for name in existing} if existing is not None else set()
    new_names = [name for name in names if canonical_name(name) not in current]
    if not new_names:
        return

    if existing is None:
        existing = tomlkit.array()
        section["ignored-packages"] = existing

    if any(reasons.get(name) for name in new_names):
        # Only reformat to multiline when it's actually needed to attach a comment --
        # otherwise a plain `.append()` (below) leaves an existing single-line array
        # untouched, matching add_to_policy's promise to preserve what's already there.
        existing.multiline(True)  # noqa: FBT003 -- tomlkit's own Array.multiline() API, not ours to name
        for name in new_names:
            reason = reasons.get(name)
            if reason:
                existing.add_line(name, comment=reason)
            else:
                existing.add_line(name)
    else:
        for name in new_names:
            existing.append(name)


def _extend_verified_packages(section: MutableMapping[str, Any], entries: Mapping[str, tuple[str, str]]) -> None:
    """Merge package pins into the ``verified-packages`` table (creating it if absent).

    Args:
        section: The policy table to modify in place.
        entries: Canonical package name -> ``(declared statement, corrected SPDX id)``.
            An entry for a name already pinned replaces the old pin -- re-verifying a
            package is exactly how you'd update one.
    """
    table = section.get("verified-packages")
    if table is None:
        table = tomlkit.table()
        section["verified-packages"] = table
    for name, (statement, spdx_id) in entries.items():
        entry = tomlkit.inline_table()
        entry["statement"] = statement
        entry["spdx-id"] = spdx_id
        table[canonical_name(name)] = entry


def _extend_verified_statements(section: MutableMapping[str, Any], entries: Mapping[str, str]) -> None:
    """Merge statement-text pins into the ``verified-statements`` table (creating it if absent).

    Args:
        section: The policy table to modify in place.
        entries: Declared statement text -> the SPDX id it corrects to.
    """
    table = section.get("verified-statements")
    if table is None:
        table = tomlkit.table()
        section["verified-statements"] = table
    for statement, spdx_id in entries.items():
        table[statement] = spdx_id


@dataclass(frozen=True)
class CorrectionTrust:
    """Free-text correction trust decisions to write via :func:`add_to_policy`.

    Bundled into one parameter rather than three, both to keep ``add_to_policy``'s
    signature manageable and because these three always come from the same place: the
    review wizard's "enable project-wide" / "verify this package" / "trust this text"
    choices.

    Attributes:
        enabled: When not ``None``, sets ``trust-corrected-licenses`` to this value.
            Only ever set to ``True`` in practice -- the wizard doesn't offer to turn
            trust back off.
        verified_packages: Canonical package name -> ``(declared statement, corrected
            SPDX id)`` pins to add to ``verified-packages``.
        verified_statements: Declared statement text -> SPDX id pins to add to
            ``verified-statements``.
    """

    enabled: bool | None = None
    verified_packages: Mapping[str, tuple[str, str]] = field(default_factory=dict)
    verified_statements: Mapping[str, str] = field(default_factory=dict)


def add_to_policy(
    path: Path,
    *,
    ignored_packages: Sequence[str] = (),
    allowed_categories: Sequence[str] = (),
    reasons: Mapping[str, str] | None = None,
    trust: CorrectionTrust | None = None,
) -> None:
    """Append to an already-configured policy file's arrays/tables, in place.

    Unlike :func:`write_policy` -- which always builds a fresh table and would clobber
    an existing config -- this preserves everything already in ``path`` (comments,
    other keys, existing entries) via ``tomlkit``, and only adds what's new. Used by the
    interactive failure-review wizard (:mod:`trustedlicenses.wizard`) to record
    decisions made after a failing check.

    Args:
        path: The policy file to modify -- must already exist and already hold a valid
            policy (see :func:`policy_source` to find it from a ``pyproject.toml``
            path).
        ignored_packages: Canonical package names to add to ``ignored-packages``.
        allowed_categories: Categories to add to ``allowed-categories``.
        reasons: Package name -> one-line reason, recorded as an inline TOML comment on
            that package's new ``ignored-packages`` entry.
        trust: Free-text correction trust decisions to write, if any.
    """
    document = tomlkit.parse(path.read_text())
    section = _policy_table(document, path)

    if allowed_categories:
        _extend_unique(section, "allowed-categories", allowed_categories)
    if ignored_packages:
        _extend_ignored_packages(section, ignored_packages, reasons or {})
    if trust is not None:
        if trust.enabled is not None:
            section["trust-corrected-licenses"] = trust.enabled
        if trust.verified_packages:
            _extend_verified_packages(section, trust.verified_packages)
        if trust.verified_statements:
            _extend_verified_statements(section, trust.verified_statements)

    path.write_text(tomlkit.dumps(document))
