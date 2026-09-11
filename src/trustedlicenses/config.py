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
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit

from trustedlicenses.detection import canonical_name, resolve_license_expression

if TYPE_CHECKING:
    from collections.abc import Sequence
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

    document: dict[str, Any] = {}
    if path.is_file():
        with path.open("rb") as handle:
            document = tomllib.load(handle)

    if standalone_path.is_file():
        with standalone_path.open("rb") as handle:
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
    )


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
