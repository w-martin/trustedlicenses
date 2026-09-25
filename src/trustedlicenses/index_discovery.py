"""Work out which package index to ask about a package, from what the project already configures.

Nothing here touches the network. The answer is always shown to the user for
confirmation before anything is sent (see :mod:`trustedlicenses.wizard`), because
guessing wrong could send an internal package's name to a public host.

Sources, first hit wins:

1. The project's lockfile -- it records which index each package actually came from, so
   this is right even for multi-index projects: ``uv.lock``, ``poetry.lock``,
   ``Pipfile.lock``.
2. Index settings in the project's own files: uv (``[tool.uv]`` / ``uv.toml``), poetry
   (``[[tool.poetry.source]]``), pipenv (``Pipfile``).
3. The environment (``UV_DEFAULT_INDEX``, ``UV_INDEX_URL``, ``PIP_INDEX_URL``) and
   ``pip.conf``.
4. Nothing configured: pypi.org, labelled as the default so the user can see that's what
   is being assumed.

Credentials are deliberately not handled here -- they come from the user's environment.
"""

from __future__ import annotations

import configparser
import json
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

from trustedlicenses.detection import canonical_name

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

DEFAULT_INDEX = "https://pypi.org/simple"


@dataclass(frozen=True)
class IndexChoice:
    """The index to ask, and why.

    Attributes:
        url: The index's "simple" API URL. May contain credentials if the user's own
            configuration does -- display it via :func:`redact_url`.
        origin: Human-readable reason this index was chosen, e.g. ``"uv.lock"``.
    """

    url: str
    origin: str


def redact_url(url: str) -> str:
    """Strip any ``user:password@`` from a URL, so it's safe to print.

    Args:
        url: A URL that may embed credentials.

    Returns:
        The same URL without userinfo.
    """
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]))


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text("utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _is_url(value: object) -> bool:
    return isinstance(value, str) and value.startswith(("http://", "https://"))


def _from_uv_lock(project_dir: Path, name: str) -> str | None:
    for package in _load_toml(project_dir / "uv.lock").get("package", []):
        if canonical_name(package.get("name", "")) == name:
            registry = (package.get("source") or {}).get("registry")
            return registry if _is_url(registry) else None
    return None


def _from_poetry_lock(project_dir: Path, name: str) -> str | None:
    for package in _load_toml(project_dir / "poetry.lock").get("package", []):
        source = package.get("source") or {}
        if canonical_name(package.get("name", "")) == name and source.get("type") == "legacy":
            return source.get("url") if _is_url(source.get("url")) else None
    return None


def _from_pipfile_lock(project_dir: Path, name: str) -> str | None:
    try:
        lock = json.loads((project_dir / "Pipfile.lock").read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    sources = lock.get("_meta", {}).get("sources", [])
    by_name = {source.get("name"): source.get("url") for source in sources}
    for section in ("default", "develop"):
        entries = {canonical_name(key): value for key, value in lock.get(section, {}).items()}
        if name in entries:
            url = by_name.get(entries[name].get("index")) or (sources[0].get("url") if sources else None)
            return url if _is_url(url) else None
    return None


def _uv_table_index(table: Mapping[str, Any]) -> str | None:
    for index in table.get("index", []):
        if isinstance(index, dict) and index.get("default") and _is_url(index.get("url")):
            return index["url"]
    legacy = table.get("index-url")
    return legacy if _is_url(legacy) else None


def _from_uv_config(project_dir: Path) -> str | None:
    pyproject_table = _load_toml(project_dir / "pyproject.toml").get("tool", {}).get("uv", {})
    return _uv_table_index(pyproject_table) or _uv_table_index(_load_toml(project_dir / "uv.toml"))


def _from_poetry_config(project_dir: Path) -> str | None:
    sources = _load_toml(project_dir / "pyproject.toml").get("tool", {}).get("poetry", {}).get("source", [])
    for priority in ("default", "primary"):
        for source in sources:
            if source.get("priority") == priority and _is_url(source.get("url")):
                return source["url"]
    return None


def _from_pipfile(project_dir: Path) -> str | None:
    sources = _load_toml(project_dir / "Pipfile").get("source", [])
    return sources[0].get("url") if sources and _is_url(sources[0].get("url")) else None


def _from_environment(environ: Mapping[str, str]) -> str | None:
    return next(
        (environ[key] for key in ("UV_DEFAULT_INDEX", "UV_INDEX_URL", "PIP_INDEX_URL") if _is_url(environ.get(key))),
        None,
    )


def _pip_conf_paths(environ: Mapping[str, str]) -> list[Path]:
    candidates = [
        Path(environ["PIP_CONFIG_FILE"]) if environ.get("PIP_CONFIG_FILE") else None,
        Path(environ["APPDATA"]) / "pip" / "pip.ini" if environ.get("APPDATA") else None,
        Path.home() / ".config" / "pip" / "pip.conf",
        Path.home() / "Library" / "Application Support" / "pip" / "pip.conf",
        Path.home() / ".pip" / "pip.conf",
        Path(sys.prefix) / "pip.conf",
        Path("/etc/pip.conf"),
    ]
    return [path for path in candidates if path is not None]


def _from_pip_conf(environ: Mapping[str, str]) -> str | None:
    for path in _pip_conf_paths(environ):
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(path, encoding="utf-8")
        except (OSError, ValueError, configparser.Error):
            # ValueError covers UnicodeDecodeError -- a pip.conf in a different
            # encoding shouldn't crash discovery, just be skipped like any other
            # unparseable config.
            continue
        for section in ("global", "install"):
            if parser.has_option(section, "index-url") and _is_url(parser.get(section, "index-url")):
                return parser.get(section, "index-url")
    return None


def discover_index(project_dir: Path, package: str, environ: Mapping[str, str] | None = None) -> IndexChoice:
    """Choose the index to ask about ``package``.

    Args:
        project_dir: The project directory (where the lockfile and config live).
        package: The package's name, any case/separator.
        environ: Environment to read; defaults to ``os.environ``.

    Returns:
        The chosen index and the reason. Falls back to pypi.org, labelled as the
        default, when nothing is configured.
    """
    env = os.environ if environ is None else environ
    name = canonical_name(package)
    lockfiles: tuple[tuple[str, Callable[[], str | None]], ...] = (
        ("uv.lock", lambda: _from_uv_lock(project_dir, name)),
        ("poetry.lock", lambda: _from_poetry_lock(project_dir, name)),
        ("Pipfile.lock", lambda: _from_pipfile_lock(project_dir, name)),
        ("uv config in pyproject.toml/uv.toml", lambda: _from_uv_config(project_dir)),
        ("[[tool.poetry.source]] in pyproject.toml", lambda: _from_poetry_config(project_dir)),
        ("Pipfile [[source]]", lambda: _from_pipfile(project_dir)),
        ("index environment variable", lambda: _from_environment(env)),
        ("pip.conf", lambda: _from_pip_conf(env)),
    )
    for origin, find in lockfiles:
        if url := find():
            return IndexChoice(url=url, origin=origin)
    return IndexChoice(url=DEFAULT_INDEX, origin="default -- no index is configured for this project")
