"""Tests for trustedlicenses.index_discovery -- formats mirror real uv/poetry/pipenv output."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from trustedlicenses.index_discovery import DEFAULT_INDEX, discover_index, redact_url

if TYPE_CHECKING:
    from pathlib import Path

INTERNAL = "https://nexus.example.com/repository/pypi-internal/simple"
OTHER = "https://other.example.com/simple"


def _find(project: Path, package: str = "webencodings", **env: str) -> tuple[str, str]:
    choice = discover_index(project, package, environ=env)
    return choice.url, choice.origin


def test_redact_url_strips_credentials_and_leaves_plain_urls_alone() -> None:
    """Credentials never reach the screen; a URL without any is returned as-is."""
    assert redact_url("https://user:s3cret@nexus.example.com/simple") == "https://nexus.example.com/simple"
    assert redact_url(INTERNAL) == INTERNAL


def test_falls_back_to_pypi_and_says_so_when_nothing_is_configured(tmp_path: Path) -> None:
    """No lockfile, config or environment -- pypi.org, labelled as an assumption."""
    url, origin = _find(tmp_path)

    assert url == DEFAULT_INDEX
    assert "default" in origin


def test_uv_lock_records_the_index_per_package(tmp_path: Path) -> None:
    """The lockfile's source for *this* package wins -- the multi-index case."""
    (tmp_path / "uv.lock").write_text(
        f'[[package]]\nname = "webencodings"\nversion = "0.5.1"\nsource = {{ registry = "{INTERNAL}" }}\n\n'
        f'[[package]]\nname = "other"\nversion = "1"\nsource = {{ registry = "{OTHER}" }}\n'
    )

    assert _find(tmp_path) == (INTERNAL, "uv.lock")
    assert _find(tmp_path, "OTHER")[0] == OTHER


def test_uv_lock_ignores_non_http_sources(tmp_path: Path) -> None:
    """An editable/path source isn't an index."""
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "webencodings"\nversion = "1"\nsource = { editable = "." }\n'
    )

    assert _find(tmp_path)[0] == DEFAULT_INDEX


def test_poetry_lock_records_a_legacy_source(tmp_path: Path) -> None:
    """poetry.lock's [package.source] (type = legacy) names the index."""
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "webencodings"\nversion = "0.5.1"\n\n'
        f'[package.source]\ntype = "legacy"\nurl = "{INTERNAL}"\nreference = "internal"\n'
    )

    assert _find(tmp_path) == (INTERNAL, "poetry.lock")


def test_pipfile_lock_resolves_the_named_index(tmp_path: Path) -> None:
    """Pipfile.lock stores an index *name* per package; the URL is in _meta.sources."""
    lock = {
        "_meta": {"sources": [{"name": "pypi", "url": DEFAULT_INDEX}, {"name": "internal", "url": INTERNAL}]},
        "default": {"webencodings": {"index": "internal", "version": "==0.5.1"}},
    }
    (tmp_path / "Pipfile.lock").write_text(json.dumps(lock))

    assert _find(tmp_path) == (INTERNAL, "Pipfile.lock")


def test_pipfile_lock_without_an_index_uses_the_first_source(tmp_path: Path) -> None:
    """A package with no explicit index came from pipenv's first source."""
    lock = {
        "_meta": {"sources": [{"name": "internal", "url": INTERNAL}]},
        "default": {"webencodings": {"version": "==0.5.1"}},
    }
    (tmp_path / "Pipfile.lock").write_text(json.dumps(lock))

    assert _find(tmp_path)[0] == INTERNAL


def test_uv_config_default_index_from_pyproject(tmp_path: Path) -> None:
    """[[tool.uv.index]] with default = true, when there's no lockfile yet."""
    (tmp_path / "pyproject.toml").write_text(
        f'[[tool.uv.index]]\nname = "x"\nurl = "{OTHER}"\n\n'
        f'[[tool.uv.index]]\nname = "d"\nurl = "{INTERNAL}"\ndefault = true\n'
    )

    assert _find(tmp_path) == (INTERNAL, "uv config in pyproject.toml/uv.toml")


def test_uv_toml_legacy_index_url(tmp_path: Path) -> None:
    """uv.toml's plain index-url is honoured too."""
    (tmp_path / "uv.toml").write_text(f'index-url = "{INTERNAL}"\n')

    assert _find(tmp_path)[0] == INTERNAL


def test_poetry_source_prefers_default_then_primary(tmp_path: Path) -> None:
    """[[tool.poetry.source]] by priority; explicit/supplemental sources aren't the main index."""
    (tmp_path / "pyproject.toml").write_text(
        f'[[tool.poetry.source]]\nname = "e"\nurl = "{OTHER}"\npriority = "explicit"\n\n'
        f'[[tool.poetry.source]]\nname = "p"\nurl = "{INTERNAL}"\npriority = "primary"\n'
    )

    assert _find(tmp_path) == (INTERNAL, "[[tool.poetry.source]] in pyproject.toml")


def test_pipfile_first_source(tmp_path: Path) -> None:
    """Pipfile [[source]] (TOML) -- the first one is the main index."""
    (tmp_path / "Pipfile").write_text(f'[[source]]\nurl = "{INTERNAL}"\nverify_ssl = true\nname = "internal"\n')

    assert _find(tmp_path) == (INTERNAL, "Pipfile [[source]]")


def test_environment_variables(tmp_path: Path) -> None:
    """UV_DEFAULT_INDEX, then UV_INDEX_URL, then PIP_INDEX_URL."""
    assert _find(tmp_path, PIP_INDEX_URL=OTHER, UV_INDEX_URL=INTERNAL)[0] == INTERNAL
    assert _find(tmp_path, PIP_INDEX_URL=OTHER) == (OTHER, "index environment variable")


def test_pip_conf(tmp_path: Path) -> None:
    """[global] index-url in a pip.conf named by PIP_CONFIG_FILE."""
    conf = tmp_path / "pip.conf"
    conf.write_text(f"[global]\nindex-url = {INTERNAL}\n")

    assert _find(tmp_path, PIP_CONFIG_FILE=str(conf)) == (INTERNAL, "pip.conf")


def test_lockfile_beats_config_and_environment(tmp_path: Path) -> None:
    """Where the package actually came from outranks what happens to be configured."""
    (tmp_path / "uv.lock").write_text(
        f'[[package]]\nname = "webencodings"\nversion = "1"\nsource = {{ registry = "{INTERNAL}" }}\n'
    )
    (tmp_path / "uv.toml").write_text(f'index-url = "{OTHER}"\n')

    assert _find(tmp_path, PIP_INDEX_URL=OTHER)[0] == INTERNAL


def test_malformed_files_are_ignored_not_fatal(tmp_path: Path) -> None:
    """A broken lockfile/config falls through to the next source instead of crashing."""
    (tmp_path / "uv.lock").write_text("not [ valid toml")
    (tmp_path / "Pipfile.lock").write_text("{nope")

    assert _find(tmp_path)[0] == DEFAULT_INDEX


def test_malformed_pip_conf_is_ignored_not_fatal(tmp_path: Path) -> None:
    """A pip.conf that can't be parsed falls through instead of crashing."""
    conf = tmp_path / "pip.conf"
    conf.write_bytes(b"[global\xffbroken")

    assert _find(tmp_path, PIP_CONFIG_FILE=str(conf))[0] == DEFAULT_INDEX


def test_poetry_lock_default_source_package_does_not_claim_an_index(tmp_path: Path) -> None:
    """A package poetry resolved from its default source has no [package.source] table at all.

    Verified against real `poetry lock` output for a plain (no custom source)
    dependency -- there's no source table to read, so this must fall through rather
    than mistake "no source recorded" for "this is the index".
    """
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "webencodings"\nversion = "0.5.1"\n')

    assert _find(tmp_path)[0] == DEFAULT_INDEX
