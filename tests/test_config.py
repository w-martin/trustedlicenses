"""Tests for trustedlicenses.config."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from trustedlicenses.config import ConfigError, NoPolicyConfiguredError, load_policy, write_policy

if TYPE_CHECKING:
    from pathlib import Path


def _write_pyproject(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "pyproject.toml"
    path.write_text(body)
    return path


def test_load_policy_reads_a_valid_config(tmp_path: Path) -> None:
    """A [tool.trustedlicenses] table resolves to a matching Policy."""
    path = _write_pyproject(
        tmp_path,
        """
        [tool.trustedlicenses]
        allowed-categories = ["Permissive", "Public Domain"]
        ignored-packages = ["mypy-extensions", "Some_Package"]
        """,
    )

    policy = load_policy(path)

    assert policy.allowed_categories == frozenset({"Permissive", "Public Domain"})
    assert policy.ignored_packages == frozenset({"mypy-extensions", "some-package"})


def test_load_policy_defaults_ignored_packages_to_empty(tmp_path: Path) -> None:
    """ignored-packages is optional and defaults to an empty set."""
    path = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    policy = load_policy(path)

    assert policy.ignored_packages == frozenset()


def test_load_policy_raises_no_policy_configured_when_file_missing(tmp_path: Path) -> None:
    """A nonexistent pyproject.toml is "unconfigured", not "misconfigured" -- NoPolicyConfiguredError."""
    with pytest.raises(NoPolicyConfiguredError, match=r"\[tool\.trustedlicenses\]"):
        load_policy(tmp_path / "nope.toml")


def test_load_policy_raises_no_policy_configured_when_table_missing(tmp_path: Path) -> None:
    """A pyproject.toml with no [tool.trustedlicenses] table is unconfigured, not broken."""
    path = _write_pyproject(tmp_path, "[tool.other]\nfoo = 1\n")

    with pytest.raises(NoPolicyConfiguredError, match=r"\[tool\.trustedlicenses\]"):
        load_policy(path)


def test_load_policy_raises_plain_config_error_when_allowed_categories_missing(tmp_path: Path) -> None:
    """A table with no allowed-categories key is a real misconfiguration -- a plain ConfigError.

    Distinct from NoPolicyConfiguredError: the project clearly tried to configure
    trustedlicenses (the table exists) and got it wrong, rather than not opting in at
    all, so this should not silently fall back to report mode.
    """
    path = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nignored-packages = ["x"]\n')

    with pytest.raises(ConfigError, match="allowed-categories") as exc_info:
        load_policy(path)
    assert not isinstance(exc_info.value, NoPolicyConfiguredError)


def test_load_policy_raises_plain_config_error_when_allowed_categories_empty(tmp_path: Path) -> None:
    """An empty allowed-categories list is treated the same as a missing one."""
    path = _write_pyproject(tmp_path, "[tool.trustedlicenses]\nallowed-categories = []\n")

    with pytest.raises(ConfigError, match="allowed-categories") as exc_info:
        load_policy(path)
    assert not isinstance(exc_info.value, NoPolicyConfiguredError)


def test_load_policy_resolves_project_license_from_pep_639_string(tmp_path: Path) -> None:
    """[project.license] as a bare SPDX-expression string (PEP 639) resolves directly."""
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "consuming-project"
        license = "GPL-3.0-only"

        [tool.trustedlicenses]
        allowed-categories = ["Copyleft"]
        """,
    )

    policy = load_policy(path)

    assert policy.project_license_keys == frozenset({"GPL-3.0-only"})


def test_load_policy_resolves_project_license_from_legacy_table_form(tmp_path: Path) -> None:
    """The pre-PEP-639 license = {text = "..."} table form is also read."""
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "consuming-project"
        license = { text = "MIT" }

        [tool.trustedlicenses]
        allowed-categories = ["Permissive"]
        """,
    )

    policy = load_policy(path)

    assert policy.project_license_keys == frozenset({"MIT"})


def test_load_policy_resolves_project_license_from_classifiers(tmp_path: Path) -> None:
    """A License :: classifier resolves too, independent of the license field."""
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "consuming-project"
        classifiers = ["License :: OSI Approved :: MIT License"]

        [tool.trustedlicenses]
        allowed-categories = ["Permissive"]
        """,
    )

    policy = load_policy(path)

    assert policy.project_license_keys == frozenset({"MIT"})


def test_load_policy_defaults_project_license_keys_to_empty_without_project_table(tmp_path: Path) -> None:
    """No [project] table at all (this project's own scaffold shape) resolves to empty."""
    path = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    policy = load_policy(path)

    assert policy.project_license_keys == frozenset()


def test_load_policy_defaults_project_license_keys_to_empty_when_unresolvable(tmp_path: Path) -> None:
    """A license = {file = "..."} form isn't parsed further -- resolves to empty, not an error."""
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "consuming-project"
        license = { file = "LICENSE" }

        [tool.trustedlicenses]
        allowed-categories = ["Permissive"]
        """,
    )

    policy = load_policy(path)

    assert policy.project_license_keys == frozenset()


def test_load_policy_reads_a_standalone_trustedlicenses_toml(tmp_path: Path) -> None:
    """A sibling trustedlicenses.toml, with no [tool.trustedlicenses] wrapper, is read directly."""
    pyproject = _write_pyproject(tmp_path, "[project]\nname = 'x'\n")
    (tmp_path / "trustedlicenses.toml").write_text(
        'allowed-categories = ["Permissive"]\nignored-packages = ["mypy-extensions"]\n'
    )

    policy = load_policy(pyproject)

    assert policy.allowed_categories == frozenset({"Permissive"})
    assert policy.ignored_packages == frozenset({"mypy-extensions"})


def test_load_policy_prefers_the_standalone_file_over_pyprojects_table(tmp_path: Path) -> None:
    """When both exist, the standalone file wins -- it's the more specific, deliberate choice."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Copyleft"]\n')
    (tmp_path / "trustedlicenses.toml").write_text('allowed-categories = ["Permissive"]\n')

    policy = load_policy(pyproject)

    assert policy.allowed_categories == frozenset({"Permissive"})


def test_load_policy_still_reads_project_license_from_pyproject_with_a_standalone_file(tmp_path: Path) -> None:
    """The project's own [project.license] always comes from pyproject.toml, regardless of policy source."""
    pyproject = _write_pyproject(tmp_path, '[project]\nname = "x"\nlicense = "MIT"\n')
    (tmp_path / "trustedlicenses.toml").write_text('allowed-categories = ["Permissive"]\n')

    policy = load_policy(pyproject)

    assert policy.project_license_keys == frozenset({"MIT"})


def test_load_policy_standalone_file_also_raises_plain_config_error_when_broken(tmp_path: Path) -> None:
    """A standalone file with no allowed-categories is a real misconfiguration too."""
    pyproject = _write_pyproject(tmp_path, "[project]\nname = 'x'\n")
    (tmp_path / "trustedlicenses.toml").write_text("ignored-packages = []\n")

    with pytest.raises(ConfigError, match="allowed-categories") as exc_info:
        load_policy(pyproject)
    assert not isinstance(exc_info.value, NoPolicyConfiguredError)


def test_write_policy_adds_a_table_to_an_existing_pyproject_preserving_the_rest(tmp_path: Path) -> None:
    """Writing to pyproject.toml only adds the new table -- everything else survives untouched."""
    pyproject = _write_pyproject(
        tmp_path,
        '[project]\nname = "x"\n# a comment worth preserving\n\n[tool.other]\nfoo = 1\n',
    )

    written = write_policy(
        pyproject,
        allowed_categories=["Permissive", "Public Domain"],
        ignored_packages=["mypy-extensions"],
        standalone=False,
    )

    assert written == pyproject
    text = pyproject.read_text()
    assert "# a comment worth preserving" in text
    assert "[tool.other]" in text
    assert "foo = 1" in text
    policy = load_policy(pyproject)
    assert policy.allowed_categories == frozenset({"Permissive", "Public Domain"})
    assert policy.ignored_packages == frozenset({"mypy-extensions"})


def test_write_policy_omits_ignored_packages_when_none_given(tmp_path: Path) -> None:
    """No ignored packages -- don't write an empty ignored-packages key at all."""
    pyproject = _write_pyproject(tmp_path, '[project]\nname = "x"\n')

    write_policy(pyproject, allowed_categories=["Permissive"], standalone=False)

    assert "ignored-packages" not in pyproject.read_text()


def test_write_policy_writes_a_standalone_file(tmp_path: Path) -> None:
    """standalone=True writes trustedlicenses.toml, with no [tool.trustedlicenses] wrapper."""
    pyproject = tmp_path / "pyproject.toml"

    written = write_policy(pyproject, allowed_categories=["Permissive"], standalone=True)

    assert written == tmp_path / "trustedlicenses.toml"
    text = written.read_text()
    assert "[tool.trustedlicenses]" not in text
    assert "Permissive" in text


def test_write_policy_writes_a_standalone_file_with_ignored_packages(tmp_path: Path) -> None:
    """standalone=True also writes ignored-packages when given some."""
    pyproject = tmp_path / "pyproject.toml"

    written = write_policy(
        pyproject, allowed_categories=["Permissive"], ignored_packages=["mypy-extensions"], standalone=True
    )

    text = written.read_text()
    assert "ignored-packages" in text
    assert "mypy-extensions" in text


def test_write_policy_raises_when_editing_a_pyproject_that_does_not_exist(tmp_path: Path) -> None:
    """standalone=False with no pyproject.toml to edit is a clear error, not a silent no-op."""
    pyproject = tmp_path / "pyproject.toml"

    with pytest.raises(ConfigError, match="doesn't exist"):
        write_policy(pyproject, allowed_categories=["Permissive"], standalone=False)
