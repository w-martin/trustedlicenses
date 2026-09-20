"""Tests for trustedlicenses.config."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from trustedlicenses.config import (
    ConfigError,
    CorrectionTrust,
    NoPolicyConfiguredError,
    add_to_policy,
    load_policy,
    policy_source,
    write_policy,
)

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


def test_load_policy_defaults_correction_trust_fields_to_off_and_empty(tmp_path: Path) -> None:
    """No trust-corrected-licenses/verified-packages/verified-statements -- all default off/empty."""
    path = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    policy = load_policy(path)

    assert policy.trust_corrected_licenses is False
    assert policy.verified_packages == {}
    assert policy.verified_statements == {}


def test_load_policy_reads_trust_corrected_licenses(tmp_path: Path) -> None:
    """trust-corrected-licenses = true is read through to the Policy."""
    path = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\ntrust-corrected-licenses = true\n',
    )

    assert load_policy(path).trust_corrected_licenses is True


def test_load_policy_reads_verified_packages(tmp_path: Path) -> None:
    """verified-packages entries resolve to (statement, spdx id) pairs, keyed by canonical name."""
    path = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n'
        "[tool.trustedlicenses.verified-packages]\n"
        'CatBoost = { statement = "Apache License, Version 2.0", spdx-id = "Apache-2.0" }\n',
    )

    policy = load_policy(path)

    assert policy.verified_packages == {"catboost": ("Apache License, Version 2.0", "Apache-2.0")}


def test_load_policy_raises_when_a_verified_package_entry_is_malformed(tmp_path: Path) -> None:
    """A verified-packages entry missing statement/spdx-id is a real misconfiguration."""
    path = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n'
        "[tool.trustedlicenses.verified-packages]\n"
        'catboost = { statement = "Apache License, Version 2.0" }\n',
    )

    with pytest.raises(ConfigError, match="verified-packages"):
        load_policy(path)


def test_load_policy_reads_verified_statements(tmp_path: Path) -> None:
    """verified-statements entries resolve to a plain statement -> spdx id mapping."""
    path = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n'
        "[tool.trustedlicenses.verified-statements]\n"
        '"Apache License, Version 2.0" = "Apache-2.0"\n',
    )

    policy = load_policy(path)

    assert policy.verified_statements == {"Apache License, Version 2.0": "Apache-2.0"}


def test_load_policy_raises_when_verified_packages_is_not_a_table(tmp_path: Path) -> None:
    """verified-packages must be a table, not e.g. a list."""
    path = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\nverified-packages = ["not-a-table"]\n',
    )

    with pytest.raises(ConfigError, match="verified-packages"):
        load_policy(path)


def test_load_policy_raises_when_verified_statements_is_not_a_table(tmp_path: Path) -> None:
    """verified-statements must be a table, not e.g. a list."""
    path = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\nverified-statements = ["not-a-table"]\n',
    )

    with pytest.raises(ConfigError, match="verified-statements"):
        load_policy(path)


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


def test_policy_source_is_pyproject_when_no_standalone_file_exists(tmp_path: Path) -> None:
    """With no sibling trustedlicenses.toml, pyproject.toml itself is the source."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    assert policy_source(pyproject) == pyproject


def test_policy_source_prefers_the_standalone_file(tmp_path: Path) -> None:
    """Matches load_policy's own "standalone wins" rule."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Copyleft"]\n')
    standalone = tmp_path / "trustedlicenses.toml"
    standalone.write_text('allowed-categories = ["Permissive"]\n')

    assert policy_source(pyproject) == standalone


def test_add_to_policy_appends_to_an_existing_pyproject_table(tmp_path: Path) -> None:
    """New ignored-packages/allowed-categories are added; everything else survives."""
    pyproject = _write_pyproject(
        tmp_path,
        '[project]\nname = "x"\n# keep me\n\n[tool.trustedlicenses]\n'
        'allowed-categories = ["Permissive"]\nignored-packages = ["mypy-extensions"]\n',
    )

    add_to_policy(
        pyproject,
        ignored_packages=["catboost"],
        allowed_categories=["Copyleft Limited"],
        reasons={"catboost": "no license detected -- accepted 2026-09-15"},
    )

    text = pyproject.read_text()
    assert "# keep me" in text
    assert "no license detected -- accepted 2026-09-15" in text
    policy = load_policy(pyproject)
    assert policy.allowed_categories == frozenset({"Permissive", "Copyleft Limited"})
    assert policy.ignored_packages == frozenset({"mypy-extensions", "catboost"})


def test_add_to_policy_appends_to_a_standalone_file(tmp_path: Path) -> None:
    """The standalone file (root-level keys, no [tool.trustedlicenses] wrapper) also works."""
    pyproject = _write_pyproject(tmp_path, '[project]\nname = "x"\n')
    standalone = tmp_path / "trustedlicenses.toml"
    standalone.write_text('allowed-categories = ["Permissive"]\n')

    add_to_policy(standalone, ignored_packages=["ds-mlops-components"])

    policy = load_policy(pyproject)
    assert policy.ignored_packages == frozenset({"ds-mlops-components"})


def test_add_to_policy_keeps_an_existing_array_single_line_when_no_reason_is_given(tmp_path: Path) -> None:
    """Adding a package with no reason doesn't reformat an existing single-line array.

    Only attaching a comment requires TOML's multiline array form -- an addition
    with nothing to comment on shouldn't touch the formatting of entries that were
    already there.
    """
    pyproject = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\nignored-packages = ["a", "b"]\n',
    )

    add_to_policy(pyproject, ignored_packages=["c"])

    text = pyproject.read_text()
    assert 'ignored-packages = ["a", "b", "c"]' in text
    assert load_policy(pyproject).ignored_packages == frozenset({"a", "b", "c"})


def test_add_to_policy_does_not_duplicate_an_already_ignored_package(tmp_path: Path) -> None:
    """A package already in ignored-packages (any case/separator) isn't added again."""
    pyproject = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\nignored-packages = ["Some_Package"]\n',
    )

    add_to_policy(pyproject, ignored_packages=["some-package"])

    assert pyproject.read_text().count("some-package") + pyproject.read_text().count("Some_Package") == 1
    assert load_policy(pyproject).ignored_packages == frozenset({"some-package"})


def test_add_to_policy_does_not_duplicate_an_already_allowed_category(tmp_path: Path) -> None:
    """A category already in allowed-categories isn't added again."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    add_to_policy(pyproject, allowed_categories=["Permissive"])

    assert pyproject.read_text().count("Permissive") == 1


def test_add_to_policy_sets_trust_corrected_licenses(tmp_path: Path) -> None:
    """CorrectionTrust(enabled=True) sets the project-wide flag."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    add_to_policy(pyproject, trust=CorrectionTrust(enabled=True))

    assert load_policy(pyproject).trust_corrected_licenses is True


def test_add_to_policy_writes_a_verified_package_pin(tmp_path: Path) -> None:
    """CorrectionTrust.verified_packages round-trips through load_policy."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    add_to_policy(
        pyproject,
        trust=CorrectionTrust(verified_packages={"catboost": ("Apache License, Version 2.0", "Apache-2.0")}),
    )

    policy = load_policy(pyproject)
    assert policy.verified_packages == {"catboost": ("Apache License, Version 2.0", "Apache-2.0")}


def test_add_to_policy_writes_a_verified_statement_pin(tmp_path: Path) -> None:
    """CorrectionTrust.verified_statements round-trips through load_policy."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    add_to_policy(
        pyproject,
        trust=CorrectionTrust(verified_statements={"Apache License, Version 2.0": "Apache-2.0"}),
    )

    policy = load_policy(pyproject)
    assert policy.verified_statements == {"Apache License, Version 2.0": "Apache-2.0"}


def test_add_to_policy_re_verifying_a_package_replaces_its_old_pin(tmp_path: Path) -> None:
    """Adding a new pin for an already-pinned package updates it, rather than erroring or duplicating."""
    pyproject = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n'
        "[tool.trustedlicenses.verified-packages]\n"
        'catboost = { statement = "Old Text", spdx-id = "MIT" }\n',
    )

    add_to_policy(
        pyproject,
        trust=CorrectionTrust(verified_packages={"catboost": ("Apache License, Version 2.0", "Apache-2.0")}),
    )

    policy = load_policy(pyproject)
    assert policy.verified_packages == {"catboost": ("Apache License, Version 2.0", "Apache-2.0")}


def test_add_to_policy_writes_a_second_verified_statement_into_an_existing_table(tmp_path: Path) -> None:
    """Adding another statement pin extends an already-existing verified-statements table."""
    pyproject = _write_pyproject(
        tmp_path,
        '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n'
        "[tool.trustedlicenses.verified-statements]\n"
        '"MIT License" = "MIT"\n',
    )

    add_to_policy(pyproject, trust=CorrectionTrust(verified_statements={"Apache License, Version 2.0": "Apache-2.0"}))

    policy = load_policy(pyproject)
    assert policy.verified_statements == {
        "MIT License": "MIT",
        "Apache License, Version 2.0": "Apache-2.0",
    }


def test_add_to_policy_ignoring_a_mixed_batch_only_comments_the_ones_with_a_reason(tmp_path: Path) -> None:
    """One new package has a reason, another doesn't -- only the first gets a comment."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    add_to_policy(
        pyproject,
        ignored_packages=["catboost", "no-reason-pkg"],
        reasons={"catboost": "no license detected -- accepted 2026-09-18"},
    )

    text = pyproject.read_text()
    assert "catboost" in text
    assert "no license detected -- accepted 2026-09-18" in text
    assert "no-reason-pkg" in text
    assert load_policy(pyproject).ignored_packages == frozenset({"catboost", "no-reason-pkg"})


def test_add_to_policy_with_no_trust_leaves_correction_settings_untouched(tmp_path: Path) -> None:
    """Omitting `trust` entirely (the default) doesn't add any of the three new keys."""
    pyproject = _write_pyproject(tmp_path, '[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    add_to_policy(pyproject, ignored_packages=["somepkg"])

    text = pyproject.read_text()
    assert "trust-corrected-licenses" not in text
    assert "verified-packages" not in text
    assert "verified-statements" not in text
