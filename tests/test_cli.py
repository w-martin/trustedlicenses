"""Tests for trustedlicenses.cli."""

from __future__ import annotations

from typing import TYPE_CHECKING

from typer.testing import CliRunner

from tests.conftest import GPL2_LICENSE_TEXT, MIT_LICENSE_TEXT, make_distribution
from trustedlicenses import cli
from trustedlicenses.cli import app
from trustedlicenses.config import ConfigError
from trustedlicenses.detection import DistributionLicence
from trustedlicenses.policy import Policy, PolicyResult
from trustedlicenses.resolve import ResolutionError

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

runner = CliRunner()


def test_main_returns_zero_when_everything_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A passing policy exits 0 and reports how many packages were checked."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    monkeypatch.setattr(cli, "detect_all", lambda **_kwargs: ())
    monkeypatch.setattr(cli, "reevaluate", lambda _detected, _policy: PolicyResult(failures=(), checked=3))

    result = runner.invoke(app, ["--pyproject", str(pyproject)])

    assert result.exit_code == 0
    assert "All 3 packages passed." in result.output


def test_main_returns_one_when_a_package_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing policy exits 1 and lists the failing package."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')
    failure = DistributionLicence(
        name="gplpkg", keys=frozenset({"gpl-2.0"}), categories=frozenset({"Copyleft"}), source="license files: X"
    )

    monkeypatch.setattr(cli, "detect_all", lambda **_kwargs: ())
    monkeypatch.setattr(cli, "reevaluate", lambda _detected, _policy: PolicyResult(failures=(failure,), checked=3))

    result = runner.invoke(app, ["--pyproject", str(pyproject)])

    assert result.exit_code == 1
    assert "Disallowed or undetectable licenses in 1 of 3 packages" in result.output
    assert "gplpkg" in result.output


def test_main_prints_compatibility_notes_without_affecting_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Compatibility notes are informational -- they print, but a passing run still exits 0."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    monkeypatch.setattr(cli, "detect_all", lambda **_kwargs: ())
    monkeypatch.setattr(
        cli,
        "reevaluate",
        lambda _detected, _policy: PolicyResult(failures=(), checked=3, compatibility_notes=("  gplpkg: a note",)),
    )

    result = runner.invoke(app, ["--pyproject", str(pyproject)])

    assert result.exit_code == 0
    assert "compatibility note" in result.output
    assert "gplpkg: a note" in result.output
    assert "All 3 packages passed." in result.output


def test_main_returns_one_on_config_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken (not just unconfigured) config exits 1 and reports the error."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    def _raise(_path: Path) -> Policy:
        message = "allowed-categories is broken somehow"
        raise ConfigError(message)

    monkeypatch.setattr(cli, "load_policy", _raise)

    result = runner.invoke(app, ["--pyproject", str(pyproject)])

    assert result.exit_code == 1
    assert "allowed-categories is broken somehow" in result.output


def test_main_falls_back_to_report_mode_when_not_interactive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No config, and no real terminal attached (the CliRunner default) -- report mode, exit 0.

    This is also exactly the safety behavior CI/pre-commit need: never hang waiting
    for input just because a policy wasn't configured.
    """
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'unconfigured'\n")
    detected = DistributionLicence(
        name="somepkg", keys=frozenset({"MIT"}), categories=frozenset({"Permissive"}), source="declared metadata"
    )

    monkeypatch.setattr(cli, "detect_all", lambda: (detected,))

    result = runner.invoke(app, ["--pyproject", str(pyproject)])

    assert result.exit_code == 0
    assert "no policy configured" in result.output
    assert "somepkg" in result.output
    assert "MIT" in result.output
    assert "Add a policy" in result.output


def test_main_falls_back_to_report_mode_with_quiet_even_if_interactive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--quiet suppresses the wizard even when a real terminal is attached."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'unconfigured'\n")

    # isatty() True simulates a real terminal; --quiet on the command line should
    # still win regardless (`not quiet` short-circuits before isatty() is even read).
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli, "detect_all", lambda: ())

    result = runner.invoke(app, ["--pyproject", str(pyproject), "--quiet"])

    assert result.exit_code == 0
    assert "no policy configured" in result.output


def test_main_runs_the_wizard_when_no_policy_and_interactive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No config, but a real terminal is attached and --quiet wasn't passed -- launch the wizard.

    Answers: run guided setup, allow Permissive/Public Domain/Copyleft Limited,
    decline Copyleft, decline saving to a standalone file (use pyproject.toml),
    confirm writing.
    """
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'consuming-project'\n")

    monkeypatch.setattr(cli, "_should_offer_wizard", lambda **_kwargs: True)
    monkeypatch.setattr("trustedlicenses.wizard.detect_all", lambda: ())
    monkeypatch.setattr(cli, "detect_all", lambda **_kwargs: ())
    monkeypatch.setattr(cli, "reevaluate", lambda _detected, _policy: PolicyResult(failures=(), checked=1))

    result = runner.invoke(app, ["--pyproject", str(pyproject)], input="y\ny\ny\ny\nn\nn\ny\n")

    assert result.exit_code == 0
    assert "Wrote policy to" in result.output
    assert "All 1 packages passed." in result.output
    written = pyproject.read_text()
    assert "[tool.trustedlicenses]" in written
    assert "Permissive" in written
    assert "Public Domain" in written
    assert "Copyleft Limited" in written
    assert '"Copyleft"' not in written  # declined -- only "Copyleft Limited" should be present


def test_main_reports_no_policy_when_wizard_is_declined(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Declining the wizard's up-front offer leaves nothing to write -- report mode, not a crash."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'consuming-project'\n")

    monkeypatch.setattr(cli, "_should_offer_wizard", lambda **_kwargs: True)
    monkeypatch.setattr("trustedlicenses.wizard.detect_all", lambda: ())
    monkeypatch.setattr(cli, "detect_all", lambda: ())

    result = runner.invoke(app, ["--pyproject", str(pyproject)], input="n\n")

    assert result.exit_code == 0
    assert "no policy configured" in result.output
    assert not pyproject.read_text().count("[tool.trustedlicenses]")


def test_main_does_not_offer_review_when_not_interactive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failing check with no real terminal attached (the CliRunner default) never offers to review."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')
    failure = DistributionLicence(name="catboost", keys=frozenset(), categories=frozenset(), source="x")

    monkeypatch.setattr(cli, "detect_all", lambda **_kwargs: ())
    monkeypatch.setattr(cli, "reevaluate", lambda _detected, _policy: PolicyResult(failures=(failure,), checked=1))

    result = runner.invoke(app, ["--pyproject", str(pyproject)])

    assert result.exit_code == 1
    assert "Review" not in result.output


def test_main_does_not_offer_review_with_quiet_even_if_interactive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--quiet suppresses the review offer too, even with a real terminal attached."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')
    failure = DistributionLicence(name="catboost", keys=frozenset(), categories=frozenset(), source="x")

    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(cli, "detect_all", lambda **_kwargs: ())
    monkeypatch.setattr(cli, "reevaluate", lambda _detected, _policy: PolicyResult(failures=(failure,), checked=1))

    result = runner.invoke(app, ["--pyproject", str(pyproject), "--quiet"])

    assert result.exit_code == 1
    assert "Review" not in result.output


def test_main_offers_review_after_a_failing_check_and_reevaluates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Accepting the review, ignoring the failure, exits 0 against the re-evaluated (now passing) policy.

    Also verifies the efficiency fix directly: detection runs exactly once (the
    expensive part), even though the policy is folded against it twice.
    """
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')
    failure = DistributionLicence(name="catboost", keys=frozenset(), categories=frozenset(), source="x")
    calls = {"detect_all": 0, "reevaluate": 0}

    def fake_detect_all(**_kwargs: object) -> tuple[DistributionLicence, ...]:
        calls["detect_all"] += 1
        return ()

    def fake_reevaluate(_detected: object, _policy: object) -> PolicyResult:
        calls["reevaluate"] += 1
        if calls["reevaluate"] == 1:
            return PolicyResult(failures=(failure,), checked=1)
        return PolicyResult(failures=(), checked=1)

    monkeypatch.setattr(cli, "_should_offer_wizard", lambda **_kwargs: True)
    monkeypatch.setattr(cli, "detect_all", fake_detect_all)
    monkeypatch.setattr(cli, "reevaluate", fake_reevaluate)

    # "review now?" y, choice "i" (ignore catboost), "write?" y
    result = runner.invoke(app, ["--pyproject", str(pyproject)], input="y\ni\ny\n")

    assert result.exit_code == 0
    assert "Re-checking against the updated policy" in result.output
    assert "All 1 packages passed." in result.output
    assert "catboost" in pyproject.read_text()
    assert calls["detect_all"] == 1
    expected_reevaluate_calls = 2  # once before the wizard, once after it writes
    assert calls["reevaluate"] == expected_reevaluate_calls


def test_main_keeps_the_failing_exit_code_when_review_is_declined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Declining the review's up-front offer leaves the original failure (and exit 1) in place."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')
    failure = DistributionLicence(name="catboost", keys=frozenset(), categories=frozenset(), source="x")

    monkeypatch.setattr(cli, "_should_offer_wizard", lambda **_kwargs: True)
    monkeypatch.setattr(cli, "detect_all", lambda **_kwargs: ())
    monkeypatch.setattr(cli, "reevaluate", lambda _detected, _policy: PolicyResult(failures=(failure,), checked=1))

    result = runner.invoke(app, ["--pyproject", str(pyproject)], input="n\n")

    assert result.exit_code == 1
    assert "Re-checking" not in result.output
    assert "catboost" not in pyproject.read_text()


def test_check_subcommand_reports_pass_for_a_resolved_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A candidate package resolved into an isolated dir is checked, and passes cleanly."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    def fake_resolve(_packages: list[str], target: Path) -> None:
        make_distribution(target, "requests", license_text=MIT_LICENSE_TEXT)

    monkeypatch.setattr(cli, "resolve_packages", fake_resolve)

    result = runner.invoke(app, ["--pyproject", str(pyproject), "check", "requests"])

    assert result.exit_code == 0
    assert "All 1 packages passed." in result.output


def test_check_subcommand_reports_failure_for_a_disallowed_transitive_dependency(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resolved package with a disallowed-category license fails, same as the environment check."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    def fake_resolve(_packages: list[str], target: Path) -> None:
        make_distribution(target, "gplpkg", license_text=GPL2_LICENSE_TEXT)

    monkeypatch.setattr(cli, "resolve_packages", fake_resolve)

    result = runner.invoke(app, ["--pyproject", str(pyproject), "check", "gplpkg"])

    assert result.exit_code == 1
    assert "gplpkg" in result.output


def test_check_subcommand_reports_resolution_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A package that can't be resolved (typo, no network, ...) exits 1 with the error."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')

    def fake_resolve(packages: list[str], _target: Path) -> None:
        message = f"could not resolve {packages[0]}: no matching distribution"
        raise ResolutionError(message)

    monkeypatch.setattr(cli, "resolve_packages", fake_resolve)

    result = runner.invoke(app, ["--pyproject", str(pyproject), "check", "definitely-not-a-real-package-xyz"])

    assert result.exit_code == 1
    assert "could not resolve" in result.output


def test_check_subcommand_requires_a_configured_policy_when_not_interactive(tmp_path: Path) -> None:
    """Checking a candidate package with no policy configured, non-interactively, has nothing to check against."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'unconfigured'\n")

    result = runner.invoke(app, ["--pyproject", str(pyproject), "check", "requests"])

    assert result.exit_code == 1
    assert "no policy configured" in result.output


def test_check_subcommand_reports_a_broken_config(tmp_path: Path) -> None:
    """A [tool.trustedlicenses] table with no allowed-categories is a real misconfiguration, not just unset."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[tool.trustedlicenses]\nallowed-categories = []\n")

    result = runner.invoke(app, ["--pyproject", str(pyproject), "check", "requests"])

    assert result.exit_code == 1
    assert "allowed-categories" in result.output


def _fake_index(monkeypatch: pytest.MonkeyPatch, *, error: str | None = None) -> list[tuple[str, str, str]]:
    from trustedlicenses import index  # noqa: PLC0415

    calls: list[tuple[str, str, str]] = []

    def audit(_client: object, url: str, package: str, version: str) -> str:
        calls.append((url, package, version))
        if error:
            raise index.IndexQueryError(error)
        return f"{package} {version}"

    monkeypatch.setattr(index, "HttpClient", object)
    monkeypatch.setattr(index, "audit_package", audit)
    monkeypatch.setattr(index, "format_audit", lambda result: f"FINDING: {result}")
    return calls


def test_index_check_uses_the_lockfile_index_and_the_installed_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The subcommand asks the index the lockfile names, and says which one before asking."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "pytest"\nversion = "1"\nsource = { registry = "https://nexus.example.com/simple" }\n'
    )
    calls = _fake_index(monkeypatch)

    result = runner.invoke(app, ["--pyproject", str(pyproject), "index-check", "pytest"])

    assert result.exit_code == 0
    assert "https://nexus.example.com/simple (from uv.lock)" in result.output
    assert "FINDING: pytest" in result.output
    assert calls[0][0] == "https://nexus.example.com/simple"
    assert calls[0][1] == "pytest"
    assert calls[0][2]  # pytest is installed here, so its version is passed


def test_index_check_reports_an_unreachable_index_and_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed query is an explained error and a non-zero exit, not a traceback."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    _fake_index(monkeypatch, error="Could not reach https://nexus: connection refused.")

    result = runner.invoke(app, ["--pyproject", str(pyproject), "index-check", "webencodings"])

    assert result.exit_code == 1
    assert "Could not reach" in result.output


def test_index_check_handles_a_package_that_is_not_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Not installed -> still works, considering every release (empty installed version)."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    calls = _fake_index(monkeypatch)

    result = runner.invoke(app, ["--pyproject", str(pyproject), "index-check", "definitely-not-installed-xyz"])

    assert result.exit_code == 0
    assert calls[0][2] == ""


def test_a_plain_check_never_imports_the_network_code() -> None:
    """The offline promise: a normal run doesn't load trustedlicenses.index at all."""
    import subprocess  # noqa: PLC0415
    import sys  # noqa: PLC0415

    code = "import sys, trustedlicenses, trustedlicenses.cli; print('trustedlicenses.index' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)  # noqa: S603

    assert out.stdout.strip() == "False"
