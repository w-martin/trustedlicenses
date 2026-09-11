"""Tests for trustedlicenses.wizard."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

import pytest
import typer

from trustedlicenses import wizard
from trustedlicenses.detection import DistributionLicence

if TYPE_CHECKING:
    from pathlib import Path


class _ScriptedAnswers:
    """Feeds pre-scripted answers to typer.confirm/typer.prompt calls, in order."""

    def __init__(self, confirms: list[bool], extra_prompt: str = "") -> None:
        self.confirms = confirms
        self.extra_prompt = extra_prompt

    def confirm(self, _text: str, *, default: bool = False) -> bool:
        return self.confirms.pop(0) if self.confirms else default

    def prompt(self, _text: str, default: str = "", **_kwargs: object) -> str:  # noqa: ARG002
        return self.extra_prompt


def _patch_prompts(monkeypatch: pytest.MonkeyPatch, answers: _ScriptedAnswers) -> None:
    monkeypatch.setattr(wizard.typer, "confirm", answers.confirm)
    monkeypatch.setattr(wizard.typer, "prompt", answers.prompt)
    monkeypatch.setattr(wizard.typer, "echo", lambda *_args, **_kwargs: None)


def test_run_writes_selected_categories_to_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Allow the first three primary categories, decline Copyleft, save to pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    monkeypatch.setattr(wizard, "detect_all", lambda: ())
    # "run guided setup?" then 4 category confirms, "save to standalone?" (False =
    # pyproject.toml), then "write?"
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True, True, True, False, False, True]))

    written = wizard.run(pyproject)

    assert written == pyproject
    text = pyproject.read_text()
    assert "[tool.trustedlicenses]" in text
    assert "Permissive" in text
    assert "Public Domain" in text
    assert "Copyleft Limited" in text
    assert '"Copyleft"' not in text


def test_run_asks_about_additional_detected_categories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A category outside the primary four, seen in the environment, is offered too."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    detected = DistributionLicence(
        name="somepkg", keys=frozenset({"LicenseRef-x"}), categories=frozenset({"Proprietary Free"}), source="x"
    )
    monkeypatch.setattr(wizard, "detect_all", lambda: (detected,))
    _patch_prompts(
        monkeypatch,
        _ScriptedAnswers([True, True, True, True, False, False, True], extra_prompt="Proprietary Free"),
    )

    written = wizard.run(pyproject)

    assert written == pyproject
    assert "Proprietary Free" in pyproject.read_text()


def test_run_reports_detected_license_count_before_asking_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The headline count is printed before the first question, not buried after it."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    with_license = DistributionLicence(
        name="haslicense", keys=frozenset({"MIT"}), categories=frozenset({"Permissive"}), source="x"
    )
    without_license = DistributionLicence(name="nolicense", keys=frozenset(), categories=frozenset(), source="x")
    monkeypatch.setattr(wizard, "detect_all", lambda: (with_license, without_license))
    # Decline the up-front "run guided setup?" -- only the headline count should print.
    _patch_prompts(monkeypatch, _ScriptedAnswers([False]))
    monkeypatch.setattr(wizard.typer, "echo", lambda *args, **_kwargs: print(*args))  # noqa: T201 -- capture for capsys

    wizard.run(pyproject)

    output = capsys.readouterr().out
    assert "Detected licenses for 1 of 2 installed packages" in output


def test_run_reports_a_per_category_count_and_names_when_one_or_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A category with only 1-2 matches names them; a category with more just counts."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    gpl_pkg = DistributionLicence(
        name="gplpkg", keys=frozenset({"GPL-3.0-only"}), categories=frozenset({"Copyleft"}), source="x"
    )
    permissive_pkgs = tuple(
        DistributionLicence(name=f"pkg{i}", keys=frozenset({"MIT"}), categories=frozenset({"Permissive"}), source="x")
        for i in range(5)
    )
    monkeypatch.setattr(wizard, "detect_all", lambda: (gpl_pkg, *permissive_pkgs))
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, False, False, False, False]))
    monkeypatch.setattr(wizard.typer, "echo", lambda *args, **_kwargs: print(*args))  # noqa: T201 -- capture for capsys

    wizard.run(pyproject)

    output = capsys.readouterr().out
    assert "(5 detected)" in output
    assert "(1 detected: gplpkg (GPL-3.0-only))" in output


def test_run_returns_none_when_guided_setup_is_declined_up_front(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Declining the initial "run guided setup?" question skips straight past it -- no categories asked."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    monkeypatch.setattr(wizard, "detect_all", lambda: ())
    _patch_prompts(monkeypatch, _ScriptedAnswers([False]))

    written = wizard.run(pyproject)

    assert written is None
    assert "[tool.trustedlicenses]" not in pyproject.read_text()


def test_run_returns_none_when_nothing_selected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Accepting guided setup but declining every category (and no extras) leaves nothing to write."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    monkeypatch.setattr(wizard, "detect_all", lambda: ())
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, False, False, False, False]))

    written = wizard.run(pyproject)

    assert written is None
    assert "[tool.trustedlicenses]" not in pyproject.read_text()


def test_run_returns_none_when_final_write_is_declined(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Selecting categories but declining the final confirmation writes nothing."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    monkeypatch.setattr(wizard, "detect_all", lambda: ())
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True, False, False, False, False, False]))

    written = wizard.run(pyproject)

    assert written is None
    assert "[tool.trustedlicenses]" not in pyproject.read_text()


def test_run_forces_standalone_when_pyproject_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No pyproject.toml to edit -- write a standalone trustedlicenses.toml without asking."""
    pyproject = tmp_path / "pyproject.toml"
    monkeypatch.setattr(wizard, "detect_all", lambda: ())
    # No "save to standalone?" question this time -- just guided-setup + 4 categories + write.
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True, False, False, False, True]))

    written = wizard.run(pyproject)

    assert written is not None
    assert written == tmp_path / "trustedlicenses.toml"
    assert written.is_file()
    assert not pyproject.is_file()


def test_run_writes_standalone_when_explicitly_chosen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An existing pyproject.toml is left untouched when the user opts for a standalone file."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    original = pyproject.read_text()
    monkeypatch.setattr(wizard, "detect_all", lambda: ())
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True, False, False, False, True, True]))

    written = wizard.run(pyproject)

    assert written is not None
    assert written == tmp_path / "trustedlicenses.toml"
    assert pyproject.read_text() == original
    assert "Permissive" in written.read_text()


def test_run_aborts_gracefully_when_a_prompt_is_never_answered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A misconfigured non-interactive job with a tty attached times out instead of hanging."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname = 'x'\n")
    monkeypatch.setattr(wizard, "PROMPT_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(wizard, "detect_all", lambda: ())
    # Never returns -- simulates a prompt nobody is there to answer.
    monkeypatch.setattr(wizard.typer, "confirm", lambda *_a, **_k: threading.Event().wait())
    monkeypatch.setattr(wizard.typer, "prompt", lambda *_a, **_k: threading.Event().wait())

    written = wizard.run(pyproject)

    assert written is None
    output = capsys.readouterr().out
    assert "No answer received within" in output
    assert "--quiet" in output
    assert "[tool.trustedlicenses]" not in pyproject.read_text()


def test_with_timeout_reraises_the_underlying_error_promptly() -> None:
    """An exception from the wrapped call (e.g. Ctrl-C -> typer.Abort) propagates, not swallowed."""

    def _raises(*_args: object, **_kwargs: object) -> None:
        raise typer.Abort

    with pytest.raises(typer.Abort):
        wizard._with_timeout(_raises)
