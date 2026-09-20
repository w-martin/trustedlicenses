"""Tests for trustedlicenses.wizard."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

import pytest
import typer

from trustedlicenses import wizard
from trustedlicenses.config import load_policy
from trustedlicenses.detection import DistributionLicence
from trustedlicenses.policy import PolicyResult

if TYPE_CHECKING:
    from pathlib import Path


class _ScriptedAnswers:
    """Feeds pre-scripted answers to typer.confirm/typer.prompt calls, in order."""

    def __init__(self, confirms: list[bool], extra_prompt: str = "", prompts: list[str] | None = None) -> None:
        self.confirms = confirms
        self.extra_prompt = extra_prompt
        self.prompts = prompts

    def confirm(self, text: str, *, default: bool = False) -> bool:
        print(text)  # noqa: T201 -- lets capsys-based tests see the real prompt text
        return self.confirms.pop(0) if self.confirms else default

    def prompt(self, _text: str, default: str = "", **_kwargs: object) -> str:
        if self.prompts is not None:
            return self.prompts.pop(0) if self.prompts else default
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


def _failure(
    name: str,
    keys: frozenset[str] = frozenset(),
    categories: frozenset[str] = frozenset(),
    suggested: frozenset[tuple[str, str]] = frozenset(),
) -> DistributionLicence:
    return DistributionLicence(name=name, keys=keys, categories=categories, source="x", suggested=suggested)


def _write_policy_file(tmp_path: Path) -> Path:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "x"\n# keep me\n\n[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n'
    )
    return pyproject


def test_review_failures_declines_up_front(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Declining the initial "review now?" question leaves the config untouched."""
    pyproject = _write_policy_file(tmp_path)
    original = pyproject.read_text()
    result = PolicyResult(failures=(_failure("catboost"),), checked=1)
    _patch_prompts(monkeypatch, _ScriptedAnswers([False]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is False
    assert pyproject.read_text() == original


def test_review_failures_ignoring_one_writes_its_name_and_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Choosing "ignore" for an undetectable package records it with a dated reason."""
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(failures=(_failure("catboost"),), checked=1)
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True], prompts=["i"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    text = pyproject.read_text()
    assert "catboost" in text
    assert "no license detected -- accepted" in text
    assert "# keep me" in text
    assert "catboost" in load_policy(pyproject).ignored_packages


def test_review_failures_ignoring_a_detected_but_disallowed_package_records_its_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure with a detected (just disallowed) license gets a reason naming it, not "no license"."""
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(_failure("gplpkg", keys=frozenset({"GPL-3.0-only"}), categories=frozenset({"Copyleft"})),),
        checked=1,
    )
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True], prompts=["i"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    text = pyproject.read_text()
    assert "detected GPL-3.0-only -- accepted" in text
    assert "gplpkg" in load_policy(pyproject).ignored_packages


def test_review_failures_allowing_a_category_writes_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Choosing "allow category" for a failure adds its category, not just that package."""
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(_failure("cons", keys=frozenset({"LGPL-3.0-or-later"}), categories=frozenset({"Copyleft Limited"})),),
        checked=1,
    )
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True], prompts=["a"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    assert load_policy(pyproject).allowed_categories == frozenset({"Permissive", "Copyleft Limited"})
    assert "cons" not in load_policy(pyproject).ignored_packages


def test_review_failures_verifying_a_package_pins_the_exact_statement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Choosing "verify" pins this package to its exact statement + corrected id.

    Below the blanket-offer threshold (only one correctable failure), so no blanket
    toggle is offered -- confirmed by the exact confirm sequence consumed and by
    trust_corrected_licenses staying False.
    """
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(_failure("catboost", suggested=frozenset({("Apache License, Version 2.0", "Apache-2.0")})),),
        checked=1,
    )
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True], prompts=["v"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    policy = load_policy(pyproject)
    assert policy.verified_packages == {"catboost": ("Apache License, Version 2.0", "Apache-2.0")}
    assert policy.trust_corrected_licenses is False


def test_review_failures_trusting_a_statement_pins_it_for_any_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Choosing "trust this text" pins the statement itself, not tied to one package."""
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(_failure("catboost", suggested=frozenset({("Apache License, Version 2.0", "Apache-2.0")})),),
        checked=1,
    )
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True], prompts=["t"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    policy = load_policy(pyproject)
    assert policy.verified_statements == {"Apache License, Version 2.0": "Apache-2.0"}
    assert policy.verified_packages == {}


def test_review_failures_offers_blanket_toggle_at_threshold_and_sweeps_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two correctable failures meets the threshold -- accepting resolves both with no per-case pins.

    Both correct to a Permissive id, matching `_write_policy_file`'s allowed-categories
    -- so both genuinely would pass once trusted, not just "have some suggestion".
    """
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(
            _failure("catboost", suggested=frozenset({("Apache License, Version 2.0", "Apache-2.0")})),
            _failure("apachepkg2", suggested=frozenset({("Apache Version 2.0", "Apache-2.0")})),
        ),
        checked=2,
    )
    # "review now?" True, blanket offer True, "write?" True -- no per-failure prompts
    # needed, both failures are swept by the blanket accept.
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True, True]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    policy = load_policy(pyproject)
    assert policy.trust_corrected_licenses is True
    assert policy.verified_packages == {}
    assert policy.verified_statements == {}


def test_review_failures_blanket_offer_excludes_a_suggestion_in_a_disallowed_category(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A suggestion isn't "correctable" for the blanket offer unless its category is actually allowed.

    Only catboost's Apache-2.0 (Permissive) matches `_write_policy_file`'s
    allowed-categories -- mozillapkg's MPL-2.0 (Copyleft Limited) doesn't, so it must
    not count toward the threshold even though it has a suggestion too. With only one
    genuinely-correctable failure, the blanket offer must not fire at all.
    """
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(
            _failure("catboost", suggested=frozenset({("Apache License, Version 2.0", "Apache-2.0")})),
            _failure("mozillapkg", suggested=frozenset({("Mozilla Public License, Version 2.0", "MPL-2.0")})),
        ),
        checked=2,
    )
    # "review now?" True, then straight to per-failure prompts (no blanket-offer confirm
    # consumed) -- catboost verified, mozillapkg skipped -- then "write?" True.
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True], prompts=["v", "s"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    policy = load_policy(pyproject)
    assert policy.trust_corrected_licenses is False
    assert policy.verified_packages == {"catboost": ("Apache License, Version 2.0", "Apache-2.0")}


def test_review_failures_blanket_offer_names_a_count_above_the_naming_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With more than two correctable failures, the offer names a count, not every package.

    All three correct to a Permissive id, matching `_write_policy_file`'s
    allowed-categories -- all three genuinely would pass once trusted.
    """
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(
            _failure("pkg-a", suggested=frozenset({("Apache License, Version 2.0", "Apache-2.0")})),
            _failure("pkg-b", suggested=frozenset({("Apache Version 2.0", "Apache-2.0")})),
            _failure("pkg-c", suggested=frozenset({("Zlib License", "Zlib")})),
        ),
        checked=3,
    )
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True, True]))

    wizard.review_failures(pyproject, result, load_policy(pyproject))

    output = capsys.readouterr().out
    assert "3 failure(s)" in output
    assert "(3 packages)" in output
    assert "pkg-a, pkg-b, pkg-c" not in output


def test_review_failures_declining_blanket_toggle_falls_through_to_per_case_choices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Declining the blanket offer still leaves both failures individually reviewable.

    Both correct to a Permissive id, matching `_write_policy_file`'s allowed-categories,
    so both meet the blanket-offer threshold in the first place.
    """
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(
            _failure("catboost", suggested=frozenset({("Apache License, Version 2.0", "Apache-2.0")})),
            _failure("apachepkg2", suggested=frozenset({("Apache Version 2.0", "Apache-2.0")})),
        ),
        checked=2,
    )
    # "review now?" True, blanket offer False, "write?" True; catboost -> verify, apachepkg2 -> skip.
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, False, True], prompts=["v", "s"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    policy = load_policy(pyproject)
    assert policy.trust_corrected_licenses is False
    assert policy.verified_packages == {"catboost": ("Apache License, Version 2.0", "Apache-2.0")}


def test_review_failures_bulk_ignore_only_sweeps_remaining_undetectable_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bulk-ignore skips the prompt for later undetectable failures, but not categorized ones."""
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(
        failures=(
            _failure("pkg-a"),
            _failure("pkg-b"),
            _failure("pkg-c", categories=frozenset({"Copyleft"})),
        ),
        checked=3,
    )
    # "review now?" True, choice "b" for pkg-a (pkg-b swept automatically, no prompt),
    # choice "s" for pkg-c (has a category -- bulk doesn't cover it), then "write?" True.
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True], prompts=["b", "s"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    ignored = load_policy(pyproject).ignored_packages
    assert ignored == frozenset({"pkg-a", "pkg-b"})
    assert load_policy(pyproject).allowed_categories == frozenset({"Permissive"})


def test_review_failures_quit_stops_early_but_keeps_prior_decisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Quitting mid-review still writes whatever was already decided."""
    pyproject = _write_policy_file(tmp_path)
    result = PolicyResult(failures=(_failure("pkg-a"), _failure("pkg-b"), _failure("pkg-c")), checked=3)
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, True], prompts=["i", "q"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is True
    ignored = load_policy(pyproject).ignored_packages
    assert ignored == frozenset({"pkg-a"})


def test_review_failures_warns_and_skips_on_a_choice_not_offered_for_that_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unrecognized choice (or one not offered for this failure) is flagged, not silently applied.

    "a" (allow category) isn't offered for a failure with no detected category --
    unlike a deliberate "s" (skip), this should tell the user their input didn't do
    anything, so they don't think a decision was recorded when it wasn't.
    """
    pyproject = _write_policy_file(tmp_path)
    original = pyproject.read_text()
    result = PolicyResult(failures=(_failure("catboost"),), checked=1)
    _patch_prompts(monkeypatch, _ScriptedAnswers([True], prompts=["a"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is False
    assert pyproject.read_text() == original
    assert "isn't one of the options" in capsys.readouterr().out


def test_review_failures_returns_false_when_nothing_selected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Skipping every failure leaves nothing to write -- no final confirmation is even asked."""
    pyproject = _write_policy_file(tmp_path)
    original = pyproject.read_text()
    result = PolicyResult(failures=(_failure("catboost"),), checked=1)
    _patch_prompts(monkeypatch, _ScriptedAnswers([True], prompts=["s"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is False
    assert pyproject.read_text() == original


def test_review_failures_returns_false_when_final_confirmation_is_declined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Selecting a decision but declining the final "write?" confirmation writes nothing."""
    pyproject = _write_policy_file(tmp_path)
    original = pyproject.read_text()
    result = PolicyResult(failures=(_failure("catboost"),), checked=1)
    _patch_prompts(monkeypatch, _ScriptedAnswers([True, False], prompts=["i"]))

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is False
    assert pyproject.read_text() == original


def test_review_failures_aborts_gracefully_when_a_prompt_is_never_answered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same timeout safety net as the initial-setup wizard -- never hangs indefinitely."""
    pyproject = _write_policy_file(tmp_path)
    original = pyproject.read_text()
    monkeypatch.setattr(wizard, "PROMPT_TIMEOUT_SECONDS", 0.05)
    result = PolicyResult(failures=(_failure("catboost"),), checked=1)
    monkeypatch.setattr(wizard.typer, "confirm", lambda *_a, **_k: threading.Event().wait())
    monkeypatch.setattr(wizard.typer, "echo", lambda *_args, **_kwargs: None)

    written = wizard.review_failures(pyproject, result, load_policy(pyproject))

    assert written is False
    assert pyproject.read_text() == original


def test_with_timeout_reraises_the_underlying_error_promptly() -> None:
    """An exception from the wrapped call (e.g. Ctrl-C -> typer.Abort) propagates, not swallowed."""

    def _raises(*_args: object, **_kwargs: object) -> None:
        raise typer.Abort

    with pytest.raises(typer.Abort):
        wizard._with_timeout(_raises)
