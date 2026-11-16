"""Tests for trustedlicenses._binary: finding the executable and choosing how to run it."""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

from trustedlicenses import _binary
from trustedlicenses._binary import BinaryNotFoundError

if TYPE_CHECKING:
    from pathlib import Path


STATUS_FROM_CAPTURE = 3
STATUS_FROM_MAIN = 7
STATUS_FROM_SHIM = 2


class _FakeExtension:
    """Stands in for `trustedlicenses._rust`, recording what it was asked to run."""

    def __init__(self, status: int = 0) -> None:
        self.status = status
        self.calls: list[list[str]] = []

    def main(self, argv: list[str]) -> int:
        self.calls.append(argv)
        return self.status

    def run_captured(self, argv: list[str]) -> tuple[int, str, str]:
        self.calls.append(argv)
        return self.status, "out", "err"


def _executable(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "trustedlicenses"
    path.write_text("#!/bin/sh\n")
    return path


@pytest.fixture(autouse=True)
def _no_in_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_binary.IN_PROCESS_VARIABLE, raising=False)


def _scripts_dir(monkeypatch: pytest.MonkeyPatch, scripts: Path, user: Path) -> None:
    def get_path(name: str, scheme: str | None = None) -> str:
        assert name == "scripts"
        return str(user if scheme == "user-scheme" else scripts)

    monkeypatch.setattr(_binary, "get_path", get_path)
    monkeypatch.setattr(_binary, "get_preferred_scheme", lambda _kind: "user-scheme")
    monkeypatch.setattr(_binary, "get_config_var", lambda _name: "")
    monkeypatch.setattr(_binary.shutil, "which", lambda _name: None)


def test_find_binary_prefers_the_interpreters_scripts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The executable next to the interpreter wins over the user's scripts directory."""
    scripts, user = tmp_path / "scripts", tmp_path / "user"
    _scripts_dir(monkeypatch, scripts, user)
    expected = _executable(scripts)
    _executable(user)

    assert _binary.find_binary() == expected


def test_find_binary_falls_back_to_the_user_scripts_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no executable beside the interpreter, the user scheme's scripts directory is next."""
    scripts, user = tmp_path / "scripts", tmp_path / "user"
    _scripts_dir(monkeypatch, scripts, user)
    expected = _executable(user)

    assert _binary.find_binary() == expected


def test_find_binary_falls_back_to_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An executable on PATH is used when no installed location holds one."""
    _scripts_dir(monkeypatch, tmp_path / "scripts", tmp_path / "user")
    on_path = _executable(tmp_path / "elsewhere")
    monkeypatch.setattr(_binary.shutil, "which", lambda _name: str(on_path))

    assert _binary.find_binary() == on_path


def test_find_binary_finds_the_pip_target_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`pip install --target` puts scripts in a `bin` directory beside the package."""
    _scripts_dir(monkeypatch, tmp_path / "scripts", tmp_path / "user")
    package = tmp_path / "target" / "trustedlicenses"
    package.mkdir(parents=True)
    expected = _executable(tmp_path / "target" / "bin")
    monkeypatch.setattr(_binary, "__file__", str(package / "_binary.py"))

    assert _binary.find_binary().resolve() == expected.resolve()


def test_find_binary_explains_how_to_get_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Nowhere to be found is a clear error naming where it looked and how to fix it."""
    _scripts_dir(monkeypatch, tmp_path / "scripts", tmp_path / "user")
    monkeypatch.setattr(_binary, "__file__", str(tmp_path / "nowhere" / "_binary.py"))

    with pytest.raises(BinaryNotFoundError, match=r"inv build"):
        _binary.find_binary()


@pytest.mark.parametrize(
    ("value", "expected"), [("1", True), ("true", True), ("0", False), ("off", False), ("", False)]
)
def test_in_process_is_requested_by_the_environment(
    monkeypatch: pytest.MonkeyPatch, value: str, *, expected: bool
) -> None:
    """Any value but empty/0/false/no/off asks for in-process mode."""
    monkeypatch.setenv(_binary.IN_PROCESS_VARIABLE, value)

    assert _binary._requested_in_process() is expected


def test_extension_reports_a_missing_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """A package installed without the extension says so, rather than raising a bare ImportError."""

    def missing(_name: str) -> object:
        raise ImportError

    monkeypatch.setattr(_binary, "import_module", missing)

    with pytest.raises(BinaryNotFoundError, match=r"_rust"):
        _binary._extension()


def test_extension_returns_the_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """The extension is imported by its full name."""
    fake = _FakeExtension()
    monkeypatch.setattr(_binary, "import_module", lambda name: fake if name == "trustedlicenses._rust" else None)

    assert _binary._extension() is fake


def _decide(monkeypatch: pytest.MonkeyPatch, *, executable: bool, extension: bool, requested: bool = False) -> bool:
    def find() -> Path:
        if not executable:
            raise BinaryNotFoundError
        return _binary.Path("/bin/true")

    def load() -> object:
        if not extension:
            raise BinaryNotFoundError
        return _FakeExtension()

    monkeypatch.setattr(_binary, "find_binary", find)
    monkeypatch.setattr(_binary, "_extension", load)
    if requested:
        monkeypatch.setenv(_binary.IN_PROCESS_VARIABLE, "1")
    else:
        monkeypatch.delenv(_binary.IN_PROCESS_VARIABLE, raising=False)
    return _binary._in_process()


def test_in_process_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process when asked, or when only the extension is installed; the executable otherwise."""
    assert _decide(monkeypatch, executable=True, extension=True, requested=True)
    assert not _decide(monkeypatch, executable=True, extension=True)
    assert _decide(monkeypatch, executable=False, extension=True)
    assert not _decide(monkeypatch, executable=False, extension=False)


def test_run_binary_runs_in_process_when_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process mode calls the extension with the program name first."""
    fake = _FakeExtension(status=STATUS_FROM_CAPTURE)
    monkeypatch.setattr(_binary, "_in_process", lambda: True)
    monkeypatch.setattr(_binary, "_extension", lambda: fake)

    result = _binary.run_binary(["--quiet"])

    assert result.returncode == STATUS_FROM_CAPTURE
    assert fake.calls == [["trustedlicenses", "--quiet"]]


def test_run_binary_can_capture_in_process(monkeypatch: pytest.MonkeyPatch) -> None:
    """Capturing returns the extension's output instead of sharing the terminal."""
    fake = _FakeExtension(status=1)
    monkeypatch.setattr(_binary, "_in_process", lambda: True)
    monkeypatch.setattr(_binary, "_extension", lambda: fake)

    result = _binary.run_binary(["check", "x"], capture=True)

    assert (result.returncode, result.stdout, result.stderr) == (1, "out", "err")


def test_run_binary_starts_the_executable_otherwise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without in-process mode the executable is run as a child process."""
    script = tmp_path / "trustedlicenses"
    script.write_text(f"#!{sys.executable}\nimport sys\nprint(*sys.argv[1:])\nsys.exit(4)\n")
    script.chmod(0o755)
    monkeypatch.setattr(_binary, "_in_process", lambda: False)
    monkeypatch.setattr(_binary, "find_binary", lambda: script)

    result = _binary.run_binary(["a", "b"], capture=True)

    assert (result.returncode, result.stdout.strip()) == (4, "a b")
    assert isinstance(result, subprocess.CompletedProcess)


def test_main_replaces_the_process_with_the_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Where exec is available, no Python process is left waiting."""
    binary = tmp_path / "trustedlicenses"
    seen: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "argv", ["prog", "--quiet"])
    monkeypatch.setattr(_binary, "_in_process", lambda: False)
    monkeypatch.setattr(_binary, "find_binary", lambda: binary)
    monkeypatch.setattr(_binary.os, "execv", lambda path, args: seen.append((path, args)))

    _binary.main()

    assert seen == [(str(binary), [str(binary), "--quiet"])]


def test_main_runs_in_process_and_exits_with_its_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """In-process mode (and Windows, which has no exec) exits with the command's status."""
    monkeypatch.setattr(sys, "argv", ["prog", "x"])
    monkeypatch.setattr(_binary, "_in_process", lambda: True)
    monkeypatch.setattr(_binary, "run_binary", lambda args: SimpleNamespace(returncode=STATUS_FROM_MAIN, args=args))

    with pytest.raises(SystemExit) as exit_info:
        _binary.main()

    assert exit_info.value.code == STATUS_FROM_MAIN


def test_main_in_process_never_starts_the_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    """`trustedlicenses-py` always uses the extension, whatever the environment says."""
    fake = _FakeExtension(status=STATUS_FROM_SHIM)
    monkeypatch.setattr(sys, "argv", ["trustedlicenses-py", "--quiet"])
    monkeypatch.setattr(_binary, "_extension", lambda: fake)

    with pytest.raises(SystemExit) as exit_info:
        _binary.main_in_process()

    assert exit_info.value.code == STATUS_FROM_SHIM
    assert fake.calls == [["trustedlicenses", "--quiet"]]
