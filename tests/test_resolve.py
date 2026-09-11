"""Tests for trustedlicenses.resolve."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from trustedlicenses.resolve import ResolutionError, resolve_packages

if TYPE_CHECKING:
    from pathlib import Path


def test_resolve_packages_uses_uv_when_available(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Uv is tried first when it's on PATH -- it's this project's own tooling and much faster."""
    monkeypatch.setattr("trustedlicenses.resolve.shutil.which", lambda _name: "/usr/local/bin/uv")
    captured: dict[str, list[str]] = {}

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        return subprocess.CompletedProcess(command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("trustedlicenses.resolve.subprocess.run", fake_run)

    resolve_packages(["requests"], tmp_path)

    assert captured["command"][0] == "/usr/local/bin/uv"
    assert "pip" in captured["command"]
    assert "install" in captured["command"]
    assert str(tmp_path) in captured["command"]
    assert "requests" in captured["command"]


def test_resolve_packages_falls_back_to_pip_when_uv_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without uv on PATH, fall back to `python -m pip install` -- nearly universally available."""
    monkeypatch.setattr("trustedlicenses.resolve.shutil.which", lambda _name: None)
    captured: dict[str, list[str]] = {}

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["command"] = command
        return subprocess.CompletedProcess(command, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("trustedlicenses.resolve.subprocess.run", fake_run)

    resolve_packages(["requests"], tmp_path)

    assert captured["command"][1:3] == ["-m", "pip"]


def test_resolve_packages_raises_on_a_failed_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A nonzero exit (typo'd package, version conflict, no network, ...) raises ResolutionError."""
    monkeypatch.setattr("trustedlicenses.resolve.shutil.which", lambda _name: None)

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, returncode=1, stdout="", stderr="No matching distribution found")

    monkeypatch.setattr("trustedlicenses.resolve.subprocess.run", fake_run)

    with pytest.raises(ResolutionError, match="No matching distribution found"):
        resolve_packages(["definitely-not-a-real-package-xyz"], tmp_path)


def test_resolve_packages_raises_when_no_installer_is_usable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Neither uv nor a working pip -- report it clearly rather than an opaque traceback."""
    monkeypatch.setattr("trustedlicenses.resolve.shutil.which", lambda _name: None)

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    monkeypatch.setattr("trustedlicenses.resolve.subprocess.run", fake_run)

    with pytest.raises(ResolutionError, match="neither `uv` nor"):
        resolve_packages(["requests"], tmp_path)
