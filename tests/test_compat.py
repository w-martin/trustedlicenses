"""Tests for the version-gated imports in ``trustedlicenses._compat``."""

from __future__ import annotations

import importlib
import sys
import typing

import pytest

from trustedlicenses import _compat


@pytest.fixture(autouse=True)
def _restore_compat() -> typing.Iterator[None]:
    yield
    importlib.reload(_compat)


def test_override_on_python_312_plus_is_the_typing_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """The 3.12+ branch re-exports ``typing.override`` itself."""
    if sys.version_info >= (3, 12):
        monkeypatch.setattr(sys, "version_info", (3, 12, 0, "final", 0))
        reloaded = importlib.reload(_compat)
        assert reloaded.override is typing.override
    else:
        pytest.skip("typing.override needs 3.12+")


def test_override_shim_on_python_311_returns_the_method_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-3.12 branch is an identity decorator, so decorated methods behave identically."""
    monkeypatch.setattr(sys, "version_info", (3, 11, 0, "final", 0))
    reloaded = importlib.reload(_compat)

    def method() -> None: ...

    assert reloaded.override(method) is method
