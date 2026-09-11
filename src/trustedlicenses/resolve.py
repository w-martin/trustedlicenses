"""Resolve a package, and its transitive dependencies, into an isolated directory.

Used by ``trustedlicenses check`` to answer "would adding this package introduce a
license problem" without installing it into the real project environment -- and
without assuming which installer (uv, pip, Poetry, Pipenv, ...) the *consuming*
project uses. Resolution always happens through this module's own isolated
mechanism, independent of the caller's own tooling.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class ResolutionError(Exception):
    """Packages could not be resolved -- no installer available, or resolution failed."""


def resolve_packages(packages: list[str], target: Path) -> None:
    """Install ``packages`` and their transitive dependencies into ``target``.

    Tries ``uv pip install`` first, since it's an order of magnitude faster and
    already this project's own tooling; falls back to ``python -m pip install``
    (available in nearly every Python installation) when ``uv`` isn't on ``PATH``.
    Neither call touches the current environment -- both install into ``target``
    only, via ``--target``.

    Args:
        packages: Package requirement strings (e.g. ``"requests"``,
            ``"django>=5,<6"``), exactly as you'd pass to ``pip install``.
        target: An existing, empty directory to install into.

    Raises:
        ResolutionError: Neither ``uv`` nor ``pip`` is usable, or resolution failed
            (a typo'd package name, a version conflict, no network, ...).
    """
    uv = shutil.which("uv")
    command = (
        [uv, "pip", "install", "--target", str(target), "--python", sys.executable, *packages]
        if uv is not None
        else [sys.executable, "-m", "pip", "install", "--target", str(target), *packages]
    )

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    except FileNotFoundError as error:
        message = (
            "could not resolve packages: neither `uv` nor a working `pip` is available. "
            "Install either to use `trustedlicenses check`."
        )
        raise ResolutionError(message) from error

    if result.returncode != 0:
        message = f"could not resolve {', '.join(packages)}:\n{result.stderr.strip()}"
        raise ResolutionError(message)
