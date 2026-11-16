"""Running the `trustedlicenses` command line: as the executable installed alongside this package, or in this process.

The in-process mode runs the same command line from the `trustedlicenses._rust` extension module. It is
for environments where the Python interpreter may run code but no other executable may be started.
"""

import os
import shutil
import subprocess
import sys
from importlib import import_module
from pathlib import Path
from sysconfig import get_config_var, get_path, get_preferred_scheme
from types import ModuleType

IN_PROCESS_VARIABLE = "TRUSTEDLICENSES_INPROC"
_OFF_VALUES = frozenset({"", "0", "false", "no", "off"})


class BinaryNotFoundError(FileNotFoundError):
    """Raised when the `trustedlicenses` executable is not installed."""


def find_binary() -> Path:
    """The `trustedlicenses` executable: next to the interpreter's scripts, then the user's, then on PATH.

    Raises:
        BinaryNotFoundError: If none of those hold it, e.g. the package was installed without it.
    """
    name = f"trustedlicenses{get_config_var('EXE') or ''}"
    scripts = Path(get_path("scripts")) / name
    user_scripts = Path(get_path("scripts", scheme=get_preferred_scheme("user"))) / name
    # `pip install --target` puts scripts in a `bin` directory beside the package.
    target = Path(__file__).resolve().parents[1] / "bin" / name
    for candidate in (scripts, user_scripts, target):
        if candidate.is_file():
            return candidate
    on_path = shutil.which("trustedlicenses")
    if on_path is not None:
        return Path(on_path)
    msg = (
        f"The trustedlicenses executable was not found (looked for {scripts}). "
        "Reinstall trustedlicenses from a wheel, or build it from source with: uv run inv build"
    )
    raise BinaryNotFoundError(msg)


def _requested_in_process() -> bool:
    """Whether the environment asks for the command line to run inside this process."""
    return os.environ.get(IN_PROCESS_VARIABLE, "").strip().lower() not in _OFF_VALUES


def _extension() -> ModuleType:
    """The `trustedlicenses._rust` extension module.

    Raises:
        BinaryNotFoundError: If the package was installed without it.
    """
    try:
        return import_module("trustedlicenses._rust")
    except ImportError as e:
        msg = (
            "The trustedlicenses extension module (trustedlicenses._rust) was not found. "
            "Reinstall trustedlicenses from a wheel, or build it from source with: uv run inv build"
        )
        raise BinaryNotFoundError(msg) from e


def _executable_missing() -> bool:
    try:
        find_binary()
    except BinaryNotFoundError:
        return True
    return False


def _in_process() -> bool:
    """Whether to run in this process: when asked to, or when the executable is missing but the extension is not."""
    if _requested_in_process():
        return True
    if not _executable_missing():
        return False
    try:
        _extension()
    except BinaryNotFoundError:
        return False
    return True


def run_binary(arguments: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    """Run the command line with `arguments`; with `capture`, its output is returned instead of shared.

    Raises:
        BinaryNotFoundError: If neither the executable nor the extension module is installed.
    """
    if _in_process():
        extension = _extension()
        if capture:
            status, stdout, stderr = extension.run_captured(["trustedlicenses", *arguments])
            return subprocess.CompletedProcess(args=arguments, returncode=status, stdout=stdout, stderr=stderr)
        return subprocess.CompletedProcess(args=arguments, returncode=extension.main(["trustedlicenses", *arguments]))
    command = [str(find_binary()), *arguments]
    return subprocess.run(command, capture_output=capture, text=True, check=False)  # noqa: S603 -- our own executable


def main() -> None:
    """Entry point for `python -m trustedlicenses`: the command line, with this process's arguments.

    Where the platform allows it the executable takes this process's place, so no Python process
    is left waiting; Windows has no such call, and runs it as a child instead. Set `TRUSTEDLICENSES_INPROC=1`
    to run in this process instead of starting the executable.
    """
    if sys.platform == "win32" or _in_process():
        sys.exit(run_binary(sys.argv[1:]).returncode)
    binary = str(find_binary())
    os.execv(binary, [binary, *sys.argv[1:]])  # noqa: S606 -- the executable this package installed, not user input


def main_in_process() -> None:
    """Entry point for `trustedlicenses-py`: always the command line inside this process, never the executable."""
    sys.exit(_extension().main(["trustedlicenses", *sys.argv[1:]]))
