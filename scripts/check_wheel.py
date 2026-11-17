"""Install a built wheel into a clean virtual environment and run every way of starting the command line.

Loading is what fails when an extension module is linked or stripped wrongly, not the file being absent,
so this runs the executable, `trustedlicenses-py`, `python -m trustedlicenses` and the in-process mode,
not merely listing the wheel's contents. Standard library only, so any CI runner can run it.

Usage: python scripts/check_wheel.py [DIST_DIR]
"""

import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from zipfile import ZipFile

IN_PROCESS = "TRUSTEDLICENSES_INPROC"
EXTENSION_SUFFIXES = (".so", ".pyd")


def _fail(message: str) -> None:
    print(f"check_wheel: {message}")  # noqa: T201
    sys.exit(1)


def _run(command: list[str], *, env: dict[str, str] | None = None, cwd: Path | None = None) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False, env=env, cwd=cwd)  # noqa: S603
    print(f"$ {' '.join(command)}  ->  exit {result.returncode}")  # noqa: T201
    if result.returncode != 0:
        _fail(f"{command} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def _check_contents(wheel: Path) -> None:
    names = ZipFile(wheel).namelist()
    scripts = {Path(name).name for name in names if ".data/scripts/" in name}
    stem = {Path(name).stem if name.endswith(".exe") else Path(name).name for name in scripts}
    if "trustedlicenses" not in stem:
        _fail(f"the wheel has no trustedlicenses executable (scripts: {sorted(scripts)})")
    if "trustedlicenses-py" not in stem:
        _fail(f"the wheel has no trustedlicenses-py script (scripts: {sorted(scripts)})")
    if not any(name.startswith("trustedlicenses/_rust.") and name.endswith(EXTENSION_SUFFIXES) for name in names):
        _fail("the wheel has no trustedlicenses._rust extension module")


def _fixture_environment(root: Path) -> tuple[Path, Path]:
    """A tiny installed environment with one MIT package, and a project whose policy allows it."""
    dist_info = root / "env" / "lib" / "python3.99" / "site-packages" / "demo-1.0.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text("Name: demo\nVersion: 1.0\nLicense-Expression: MIT\n")
    project = root / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text('[tool.trustedlicenses]\nallowed-categories = ["Permissive"]\n')
    return root / "env", project / "pyproject.toml"


def main(dist: Path) -> None:
    """Check the wheel in `dist`."""
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        _fail(f"expected exactly one wheel in {dist}, found {[wheel.name for wheel in wheels]}")
    wheel = wheels[0]
    version = wheel.name.split("-")[1]
    _check_contents(wheel)

    with tempfile.TemporaryDirectory(prefix="check-wheel-") as scratch:
        root = Path(scratch)
        venv.create(root / "venv", with_pip=True)
        bin_dir = root / "venv" / ("Scripts" if sys.platform == "win32" else "bin")
        exe = ".exe" if sys.platform == "win32" else ""
        python = bin_dir / f"python{exe}"
        _run([str(python), "-m", "pip", "install", "--quiet", str(wheel)])

        environment, pyproject = _fixture_environment(root)
        base = {key: value for key, value in os.environ.items() if key != IN_PROCESS}
        in_process = {**base, IN_PROCESS: "1"}
        entry_points = {
            "executable": ([str(bin_dir / f"trustedlicenses{exe}")], base),
            "python -m": ([str(python), "-m", "trustedlicenses"], base),
            "python -m, in process": ([str(python), "-m", "trustedlicenses"], in_process),
        }
        # pip makes a launcher for entry points but copies a wheel's data scripts as they are, so on
        # Windows `trustedlicenses-py` has no executable to start by name; `python -m` covers that path.
        if sys.platform != "win32":
            entry_points["trustedlicenses-py"] = ([str(bin_dir / "trustedlicenses-py")], base)
        check = ["--pyproject", str(pyproject), "--quiet", "--installed", "--venv", str(environment)]
        for label, (command, env) in entry_points.items():
            if version not in _run([*command, "--version"], env=env):
                _fail(f"{label}: --version does not report {version}")
            if "All 1 packages passed." not in _run([*command, *check], env=env):
                _fail(f"{label}: the fixture check did not pass")
    print(f"check_wheel: {wheel.name} OK")  # noqa: T201


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dist"))
