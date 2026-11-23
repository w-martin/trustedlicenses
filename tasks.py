"""Invoke tasks for trustedlicenses development."""

import sys
from pathlib import Path
from shutil import rmtree
from sysconfig import get_config_var, get_path
from zipfile import ZipFile

from invoke import Context, task

RUST_DIR = Path("rust")
PACKAGE_DIR = Path("src") / "trustedlicenses"
EXTENSION_BUILD_DIR = RUST_DIR / "target" / "extension"
EXTENSION_SUFFIXES = {".so", ".pyd"}
# CI lints on this version (the `requires-python` floor); the local venv is usually newer.
PYTHON_FLOOR = "3.11"
# (crate directory, extension module name): the extension modules staged into the package.
EXTENSIONS = ((RUST_DIR / "python", "_rust"),)
# The maturin arguments of each stable-ABI build staged side by side: abi3 for GIL interpreters, and abi3t
# (PEP 803) for free-threaded 3.15+, which loads nothing else. maturin needs only the interpreter's name for
# a stable-ABI build, not the interpreter. Windows names both `_rust.pyd`, so it gets abi3 alone.
ABI_BUILDS = ("",) if sys.platform == "win32" else ("", "-i python3.15t --features pyo3/abi3t-py315")


def _installed_binary() -> Path | None:
    """The `trustedlicenses` executable `maturin develop` installed into this environment, if any."""
    candidate = Path(get_path("scripts")) / f"trustedlicenses{get_config_var('EXE') or ''}"
    return candidate if candidate.is_file() else None


def _staged_extensions() -> list[Path]:
    """The compiled extension modules staged in the package directory (not their stubs)."""
    return [
        path
        for _crate, name in EXTENSIONS
        for path in PACKAGE_DIR.glob(f"{name}.*")
        if path.suffix in EXTENSION_SUFFIXES
    ]


def _stage_extensions(ctx: Context, *, release: bool) -> None:
    """Build the extension module for each stable ABI and copy it into the package directory, for the wheel.

    maturin builds it, not cargo, so the cross-compiling toolchains and the macOS link flags are the ones
    the wheels use. The package's own wheel is built with `bindings = "bin"`, which cannot build it.
    """
    profile = "--release" if release else ""
    for crate, name in EXTENSIONS:
        for stale in PACKAGE_DIR.glob(f"{name}.*"):
            if stale.suffix in EXTENSION_SUFFIXES:
                stale.unlink()
        for abi in ABI_BUILDS:
            rmtree(EXTENSION_BUILD_DIR, ignore_errors=True)
            # From the crate's own directory: maturin would otherwise apply the root pyproject's `bindings = "bin"`.
            with ctx.cd(crate):
                ctx.run(f'maturin build {profile} {abi} -o "{EXTENSION_BUILD_DIR.resolve()}"')
            with ZipFile(next(EXTENSION_BUILD_DIR.glob("*.whl"))) as wheel:
                for member in wheel.namelist():
                    if Path(member).name.startswith(f"{name}.") and Path(member).suffix in EXTENSION_SUFFIXES:
                        (PACKAGE_DIR / Path(member).name).write_bytes(wheel.read(member))


def _needs_build() -> bool:
    """Check if the installed executable or the staged extensions need rebuilding.

    Must check the executable `maturin develop` installs into the environment, not the one
    `cargo build`/`cargo test` leave in `rust/target/debug`: the two are built independently, so
    a bare `cargo test` can leave this check thinking the installed one is fresh when it is stale.
    """
    binary = _installed_binary()
    extensions = _staged_extensions()
    if binary is None or len(extensions) < len(EXTENSIONS) * len(ABI_BUILDS):
        return True

    built = min(binary.stat().st_mtime, *(extension.stat().st_mtime for extension in extensions))
    sources = [
        *RUST_DIR.glob("*/src/**/*.rs"),
        *RUST_DIR.glob("src/**/*.rs"),
        *RUST_DIR.glob("*/Cargo.toml"),
        *RUST_DIR.glob("*/build.rs"),
        RUST_DIR / "Cargo.toml",
        RUST_DIR / "Cargo.lock",
        Path("pyproject.toml"),
    ]
    return any(source.exists() and source.stat().st_mtime > built for source in sources)


@task
def build(ctx: Context, *, force: bool = False) -> None:
    """Build the `trustedlicenses` executable and extension modules, and install them with the package, if needed."""
    if force or _needs_build():
        print("Building the Rust command line...")
        _stage_extensions(ctx, release=False)
        ctx.run("maturin develop")
    else:
        print("The Rust command line is up to date.")


@task
def wheel(ctx: Context) -> None:
    """Build a release wheel into dist/: the executable (cli profile) plus the extension module."""
    _stage_extensions(ctx, release=True)
    ctx.run("maturin build --profile cli -o dist")


@task(name="check-wheel", iterable=["python"])
def check_built_wheel(ctx: Context, python: list[str] | None = None) -> None:
    """Install the wheel in dist/ into a clean venv and run every way of starting the command line.

    Repeat `--python` to check it under each of those interpreters instead of this one.
    """
    interpreters = " ".join(f'"{interpreter}"' for interpreter in python or [])
    ctx.run(f"python scripts/check_wheel.py dist {interpreters}")


@task(name="format-check")
def check_if_code_needs_formatting(ctx: Context) -> None:
    """Check that the codebase is formatted with ruff."""
    ctx.run("ruff format --check")


@task(name="format")
def format_code(ctx: Context) -> None:
    """Run ruff format on the codebase."""
    ctx.run("ruff format .")


@task(name="floor-check")
def check_python_floor(ctx: Context) -> None:
    """Type-check against the minimum supported Python, catching version-gating mistakes."""
    ctx.run(f"ty check --python-version {PYTHON_FLOOR} .")
    ctx.run(f"pyrefly check --python-version {PYTHON_FLOOR} .")


@task(post=[check_python_floor])
def lint(ctx: Context) -> None:
    """Run all linters: ruff check, ty check, pyrefly check, cargo fmt, cargo clippy, and the Python-floor check."""
    ctx.run("ruff check .")
    ctx.run("ty check .")
    ctx.run("pyrefly check .")
    print("Checking Rust formatting...")
    ctx.run(f"cd {RUST_DIR} && cargo fmt --all -- --check")
    print("Running Rust clippy...")
    ctx.run(f"cd {RUST_DIR} && cargo clippy --workspace -- -D warnings")


@task
def lint_fix(ctx: Context) -> None:
    """Run ruff check with --fix and ruff format."""
    ctx.run("ruff check --fix .")
    ctx.run("ruff format .")


@task(pre=[build])
def test(ctx: Context) -> None:
    """Run pytest with branch coverage and Rust tests. Builds the Rust matcher if needed."""
    print("Running Python tests...")
    ctx.run("python -m pytest tests/")
    print("Running Rust tests...")
    # The extension crate has no tests, and as an extension module its test harness would not link.
    ctx.run(f"cd {RUST_DIR} && cargo test --workspace --exclude trustedlicenses_python")


@task(name="all", pre=[build])
def all_checks(ctx: Context) -> None:
    """Run all checks: format, lint, test."""
    format_code(ctx)
    lint(ctx)
    test(ctx)
