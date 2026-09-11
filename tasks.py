"""Invoke tasks for trustedlicenses development."""

from pathlib import Path

from invoke import Context, task

RUST_DIR = Path("rust")
BINARY_PATH = RUST_DIR / "target" / "debug" / "librust_matcher.dylib"


def _needs_build() -> bool:
    """Check if the Rust matcher extension needs rebuilding."""
    if not BINARY_PATH.exists():
        return True

    binary_mtime = BINARY_PATH.stat().st_mtime
    src_dir = RUST_DIR / "src"

    for src_file in src_dir.rglob("*.rs"):
        if src_file.stat().st_mtime > binary_mtime:
            return True

    cargo_toml = RUST_DIR / "Cargo.toml"
    return cargo_toml.exists() and cargo_toml.stat().st_mtime > binary_mtime


@task
def build(ctx: Context, *, force: bool = False) -> None:
    """Build the Rust matcher extension (maturin develop) if needed."""
    if force or _needs_build():
        print("Building Rust matcher...")
        ctx.run("maturin develop --manifest-path rust/Cargo.toml")
    else:
        print("Rust matcher is up to date.")


@task(name="format-check")
def check_if_code_needs_formatting(ctx: Context) -> None:
    """Check that the codebase is formatted with ruff."""
    ctx.run("ruff format --check")


@task(name="format")
def format_code(ctx: Context) -> None:
    """Run ruff format on the codebase."""
    ctx.run("ruff format .")


@task
def lint(ctx: Context) -> None:
    """Run all linters: ruff check, ty check, pyrefly check, cargo fmt, cargo clippy."""
    ctx.run("ruff check .")
    ctx.run("ty check .")
    ctx.run("pyrefly check .")
    print("Checking Rust formatting...")
    ctx.run(f"cd {RUST_DIR} && cargo fmt --all -- --check")
    print("Running Rust clippy...")
    ctx.run(f"cd {RUST_DIR} && cargo clippy -- -D warnings")


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
    ctx.run(f"cd {RUST_DIR} && cargo test")


@task(name="all", pre=[build])
def all_checks(ctx: Context) -> None:
    """Run all checks: format, lint, test."""
    format_code(ctx)
    lint(ctx)
    test(ctx)
