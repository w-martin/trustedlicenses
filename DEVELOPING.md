# Developing trustedlicenses

## Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) - Python package manager
- Rust toolchain (the command line itself is a Rust program)

> **macOS note:** If you installed Rust via `brew install rustup` and `rustc`/`cargo`
> are not found even after `rustup toolchain install stable`, it's because Homebrew's
> `rustup` formula is keg-only (it conflicts with the `rust` formula) and only symlinks
> the `rustup` binary itself into your PATH. The actual `rustc`/`cargo`/etc. shims live
> in `$(brew --prefix rustup)/bin` but are never added to PATH automatically, unlike the
> official rustup.rs installer. Fix by adding that directory to your shell profile:
>
> ```shell
> echo 'export PATH="'"$(brew --prefix rustup)"'/bin:$PATH"' >> ~/.zshrc
> source ~/.zshrc
> ```

## Setup

```shell
git clone https://github.com/w-martin/trustedlicenses.git
cd trustedlicenses
uv sync
uv run inv build
```

`inv build` builds the `trustedlicenses` executable and the extension modules and
installs them into the environment, so `uv run trustedlicenses` runs your working tree.

## Task Commands

All development tasks are managed via [Invoke](https://www.pyinvoke.org/). Run
`uv run inv --list` to see available tasks.

- `uv run inv build` -- build the executable and extension modules (`maturin develop`)
  if their source has changed since the last build
- `uv run inv wheel` -- build a release wheel into `dist/`: the executable on the
  `cli` profile plus both extension modules, exactly as the publish workflow does
- `uv run inv check-wheel` -- install the wheel in `dist/` into a clean virtual
  environment and run every way of starting the command line (the executable,
  `trustedlicenses-py`, `python -m trustedlicenses`, and the in-process mode)
- `uv run inv format` -- run `ruff format`
- `uv run inv lint` -- run `ruff check`, `ty check`, `pyrefly check`, `cargo fmt
  --check`, and `cargo clippy`, then `floor-check`
- `uv run inv floor-check` -- run `ty` and `pyrefly` at the minimum supported Python
  (3.11), which CI uses; also run by the pre-commit hook
- `uv run inv lint-fix` -- auto-fix with `ruff check --fix` and `ruff format`
- `uv run inv test` -- build if needed, then run pytest (with branch coverage) and
  `cargo test`
- `uv run inv all` -- format, lint, then test, in order

## Layout

The Rust workspace is in `rust/`:

| Crate | Role |
|---|---|
| `core` | Detection, policy, config, package sources (installed environments, lock files, requirements) and the package-index client. No Python. |
| `cli` | The command line, as a library (`run`) and the `trustedlicenses` executable. |
| `python` | The `trustedlicenses._rust` extension module (abi3), which runs the command line inside the Python process. Kept apart because PyO3's macros expand to `unsafe`, which the other crates forbid. |

The wheel is built with `bindings = "bin"`, which cannot build the extension modules,
so they are built on their own and staged into `src/trustedlicenses/` (`inv build` and
`inv wheel` do this; the publish workflow does the same). The `cli` profile builds the
executable with `panic = "abort"`; the extension keeps unwinding so a panic becomes a
Python exception.

Two things to know when changing the build:

- **`cargo test` excludes the extension crate** (`--exclude trustedlicenses_python`):
  it enables PyO3's `extension-module` feature, which would otherwise unify into the
  other crates' test builds and leave them unable to link.
- **The extension is not stripped.** On macOS the system `strip` leaves a shared
  library that `dlopen` refuses ("mis-aligned LINKEDIT string pool") whether asked to
  strip symbols or only debug info. `inv check-wheel` exists to catch this class of
  failure: it *loads* the extension, not just checks that it is present.

`TRUSTEDLICENSES_TRACE=1` prints every package-index request's time, size and URL to
standard error, which is how the lock-file audit was tuned (see
[Performance](docs/performance.md#auditing-a-lock-file)).

Allocators: jemalloc on Linux (including the static musl executables), mimalloc on
Windows, the platform's on macOS. Build with `--features system-allocator` to compare.

## Configuring a consuming project

A project adopting `trustedlicenses` declares its policy in its own
`pyproject.toml`:

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
ignored-packages = ["mypy-extensions"]
```

`allowed-categories` is required -- there is no default, so a project states its
policy explicitly rather than inheriting an assumption about what it's willing to
accept. See `rust/core/src/config.rs` for the full format.

Run the check with:

```shell
uv run trustedlicenses
```

## Documentation

Docs are built with [MkDocs](https://www.mkdocs.org/) (Material theme) and published
to [Read the Docs](https://trustedlicenses.readthedocs.io/). Build and serve locally:

```shell
uv sync --group docs
uv run mkdocs serve
```

Docs source lives in `docs/`; `mkdocs.yml` controls navigation.

## Attribution

This project bundles data derived from the SPDX License List and ScanCode Toolkit's
license database, and depends on the Apache-2.0-licensed `spdx` Rust crate. See
`NOTICE` for the required attribution.
