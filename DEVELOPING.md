# Developing trustedlicenses

## Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) - Python package manager
- Rust toolchain (for building the license-text matcher extension)

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
uv run maturin develop
```

## Task Commands

All development tasks are managed via [Invoke](https://www.pyinvoke.org/). Run
`uv run inv --list` to see available tasks.

- `uv run inv build` -- build the Rust matcher extension (`maturin develop`) if its
  source has changed since the last build
- `uv run inv format` -- run `ruff format`
- `uv run inv lint` -- run `ruff check`, `ty check`, `pyrefly check`, `cargo fmt
  --check`, and `cargo clippy`
- `uv run inv lint-fix` -- auto-fix with `ruff check --fix` and `ruff format`
- `uv run inv test` -- build the Rust matcher if needed, then run pytest (with branch
  coverage) and `cargo test`
- `uv run inv all` -- format, lint, then test, in order

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
accept. See `src/trustedlicenses/config.py` for the full format.

Run the check with:

```shell
uv run trustedlicenses
```

or embed it in code via `trustedlicenses.load_policy()` and
`trustedlicenses.evaluate()`.

## Documentation

Docs are built with [MkDocs](https://www.mkdocs.org/) (Material theme) and published
to [Read the Docs](https://trustedlicenses.readthedocs.io/). Build and serve locally:

```shell
uv sync --group docs
uv run mkdocs serve
```

Docs source lives in `docs/`; `mkdocs.yml` controls navigation and the
[mkdocstrings](https://mkdocstrings.github.io/) plugin pulls API reference pages
directly from docstrings in `src/trustedlicenses/`.

## Attribution

This project bundles data derived from the SPDX License List and ScanCode Toolkit's
license database, and depends on the Apache-2.0-licensed `spdx` Rust crate. See
`NOTICE` for the required attribution.
