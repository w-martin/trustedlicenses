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

`TRUSTEDLICENSES_TRACE=1` prints every package-index request's time, size and URL, and each
scanned file's time and size, to standard error. That's how the lock-file audit was tuned
([Design notes](#lock-file-audit-traffic)).

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

`allowed-categories` (or, for a pinned policy, `allowed-licenses`) is required -- there is
no default, so a project states its policy explicitly rather than inheriting an assumption
about what it's willing to accept. See `rust/core/src/config.rs` for the full format.

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

## Design notes

Measurements below were taken on the [Performance](docs/performance.md) benchmark environment
when it had 436 packages (18 cores); the current figures are on that page.

### Lock-file audit traffic

Reading the simple-API listing for every package, and whole wheels for license files, took
4.2s cold and moved 288 MB to learn about 6 MB of license data:

| | Listings and whole wheels | Current |
|---|---|---|
| Project listings (`/simple/<name>/`) | 436 requests, 195 MB | skipped on pypi.org |
| Whole wheels, to read a license file | about 100 downloads | ranged reads |
| Bytes fetched | 288 MB | **26 MB** |
| Requests | 968 | 976 |
| Cold run, 8 lookups at a time | 4.2s | 3.2s |
| Cold run, 16 lookups at a time | – | 2.4s |

A listing names every file of every release (`pydantic-core`'s alone is 9.8 MB), so for the
default index the single-release document pypi.org serves (`/pypi/<name>/<version>/json`) is
used instead; any other index, and any failure there, uses the standard simple API. A wheel
is a zip with its index at the end, so when declared metadata names no license the wheel is
opened with HTTP `Range` requests: the index first, then only `METADATA` and the license
files, typically one request of up to 128 KB. A server that ignores `Range` gets a whole-file
download, capped at 25 MB. With the traffic cut, what's left is per-request latency across a
chain of dependent requests per package, which is why lookups run concurrently (`--jobs`).

### Why the fallback scans run concurrently

Each package's detection is independent, so the native build spreads them over a
work-stealing thread pool (`rayon`, in
[`detect_all`](https://github.com/w-martin/trustedlicenses/blob/main/rust/core/src/policy.rs))
with no interpreter lock to serialize on. The pure-Python 0.3.4 got the same effect with a
`ThreadPoolExecutor` and a native matcher that released the GIL during each scan.

The bundled license files of the 91 packages that need the fallback come to 80 distinct
texts, which take 5.2s combined run one at a time. Some take well over half a second:
`docutils`'s `COPYING.rst`, a short but structurally complex document mixing a public-domain
dedication with several third-party license exceptions, takes 794ms; `numba`'s and
`paramiko`'s take 732ms and 678ms.

### Text matching costs and design choices

A file is scanned as a series of windows of lines, each scored against the whole SPDX corpus.
Single-threaded, a plain 11 KB Apache-2.0 text takes about 0.17s. Each file is scanned
sequentially, so on 18 cores the run (about 1.0s) is close to the slowest file, which sets
the floor however many cores are free.

Identical texts are scanned once, before detection fans out over packages, with identical
results. 16 of the 96 files scanned were byte-identical repeats, 26% of the scan time (the
Apache-2.0 text alone appears 9 times). Repeats are found by comparing the text itself, not a
hash, so a crafted license file can't borrow another's result. On 18 cores that shortens a
run by only 5-8%; limited to what a CI runner has (`RAYON_NUM_THREADS`), the run took 84% of
its previous time on 2 threads and 70% on 4.

Each text's matches are cached on disk beside the other caches, keyed by a SHA-256 of the
full text, the matching threshold and the license-data version, and give the same output as
a fresh scan. A truncated or corrupt entry is a miss, never an answer.

Two speedups were left out. Scoring a file's windows in parallel reproduced the decisions
exactly on all 463 license files in this environment and was 3.6x faster on that set, but on
a normal run it used 1.5-2x the CPU, because the extra threads spin and over-compute, and it
meant keeping a copy of the library's algorithm. A shortcut for an unmodified single license
(score the whole text against its best match, and skip the window search when that match
covers all but a few words) disagreed with the full search on 10 of 998 inputs: it found a
license in roughly 1 KB MIT and BSD texts that the window search doesn't, and left `Pixar`
out of an Apache text with a few extra words. Either difference changes a verdict, and the
result cache already removes the cost after the first run, so the search stays exact.
