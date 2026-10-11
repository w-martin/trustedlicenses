# Performance

Measured timing against a large, realistic environment where a meaningful fraction
of packages have no clean declared metadata, forcing the text-matching fallback —
the case worth stress-testing, since the metadata-only path is essentially free and
the fallback is where the real cost lives.

## Methodology

A single synthetic environment, built once and reused for every tool below:

- **453 installed distributions** (`importlib.metadata.distributions()`), built from
  96 directly-requested packages (the exact list is in
  [`benchmark/requirements.txt`](https://github.com/w-martin/trustedlicenses/blob/main/docs/benchmark/requirements.txt)),
  on Python 3.14.8, spanning data science (pandas, numpy, scipy,
  scikit-learn, polars, xgboost, ...), web frameworks (fastapi, django, flask, ...),
  cloud SDKs (boto3, azure-identity, google-cloud-storage, ...), ML/LLM tooling
  (openai, anthropic, langchain, mlflow, ...), databases (psycopg2, pymongo,
  elasticsearch, ...), and dev tooling (pytest, sphinx, pylint, ...) — installed via
  `uv pip install` with their full transitive dependency trees resolved normally.
- One machine (Apple Silicon macOS), `/usr/bin/time -p`, five runs per tool, cold
  process each time (no warm-cache reuse between runs). This is order-of-magnitude
  timing from one environment, not a rigorous statistical benchmark — reproduce it
  yourself before trusting it for a decision that matters to you.
- `trustedlicenses` and `pip-licenses` both simply enumerate every installed
  distribution. `licensecheck` instead resolves against a *declared* dependency list,
  so it needs a real `pyproject.toml` with all 96 direct packages listed to get a
  fair, complete run — a minimal or incomplete dependency list produces a crash
  instead of a comparable measurement. `liccheck` couldn't be measured at all — see
  its section below.

## Results

Tool versions: `trustedlicenses` 0.3.4, `pip-licenses` 5.5.5, `licensecheck` 2026.0.8,
`liccheck` 0.9.2.

| Tool | Mean ± 1 SD (n=5) | Runs (s) |
|---|---|---|
| `trustedlicenses` | **1.23 ± 0.02s** | 1.21, 1.21, 1.24, 1.23, 1.24 |
| `pip-licenses` | 1.59 ± 0.01s | 1.60, 1.60, 1.58, 1.58, 1.60 |
| `licensecheck` | 2.35 ± 0.59s | 3.40, 2.10, 2.07, 2.08, 2.12 |
| `liccheck` | — | crashes immediately, see below |

## Why the fallback scans run concurrently

Detection runs the text-matching fallback across a thread pool
(`concurrent.futures.ThreadPoolExecutor` in
[`detect_all()`](https://github.com/w-martin/trustedlicenses/blob/main/src/trustedlicenses/policy.py)),
and the underlying Rust matcher releases Python's GIL for the duration of each scan
(`Python::detach` around the `spdx` crate's scan call in
[`scan_license_text`](https://github.com/w-martin/trustedlicenses/blob/main/rust/src/matcher.rs)).
Since every package's detection is independent work, this lets the fallback scans
run genuinely in parallel across multiple cores rather than serializing behind
Python's interpreter lock.

This matters because the fallback triggers for 86 of the 453 packages in this
environment. Breaking down the cost: 361 of 453 packages resolve from declared
metadata (0.08s total — that path is essentially free); the remaining 6 have no
license detected via either path. The 86 bundled-LICENSE-file text matches take
7.48s combined run serially, some individual files well over half a second
(`docutils`'s `COPYING.rst`, a short but structurally complex document mixing a
public-domain dedication with several distinct third-party license exceptions,
takes 834ms; `numba`'s and `paramiko`'s license files take 756ms and 723ms).
Calling the same per-package detection one package at a time in a single thread
([`benchmark/serial.py`](https://github.com/w-martin/trustedlicenses/blob/main/docs/benchmark/serial.py))
takes **7.6–7.8s** over two runs on this 453-package environment — roughly 6x
slower than the 1.23s mean reported above. That serial figure was measured by
running detection sequentially, not by rebuilding the matcher without its GIL
release, so it shows what the thread pool buys, not what the GIL release buys on
its own.

A pure-Python tool doing the same fallback text-matching work would not get this
benefit from threading alone — the GIL release in the Rust matcher is what makes
the scan genuinely multi-core rather than merely concurrent.

## `liccheck` couldn't be benchmarked

`liccheck` (last released 2023-09-22) crashed immediately in this environment:

```
ModuleNotFoundError: No module named 'pkg_resources'
```

This is not an artifact of a stripped-down environment: `setuptools` (84.0.0,
current at the time of this test) was installed, and `pkg_resources` still wasn't
importable — recent `setuptools` releases have been deprecating and dropping it.
`liccheck` imports `pkg_resources` directly (`liccheck/requirements.py`), so it
doesn't run at all on a current Python/setuptools combination without manually
installing an older `setuptools` alongside it. This is a concrete,
current-as-of-testing data point in addition to the two-year-old last release noted
in the [comparison](comparison.md#liccheck).

## Why `licensecheck`'s range is so wide

`licensecheck`'s five runs ranged from 2.07s to 3.40s; four of the five were within
2.07s–2.12s and the 3.40s outlier was the first run. An earlier measurement on a
different environment saw a much wider range (2.08s to 9.30s) with no such pattern.
The cause isn't confirmed. `licensecheck` can fall back to the PyPI JSON API for
packages it can't resolve locally, which would plausibly explain network-dependent
variance (including a slow first request), but this remains an unconfirmed
hypothesis, not a verified cause.
