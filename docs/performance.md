# Performance

Measured timing against a large, realistic environment where a meaningful fraction
of packages have no clean declared metadata, forcing the text-matching fallback —
the case worth stress-testing, since the metadata-only path is essentially free and
the fallback is where the real cost lives.

## Methodology

A single synthetic environment, built once and reused for every tool below:

- **425 installed distributions** (`importlib.metadata.distributions()`), built from
  ~97 directly-requested packages spanning data science (pandas, numpy, scipy,
  scikit-learn, polars, xgboost, ...), web frameworks (fastapi, django, flask, ...),
  cloud SDKs (boto3, azure-identity, google-cloud-storage, ...), ML/LLM tooling
  (openai, anthropic, langchain, mlflow, ...), databases (psycopg2, pymongo,
  elasticsearch, ...), and dev tooling (pytest, sphinx, pylint, ...) — installed via
  `uv pip install` with their full transitive dependency trees resolved normally.
- One machine (Apple Silicon macOS), `/usr/bin/time -p`, three runs per tool, cold
  process each time (no warm-cache reuse between runs). This is order-of-magnitude
  timing from one environment, not a rigorous statistical benchmark — reproduce it
  yourself before trusting it for a decision that matters to you.
- `trustedlicenses` and `pip-licenses` both simply enumerate every installed
  distribution. `licensecheck` instead resolves against a *declared* dependency list,
  so it needs a real `pyproject.toml` with all ~97 direct packages listed to get a
  fair, complete run — a minimal or incomplete dependency list produces a crash
  instead of a comparable measurement. `liccheck` couldn't be measured at all — see
  its section below.

## Results

| Tool | Median | Range (3-5 runs) |
|---|---|---|
| `trustedlicenses` | **1.29s** | 1.25s – 2.05s |
| `pip-licenses` | 1.60s | 1.56s – 2.58s |
| `licensecheck` | 2.13s | 2.08s – 9.30s |
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

This matters because the fallback triggers for 96 of the 425 packages in this
environment. Breaking down the cost: 322 of 425 packages resolve from declared
metadata (0.04s total — that path is essentially free); the remaining 7 have no
license detected via either path and so never reach a fallback scan at all. The 96
bundled-LICENSE-file text matches take 7.47s combined run serially, some individual
files
well over half a second (`docutils`'s `COPYING.rst`, a short but structurally
complex document mixing a public-domain dedication with several distinct
third-party license exceptions, takes 781ms; `paramiko`'s and `numba`'s license
files each take ~670ms). Run one package at a time with the GIL held throughout
the scan, this same 425-package environment takes **7.7–8.9s** — roughly 6x slower
than the 1.29s median reported above. The parallelized and serial versions produce
byte-identical results on this same environment, in the same order; only wall time
differs.

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

`licensecheck`'s five runs ranged from 2.08s to 9.30s with no clear pattern (not
simply "first run slow, rest fast"). The cause isn't confirmed. `licensecheck` can
fall back to the PyPI JSON API for packages it can't resolve locally, which would
plausibly explain network-dependent variance in the range, but this remains an
unconfirmed hypothesis, not a verified cause.
