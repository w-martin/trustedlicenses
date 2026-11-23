# Performance

These timings come from a large, realistic environment where many packages have no clean
declared metadata, so the text-matching fallback does real work; reading metadata is
essentially free. The numbers are from one machine, so reproduce them
([Methodology](#methodology)) before relying on them for a decision that matters to you.

## Results

Tool versions: `trustedlicenses` 0.5.0 (native) and 0.3.4 (pure Python),
`pip-licenses` 5.5.5, `licensecheck` 2026.0.8, `liccheck` 0.9.2. SD is the sample standard
deviation.

| Tool | Mean ± 1 SD (n=5) | Runs (s) |
|---|---|---|
| `trustedlicenses` 0.5.0, installed environment | **1.10 ± 0.05s** | 1.07, 1.15, 1.12, 1.04, 1.14 |
| `trustedlicenses` 0.3.4 (pure Python) | 1.26 ± 0.02s | 1.24, 1.25, 1.24, 1.27, 1.28 |
| `pip-licenses` | 1.66 ± 0.28s | 2.16, 1.55, 1.54, 1.53, 1.54 |
| `licensecheck` | 2.60 ± 1.15s | 4.65, 2.14, 2.06, 2.03, 2.12 |
| `trustedlicenses` 0.5.0, lock file, cold (network), n=6 | 2.67 ± 1.31s | 5.33, 2.07, 2.12, 2.18, 2.14, 2.16 |
| `trustedlicenses` 0.5.0, installed environment, results already cached | **0.035 ± 0.000s** | 0.035, 0.035, 0.035, 0.035, 0.035 |
| `trustedlicenses` 0.5.0, lock file, everything cached (`--offline`) | **0.031 ± 0.000s** | 0.031, 0.031, 0.032, 0.031, 0.031 |
| `liccheck` | — | crashes immediately, see below |

The first run of `pip-licenses`, `licensecheck` and the cold lock-file audit was much slower
than the rest (2.16s, 4.65s and 5.33s), which inflates their means and SDs. Without it they
take 1.5s, 2.1s and 2.1s, so the ordering holds either way. A cold file cache, or for the
lock-file audit a cold connection to the index, is a plausible cause, but that's a
hypothesis, not confirmed.

The native build is about 1.1x faster than 0.3.4 here, not an order of magnitude, because
nearly all the time goes on matching license text, the same Rust code in both. What the
native binary removes is fixed cost: no interpreter to start, no GIL to hand over. On a
20-package environment where every package declares its license, so nothing needs matching,
fixed cost is everything: **5.8 ms against 61 ms** (n=30 each, measured with 0.4.0).

With results kept between runs (the default), a repeat run takes **0.035s**, about 32x
faster, because the text matching is read back from disk. Only packages that change are
scanned again.

### Cores

Text matching runs across every core. Limiting the threads (`RAYON_NUM_THREADS`, n=3 each)
took 6.3s on 1, 3.4s on 2, 1.7s on 4, 1.5s on 8 and 1.3s on 12, against 1.22s on all 18 in
the same session. The fallback triggers for 83 of the 453 packages; 361 resolve from declared
metadata, and the other 9 have no license detected either way.

## Methodology

Every tool ran against one synthetic environment, built once: **453 installed
distributions** (`importlib.metadata.distributions()`). They are 96 directly requested
packages on Python 3.14.8, installed with `uv pip install` along with their full transitive
dependency trees, plus the tools being compared and their dependencies. They span data
science, web frameworks, cloud SDKs, ML/LLM tooling, databases and dev tooling; the full
list is in
[`benchmark/requirements.txt`](https://github.com/w-martin/trustedlicenses/blob/main/docs/benchmark/requirements.txt).

Each tool ran five times on one machine (Apple M5 Pro, 18 cores, macOS 27.2.1), in a fresh
process each time, timed by wall clock around the whole process. `trustedlicenses` ran with
`--no-cache` unless a row says otherwise; rows that use the caches primed them once
beforehand, outside the timing. The measured build is the release build (the `cli`
profile). This is order-of-magnitude timing, not a rigorous statistical benchmark, and
machines with fewer cores will be slower ([Cores](#cores)).

`trustedlicenses` and `pip-licenses` enumerate every installed distribution. `licensecheck`
resolves against a declared dependency list, so a fair, complete run needs a real
`pyproject.toml` listing all 96 direct packages; a minimal or incomplete list crashes it.

Both `trustedlicenses` builds flag **the same 10 packages with the same exit code**, so the
timings compare equivalent work. Only the hint under each failure is worded differently.

## Auditing a lock file

The same packages, pinned exactly (`uv pip freeze` of the environment above, passed with
`--lock`), were audited against the live pypi.org. That's 452 of the 453: the benchmark's
own locally built `trustedlicenses` 0.3.4 isn't on PyPI, so it was left out.

- Cold, with no cache and 16 lookups at a time (`--jobs`): **2.1s** once the first run is
  set aside (2.67 ± 1.31s with it).
- Cold at 4, 8, 16 and 32 lookups at a time: 4.0s, 2.9s, 2.1s and 1.8s (five runs each,
  interleaved; network figures drift from day to day, so compare these with each other). The
  default is 16; lower it for a shared or rate-limited index.
- Warm, with everything cached and `--offline`: **0.031s**, with no network and no scanning.
  The cache for these packages is 6.6 MiB of index metadata and scan results.

A cold run fetches 26.2 MB in 1,004 requests. The same 10 packages fail from the lock file as
from the installed environment.

## `liccheck` couldn't be benchmarked

`liccheck` (last released 2023-09-22) crashed immediately in this environment:

```
ModuleNotFoundError: No module named 'pkg_resources'
```

`setuptools` 84.0.0, current at the time, was installed, but recent `setuptools` releases
have been deprecating and dropping `pkg_resources`. `liccheck` imports `pkg_resources` directly
(`liccheck/requirements.py`), so it doesn't run on a current Python/setuptools combination
unless you install an older `setuptools` beside it.
