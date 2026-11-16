# Performance

Measured timing against a large, realistic environment where a meaningful fraction
of packages have no clean declared metadata, forcing the text-matching fallback —
the case worth stress-testing, since the metadata-only path is essentially free and
the fallback is where the real cost lives.

## Methodology

A single synthetic environment, built once and reused for every tool below:

- **436 installed distributions** (`importlib.metadata.distributions()`), built from
  96 directly-requested packages (the exact list is in
  [`benchmark/requirements.txt`](https://github.com/w-martin/trustedlicenses/blob/main/docs/benchmark/requirements.txt)),
  on Python 3.14.8, spanning data science (pandas, numpy, scipy,
  scikit-learn, polars, xgboost, ...), web frameworks (fastapi, django, flask, ...),
  cloud SDKs (boto3, azure-identity, google-cloud-storage, ...), ML/LLM tooling
  (openai, anthropic, langchain, mlflow, ...), databases (psycopg2, pymongo,
  elasticsearch, ...), and dev tooling (pytest, sphinx, pylint, ...) — installed via
  `uv pip install` with their full transitive dependency trees resolved normally.
- One machine (Apple M5 Pro, 18 cores, macOS 27.2), five runs per tool, a fresh process
  each time, wall-clock time measured around the whole process. `trustedlicenses` is run
  with `--no-cache` unless a row says otherwise, so no result is kept from one run to the
  next; the rows that use the caches prime them once beforehand, outside the timing. The
  published release build (the `cli` profile) is the one measured. This is order-of-magnitude timing from one environment,
  not a rigorous statistical benchmark — reproduce it yourself before trusting it for
  a decision that matters to you. Other machines have fewer cores, and detection
  scales with core count (see below).
- `trustedlicenses` and `pip-licenses` both simply enumerate every installed
  distribution. `licensecheck` instead resolves against a *declared* dependency list,
  so it needs a real `pyproject.toml` with all 96 direct packages listed to get a
  fair, complete run — a minimal or incomplete dependency list produces a crash
  instead of a comparable measurement. `liccheck` couldn't be measured at all — see
  its section below.
- Both `trustedlicenses` builds flag **the same 10 packages with the same detections and the same
  exit code** on this environment, so the timings below compare equivalent work. (The hint under
  each failure is worded differently in 0.4.0: it suggests `accepted-licenses` and
  `allow-unlicensed`.)

## Results

Tool versions: `trustedlicenses` 0.4.0 (native) and 0.3.4 (pure Python),
`pip-licenses` 5.5.5, `licensecheck` 2026.0.8, `liccheck` 0.9.2.

| Tool | Mean ± 1 SD (n=5) | Runs (s) |
|---|---|---|
| `trustedlicenses` 0.4.0, installed environment | **1.04 ± 0.05s** | 1.08, 1.11, 1.00, 0.98, 1.03 |
| `trustedlicenses` 0.3.4 (pure Python) | 1.37 ± 0.04s | 1.43, 1.34, 1.33, 1.35, 1.39 |
| `pip-licenses` | 1.66 ± 0.54s | 2.63, 1.43, 1.42, 1.41, 1.41 |
| `licensecheck` | 2.56 ± 1.19s | 4.69, 2.00, 2.12, 2.00, 1.99 |
| `trustedlicenses` 0.4.0, lock file, cold (network), n=6 | 2.42 ± 0.09s | 2.36, 2.57, 2.41, 2.41, 2.31, 2.46 |
| `trustedlicenses` 0.4.0, installed environment, results already cached | **0.032 ± 0.002s** | 0.032, 0.031, 0.031, 0.033, 0.035 |
| `trustedlicenses` 0.4.0, lock file, everything cached (`--offline`) | **0.031 ± 0.000s** | 0.032, 0.031, 0.031, 0.031, 0.031 |
| `liccheck` | — | crashes immediately, see below |

(SD is the sample standard deviation.)

The first run of `pip-licenses` and of `licensecheck` was much slower than the rest (2.63s and
4.69s), which is what inflates their means and SDs; without it they take 1.4s and 2.0s, so the
ordering is the same either way. The cold lock-file run is the one row that depends on the network,
and it varies from day to day: the same code measured 1.96s on an earlier day. Alternating the
current binary with the previous build in one session gave 2.42s and 2.41s, so the difference is the
network and not the code.

The native build is about 1.3x faster than the pure-Python 0.3.4 here, not an order of
magnitude, and that is expected: on this environment nearly all the time goes on
matching license *text* (below), which is the same Rust code in both. What the native
binary removes is fixed cost — no interpreter to start, no GIL to hand over. On a small
20-package environment where every package declares its license, so there is no matching to
do, that fixed cost is the whole story: **5.8 ms against 61 ms** (n=30 each).

With results kept between runs (the default), a repeat run of the same environment takes
**0.032s**, about 33x faster than the 1.04s above, because the text matching, which is nearly all of
that time, is read back from disk. Packages that change are the only ones scanned again.

## Auditing a lock file

With a lock file (or pinned requirements) the packages don't need to be installed at
all, so the license metadata comes from the package index instead. The same 436
packages, pinned exactly (`uv pip freeze` of the environment above, passed with
`--lock`), against the live pypi.org:

- **Cold** (empty cache): **2.42 ± 0.09s**, with 16 lookups at a time (`--jobs`).
- **Warm** (everything cached, `--offline`): **0.031s**. The metadata and the text-matching
  results are both read from the cache, so there is no network and no scanning. The
  cache for these 436 packages is 6.6M (index metadata and scan results).
- **Same answers:** the same 10 packages fail from the lock file as from the installed
  environment, with the same reasons. One of the 436 is published only as a source
  distribution; its `PKG-INFO` and license files are read from the archive.

A first version of this took 4.2s cold and moved **288 MB** over the network to learn about
6 MB of license data. Tracing every request (`TRUSTEDLICENSES_TRACE=1` prints each one's
time and size) showed where it went, and it wasn't where I first assumed:

| | First version | Now |
|---|---|---|
| Project listings (`/simple/<name>/`) | 436 requests, 195 MB | skipped on pypi.org |
| Whole wheels, to read a license file | about 100 downloads | ranged reads |
| Bytes fetched | 288 MB | **26 MB** |
| Requests | 968 | 976 |
| Cold run, 8 lookups at a time | 4.2s | 3.2s |
| Cold run, 16 lookups at a time | – | 2.4s |

- **The listing is the expensive part of the simple API.** It names every file of every
  release, so `pydantic-core` alone is 9.8 MB, and only one release is wanted. pypi.org
  also serves a document for a single release (`/pypi/<name>/<version>/json`), which is
  used for the default index; any other index, and any failure there, uses the standard
  simple API.
- **A wheel is a zip, and a zip's index is at the end.** A package whose declared metadata
  names no license has its wheel opened with HTTP `Range` requests: the index first, then
  only the entries wanted (`METADATA` and the license files). For a typical wheel that is one
  request of up to 128 KB. A server that ignores `Range` gets a whole-file download instead,
  capped at 25 MB.
- **Concurrency matters.** With the traffic cut, the remaining time is per-request latency
  across a chain of dependent requests per package, so more lookups at once helps:
  4.7s, 3.2s, 2.4s and 1.9s cold at 4, 8, 16 and 32 (five runs each, interleaved). The default is
  16; lower it for an index that is shared or rate-limited. The network-bound figures in this
  section drift with conditions on the day, so compare them with each other, not with the 4.2s
  of the first version, which was measured on another day.

Two limits of reading licenses from an index, both reported as failures rather than skipped:
a source distribution that isn't a readable archive, and, on a server that doesn't support
`Range`, a wheel or source distribution over 25 MB that has to be downloaded whole.

## Why the fallback scans run concurrently

Detection runs the text-matching fallback across every core. The native build uses a
work-stealing thread pool (`rayon`, in
[`detect_all`](https://github.com/w-martin/trustedlicenses/blob/main/rust/core/src/policy.rs)),
and there is no interpreter lock to serialize on. The pure-Python 0.3.4 reached the
same effect with a `ThreadPoolExecutor` and a matcher that released Python's GIL for the
duration of each scan. Since every package's detection is independent work, both let the
fallback scans run genuinely in parallel.

This matters because the fallback triggers for 91 of the 436 packages in this
environment. Breaking down the cost: 338 of 436 packages resolve from declared
metadata (0.08s total — that path is essentially free); the remaining 7 have no
license detected via either path. The bundled-LICENSE-file text matches come to 80
distinct texts, which take 5.2s combined run one at a time, some individual files well over half a second
(`docutils`'s `COPYING.rst`, a short but structurally complex document mixing a
public-domain dedication with several distinct third-party license exceptions,
takes 794ms; `numba`'s and `paramiko`'s license files take 732ms and 678ms).
Running the whole audit on a single thread (`RAYON_NUM_THREADS=1`) took **5.1s** on this
436-package environment — about 4.9x slower than the 1.04s native figure above. That serial
figure shows what parallelism buys, not what any single change inside the matcher buys.

That is also why the result depends on your core count: the machine here has 18 cores.
Pinning the native build to fewer threads on the same environment
(`RAYON_NUM_THREADS`) took 3.0s on 2 threads, 1.5s on 4, 1.2s on 8 and 1.1s on 12, against
1.03s with all 18 — the matching, not the program, is the bottleneck.

A pure-Python tool doing the same fallback text-matching work would not get this
benefit from threading alone — the matcher being native code that doesn't hold the GIL
is what makes the scan genuinely multi-core rather than merely concurrent.

## Text matching: what costs, and what was tried

Almost all the time in a normal run is matching license *text* (see above), so it was worth
asking whether it can be faster. Tracing every scan (`TRUSTEDLICENSES_TRACE=1` prints each
file's time and size) on the 436-package environment showed:

- **A file is scanned as a series of windows of lines, each scored against the whole SPDX
  corpus.** Single-threaded, a plain 11 KB Apache-2.0 text takes about 0.17s, and the 80
  distinct texts in this environment take 5.2s in total. A few files dominate: `docutils`'
  `COPYING.rst` (6 KB, a mix of several licenses) takes 0.79s, and `paramiko`'s and `numba`'s
  26 KB texts about 0.7s each. On this 18-core machine the whole run takes about 1.0s, which
  is close to that one slowest file: while each file is scanned sequentially, that is the floor
  however many cores are free.
- **Many packages ship byte-identical text.** 16 of the 96 files scanned were repeats, 26% of
  the scan time, and the Apache-2.0 text alone appears 9 times. Each distinct text is now
  scanned once, before detection fans out over packages. The results are identical. Repeats are found by comparing the text
  itself, not a hash of it, so a crafted license file can't borrow another's result.

  On this 18-core machine that is only a 5-8% shorter run, because the wall time is set by that
  one slowest file. Where cores are scarce it
  shows: limiting the thread pool to what a CI runner has (`RAYON_NUM_THREADS`), the run took
  84% of its previous time on 2 threads and 70% on 4.
- **Scoring the windows of a file in parallel was tried and dropped.** The decisions can be
  reproduced exactly (the results matched the library's scan on all 463 license files in this
  environment, and it was 3.6x faster on that set, dominated by a few very large files), but on
  a normal run it used 1.5-2x the CPU, because the extra threads spin and over-compute, and it
  meant keeping a copy of the library's algorithm.

- **Results are kept between runs.** Each text's matches are cached on disk beside the other
  caches, keyed by a SHA-256 of the full text, the matching threshold and the version of the
  license data. A repeat run of the benchmark environment takes 0.03s of wall time against 1.04s
  without the result cache, and prints the same output.
  `--no-cache` leaves nothing behind. A truncated or corrupt entry is a miss, never an answer.
- **A shortcut for an unmodified single license was tried and dropped.** The idea was to score
  the whole text against its best match and skip the window search when that match covered
  everything but a few words. Compared with the library's search over 998 inputs (the 463 license
  files in the benchmark environment, pairs of them concatenated, and real licenses with short
  headers added), it disagreed on 10. On roughly 1 KB MIT and BSD texts it found a license
  the window search does not; on an Apache text with a few words more it left out `Pixar`, which
  the full search reports. Either difference changes a verdict, and the result cache already
  removes the cost from every run after the first, so the search stays exact.

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

## Why the first run is sometimes slower

`licensecheck`'s five runs ranged from 1.99s to 4.69s; four of the five were within
1.99s–2.12s and the 4.69s outlier was the first run. `pip-licenses` shows the same
shape (a 2.63s first run, then 1.41s–1.43s). `licensecheck` can fall back to the PyPI
JSON API for packages it can't resolve locally, which could explain network-dependent
variance, but `pip-licenses` makes no network requests, so a cold file cache (the first
run of each tool touches files the previous tool didn't) is at least as plausible. The
cause isn't confirmed; this is a hypothesis, not a verified finding.
