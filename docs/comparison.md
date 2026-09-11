# Comparison to Alternatives

This page summarizes research done while designing `trustedlicenses`, plus a
reproducible benchmark against the two most directly comparable tools. Where a claim
is backed by primary-source verification, it's cited; where a benchmark number is
ours, the methodology is given so you can reproduce or challenge it.

## Summary

| Tool | Detection strategy | Speed (134-package env, this benchmark) | Network calls | Text-matching fallback |
|---|---|---|---|---|
| [`pip-licenses`](https://github.com/raimon49/pip-licenses) | Declared metadata only (`License-Expression` → classifiers → `License`) | 0.94s | No | No |
| [`licensecheck`](https://github.com/FHPythonUtils/LicenseCheck) | Declared metadata, plus PyPI API fallback for packages not resolvable locally | 2.70s | Only on that fallback path | No |
| [`liccheck`](https://github.com/dhatim/python-license-check) | Declared metadata only, via the deprecated `pkg_resources` API | not benchmarked (see below) | No | No |
| ScanCode Toolkit (what this project used to wrap) | Full rule-based multi-region text matching against ~2,100 texts + ~32,000 rule variants | not comparable — a whole-tree source scanner, not built for this | No | Yes (primary signal) |
| **`trustedlicenses`** | Declared metadata first; Rust text-matching fallback only when nothing declared resolves | 1.89s | No | Yes (fallback only) |

**Methodology, so the numbers aren't misleading:** all three benchmarked tools were
run against the same synthetic virtual environment (134 installed distributions —
`pandas`, `scikit-learn`, `fastapi`, `boto3`, `requests`, `jupyter`, and their full
transitive dependency trees), on the same machine, wall-clock time via `time`, one run
each (not averaged over multiple runs — treat these as order-of-magnitude, not
precision benchmarks). `pip-licenses` and `trustedlicenses` both simply enumerate
`importlib.metadata.distributions()`; `licensecheck` instead resolves against a
project's *declared* dependency tree (parsed from `pyproject.toml`), which is a
meaningfully different (and apparently slower) code path, not a strictly
apples-to-apples race. ScanCode wasn't benchmarked directly here since it's designed
to scan whole source trees, not enumerate installed packages — see the informal
third-party benchmark cited below instead.

## `pip-licenses`

Pure metadata reading — `License-Expression` when present (added in v5.5.0), falling
back to classifiers, falling back to the free-text `License` field. No text matching
of any kind. Very actively maintained (commits within the last day, as of this
research). It's a *lister*, not a policy-enforcement tool: it has no built-in
pass/fail concept against a set of allowed categories the way `trustedlicenses` and
`licensecheck` do — you'd need to post-process its output yourself to get that.

## `licensecheck`

Reads `LocalPackageInfo.get_license()` as `License-Expression or classifiers or
License field` — verified directly from its source
([`packageinforesolver.py`](https://github.com/FHPythonUtils/LicenseCheck)) — the
same metadata-priority strategy `trustedlicenses` uses for its primary path. No
bundled-LICENSE-file text matching anywhere in its code. When a package isn't
installed locally, it can fall back to the PyPI JSON API instead — not applicable to
`trustedlicenses`'s installed-environment-only scope. Very actively maintained
(releases every few days).

**We particularly like its legal disclaimer** and modeled our own on it — see the
[README](https://github.com/w-martin/trustedlicenses#legal-disclaimer).

## `liccheck`

Same metadata-only strategy, but via the deprecated `pkg_resources` API rather than
`importlib.metadata`, and with no `License-Expression` support found in its source.
Last released 2023-09-22 — over two years old as of this writing, predating PyPI's
PEP 639 rollout (November 2024) entirely. Not benchmarked here because it wasn't worth
installing a legacy tool for a timing number; treat it as effectively unmaintained
for this purpose.

## ScanCode Toolkit (and what `trustedlicenses` used to be)

`trustedlicenses` originally wrapped `scancode-toolkit-mini`: a full rule-based engine
matching against ~2,100 full license texts plus ~32,000 notice/variant rules, combined
via hash matching, an Aho-Corasick-style matcher, and sequence alignment. It requires
a system `libmagic` install (for file-type sniffing) and is significantly heavier than
this project's narrower need — auditing bundled LICENSE files of *installed Python
packages*, not scanning arbitrary source trees for embedded license fragments.

The one public benchmark we found (Thomas Wolter, *"A Comparison Study of Open Source
License Crawler,"* bachelor's thesis, FAU Erlangen-Nürnberg, 2019 — informal, a small
25-case manually-judged sample, not peer-reviewed) measured ScanCode's precision at
only **37.5%** on cases where it disagreed with FOSSology, i.e. on genuinely disputed
matches specifically, not its overall accuracy. Take that as a data point that
ScanCode's much heavier machinery doesn't obviously buy proportionally better
precision for this narrower use case, not as a rigorous accuracy claim either way.

## The algorithm family `trustedlicenses` actually uses

`trustedlicenses`'s text-matching fallback wraps the
[`spdx`](https://github.com/EmbarkStudios/spdx) Rust crate, which inlines
[askalono](https://github.com/jpeddicord/askalono)'s word-bigram Sørensen–Dice
matching algorithm against the SPDX license-list-data corpus (askalono itself,
originally built at Amazon, is now unmaintained — the `spdx` crate is the maintained
continuation, and what `cargo-deny`/`cargo-about` migrated to for the same reason).
This is the same *family* of approach as:

- **GitHub's own [Licensee](https://github.com/licensee/licensee)** — a wordset Dice
  coefficient plus a bigram Dice coefficient as an anti-scrambling guard, at a 98%
  threshold, against a curated 47-license corpus from choosealicense.com (not the full
  SPDX list). Verified from source: it has no segmentation for a LICENSE file that
  concatenates multiple licenses — the whole file is scored as one blob, so a file
  like the `pandas`-style vendored-notices case this project's own test suite covers
  would silently score below threshold and report no match at all, rather than a
  wrong one.
- **Google's [licenseclassifier](https://github.com/google/licenseclassifier)** — word-trigram
  hashing to locate candidate spans, then Levenshtein distance per span, at a 0.80
  threshold. Its README states plainly it's "not an official Google product," though
  Google's own [opensource.google documentation](https://opensource.google/documentation/reference/thirdparty/classify-a-license)
  describes an internal tool of the same name as "the source of truth for license
  classifications at Google" — good circumstantial evidence of the same lineage, not
  proof the codebases are identical.

## A real limitation we found in our own tool

While benchmarking, we found that `askalono`'s (and by inheritance, `spdx`'s) own
library-default confidence threshold of `0.9` produces real false negatives: two
extremely common, correctly-licensed PyPI packages —
[`jupyter`](https://pypi.org/project/jupyter/)'s and
[`prompt-toolkit`](https://pypi.org/project/prompt-toolkit/)'s genuine, unmodified
BSD-3-Clause `LICENSE` files score `0.85` and `0.91` respectively against the corpus.
At `0.9`, both are missed; at `0.8` — which turns out to be what
[askalono's own CLI actually uses](https://github.com/jpeddicord/askalono), overriding
its *library's* `0.9` default for evidently the same reason — both resolve correctly,
without introducing false positives at nearby scores (`0.7` starts misidentifying
BSD-3-Clause variants as the wrong license). `trustedlicenses` uses `0.8` for exactly
this reason; see `TEXT_MATCH_CONFIDENCE_THRESHOLD` in
[`detection.py`](https://github.com/w-martin/trustedlicenses/blob/main/src/trustedlicenses/detection.py).

This is disclosed here deliberately: any similarity-based text matcher — ours
included — has a real, tunable false-negative/false-positive tradeoff. It is not a
rule engine, and it will not be right 100% of the time. See the
[legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer).

## A narrow, FSF-grounded compatibility check

An earlier version of this design considered flagging *category-level* copyleft
compatibility — e.g. "your project isn't copyleft, this dependency is." Research
before implementing it found that's a real trap, not just an oversimplification:

- **[`licensecheck`](https://github.com/FHPythonUtils/LicenseCheck) is the one tool in
  this space that actually ships project-vs-dependency compatibility checking**, and
  it deliberately doesn't use categories — verified from source
  (`license_matrix/__init__.py`, `matrix.csv`), it's a hand-rolled pairwise matrix
  over **27 granular license variants** (`GPL_2`, `GPL_2_PLUS`, `GPL_3`, `LGPL_2_PLUS`,
  ...), not 4 buckets.
- **`license-expression`** (the library both ScanCode and `licensecheck` use to parse
  SPDX boolean expressions) has zero compatibility logic — confirmed by reading its
  source; "compare" in its own README refers to boolean-expression equivalence, not
  legal compatibility between two different licenses.
- **The FSF's own [GPL compatibility guidance](https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility)**
  states plainly: *"GPLv2 is, by itself, not compatible with GPLv3."* Both are
  "Copyleft" in ScanCode's taxonomy — a category-only check would call this fine, and
  be wrong.
- **MPL-2.0** (bucketed "Copyleft Limited") has an explicit, conditional
  GPL-compatibility clause written into the license text itself (§3.3), which authors
  can opt out of — something a "Copyleft Limited vs Copyleft" boundary check can't
  represent either.
- ORT's example compatibility rules are also category-based ("is this a strong-copyleft
  license, at all"), not pairwise — real pairwise compatibility matrices (like the
  [OSADL Compatibility Matrix](https://www.osadl.org/Access-to-raw-data.oss-compliance-raw-data-access.0.html))
  are a meaningfully bigger undertaking than a 4-bucket comparison.

Given `trustedlicenses`'s [legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer)
stance, shipping a category-level verdict risked exactly what we're trying to avoid: a
confident-sounding wrong answer. So the check that shipped is much narrower than
"compatibility checking" — it fires only on the small number of pairings the FSF
states explicitly and unambiguously, using exact SPDX identifiers rather than
categories, and is presented as a note to verify, never a verdict, and never something
that affects pass/fail:

1. **GPL-2.0-only project + GPL-3.0/AGPL-3.0-family dependency (or vice versa)** — the
   specific FSF-documented mismatch above. Deliberately excludes `GPL-2.0-or-later`,
   which grants permission to relicense under GPLv3.
2. **Non-copyleft project + a plain strong-copyleft dependency** (`GPL-2.0-only`,
   `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`, `AGPL-3.0-only`,
   `AGPL-3.0-or-later` — never `LGPL`/`MPL`, which have their own linking/conditional
   exceptions) — a general "worth a second look" heads-up, not a specific citation.

This requires your own project to declare `[project.license]` (PEP 639); with nothing
declared, no notes fire at all — a responsible note needs both sides. See
`_compatibility_note` in
[`policy.py`](https://github.com/w-martin/trustedlicenses/blob/main/src/trustedlicenses/policy.py)
for the exact logic, and the real example (a GPL-2.0-only project pulling in `scipy`,
GPL-3.0-or-later, via `scikit-learn`) in the
[README](https://github.com/w-martin/trustedlicenses#usage).
