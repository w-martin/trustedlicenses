# Usage Guide

## Installation

```shell
uv add --dev trustedlicenses
```

or with pip:

```shell
pip install trustedlicenses
```

No system dependencies are required — the license-text matcher is a compiled Rust
extension with the SPDX corpus baked in at build time, not something that loads data
at runtime or shells out to another tool.

## Step 1 — Declare a policy

The easiest way is to just run `trustedlicenses` in a terminal with nothing
configured yet — see [No policy configured yet?](#no-policy-configured-yet) below,
it'll interactively build this file for you. To write it by hand instead, add a
`[tool.trustedlicenses]` table to your project's `pyproject.toml`:

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
ignored-packages = ["mypy-extensions"]
```

Or, equivalently, a standalone `trustedlicenses.toml` next to it — same keys, no
`[tool.trustedlicenses]` wrapper needed (the same convention `ruff.toml` uses
relative to `[tool.ruff]`):

```toml
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
ignored-packages = ["mypy-extensions"]
```

If both exist, the standalone file wins.

- **`allowed-categories`** (required, no default) — a distribution passes if *at least
  one* of its detected licenses falls into one of these categories. There's no default
  on purpose: a project should state what it's willing to accept explicitly, rather
  than inherit an assumption. See [Policy § categories](#categories) below for the
  full vocabulary.
- **`ignored-packages`** (optional) — canonical (PEP 503 normalised) names exempted
  from the check entirely, regardless of what they detect as. Use this for packages
  you've manually verified are fine despite failing automated detection (e.g. a
  package with a `LicenseRef-` custom license your legal team has already reviewed).
- **`trust-corrected-licenses`**, **`verified-packages`**, **`verified-statements`**
  (all optional, all off/empty by default) — opt in to trusting a *free-text*
  `License` field correction (e.g. `"Apache License, Version 2.0"` → `Apache-2.0`).
  See [Free-text correction](#free-text-correction-opt-in) below; normally set by the
  interactive review wizard, not by hand.

### A narrow, FSF-grounded compatibility check

If your project's own `[project.license]` is declared (per
[PEP 639](https://peps.python.org/pep-0639/)), a small set of narrow, FSF-documented
copyleft compatibility notes are also checked, printed separately from pass/fail
results and never affecting them.

`trustedlicenses` does not implement general project-vs-dependency compatibility
checking. `licensecheck` is the one tool in this space that ships that feature, and
it doesn't use categories at all — per its source (`license_matrix/__init__.py`,
`matrix.csv`), it's a hand-rolled pairwise matrix over **27 granular license
variants** (`GPL_2`, `GPL_2_PLUS`, `GPL_3`, `LGPL_2_PLUS`, ...), not 4 buckets. The
FSF's own [GPL compatibility guidance](https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility)
states plainly: *"GPLv2 is, by itself, not compatible with GPLv3."* Both are
"Copyleft" in the category taxonomy this project uses — a category-only check would
call that pairing fine, and be wrong. MPL-2.0 (bucketed "Copyleft Limited") makes it
worse: it has an explicit, conditional GPL-compatibility clause written into the
license text itself, which authors can opt out of — something no simple
category-boundary check can represent either.

A category-level compatibility verdict risks a confident-sounding wrong answer,
which is exactly what the [legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer)
warns against. So this check is much narrower than general "compatibility
checking" — it fires only on the small number of pairings the FSF states explicitly
and unambiguously, using exact SPDX identifiers rather than categories, and is
presented as a note to verify, never a verdict:

1. **GPL-2.0-only project + GPL-3.0/AGPL-3.0-family dependency (or vice versa)** — the
   specific FSF-documented mismatch above. Deliberately excludes `GPL-2.0-or-later`,
   which grants permission to relicense under GPLv3.
2. **Non-copyleft project + a plain strong-copyleft dependency** (`GPL-2.0-only`,
   `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`, `AGPL-3.0-only`,
   `AGPL-3.0-or-later` — never `LGPL`/`MPL`, which have their own linking/conditional
   exceptions) — a general "worth a second look" heads-up, not a specific citation.

This requires your own project to declare `[project.license]`; with nothing
declared, no notes fire at all — a responsible note needs both sides. See
`_compatibility_note` in
[`policy.py`](https://github.com/w-martin/trustedlicenses/blob/main/src/trustedlicenses/policy.py)
for the exact logic, and a real example — a GPL-2.0-only project pulling in `scipy`
(GPL-3.0-or-later) via `scikit-learn` — in the
[README](https://github.com/w-martin/trustedlicenses#usage).

## Step 2 — Run the check

```shell
uv run trustedlicenses
```

This checks every distribution installed in the *current* Python environment —
exactly what `importlib.metadata.distributions()` sees, the same interpreter you'd run
your actual code with. It exits `0` if every checked package has an allowed license,
`1` otherwise (so it plugs directly into CI):

```shell
$ uv run trustedlicenses
Checking dependency licenses...
✗ Disallowed or undetectable licenses in 2 of 134 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> add "Copyleft Limited" to allowed-categories, or "certifi" to ignored-packages, to allow this
  fqdn: detected MPL-2.0 (categories: Copyleft Limited) -- from license files: LICENSE
    -> add "Copyleft Limited" to allowed-categories, or "fqdn" to ignored-packages, to allow this
```

Each failure line is followed by a concrete suggestion — add the missing category to
`allowed-categories`, or the package to `ignored-packages`, whichever fits. When
nothing was detected at all, there's no category to suggest, so the suggestion points
at manual verification instead:

```
  somepkg: no license detected -- from license files: LICENSE
    -> no license could be detected; verify "somepkg" manually, then add it to
       ignored-packages if acceptable
```

When nothing was detected but a free-text `License` field looks like a real SPDX id
once reformatted, the suggestion says so instead — see
[Free-text correction](#free-text-correction-opt-in):

```
  catboost: no license detected -- from no license information found
    -> looks like Apache-2.0 from its declared metadata ("Apache License, Version 2.0"),
       not trusted by default -- review interactively, or add trust-corrected-licenses /
       verified-packages / verified-statements to your policy
```

A passing run:

```shell
$ uv run trustedlicenses
Checking dependency licenses...
✓ All 134 packages passed.
```

Point it at a different `pyproject.toml` with `--pyproject`:

```shell
uv run trustedlicenses --pyproject path/to/pyproject.toml
```

## No policy configured yet?

Running `trustedlicenses` before you've configured anything doesn't error. What
happens depends on whether a real terminal is attached:

**In a terminal, interactively**, it walks you through setting one up — explaining
each category as it goes, so you're not guessing what "Copyleft Limited" means:

```shell
$ trustedlicenses
Detected licenses for 20 of 20 installed packages.

No policy configured yet -- would you like to run the guided setup? [Y/n]: y

Permissive: MIT, BSD, Apache-2.0, ISC, ... -- minimal restrictions: use, modify, and
redistribute freely, usually with just an attribution/copyright notice.
  (20 detected)
Allow Permissive licenses? [Y/n]: y

Public Domain: CC0, Unlicense, ... -- copyright is waived entirely. No restrictions at all.
  (none detected in your environment)
Allow Public Domain licenses? [Y/n]: y

Copyleft Limited: LGPL, MPL-2.0, ... -- changes to the licensed code itself must be shared
back, but you can still use it inside a project under a different license (e.g. dynamic
linking is fine). Doesn't require your whole project to adopt the same license.
  (none detected in your environment)
Allow Copyleft Limited licenses? [Y/n]: y

Copyleft: GPL, AGPL, ... -- a much bigger commitment: distributing a work that includes
this code generally requires your entire project to also be released under a compatible
copyleft license.
  (1 detected: gplpkg (GPL-2.0-only))
Allow Copyleft licenses? [y/N]: n

Allowed categories: Permissive, Public Domain, Copyleft Limited

Save to a separate trustedlicenses.toml instead of adding to pyproject.toml? [y/N]: n

Write this configuration? [Y/n]: y

Wrote policy to pyproject.toml.

Checking dependency licenses...
✓ All 20 packages passed.
```

Declining the very first question (`would you like to run the guided setup?`) skips
straight to the report-only fallback below — no category questions asked.

The per-category line shows how many installed packages fall into it, and — since
naming more than a couple stops being skimmable — names them individually only when
there are one or two, as `Copyleft` does above. If any package in your environment
carries a category outside the primary four (e.g. `Proprietary Free`,
`Source-available`), the wizard lists what it saw afterward and lets you type in the
exact names to allow, comma-separated — nothing outside the primary four is ever
silently assumed.

`✓`/`✗` lines, and the wizard's own confirmations, are colored (green/red/yellow) in
a real terminal, stripped automatically otherwise — handled by
[Typer](https://typer.tiangolo.com/)/Click, not something you need to configure.

**Without a real terminal — CI, pre-commit, piped input, or `--quiet` explicitly** —
it never prompts (that would just hang a pipeline waiting for input that's never
coming). Instead it falls back to a report-only mode: every installed package's
detected license and category, no pass/fail judgment, exit code `0`:

```shell
$ trustedlicenses --quiet
i pyproject.toml has no policy configured yet -- showing detected licenses only.
  babel: BSD-3-Clause (Permissive)
  certifi: MPL-2.0 (Copyleft Limited)
  jinja2: BSD-3-Clause (Permissive)
  ...

Add a policy to start enforcing this (re-run without --quiet in a terminal for guided setup).
```

**Use `--quiet` (`-q`) in CI/CD and pre-commit hooks.** Both are non-interactive by
default anyway — `trustedlicenses` detects that and falls back to report mode on its
own — but pass `--quiet` explicitly so that stays true even if a step happens to have
a terminal attached (e.g. a local pre-commit run), rather than relying on the
auto-detection alone.

### pre-commit

`trustedlicenses` audits whatever's actually installed in the current Python
environment, so the hook needs your project's own dependencies already installed —
not an isolated hook-specific environment the way most pre-commit hooks work. Add
`trustedlicenses` as a dev dependency, then reference this repo directly:

```yaml
- repo: https://github.com/w-martin/trustedlicenses
  rev: v0.2.0
  hooks:
    - id: trustedlicenses
```

Or write the same thing as a local hook without depending on this repo's tag:

```yaml
- repo: local
  hooks:
    - id: trustedlicenses
      name: trustedlicenses
      entry: trustedlicenses --quiet
      language: system
      pass_filenames: false
```

### GitHub Actions

A composite action wraps the same install-then-run steps. Run it in the same job as
your dependency install step, after your project's own dependencies are already on
the Python path:

```yaml
- name: Install dependencies
  run: pip install -r requirements.txt   # or uv sync, poetry install, ...

- name: Check dependency licenses
  uses: w-martin/trustedlicenses@v0.2.0
```

It accepts two optional inputs: `version` (pin the `trustedlicenses` release, as a
pip version specifier — defaults to latest) and `args` (defaults to `--quiet`). It
installs with `uv pip install` when `uv` is already on `PATH`, falling back to plain
`pip install` otherwise.

**A second safety net, in case `--quiet` was left off by mistake:** every individual
wizard prompt also times out after 30 seconds with no answer. Some CI runners attach
something that looks enough like a real terminal that `trustedlicenses` can't
reliably tell it's non-interactive — a misconfigured job like that would otherwise
hang forever waiting for an answer nobody's there to give. A timeout aborts the
wizard the same way declining it does: report-only mode for the environment check
(exit `0`, not a failure), or a clear error for `check <package>` (exit `1`, since
there's nothing to check the candidate against).

This is all deliberately different from an actual misconfiguration: a
`[tool.trustedlicenses]` table (or `trustedlicenses.toml`) with an empty or missing
`allowed-categories` is a project that clearly tried to configure this and got it
wrong, so that's still a hard error (`1`), with the exact TOML to add in the message
— never the wizard, never the report-only fallback.

## Checking a package before you add it

```shell
trustedlicenses check <package> [<package> ...]
```

`<package>` is a pip-style requirement string, e.g. `requests` or `"django>=5,<6"`.
This resolves each package — and its full transitive dependency tree — into an
isolated temporary location, then evaluates the whole resolved set against your
project's policy, exactly like the environment check. Nothing is installed into your
real environment, and it doesn't assume which installer (`uv`, `pip`, Poetry,
Pipenv, ...) your project actually uses: resolution always goes through its own
isolated mechanism (`uv pip install --target`, falling back to `pip install
--target` when `uv` isn't on `PATH`).

A real example — checking `requests` against a Permissive-only policy surfaces its
transitive `certifi` dependency (MPL-2.0):

```shell
$ trustedlicenses check requests
Resolving requests and its transitive dependencies...
Checking 5 package(s) (requested plus transitive dependencies)...
✗ Disallowed or undetectable licenses in 1 of 5 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> add "Copyleft Limited" to allowed-categories, or "certifi" to ignored-packages, to allow this
```

`check` needs a policy to check the candidate against. If none is configured, it
follows the same interactive-vs-quiet rule as the environment check: in a real
terminal without `--quiet`, it offers the same wizard first, then checks the
candidate against whatever you just configured; non-interactively (or with
`--quiet`), it exits `1` with a message pointing at the docs instead, since there's
nothing sensible to fall back to when you're specifically asking "would this pass?"

## Embedding in code

```python
from trustedlicenses import load_policy, evaluate

policy = load_policy()  # reads ./pyproject.toml by default
result = evaluate(policy)

if not result.passed:
    for failure in result.failures:
        print(failure.name, failure.keys, failure.categories)
```

`evaluate()` also accepts an explicit `distributions_` iterable (overriding the
default of every installed distribution), which is how the test suite exercises it
against synthetic distributions rather than the real environment — and how `check`
evaluates a package resolved into a temporary location. `detect_all()` runs the same
detection with no policy applied, for report-only output.

## How detection works

For each installed distribution, in priority order:

1. **Declared metadata.** The [PEP 639](https://peps.python.org/pep-0639/)
   `License-Expression` field (already SPDX syntax), `License :: ...` trove
   classifiers, and the free-text `License` field. A token is trusted directly once
   it's confirmed to name a real SPDX identifier — no text matching involved. This is
   the primary source; it's what PyPI itself serves and what ecosystem tools like
   `licensecheck` and `pip-licenses` rely on.
2. **Bundled license file text**, only when nothing declared resolves. Any file
   matching `LICENSE*`, `LICENCE*`, `COPYING*`, or `NOTICE*` in the package's
   `.dist-info` directory is matched against the official SPDX
   [license-list-data](https://github.com/spdx/license-list-data) corpus, via a small
   Rust matcher wrapping the [`spdx`](https://github.com/EmbarkStudios/spdx) crate's
   word-bigram Sørensen–Dice text detection.

If neither resolves anything, the package reports `no license information found` and
fails any policy (an unknown license is never assumed to be safe).

### Free-text correction (opt-in)

Some packages declare a free-text `License` field that isn't SPDX syntax but is
otherwise unambiguous once reformatted — PyPI's `catboost`, for example, ships
`License: "Apache License, Version 2.0"` with no `License-Expression` field and no
bundled `LICENSE` file for the text matcher to fall back on. A small set of
deterministic, validated transforms (reformat punctuation and a version number
*already present in the text* — see `_correct_license_statement` in `detection.py`)
tries to turn text like that into a real SPDX id, accepting the result only once it's
confirmed to be one. It never guesses a version or variant the text doesn't state —
PEP 639's own appendix says tools "MUST NOT" auto-infer an SPDX id for exactly that
kind of genuinely ambiguous classifier (bare `"BSD License"`, bare `"GNU General
Public License"`, ...), and this correction holds to the same rule.

**This is off by default.** A project shouldn't start silently passing packages it
previously flagged just because detection got smarter than it used to be — trusting
a correction is something you opt into, at whichever scope fits:

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive"]

# Trust every free-text correction, project-wide, from now on:
trust-corrected-licenses = true

# Or narrower: pin one package to the exact statement + id you verified. If that
# package's declared text ever changes, the pin silently stops applying and it needs
# review again -- it isn't just remembering the package name.
[tool.trustedlicenses.verified-packages]
catboost = { statement = "Apache License, Version 2.0", spdx-id = "Apache-2.0" }

# Or narrower still: trust that exact statement text for any package that has it
# (e.g. several internal packages sharing identical boilerplate).
[tool.trustedlicenses.verified-statements]
"Apache License, Version 2.0" = "Apache-2.0"
```

In practice you won't hand-write these: the interactive review wizard (see
[No policy configured yet?](#no-policy-configured-yet) for the initial setup wizard —
this is its counterpart, offered after a *failing* check against an existing policy)
walks through each failure and, for one a correction applies to, offers to verify
just that package, trust that exact text everywhere, or — when two or more of the
current failures would resolve — enable it project-wide in one step.

### The text-matching algorithm

This is the same general *family* of approach as GitHub's own
[Licensee](https://github.com/licensee/licensee) (a wordset+bigram Dice coefficient
against a curated 47-license corpus from choosealicense.com, at a 98% threshold) and
[askalono](https://github.com/jpeddicord/askalono) (word-bigram Sørensen–Dice against
the full SPDX corpus, originally built at Amazon — per its shipped copyright
headers — now unmaintained). The `spdx` crate `trustedlicenses` depends on inlines
askalono's algorithm as a maintained continuation of it — see `cargo-deny`'s own
changelog documenting its migration off raw askalono onto this crate — the same
reason `cargo-deny`/`cargo-about` depend on it too.

This is deliberately *not* ScanCode Toolkit's approach: a full rule-based engine
matching against ~2,100 license texts plus ~32,000 notice/variant rules via hash
matching, an Aho-Corasick-style matcher, and sequence alignment, which is real
machinery built for scanning arbitrary source trees for embedded license fragments
— a different, harder problem than auditing one package's own declared license. See
[Comparison to Alternatives](comparison.md) for how that tradeoff plays out in
practice, and what it costs to have skipped it.

Worth knowing: a LICENSE file that concatenates several licenses (e.g. a package's
own permissive grant alongside a vendored dependency's copyleft notice) is
segmented, not treated as one blob, so both are reported — Licensee's whole-file
wordset/bigram approach has no equivalent segmentation, per its source, so it would
silently score such a file below threshold and report no match at all, rather than
a wrong one. `trustedlicenses` uses the `spdx`/askalono lineage's `TopDown` scan
mode specifically because it handles this correctly — see the module doc comment in
[`matcher.rs`](https://github.com/w-martin/trustedlicenses/blob/main/rust/src/matcher.rs)
for why the alternative `Elimination` scan mode is not used instead (it drops
matches near the start of a document after a prior elimination pass).

### Categories

License *categories* (`Permissive`, `Copyleft`, `Copyleft Limited`, `Public Domain`,
...) aren't something SPDX itself publishes — they're an editorial taxonomy. The
mapping this project bundles was extracted from ScanCode Toolkit's CC-BY-4.0-licensed
license database (see [NOTICE](https://github.com/w-martin/trustedlicenses/blob/main/NOTICE)
for the required attribution), since that's the same vocabulary most existing
`allowed-categories` configurations (including this project's own) already assume.

### A note on the text-matching fallback's confidence threshold

Text similarity matching is inherently probabilistic — unlike a rule engine (ScanCode)
or pure metadata reading (`pip-licenses`), there's a tunable confidence threshold a
match must clear to be reported at all. `trustedlicenses` uses `0.8`, not the `spdx`/
askalono library's own default of `0.9`.

This has a concrete, real-world effect: two extremely common, correctly-licensed
PyPI packages — [`jupyter`](https://pypi.org/project/jupyter/)'s and
[`prompt-toolkit`](https://pypi.org/project/prompt-toolkit/)'s genuine, unmodified
BSD-3-Clause `LICENSE` files — score `0.85` and `0.91` respectively
against the corpus. At the library's own default of `0.9`, both are missed. At
`0.8` — which turns out to be what
[askalono's own CLI actually uses](https://github.com/jpeddicord/askalono),
overriding its *library's* `0.9` default for evidently the same reason — both
resolve correctly, without introducing false positives at nearby scores (`0.7`
starts misidentifying BSD-3-Clause variants as the wrong license). See
`TEXT_MATCH_CONFIDENCE_THRESHOLD` in
[`detection.py`](https://github.com/w-martin/trustedlicenses/blob/main/src/trustedlicenses/detection.py).

Any similarity-based text matcher — ours included — has a real, tunable
false-negative/false-positive tradeoff. It is not a rule engine, and it will not be
right 100% of the time. See the
[legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer).

## Development

See [DEVELOPING.md](https://github.com/w-martin/trustedlicenses/blob/main/DEVELOPING.md)
for building from source, running the test suite, and linting.
