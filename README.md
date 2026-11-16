# trustedlicenses

[![CI](https://github.com/w-martin/trustedlicenses/actions/workflows/ci.yml/badge.svg)](https://github.com/w-martin/trustedlicenses/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/trustedlicenses.svg)](https://pypi.org/project/trustedlicenses/)
[![Python versions](https://img.shields.io/pypi/pyversions/trustedlicenses.svg)](https://pypi.org/project/trustedlicenses/)
[![Documentation](https://readthedocs.org/projects/trustedlicenses/badge/?version=latest)](https://trustedlicenses.readthedocs.io/en/latest/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> ⚠️ **Project Status: Experimental**
>
> `trustedlicenses` (v0.4.0) is an early, experimental release. Detection, policy
> evaluation, and the CLI work end-to-end with full test coverage, but the API and
> config format aren't stable yet, and license detection — declared-metadata parsing
> and the Rust text-matching fallback alike — can be wrong. See the
> [legal disclaimer](#legal-disclaimer) before relying on this for a real compliance
> decision.

**`trustedlicenses` checks that every package installed in your Python project has a
license you've agreed to allow, so you can gate a CI build on it.** Point it at your
environment, tell it which kinds of license are acceptable, and it tells you which
packages don't comply and why.

## Quick look

Nothing to configure first — just run it. With no policy set up yet, a real terminal
walks you through one interactively, explaining what each license category actually
means as you go:

```shell
$ trustedlicenses
Detected licenses for 20 of 20 installed packages.

No policy configured yet -- would you like to run the guided setup? [Y/n]: y

Permissive: MIT, BSD, Apache-2.0, ISC, ... -- minimal restrictions: use, modify, and
redistribute freely, usually with just an attribution/copyright notice.
  (20 detected)
Allow Permissive licenses? [Y/n]: y
...
Wrote policy to pyproject.toml.
```

That writes a `[tool.trustedlicenses]` table to your `pyproject.toml` (or a
standalone `trustedlicenses.toml`, your choice) — see
[No policy configured yet?](#no-policy-configured-yet) below for the full transcript.
Or skip the wizard and write it yourself:

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
```

Either way, running it again just checks:

```shell
uv run trustedlicenses
```

If everything's fine, you get a one-line pass:

```
Checking dependency licenses...
✓ All 134 packages passed.
```

If something isn't, you get exactly what's wrong, and a concrete suggestion for how
to fix it:

```
Checking dependency licenses...
✗ Disallowed or undetectable licenses in 2 of 134 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> to accept only this license for this package, add `certifi = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
  fqdn: detected MPL-2.0 (categories: Copyleft Limited) -- from license files: LICENSE
    -> to accept only this license for this package, add `fqdn = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
```

The process exits non-zero on any failure, so it plugs straight into CI. `✓`/`✗`
lines are green/red (and compatibility notes yellow) in a real terminal — colors are
stripped automatically when output isn't a TTY (piped, redirected, `NO_COLOR`),
exactly like ANSI color handling in most CLI tools.

Full docs: **[trustedlicenses.readthedocs.io](https://trustedlicenses.readthedocs.io/)**

## Installation

```shell
uv add --dev trustedlicenses
```

## Usage

Add a `[tool.trustedlicenses]` table to your `pyproject.toml` (or run `trustedlicenses`
interactively and let the wizard write it — see below):

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
ignored-packages = ["mypy-extensions"]
```

A standalone `trustedlicenses.toml` (same keys, no `[tool.trustedlicenses]` wrapper)
works too, and takes priority if both exist.

- **`allowed-categories`** (required, no default) — the kinds of license your
  project accepts. A package passes if at least one of its detected licenses falls
  into one of these categories. There's no default on purpose: you say what you're
  willing to accept, rather than inherit an assumption.
- **`accepted-licenses`** (optional) — accept specific licenses for specific packages
  only, without allowing the whole category:

  ```toml
  [tool.trustedlicenses.accepted-licenses]
  certifi = ["MPL-2.0"]
  ```

  `certifi` passes while its detected license is `MPL-2.0`; a different license on it, or
  `MPL-2.0` on another package, is still judged by `allowed-categories`. Every failure
  prints the exact line to add, and the guided review writes it for you. Packages that pass
  this way are listed in the output, so the exceptions stay visible.
- **`allow-unlicensed`** (optional, or `--allow-unlicensed`) — let a package with no license
  at all (no license file, no declared statement) pass, for internal packages that don't carry
  one. It does not cover a detected but disallowed license, a license file or statement that
  couldn't be identified, a free-text statement awaiting review, or a package whose license
  couldn't be read (a git dependency, one missing from the index).
- **`ignored-packages`** (optional) — specific packages to skip entirely, whatever is
  detected. This trusts the package rather than a license, so prefer the two options
  above; a run that uses it says so.

If your own project declares its license (`[project.license]`, per
[PEP 639](https://peps.python.org/pep-0639/)), `trustedlicenses` also checks it against
each dependency for a small number of specific, well-documented copyleft
compatibility problems — e.g. a real installed environment where a GPL-2.0-only
project pulled in `scipy` (GPL-3.0-or-later):

```
i 1 compatibility note(s) -- not a pass/fail result, see below:
  scipy: your project is GPL-2.0-only; scipy is GPL-3.0-or-later -- the FSF states
  GPLv2 is not, by itself, compatible with GPLv3 (https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility)
```

This is deliberately narrow and never affects pass/fail — see
[Usage Guide § compatibility notes](https://trustedlicenses.readthedocs.io/en/latest/usage/#a-narrow-fsf-grounded-compatibility-check)
for exactly what it does and doesn't check, and why.

Then run:

```shell
uv run trustedlicenses
```

This checks every package installed in the current environment — or, if a lock file
sits beside `pyproject.toml`, every package it pins (see
[Auditing a lock file](#auditing-a-lock-file)). See the
[Usage Guide](https://trustedlicenses.readthedocs.io/en/latest/usage/) for the full
category vocabulary, running it where executables can't be started, and how detection works
under the hood.

### No policy configured yet?

**In a real terminal**, running `trustedlicenses` with nothing configured first
reports how many installed packages actually have a detectable license, then offers
the interactive wizard shown above — allow/decline each of Permissive, Public
Domain, Copyleft Limited, and (strong) Copyleft with an explanation for each *and*
how many (and, for one or two, which) of your installed packages fall into it, choose
`pyproject.toml` or a standalone `trustedlicenses.toml`, and it writes the config and
runs the check immediately.

**Without a real terminal — CI, pre-commit, piped input, or `--quiet` explicitly —**
it never prompts (that would just hang a pipeline). Instead: report-only mode, every
installed package's detected license and category, no pass/fail judgment, exit code
`0`:

```
$ trustedlicenses --quiet
i pyproject.toml has no policy configured yet -- showing detected licenses only.
  babel: BSD-3-Clause (Permissive)
  certifi: MPL-2.0 (Copyleft Limited)
  jinja2: BSD-3-Clause (Permissive)
  ...
```

**Use `--quiet` (`-q`) in CI/CD and pre-commit hooks.** Both are non-interactive
already, so `trustedlicenses` falls back on its own — but pass `--quiet` explicitly
so that holds even if a step happens to have a terminal attached.

### Auditing a lock file

A lock file pins every package your project resolves to, so it can be audited without
installing anything. If one of `uv.lock`, `pylock.toml`, `poetry.lock` or
`Pipfile.lock` sits beside your `pyproject.toml`, a plain `trustedlicenses` audits
what it pins, reading each package's license metadata from the package index the lock
records (or the one your project configures):

```
$ trustedlicenses
Checking dependency licenses...
Reading 51 package(s) pinned in uv.lock; license metadata comes from the package index.
✓ All 51 packages passed.
```

- **Pick the source yourself** with `--lock FILE` (any of the above, or a
  `requirements.txt` whose entries are all pinned with `==`; loose ranges can't be
  audited, so one is never picked up automatically), or `--installed` to audit the
  installed environment even when a lock file is present. `--python EXE` and
  `--venv DIR` choose which environment `--installed` reads. `--prefer-installed` reads a lock
  entry from the installed copy when its name and version match (for local and offline
  use; weaker than the index, so not for a release gate). `--exclude-group dev` leaves out
  packages reached only through a dependency group or extra (uv.lock, poetry.lock,
  Pipfile.lock, pylock.toml).
- **It uses the network** — but sends only package names (and versions), to the index. Credentials come
  from your environment (`user:pass@` in the index URL, or `.netrc`); nothing is managed
  for you. Results are cached per index (in your platform's cache directory, or
  `TRUSTEDLICENSES_CACHE_DIR`), so a repeat run needs no network. `--offline` uses the
  cache only, and `--no-cache` keeps nothing.
- **It fails closed.** A dependency whose license can't be read from an index — a git,
  URL or local-path dependency, a source distribution that can't be read, a
  package the index doesn't serve, a wheel over 25 MB on a server that can't send part of
  a file — is listed as a failure with the reason, never skipped. `allow-unlicensed`
  doesn't cover these, since the license wasn't read; add one to `ignored-packages` only if
  you trust the package itself.
- **Your own project is not audited** — a lock file's editable and virtual entries
  (your project, workspace members) are skipped as local code.

On a 436-package environment this takes about 2.4 seconds cold and about 0.03 seconds with
everything cached; see [Performance](https://trustedlicenses.readthedocs.io/en/latest/performance/).

### pre-commit

By default the hook audits whatever's actually installed in the current Python
environment (it passes `--installed`, so it stays offline even when a lock file is
present), so the hook needs to run with your project's own dependencies already
installed — not in an isolated hook-specific environment the way most pre-commit
hooks work. Add `trustedlicenses` as a dev dependency (see
[Installation](#installation)), then reference this repo directly:

```yaml
- repo: https://github.com/w-martin/trustedlicenses
  rev: v0.4.0
  hooks:
    - id: trustedlicenses
```

Or write the same thing as a local hook without depending on this repo's tag:

```yaml
- repo: local
  hooks:
    - id: trustedlicenses
      name: trustedlicenses
      entry: trustedlicenses --quiet --installed
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
  uses: w-martin/trustedlicenses@v0.4.0
```

It accepts two optional inputs: `version` (pin the `trustedlicenses` release, as a
pip version specifier — defaults to latest) and `args` (defaults to
`--quiet --installed`, which audits the installed environment; pass `--quiet` alone to
audit a lock file instead). It
installs with `uv pip install` when `uv` is already on `PATH`, falling back to plain
`pip install` otherwise.

As a second safety net if `--quiet` gets left off by mistake, every wizard prompt
also times out after 30 seconds with no answer — some CI runners attach something
that looks enough like a real terminal that this can't be told apart reliably, so a
misconfigured job times out and falls back gracefully instead of hanging forever.

An actual misconfiguration (a config with an empty or missing `allowed-categories`)
is always a hard error, with the exact TOML to add — never the wizard, never the
report-only fallback.

### Checking a package before you add it

`trustedlicenses check <package> [<package> ...]` resolves the package(s) — and every
transitive dependency — into an isolated temporary location, and checks the whole set
against your project's policy, without installing anything into your real
environment or assuming which installer (`uv`, `pip`, Poetry, Pipenv, ...) your
project uses. A real example, checking `requests` against a Permissive-only policy:

```
$ trustedlicenses check requests
Resolving requests and its transitive dependencies...
Checking 5 package(s) (requested plus transitive dependencies)...
✗ Disallowed or undetectable licenses in 1 of 5 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> to accept only this license for this package, add `certifi = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
```

### Accepting a non-standard license declaration

Some packages declare a license only as free text. `catboost`, for example, declares
`License: Apache License, Version 2.0` with no SPDX identifier, no classifier, and no
bundled license file. `trustedlicenses` flags it, suggests `Apache-2.0`, and does not
trust the suggestion by default. To accept it, pin the exact statement you reviewed:

```toml
[tool.trustedlicenses.verified-packages]
catboost = { statement = "Apache License, Version 2.0", spdx-id = "Apache-2.0" }
```

Unlike `ignored-packages`, which exempts a package by name whatever it declares
later, a pin applies only while the declared statement still matches. If `catboost`
later declares a different license, the pin stops applying and the package is checked
against your policy again, so a strong-copyleft license fails unless your policy
allows it. `verified-statements` does the same for one exact statement shared by
several packages, and `trust-corrected-licenses = true` trusts every free-text
correction project-wide. See the
[Usage Guide](https://trustedlicenses.readthedocs.io/en/latest/usage/#free-text-correction-opt-in).

## Why not just read `pip list`'s license column?

Most Python license tools ([`pip-licenses`](https://github.com/raimon49/pip-licenses),
[`licensecheck`](https://github.com/FHPythonUtils/LicenseCheck)) only read what a
package *says* its license is, in its own metadata. That's usually right, but a
meaningful slice of installed packages declare nothing usable at all — no metadata to
read, so nothing to check.

`trustedlicenses` does that same check first, then — only when a package hasn't
declared anything usable — actually reads the license *text* it ships and matches it
against the official list of known open-source licenses. No extra software to
install, and it doesn't need special system libraries the way some older tools in
this space do. The matcher is the [`spdx`](https://docs.rs/spdx) Rust crate (word-bigram
Sørensen–Dice matching against the SPDX license list), the same family of approach as
GitHub's [Licensee](https://github.com/licensee/licensee); `trustedlicenses` wraps it
and does not reimplement it. Checking the installed environment makes no network calls at all (auditing a lock file
does, see above); `trustedlicenses
index-check` is a separate, opt-in command (see the
[Usage Guide](https://trustedlicenses.readthedocs.io/en/latest/usage/#would-upgrading-help-opt-in-uses-the-network))
for the rarer case where nothing usable is declared *or* bundled, and the fix is
upgrading.

See **[Comparison to Alternatives](https://trustedlicenses.readthedocs.io/en/latest/comparison/)**
for how this differs from `pip-licenses`, `licensecheck`, `liccheck`, and ScanCode
Toolkit in practice.

## Speed

On a 436-package real-world environment (data science + web + cloud + ML stack, full
transitive dependency trees — see [Performance](https://trustedlicenses.readthedocs.io/en/latest/performance/)
for exactly what's in it), `trustedlicenses` comes out fastest of the tools tested,
despite doing genuine text-matching work for the ~21% of packages with no usable
declared metadata:

| Tool | Mean ± 1 SD (n=5) |
|---|---|
| **`trustedlicenses`** 0.4.0 | **1.04 ± 0.05s** |
| `trustedlicenses` 0.3.4 (pure Python) | 1.37 ± 0.04s |
| `pip-licenses` | 1.66 ± 0.54s |
| `licensecheck` | 2.56 ± 1.19s |
| `liccheck` | crashes on a current Python/setuptools combination |

Most of that time is license-*text* matching, which is the expensive part and runs in
parallel across every core: one package at a time, the same detection work takes
**5.1s** on this environment — roughly 4.9x slower — so the result scales with how many
cores you have. When there's little text to match the native build's saving is mostly
fixed cost: **5.8 ms against 61 ms** on a 20-package environment. Results are kept between
runs, so a repeat run of the same environment takes **0.03s**. Auditing a lock file instead of an
installed environment costs about 2.4s cold (network) and 0.03s with everything cached. See
[Performance](https://trustedlicenses.readthedocs.io/en/latest/performance/) for the
full breakdown, methodology, and why `liccheck` couldn't be measured at all.

## Legal disclaimer

**trustedlicenses is not a lawyer and does not provide legal advice.** Its output —
which license a package resolves to, which category that falls into, and whether a
package passes your configured policy — is a best-effort technical signal, not a
legal opinion. It can be wrong: a package's declared metadata can be inaccurate or
absent, and the text-matching fallback is a similarity match with a real, disclosed
false-negative/false-positive tradeoff (see
[Usage Guide § confidence threshold](https://trustedlicenses.readthedocs.io/en/latest/usage/#a-note-on-the-text-matching-fallbacks-confidence-threshold)
for a concrete case where this matters). Do not rely on `trustedlicenses`'s output as
a substitute for review by a qualified professional before making a legal or license-
compliance decision. Use of this software is entirely at your own risk — see
[LICENSE](LICENSE) for the full disclaimer of warranty.

See also: [en.wikipedia.org/wiki/IANAL](https://en.wikipedia.org/wiki/IANAL).

## Status

Experimental — API and config format are not yet stable.
