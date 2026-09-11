# trustedlicenses

[![CI](https://github.com/w-martin/trustedlicenses/actions/workflows/ci.yml/badge.svg)](https://github.com/w-martin/trustedlicenses/actions/workflows/ci.yml)
[![Documentation](https://readthedocs.org/projects/trustedlicenses/badge/?version=latest)](https://trustedlicenses.readthedocs.io/en/latest/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> ⚠️ **Project status: early scaffold.** The API and config format are not yet
> stable.

**`trustedlicenses` checks that every package installed in your Python project has a
license you've actually agreed to allow — and fails your CI build if one doesn't.**
Point it at your environment, tell it which kinds of license are acceptable, and it
tells you which packages don't comply and why.

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
    -> add "Copyleft Limited" to allowed-categories, or "certifi" to ignored-packages, to allow this
  fqdn: detected MPL-2.0 (categories: Copyleft Limited) -- from license files: LICENSE
    -> add "Copyleft Limited" to allowed-categories, or "fqdn" to ignored-packages, to allow this
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
- **`ignored-packages`** (optional) — specific packages to skip entirely, for cases
  you've reviewed by hand and decided are fine regardless of what's detected.

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
[Comparison to Alternatives § compatibility notes](https://trustedlicenses.readthedocs.io/en/latest/comparison/#a-narrow-fsf-grounded-compatibility-check)
for exactly what it does and doesn't check, and why.

Then run:

```shell
uv run trustedlicenses
```

This checks every package installed in the current environment. See the
[Usage Guide](https://trustedlicenses.readthedocs.io/en/latest/usage/) for the full
category vocabulary, embedding the check in your own code, and how detection works
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
so that holds even if a step happens to have a terminal attached. A pre-commit hook:

```yaml
- repo: local
  hooks:
    - id: trustedlicenses
      name: trustedlicenses
      entry: trustedlicenses --quiet
      language: system
      pass_filenames: false
```

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
    -> add "Copyleft Limited" to allowed-categories, or "certifi" to ignored-packages, to allow this
```

## Why not just read `pip list`'s license column?

Most Python license tools ([`pip-licenses`](https://github.com/raimon49/pip-licenses),
[`licensecheck`](https://github.com/FHPythonUtils/LicenseCheck)) only read what a
package *says* its license is, in its own metadata. That's usually right, but a
meaningful slice of installed packages declare nothing usable at all — no metadata to
read, so nothing to check.

`trustedlicenses` does that same check first, then — only when a package hasn't
declared anything usable — actually reads the license *text* it ships and matches it
against the official list of known open-source licenses. No extra software to
install, no network calls, and it doesn't need special system libraries the way some
older tools in this space do.

See **[Comparison to Alternatives](https://trustedlicenses.readthedocs.io/en/latest/comparison/)**
for the deeper technical dive — how this differs from `pip-licenses`, `licensecheck`,
`liccheck`, and ScanCode Toolkit, a reproducible speed benchmark, and a real
false-negative we found and fixed in our own matcher along the way.

## Legal disclaimer

**trustedlicenses is not a lawyer and does not provide legal advice.** Its output —
which license a package resolves to, which category that falls into, and whether a
package passes your configured policy — is a best-effort technical signal, not a
legal opinion. It can be wrong: a package's declared metadata can be inaccurate or
absent, and the text-matching fallback is a similarity match with a real, disclosed
false-negative/false-positive tradeoff (see
[Comparison to Alternatives](https://trustedlicenses.readthedocs.io/en/latest/comparison/#a-real-limitation-we-found-in-our-own-tool)
for a concrete case we found and fixed). Do not rely on `trustedlicenses`'s output as
a substitute for review by a qualified professional before making a legal or license-
compliance decision. Use of this software is entirely at your own risk — see
[LICENSE](LICENSE) for the full disclaimer of warranty.

See also: [en.wikipedia.org/wiki/IANAL](https://en.wikipedia.org/wiki/IANAL).

## Status

Early scaffold — API and config format are not yet stable.
