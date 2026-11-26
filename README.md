# trustedlicenses

[![CI](https://github.com/w-martin/trustedlicenses/actions/workflows/ci.yml/badge.svg)](https://github.com/w-martin/trustedlicenses/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/trustedlicenses.svg)](https://pypi.org/project/trustedlicenses/)
[![Python versions](https://img.shields.io/pypi/pyversions/trustedlicenses.svg)](https://pypi.org/project/trustedlicenses/)
[![Documentation](https://readthedocs.org/projects/trustedlicenses/badge/?version=latest)](https://trustedlicenses.readthedocs.io/en/latest/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> ⚠️ **Experimental (v0.6.0).** The API and config format aren't stable yet, and license
> detection can be wrong. Read the [legal disclaimer](#legal-disclaimer) before relying on it
> for a real compliance decision.

`trustedlicenses` checks that every package in your Python project, installed or pinned in a
lock file, has a license you've agreed to allow. It exits non-zero when one doesn't, so it can
gate a CI build.

## Installation

```shell
uv add --dev trustedlicenses
```

## Quick start

Run `trustedlicenses` in a terminal. With no policy yet, it
[sets one up with you](#no-policy-configured-yet). Or write one in `pyproject.toml` (or a
standalone `trustedlicenses.toml`):

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
```

From then on, each run is a check:

```shell
uv run trustedlicenses
```

A failure says what's wrong and how to fix it:

```
Checking dependency licenses...
✗ Disallowed or undetectable licenses in 2 of 134 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> to accept only this license for this package, add `certifi = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
  fqdn: detected MPL-2.0 (categories: Copyleft Limited) -- from license files: LICENSE
    -> to accept only this license for this package, add `fqdn = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
```

A pass is one line:

```
Checking dependency licenses...
✓ All 134 packages passed.
```

If a lock file (`uv.lock`, `pylock.toml`, `poetry.lock` or `Pipfile.lock`) sits beside
`pyproject.toml`, it audits that without installing anything. Not sure what to allow?
[Choosing a policy](https://trustedlicenses.readthedocs.io/en/latest/choosing-a-policy/)
covers internal tooling, open-source packages and products.

## Commands

- `trustedlicenses` checks the project against your policy.
- `trustedlicenses setup` runs the guided setup again over an existing policy, each answer
  defaulting to what the policy says now.
- `trustedlicenses check <package> ...` checks packages, and their transitive dependencies,
  before you add them.
- `trustedlicenses pin [--category NAME] [--dry-run]` swaps your categories, or just one,
  for the specific licenses in use.
- `trustedlicenses report [--output FILE]` writes a Markdown summary for legal or compliance
  review.
- `trustedlicenses audit PATH... [--policy FILE]` reports on several codebases at once,
  including ones that don't use trustedlicenses yet.
- `trustedlicenses index-check <package>` asks your package index whether a newer release
  declares a license.

## No policy configured yet?

In a terminal, `trustedlicenses` offers a guided setup that explains each license category.
Without one (CI, pre-commit, piped input, or `--quiet`) it never prompts: it lists each
package's detected license and exits `0`. See the
[Usage Guide](https://trustedlicenses.readthedocs.io/en/latest/usage/#no-policy-configured-yet).

## Documentation

- [Usage Guide](https://trustedlicenses.readthedocs.io/en/latest/usage/): every key, command
  and flag, lock files, pre-commit and GitHub Actions.
- [How it works](https://trustedlicenses.readthedocs.io/en/latest/how-it-works/): detection,
  text matching, and where lock-file licenses come from.
- [Comparison to Alternatives](https://trustedlicenses.readthedocs.io/en/latest/comparison/)
  and [Performance](https://trustedlicenses.readthedocs.io/en/latest/performance/).

## Legal disclaimer

**trustedlicenses is not a lawyer and does not provide legal advice.** Its output (which
license a package resolves to, its category, and whether it passes your policy) is a
best-effort technical signal, not a legal opinion. It can be wrong: declared metadata can be
inaccurate or absent, and the text-matching fallback is a similarity match with a real
false-negative/false-positive tradeoff
([a concrete case](https://trustedlicenses.readthedocs.io/en/latest/how-it-works/#a-note-on-the-text-matching-fallbacks-confidence-threshold)).
Don't rely on it in place of review by a qualified professional before a legal or
license-compliance decision. Use it at your own risk; see
[LICENSE](https://github.com/w-martin/trustedlicenses/blob/main/LICENSE) for the full
disclaimer of warranty.

See also: [en.wikipedia.org/wiki/IANAL](https://en.wikipedia.org/wiki/IANAL).
