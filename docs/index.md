# trustedlicenses

`trustedlicenses` checks that every package in your Python project — installed, or
pinned in a lock file — has a license you've agreed to allow, so you can gate a CI build
on it.

```toml
# pyproject.toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
ignored-packages = ["mypy-extensions"]
```

```shell
$ uv run trustedlicenses
Checking dependency licenses...
✗ Disallowed or undetectable licenses in 2 of 134 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> to accept only this license for this package, add `certifi = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
  fqdn: detected MPL-2.0 (categories: Copyleft Limited) -- from license files: LICENSE
    -> to accept only this license for this package, add `fqdn = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
```

## Why not just read `pip list`'s license column?

Most Python license tools (`pip-licenses`, `licensecheck`) only read what a package
*says* its license is, in its own metadata — the `License-Expression` field,
`License ::` classifiers, or the free-text `License` field. That's usually right, but
a meaningful slice of installed packages either predate
[PEP 639](https://peps.python.org/pep-0639/) or declare nothing usable at all.

`trustedlicenses` does that same check first, then — only when a package hasn't
declared anything usable — falls back to matching the actual license *text* it
bundles in its `.dist-info` directory against the official SPDX
[license-list-data](https://github.com/spdx/license-list-data) corpus, via a small
Rust matcher. No system dependencies and no rule-engine to install; checking an
installed environment makes no network calls (auditing a lock file reads license
metadata from the package index).

See [Comparison to Alternatives](comparison.md) for how this stacks up against
`pip-licenses`, `licensecheck`, `liccheck`, and ScanCode Toolkit-based tools, and
[Performance](performance.md) for measured speed on a 436-package real-world
environment.

## Installation

```shell
uv add --dev trustedlicenses
```

## Legal disclaimer

**trustedlicenses is not a lawyer and does not give legal advice.** Its output —
detected licenses, categories, and policy pass/fail — is a best-effort technical
signal, not a legal opinion. See the [README](https://github.com/w-martin/trustedlicenses#legal-disclaimer)
for the full disclaimer before relying on it for a compliance decision.
