# Usage Guide

This guide covers each key, command and flag; [How it works](how-it-works.md) covers the
mechanics. With nothing configured, `trustedlicenses` [builds a policy with you](#no-policy-configured-yet).

## Installation

```shell
uv add --dev trustedlicenses
```

or with pip:

```shell
pip install trustedlicenses
```

There are no system dependencies: it's a compiled Rust program with the SPDX license data
built in.

## Step 1: Declare a policy

The guided setup writes the policy for you. By hand, add a `[tool.trustedlicenses]` table to
`pyproject.toml`:

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
ignored-packages = ["mypy-extensions"]
```

Or put the same keys, without the header, in a standalone `trustedlicenses.toml` next to it,
as `ruff.toml` does for `[tool.ruff]`. If both exist, the standalone file wins.

`allowed-categories` is required unless you set `allowed-licenses`. A distribution passes if
at least one of its detected licenses is in one of these [categories](#categories). It has no
default, so a project states what it accepts rather than inheriting an assumption. The other
keys are optional:

- `allowed-licenses` lists SPDX ids allowed for every package, whatever their category.
  [`trustedlicenses pin`](#pinning-to-specific-licenses) writes it. Ids are spelled as on
  [spdx.org/licenses](https://spdx.org/licenses/); an unknown or wrongly cased id is a config
  error that names the right spelling, except custom `LicenseRef-` ids. A license with an
  exception, such as `GPL-2.0-only WITH Classpath-exception-2.0`, is its own license with no
  category, so it passes only when listed here or in `accepted-licenses`.
- `pinned-categories` records the categories `pin` replaced with their licenses. It allows
  nothing itself: a license new to the project in one of them fails, and the fix suggests
  listing that license rather than allowing the category again. A category can't be in both
  `allowed-categories` and `pinned-categories`.
- `accepted-licenses` maps a package name to the SPDX ids accepted for that package alone:

  ```toml
  [tool.trustedlicenses.accepted-licenses]
  certifi = ["MPL-2.0"]
  ```

  That allows neither the whole category nor whatever `certifi` ships: if it later detects as
  something else, the rest of the policy judges it again. Packages that pass this way are
  listed (`certifi: MPL-2.0 (accepted for this package in accepted-licenses)`). Each failure
  prints the line to paste, and the review's `[l]` choice writes it.
- `allow-unlicensed` (default `false`; also `--allow-unlicensed`) passes, and lists, a
  package that was read and has no license at all: no license file and no declared statement.
  It never covers a detected but disallowed license, a license file or statement that
  couldn't be identified, a free-text `License` statement awaiting review, or a package whose
  license couldn't be read (a git or local-path dependency, a package missing from the
  index). Those keep failing with their reason.
- `trusted-indexes` lists package indexes, such as an internal Nexus or Artifactory
  repository, whose packages pass when they have no license or one that can't be identified:
  your own code, published without a license. A package from one of them with a detected
  license is still judged as usual, and one whose license couldn't be read still fails.
  Because a declared but unidentifiable license passes too, trust only an index of your own
  code, not a curated mirror of other people's. It needs a
  [lock file](#auditing-a-lock-file), which records where each package comes from; an
  installed environment doesn't. Write each URL as your lock file or pip/uv config has it,
  without credentials (an entry with credentials, or PyPI's, is a config error):

  ```toml
  trusted-indexes = ["https://nexus.example.com/repository/pypi-internal/simple"]
  ```

  Trust a repository that serves only your packages, not a group repository that also
  proxies PyPI: every unlicensed PyPI package fetched through it would pass too.
- `ignored-packages` skips packages entirely, whatever they detect as, by canonical (PEP 503
  normalised) name: for a package you've verified by hand, e.g. a `LicenseRef-` custom license
  your legal team has reviewed. It trusts the package rather than a license, so prefer the
  keys above. A run that uses it says so.
- `trust-corrected-licenses`, `verified-packages` and `verified-statements` (off or empty by
  default) trust a correction of a free-text `License` field, e.g.
  `"Apache License, Version 2.0"` → `Apache-2.0`. The interactive review usually sets them
  for you ([Free-text correction](how-it-works.md#free-text-correction-opt-in)).
- `use-case` is `"internal"`, `"open-source"` or `"product"`, as answered in the guided setup.
  It appears in the [report](#a-report-for-review) and never affects pass/fail.

### Categories

`allowed-categories` accepts these ten: `Permissive`, `Public Domain`, `Copyleft Limited`,
`Copyleft`, `Proprietary Free`, `Free Restricted`, `Source-available`, `Commercial`,
`Patent License` and `CLA`. An eleventh, `Unstated License`, can't be allowed.

SPDX doesn't publish license categories, so these are an editorial taxonomy, the one most
existing `allowed-categories` configurations already assume. The bundled mapping covers 2,483
license ids (753 SPDX ids, 1,729 ScanCode-specific `LicenseRef-scancode-*` ids and one other
`LicenseRef-`) and comes
from ScanCode Toolkit's CC-BY-4.0-licensed license database
([NOTICE](https://github.com/w-martin/trustedlicenses/blob/main/NOTICE) has the required
attribution).

Some members of a category behave quite differently from the rest: see
[licenses to check individually](choosing-a-policy.md#licenses-to-check-individually).

### A narrow, FSF-grounded compatibility check

If your project declares its own `[project.license]`
([PEP 639](https://peps.python.org/pep-0639/)), `trustedlicenses` also prints notes on a few
copyleft mismatches the FSF documents. They never affect pass/fail. Here a GPL-2.0-only
project pulled in `scipy` (GPL-3.0-or-later) via `scikit-learn`:

```
i 1 compatibility note(s) -- not a pass/fail result, see below:
  scipy: your project is GPL-2.0-only; scipy is GPL-3.0-or-later -- the FSF states
  GPLv2 is not, by itself, compatible with GPLv3 (https://www.gnu.org/licenses/license-list.html#GPLv2)
```

Notes fire only on pairings the FSF states explicitly and unambiguously, match exact SPDX
identifiers rather than categories, and are something to verify, never a verdict:

1. A GPL-2.0-only project with a GPL-3.0 or AGPL-3.0-family dependency, or the reverse, as in
   the example above. `GPL-2.0-or-later` is excluded, since it grants permission to relicense
   under GPLv3.
2. A non-copyleft project with a plain strong-copyleft dependency (`GPL-2.0-only`,
   `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`, `AGPL-3.0-only`,
   `AGPL-3.0-or-later`). This is a general "worth a second look", not a specific citation.
   `LGPL` and `MPL` never trigger it, since they have their own linking and conditional
   exceptions.

With no `[project.license]` declared, no notes fire, since a note needs both sides
([why it goes no further](how-it-works.md#why-the-compatibility-check-is-narrow)).

## Step 2: Run the check

```shell
uv run trustedlicenses
```

This checks every distribution installed in the current Python environment (what your code's
interpreter can import), with no network calls, or, if a lock file sits beside
`pyproject.toml`, every package it pins ([Auditing a lock file](#auditing-a-lock-file)). It
exits `0` if every checked package has an allowed license and `1` otherwise:

```shell
$ uv run trustedlicenses
Checking dependency licenses...
✗ Disallowed or undetectable licenses in 2 of 134 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> to accept only this license for this package, add `certifi = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
  fqdn: detected MPL-2.0 (categories: Copyleft Limited) -- from license files: LICENSE
    -> to accept only this license for this package, add `fqdn = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
```

A package with no license at all gets a hint pointing at `allow-unlicensed`:

```
  somepkg: no license detected -- from no license information found
    -> no license could be detected; verify "somepkg" manually, then set
       allow-unlicensed = true (or pass --allow-unlicensed) to allow packages that have none
```

A license that's declared or shipped but can't be identified isn't covered by
`allow-unlicensed`, because there's a license to read:

```
  closedpkg: no license detected -- from license files: LICENSE
    -> a license is declared or shipped but could not be identified; read it yourself, then
       trust "closedpkg" outright with ignored-packages if it is acceptable (allow-unlicensed
       covers only packages with no license at all)
```

A free-text `License` field that reads as a real SPDX id once reformatted gets its own hint
([Free-text correction](how-it-works.md#free-text-correction-opt-in)):

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

Output is colored in a real terminal, and plain otherwise or whenever `NO_COLOR` is set. To
use a different `pyproject.toml`, pass `--pyproject`:

```shell
uv run trustedlicenses --pyproject path/to/pyproject.toml
```

## No policy configured yet?

With nothing configured, `trustedlicenses` doesn't error. In a terminal it walks you through a
policy, explaining each category:

```shell
$ trustedlicenses
Detected licenses for 20 of 20 installed packages.

No policy configured yet -- would you like to run the guided setup? [Y/n]: y

What are you building?
  [i] internal tooling or pipelines -- nothing leaves your organisation
  [o] an open-source package or tool others install (e.g. from PyPI)
  [p] a product you ship to customers or host for them
  Not sure, or it may ship later? Choose p.
Choice (i/o/p): p

Permissive: MIT, BSD, Apache-2.0, ISC, ... -- minimal restrictions: use, modify, and
redistribute freely, usually with just an attribution/copyright notice.
  (19 detected)
Allow Permissive licenses? [Y/n]: y

Public Domain: CC0, Unlicense, ... -- copyright is waived entirely. No restrictions at all.
  (none detected in your environment)
Allow Public Domain licenses? [Y/n]: y

Copyleft Limited: LGPL, MPL-2.0, ... -- changes to the licensed code must be shared with
anyone you distribute it to; the rest of your project can keep its own license. A few
licenses here (RPL, APSL, EUPL, ...) also count internal or network use, so check any you see.
  (1 detected: certifi (MPL-2.0))
Allow Copyleft Limited licenses? [Y/n]: y

Copyleft: GPL, AGPL, ... -- a much bigger commitment: distributing a work that includes
this code generally requires the combined work to be distributed under that license, so
your own code needs a compatible one.
  For a product: shipping copies brings in GPL's full terms; hosting only doesn't,
  but AGPL does if you modify it. Answer n and accept individual packages in the
  review after the check.
  (none detected in your environment)
Allow Copyleft licenses? [y/N]: n

Allowed categories: Permissive, Public Domain, Copyleft Limited

Pinning a category lists the licenses it allows in your environment now, so a
  license from it that's new to the project fails until you accept it. Worth it
  where a category's licenses ask different things (Copyleft Limited: LGPL, MPL,
  EUPL, ...); `trustedlicenses pin --category` can pin one later.
  Permissive: Apache-2.0, BSD-3-Clause, MIT (19 package(s))
Pin Permissive? [y/N]: n
  Copyleft Limited: MPL-2.0 (1 package(s))
Pin Copyleft Limited? [Y/n]: y

Save to a separate trustedlicenses.toml instead of adding to pyproject.toml? [y/N]: n

Write this configuration? [Y/n]: y

Wrote policy to pyproject.toml.

Checking dependency licenses...
✓ All 20 packages passed.
```

Answering `n` to the first question goes straight to report-only mode (below).
`What are you building?` has no default and asks until your answer starts with `i`, `o` or
`p`. The answer changes the Copyleft hint and is saved as `use-case`; the suggested
categories are the same in every case ([Choosing a policy](choosing-a-policy.md)).

Packages in a category are named when there are one or two. Categories outside these four
(e.g. `Proprietary Free`) are never assumed: the wizard lists
what it saw and lets you type the exact names to allow, comma-separated. It then offers to
pin each allowed category that has a license in use ([Pinning one
category](#pinning-one-category)). Copyleft Limited and Copyleft default to pinned, since
their licenses ask the most different things; Permissive and Public Domain default to
staying whole. Packages with no identifiable license from an index other than PyPI are
grouped by index, with an offer to add it to `trusted-indexes`. That defaults to yes, unless
the index also serves packages that do have a license, which suggests it proxies PyPI. The
review after a check offers the same as `[o]ur index`. If any package with no license is
left, it lists them and asks whether to set `allow-unlicensed`, defaulting to no: with no
license stated you'd be relying on an implied permission, and it's often just missing
metadata worth checking package by package.

Without a real terminal (CI, pre-commit, piped input, or `--quiet`) it never prompts, since
that would hang a pipeline. Instead it lists every installed package's detected license and
category, with no pass/fail, and exits `0`:

```shell
$ trustedlicenses --quiet
i pyproject.toml has no policy configured yet -- showing detected licenses only.
  babel: BSD-3-Clause (Permissive)
  certifi: MPL-2.0 (Copyleft Limited)
  jinja2: BSD-3-Clause (Permissive)
  ...

Add a policy to start enforcing this (re-run without --quiet in a terminal for guided setup).
```

Use `--quiet` (`-q`) in CI/CD and pre-commit hooks, so they stay non-interactive even when a
step has a terminal attached. As a backstop, every wizard prompt times out after 30 seconds,
since some CI runners look like a terminal. A timeout ends the wizard as declining does:
report-only mode for the environment check (exit `0`), or an error for `check <package>`
(exit `1`, since there's no policy to check the candidate against).

A misconfiguration is different: a `[tool.trustedlicenses]` table (or `trustedlicenses.toml`)
with neither `allowed-categories` nor `allowed-licenses` is a hard error (exit `1`) that shows
the exact TOML to add, and never starts the wizard or report-only mode.

### Re-running setup

The guided setup offers itself only while there is no policy. `trustedlicenses setup` runs it
on demand, with or without one. Over an existing policy, each answer defaults to what the
policy says now, so pressing Enter throughout changes nothing:

- a category already pinned keeps the licenses it's pinned to, while one newly pinned takes
  those its packages use today;
- `allowed-licenses` entries with no category of their own (a `LicenseRef-`, a `WITH`
  expression) are kept, and any for a category you stop pinning are listed as they go;
- before writing, it lists the decisions earlier reviews recorded package by package
  (`accepted-licenses`, `ignored-packages`, `verified-packages`, `verified-statements`,
  `trust-corrected-licenses`) and asks whether to keep them, defaulting to yes.

It rewrites the policy where it lives, leaving the rest of the file as it was, then runs a
check. Like the first setup, it needs a terminal and refuses under `--quiet`.

## Auditing a lock file

A lock file can be audited without installing anything. One beside `pyproject.toml` is
picked up automatically:

```
$ trustedlicenses
Checking dependency licenses...
Reading 51 package(s) pinned in uv.lock; license metadata comes from the package index.
✓ All 51 packages passed.
```

License metadata comes from the index the lock file records, or else the one your project
configures. Only package names and versions are sent, and results are cached, so a repeat run
needs no network ([details](how-it-works.md#reading-licenses-from-a-package-index)).
When more than one of these is present, the first wins:

- `uv.lock`. Your own project and workspace members (`editable`/`virtual` entries) are skipped
  as local code.
- `pylock.toml` ([PEP 751](https://peps.python.org/pep-0751/)). `pylock.<name>.toml` works
  with `--lock`.
- `poetry.lock`. A package with no `[package.source]` came from the default index.
- `Pipfile.lock`, both its `default` and `develop` sections.
- A requirements file, only with `--lock FILE`, never picked up automatically. Every
  requirement must be pinned with `==`, and `-r` includes are followed. Loose ranges are an
  error that lists every offender, since they can't be audited without a resolver.

These flags choose what is audited and how:

- `--lock FILE` audits this lock or requirements file.
- `--installed` audits the installed environment even though a lock file is present.
- `--python EXE`, with `--installed`, queries this interpreter's exact `sys.path`.
- `--venv DIR`, with `--installed`, scans this virtual environment without running Python.
- `--jobs N` sets how many package lookups run at once (1 to 64, default 16). Lower it for a
  shared or rate-limited index.
- `--offline` never uses the network, reading only what's already [cached](how-it-works.md#caching).
- `--no-cache` keeps nothing from this run.
- `--prefer-installed` reads a package from the installed environment when its name and
  version match the lock entry, and uses the index for the rest
  ([below](#using-the-installed-environment-for-local-work)).
- `--exclude-group NAME` leaves out packages reached only through this dependency group or
  extra. It's repeatable ([below](#leaving-out-dev-dependencies)).
- `--ca-cert FILE` and `--system-certs` choose which certificates to trust
  ([below](#an-index-behind-a-private-ca)).

A package whose license can't be read, such as a git or local-path dependency, fails with the
reason ([when that happens](how-it-works.md#it-fails-closed)). Review each one:
`allow-unlicensed` doesn't apply, so add it to `ignored-packages` only if you trust the
package itself.

### An index behind a private CA

Certificates are checked against Mozilla's root certificates, built into the binary. For a
private CA, such as a company Nexus or Artifactory, pass its PEM certificate with
`--ca-cert FILE`; it's trusted alongside the built-in roots, so pypi.org keeps working.
Without the flag, the first set of `SSL_CERT_FILE`, `PIP_CERT`, `cert` in `pip.conf` and
`REQUESTS_CA_BUNDLE` is used the same way. Any of these can also name a directory, whose PEM
files are all trusted.

`--system-certs` trusts your operating system's store instead (the macOS keychain, the
Windows certificate store, the system bundle on Linux). It can't be combined with
`--ca-cert` and ignores the settings above, except that on Linux a set `SSL_CERT_FILE` or
`SSL_CERT_DIR` replaces the system bundle. An unreadable bundle is reported by the first
request that needs the network, so a stale setting doesn't break an offline run, and a TLS
failure names the certificates that were trusted.

### Using the installed environment for local work

`--prefer-installed` reads a package's license from the installed copy (chosen with `--venv`,
`--python` or the usual discovery) when its canonical name and version equal the lock
entry's, and asks the index for the rest. With `--offline` too, nothing installed needs the
network.

It's weaker, so it's opt-in: a lock file hashes the wheel or sdist, which an installed
environment doesn't keep, so a patched copy at the same version would be trusted. Copies
installed from a URL, VCS or path (they carry `direct_url.json`) are never used, only
registry entries in the lock are eligible, and a failure from an installed copy is marked
`[installed environment]`. Don't use it for the audit that gates a release.

### Leaving out dev dependencies

`--exclude-group dev` drops packages reached only through that dependency group or optional
extra, so a policy for what you ship needn't cover your test tools. A package also reached
another way stays. The groups come from the lock file:

- In `uv.lock`, the project's `dependencies`, `dev-dependencies` and `optional-dependencies`,
  followed through the dependency graph (including the extras of a dependency).
- In `poetry.lock`, `groups` (Poetry 2), or `category` in older locks.
- In `Pipfile.lock`, `default` is the runtime and `develop` is the group named `develop`.
- In `pylock.toml`, markers of the form `'dev' in dependency_groups`, `'x' in extras` and
  `extra == 'x'`.

An unknown name is an error that lists the groups and extras the lock has. `main` (the
project's own dependencies) can't be excluded, and a package the lock says nothing about is
never dropped. Requirements files and installed environments record no groups, so the flag is
refused for them.

## Running in CI

### pre-commit

The hook passes `--installed`, so it audits the current Python environment and stays offline
even when a lock file is present. It needs your project's own dependencies installed, not the
isolated environment most hooks use. Add `trustedlicenses` as a dev dependency, then:

```yaml
- repo: https://github.com/w-martin/trustedlicenses
  rev: v0.6.0
  hooks:
    - id: trustedlicenses
```

Or, without depending on this repo's tag, as a local hook:

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

The composite action installs and runs `trustedlicenses`. Use it in the same job, after
installing your project's dependencies:

```yaml
- name: Install dependencies
  run: pip install -r requirements.txt   # or uv sync, poetry install, ...

- name: Check dependency licenses
  uses: w-martin/trustedlicenses@v0.6.0
```

It takes two optional inputs: `version`, an exact release such as `0.6.0` (default latest),
and `args`, default `--quiet --installed`; pass `--quiet` alone to audit a lock file instead.
It installs with `uv pip install` when `uv` is on `PATH`, otherwise `pip install`.

## Checking a package before you add it

```shell
trustedlicenses check <package> [<package> ...]
```

Checking `requests` against a Permissive-only policy surfaces its transitive `certifi`
dependency (MPL-2.0):

```shell
$ trustedlicenses check requests
Resolving requests and its transitive dependencies...
Checking 5 package(s) (requested plus transitive dependencies)...
✗ Disallowed or undetectable licenses in 1 of 5 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> to accept only this license for this package, add `certifi = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
```

`<package>` is a pip-style requirement, e.g. `requests` or `"django>=5,<6"`. Each package and
its full transitive dependency tree is resolved into an isolated temporary location with
`uv pip install --target` (or `pip install --target` when `uv` isn't on `PATH`), whatever
installer your project uses, and the whole set is checked against your policy. Nothing is
installed into your real environment.

`check` needs a policy. With none, in a real terminal without `--quiet`, it offers the wizard
first; otherwise it exits `1` with a message pointing at the docs.

## Pinning to specific licenses

A category allows every license in it, including ones your project has never used.
`trustedlicenses pin` replaces `allowed-categories` with `allowed-licenses`: the SPDX ids
those categories let through in your project today. Every package keeps its current result,
and a license new to the project fails until you accept it. Use it before publishing.
It records the categories it replaced in `pinned-categories`.

```shell
$ trustedlicenses pin --dry-run
allowed-categories (Copyleft Limited, Permissive) becomes allowed-licenses with 3 license(s):
  BSD-3-Clause
  MIT
  MPL-2.0

Dry run -- nothing written.
```

Without `--dry-run` it writes the list, one id per line, leaving the rest of the file,
comments included, as it was. It reads the same environment or lock file as a check
(`--venv`, `--lock`, ...). Only a passing package's licenses in an allowed category are
pinned, so a package that passes on BSD-3-Clause while bundling GPL text pins BSD-3-Clause
only. [Licenses to check individually](choosing-a-policy.md#licenses-to-check-individually)
are marked in the list. Once pinned, a failure suggests adding its license to
`allowed-licenses`, and the review's `[a]` choice does that.

### Pinning one category

Not every category needs the same care. Most permissive licenses ask little beyond keeping a
notice, while Copyleft Limited covers licenses as different as LGPL, MPL-2.0 and EUPL-1.2.
`--category` pins only the category you name, and keeps allowing the others whole:

```shell
$ trustedlicenses pin --category "Copyleft Limited"
"Copyleft Limited" becomes 1 license(s) in allowed-licenses; "Permissive" stays allowed whole:
  MPL-2.0

Pinned "Copyleft Limited" in pyproject.toml. A "Copyleft Limited" license new to the project now fails until you accept it.
```

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive"]
allowed-licenses = [
    "MPL-2.0",
]
pinned-categories = ["Copyleft Limited"]
```

A new permissive dependency still passes. A new LGPL one fails, and its fix suggests adding
its license to `allowed-licenses`. Repeat `--category` to pin several. Pinning a category
nothing uses today records it all the same, so any license from it fails until accepted.

## A report for review

`trustedlicenses report` writes a Markdown summary of the policy for a legal, compliance or
security reviewer, from the same environment or lock file as a check. `--output FILE` writes
it to a file; on standard output it's only Markdown, with progress and errors on standard
error. It exits 0 once the report is written, whatever the packages' licenses, and 1 on a
config error or a failure to read packages or write the file.

*What we accept* gives the use case (from `use-case`), the allowed categories or pinned
licenses, each license in use with the packages it covers, and every exception
(`accepted-licenses`, `allow-unlicensed`, and `ignored-packages` with the reason recorded
beside it). *What we could accept but don't* lists packages that fail today and why, and the
[licenses to check individually](choosing-a-policy.md#licenses-to-check-individually) in your
allowed categories; any listed in `allowed-licenses` are flagged under *What we accept*
instead. It doesn't describe what each license obliges you to do; it links the
[legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer).

## Auditing several codebases

`trustedlicenses audit` writes one Markdown report covering several codebases, including
ones that don't use trustedlicenses yet:

```shell
trustedlicenses audit ../api ../billing ../tools/requirements.txt --policy org-policy.toml
```

Each path is a project directory or a lock file. A directory is read from its `uv.lock`,
`pylock.toml`, `poetry.lock`, `Pipfile.lock` or, failing those, a `requirements.txt` with
every requirement pinned with `==`. Nothing is installed or run: license metadata comes from
the package index, as when [auditing a lock file](#auditing-a-lock-file).

Each codebase is judged by its own policy (`[tool.trustedlicenses]` or `trustedlicenses.toml`)
if it has one, else by `--policy FILE`, else not judged and just listed. `--policy` takes a
standalone `trustedlicenses.toml`-style file or a `pyproject.toml` with the table, so one
policy can be applied to codebases that have none.

The report opens with a summary row per codebase and a table of every license in use across
them, with the codebases each one appears in and where it fails the policy. Then comes each
codebase's own [report](#a-report-for-review). A codebase that can't be read, for example one
without a lock file or with loose requirements, gets a row saying why, and the others are
still audited. Like `report`, `audit` takes `--output FILE`, writes progress to standard
error, and exits 0 once the report is written. It doesn't take `--lock`, `--installed`,
`--venv` or `--python`, since each codebase is read from its path.

## Would upgrading help? (opt-in, uses the network)

The usual fix for "no license information found" is a newer release: `webencodings` 0.5.1
bundles no license file, and 0.6.0 and later do. `trustedlicenses` asks your package index
whether a newer release declares one only when you ask, from the review wizard (**c**heck the
package index, on an undetected package) or directly:

```shell
$ trustedlicenses index-check webencodings
Asking https://pypi.org/simple (from default -- no index is configured for this project) about 'webencodings'...
  Index: https://pypi.org/simple
    credentials: none; JSON API: yes; separate metadata (PEP 658): yes
  webencodings 0.5.1:
    0.6.0 is the first newer release that ships a license (License-File: LICENSE).
    The latest release is 0.6.1.
    -> upgrading to webencodings>=0.6.0 would let this be detected. ...
```

It asks the index your project uses, says which it chose, and sends only the package name;
the wizard asks first. Whether your other dependencies allow the upgrade is up to your
resolver. [How it works](how-it-works.md#reading-licenses-from-a-package-index) has the index
discovery order, credentials, and what counts as shipping a license.

## Running where executables can't be started

Some hosts let Python run but refuse other executables, such as unsigned binaries.
`trustedlicenses` has no Python API (the command line and exit code are the interface), but
the wheel also carries the command line as an extension module, and two entry points run it
inside the interpreter's process:

```shell
trustedlicenses-py --quiet                       # always in this process
TRUSTEDLICENSES_INPROC=1 python -m trustedlicenses --quiet
```

Both take the executable's arguments and give the same output and exit code. On Windows, use
the second form: pip only makes launchers for entry points, not a wheel's script files, so
`trustedlicenses-py` can't be started by name there. Plain `python -m trustedlicenses` starts
the executable, replacing the Python process with it where the platform allows.

## Development

[DEVELOPING.md](https://github.com/w-martin/trustedlicenses/blob/main/DEVELOPING.md) covers
building from source, running the test suite, and linting.
