# Usage Guide

## Installation

```shell
uv add --dev trustedlicenses
```

or with pip:

```shell
pip install trustedlicenses
```

No system dependencies are required — `trustedlicenses` is a compiled Rust program with
the SPDX corpus baked in at build time, not something that loads data at runtime or
shells out to another tool.

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
- **`accepted-licenses`** (optional) — a table of package name to the SPDX ids accepted
  for that package alone. A package whose categories aren't allowed still passes when a
  license detected for it is listed:

  ```toml
  [tool.trustedlicenses.accepted-licenses]
  certifi = ["MPL-2.0"]
  ```

  This is a decision about one license on one package, not the whole `Copyleft Limited`
  category and not the package whatever it ships. It does not follow the package to a
  different license: if `certifi` later detects as something else, it is checked against
  `allowed-categories` again. Packages that pass this way are listed in the output
  (`certifi: MPL-2.0 (accepted for this package in accepted-licenses)`). The failure
  message gives the ready-to-paste line, and the guided review's `[l]` choice writes it.
- **`allow-unlicensed`** (optional, default `false`; also `--allow-unlicensed`) — a package
  that was read and has no license at all (no license file shipped and no license
  statement declared) passes, and is listed as such. It never covers a license that was detected
  but is disallowed, a license file or statement that couldn't be identified, a free-text
  `License` statement awaiting review, or a package whose license couldn't be read (a git or local-path
  dependency, a package missing from the index): those aren't "no license", and they
  keep failing with their reason.
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
`compatibility_note` in
[`policy.rs`](https://github.com/w-martin/trustedlicenses/blob/main/rust/core/src/policy.rs)
for the exact logic, and a real example — a GPL-2.0-only project pulling in `scipy`
(GPL-3.0-or-later) via `scikit-learn` — in the
[README](https://github.com/w-martin/trustedlicenses#usage).

## Step 2 — Run the check

```shell
uv run trustedlicenses
```

This checks every distribution installed in the *current* Python environment — the
same packages the interpreter you'd run your actual code with can import — or, if a
lock file sits beside `pyproject.toml`, every package it pins (see
[Auditing a lock file](#auditing-a-lock-file)). It exits `0` if every checked package has an allowed license,
`1` otherwise (so it plugs directly into CI):

```shell
$ uv run trustedlicenses
Checking dependency licenses...
✗ Disallowed or undetectable licenses in 2 of 134 packages:
  certifi: detected MPL-2.0 (categories: Copyleft Limited) -- from declared metadata
    -> to accept only this license for this package, add `certifi = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
  fqdn: detected MPL-2.0 (categories: Copyleft Limited) -- from license files: LICENSE
    -> to accept only this license for this package, add `fqdn = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
```

Each failure line is followed by a concrete suggestion — add the missing category to
`allowed-categories`, or just this license for this package to `accepted-licenses`,
whichever fits. When the package has no license at all (no license files, no declared
statement), there's no category or license to suggest, so the suggestion points at manual
verification and `allow-unlicensed`:

```
  somepkg: no license detected -- from no license information found
    -> no license could be detected; verify "somepkg" manually, then set
       allow-unlicensed = true (or pass --allow-unlicensed) to allow packages that have none
```

When a license *is* declared or shipped but couldn't be identified (a proprietary license
file, a free-text `License` field), `allow-unlicensed` doesn't apply, because there is a license
to read. The suggestion says to read it, and to trust the package with `ignored-packages` if it
is acceptable:

```
  closedpkg: no license detected -- from license files: LICENSE
    -> a license is declared or shipped but could not be identified; read it yourself, then
       trust "closedpkg" outright with ignored-packages if it is acceptable (allow-unlicensed
       covers only packages with no license at all)
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

### Auditing a lock file

A lock file pins every package your project resolves to, so it can be audited without
installing anything — useful for a CI job that shouldn't have to build your whole
environment first. `trustedlicenses` reads these formats:

| File | Notes |
|---|---|
| `uv.lock` | Your own project and workspace members (`editable`/`virtual` entries) are skipped as local code. |
| `pylock.toml` | [PEP 751](https://peps.python.org/pep-0751/). `pylock.<name>.toml` works with `--lock`. |
| `poetry.lock` | A package with no `[package.source]` came from the default index. |
| `Pipfile.lock` | Both `default` and `develop` sections. |
| a requirements file | Only with `--lock FILE`, and every requirement must be pinned with `==`. `-r` includes are followed. Loose ranges can't be audited without a resolver, so they're an error that lists every offender, and a `requirements.txt` is never picked up automatically. |

A lock file beside `pyproject.toml` is picked up automatically, in the order above. The
flags that choose what is audited:

| Flag | Effect |
|---|---|
| `--lock FILE` | Audit this lock or requirements file. |
| `--installed` | Audit the installed environment even though a lock file is present. |
| `--python EXE` | With `--installed`: query this interpreter's exact `sys.path`. |
| `--venv DIR` | With `--installed`: scan this virtual environment without running Python. |
| `--jobs N` | How many package lookups to run at once (default 16). Lower it for a shared or rate-limited index. |
| `--offline` | Never use the network; read only what is already cached. |
| `--no-cache` | Keep nothing from this run. |
| `--prefer-installed` | Read a package from the installed environment when its name and version match the lock entry; use the index for the rest. For local and offline work. |
| `--exclude-group NAME` | Leave out packages reached only through this dependency group or extra. Repeatable. See below. |

**Where the licenses come from.** Each package's license metadata is read from the
package index the lock file records for it (a package with no recorded index uses the
[discovery rules](#would-upgrading-help-opt-in-uses-the-network) below: your project's
configuration, then `UV_INDEX_URL`/`PIP_INDEX_URL`, then `pip.conf`, then pypi.org).
On pypi.org the files of the one release are listed from its release document, which is
a few kilobytes; any other index is asked for the project's standard listing. The small
separate metadata file ([PEP 658](https://peps.python.org/pep-0658/)) is read first, and
that is the end of it when the declared metadata already names a license. Otherwise the
wheel's bundled license files are matched exactly as they would be for an installed
package, reading only those entries with HTTP `Range` requests where the server allows
(kilobytes, not the whole wheel), and downloading the wheel (up to 25 MB) where it doesn't.
When a release has no wheel at all, its source distribution (`.tar.gz`, or `.zip`) is downloaded
and its `PKG-INFO` is read; license files are taken from those `PKG-INFO` names, the top of the
project and a top-level `licenses` directory, but not from vendored code deeper in the tree.
Only package names and versions are sent;
credentials come from your environment (`user:pass@` in the index URL, or `.netrc`) and
are never forwarded to another host or printed.

**Using the installed environment for local work.** `--prefer-installed` (with `--venv` or
`--python` to choose the environment, otherwise the usual discovery) reads a package's
license from the installed copy when its canonical name and version equal the lock entry's,
and asks the index only for the rest. With `--offline` that makes a lock audit work with no
network for whatever is installed. It is opt-in because it is weaker than the default: an
installed copy is matched on name and version only, since a lock file's hashes are of the
wheel or sdist archive and an installed environment doesn't keep that, so a patched or
differently sourced copy at the same version would be trusted. Copies installed from a URL,
VCS or path (they carry `direct_url.json`) are never used, only registry entries in the lock
are eligible, and a failure from an installed copy is marked `[installed environment]`. Don't use it for
the audit that gates a release.

**Leaving out dev dependencies.** `--exclude-group dev` (repeat it for more) drops the packages
that are reached only through that dependency group or optional extra, so a policy for what you
ship need not cover your test tools. A package that is also reached some other way stays: a
dev tool that is a runtime dependency of something else is still audited. The groups are read
from the lock file:

| File | Where the groups come from |
|---|---|
| `uv.lock` | The project's `dependencies`, `dev-dependencies` and `optional-dependencies`, followed through the dependency graph (including the extras of a dependency). |
| `poetry.lock` | `groups` (Poetry 2), or `category` in older locks. |
| `Pipfile.lock` | `default` is the runtime; `develop` is the group named `develop`. |
| `pylock.toml` | Markers of the form `'dev' in dependency_groups`, `'x' in extras` and `extra == 'x'`. |

A name that is not a group or extra in the lock is an error that lists the ones that are, `main`
(the project's own dependencies) can't be excluded, and a requirements file or an installed
environment records no groups, so the flag is refused for them. A package the lock says nothing
about is never dropped.

**Caching.** Results are cached per index under your platform's cache directory
(`~/Library/Caches/trustedlicenses` on macOS, `$XDG_CACHE_HOME/trustedlicenses` or
`~/.cache/trustedlicenses` on Linux, `%LOCALAPPDATA%\trustedlicenses` on Windows), or
`TRUSTEDLICENSES_CACHE_DIR`. A repeat run needs no network, and a failed lookup leaves
nothing behind. The text-matching results are cached too, so unchanged license files are not
scanned again. A pinned release's metadata never changes, so there is nothing to
expire.

**It fails closed.** A package whose license can't be read is a failure with the
reason, never a quiet pass:

- a git, URL or local-path dependency has no index to ask;
- a release published only as a source distribution is read from the archive itself (its
  `PKG-INFO` and top-level license files, never executing anything), and fails with the reason
  if that archive can't be read, is over 25 MB, or holds more than 64 license files (8 MB) or
  a license file over 2 MB;
- a package the index doesn't serve (an internal one on a different index) is "not found
  on this index";
- a wheel that must be downloaded whole for its license files, because the server can't
  send part of a file, but is over 25 MB isn't downloaded.

Review each. These are packages whose license couldn't be read, so `allow-unlicensed` doesn't
apply to them; add one to `ignored-packages` only if you trust the package itself. On the benchmark
environment on the [performance page](performance.md#auditing-a-lock-file), all 436
packages got the same verdict from the lock file as from the installed environment.

### pre-commit

By default the hook audits whatever's actually installed in the current Python
environment (it passes `--installed`, so it stays offline even when a lock file is
present), so the hook needs your project's own dependencies already installed —
not an isolated hook-specific environment the way most pre-commit hooks work. Add
`trustedlicenses` as a dev dependency, then reference this repo directly:

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
pip version specifier — defaults to latest) and `args` (defaults to `--quiet --installed`, which audits the installed environment;
pass `--quiet` alone to audit a lock file instead). It
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
    -> to accept only this license for this package, add `certifi = ["MPL-2.0"]` under [tool.trustedlicenses.accepted-licenses]; or add "Copyleft Limited" to allowed-categories to allow every package in it
```

`check` needs a policy to check the candidate against. If none is configured, it
follows the same interactive-vs-quiet rule as the environment check: in a real
terminal without `--quiet`, it offers the same wizard first, then checks the
candidate against whatever you just configured; non-interactively (or with
`--quiet`), it exits `1` with a message pointing at the docs instead, since there's
nothing sensible to fall back to when you're specifically asking "would this pass?"

## Would upgrading help? (opt-in, uses the network)

The usual fix for "no license information found" is a newer release: `webencodings`
0.5.1 bundles no license file, 0.6.0 and later do. `trustedlicenses` can ask your
package index whether a newer release of a package declares one. Nothing in a plain
check does this — it is only ever run on request, from the review wizard (choose
**c**heck the package index on an undetected package) or directly:

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

**Which index it asks.** The one your project already uses, in this order: the
lockfile's recorded source for that package (`uv.lock`, `poetry.lock`,
`Pipfile.lock` — correct even with several indexes), then index settings in
`pyproject.toml`/`uv.toml`/`Pipfile`, then `UV_DEFAULT_INDEX` / `UV_INDEX_URL` /
`PIP_INDEX_URL` and `pip.conf`. It says which it chose, and only falls back to pypi.org
when nothing is configured (labelled as a default). The wizard asks before sending
anything.

**What is sent.** Only the package name, to that index. Credentials are *not* managed
by this tool: they come from your environment — `user:password@` in the index URL, or
`.netrc` (`NETRC` to point elsewhere) — and are never forwarded if the index redirects
to a different host. A private CA is picked up from `SSL_CERT_FILE`; proxy settings from
the usual `HTTPS_PROXY` variables.

**What it can tell.** It works with any index that speaks the standard simple API. Where
the index offers per-release metadata (PEP 658, as PyPI does) that is all it reads;
otherwise it downloads the wheel (up to 25 MB) to look inside. The line under
`Index:` tells you which your index supports. A release "ships a license" if it
declares a license file or a license the tool can resolve, so a wheel that bundles a
file without declaring it can be missed. Whether your other dependencies allow the
upgrade is up to your resolver.

## Running where executables can't be started

`trustedlicenses` is a native program with no Python API: the command line and its exit
code are the interface. Some environments let the Python interpreter run code but kill or
refuse other executables (for example, a host that terminates unsigned binaries). The wheel
also carries the same command line as a Python extension module, and two entry points run it
inside the interpreter's own process:

```shell
trustedlicenses-py --quiet                       # always in this process
TRUSTEDLICENSES_INPROC=1 python -m trustedlicenses --quiet
```

Both take exactly the arguments the executable does and give the same output and exit code.
On Windows, use the second form: pip installs a wheel's script files as they are and only
makes a launcher for entry points, so `trustedlicenses-py` can't be started by name there.
Plain `python -m trustedlicenses` starts the executable, replacing the Python process with it
where the platform allows.

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
*already present in the text* — see `correct_license_statement` in `rust/core/src/detection.rs`)
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
[`matcher.rs`](https://github.com/w-martin/trustedlicenses/blob/main/rust/core/src/matcher.rs)
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
`DEFAULT_CONFIDENCE_THRESHOLD` in
[`matcher.rs`](https://github.com/w-martin/trustedlicenses/blob/main/rust/core/src/matcher.rs).

Any similarity-based text matcher — ours included — has a real, tunable
false-negative/false-positive tradeoff. It is not a rule engine, and it will not be
right 100% of the time. See the
[legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer).

## Development

See [DEVELOPING.md](https://github.com/w-martin/trustedlicenses/blob/main/DEVELOPING.md)
for building from source, running the test suite, and linting.
