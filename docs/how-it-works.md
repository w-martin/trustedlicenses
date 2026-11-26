# How it works

How `trustedlicenses` decides a package's license, where it reads licenses for a lock file,
and why some checks stop where they do. The [Usage Guide](usage.md) covers running it.

## How detection works

For each installed distribution, in priority order:

1. Declared metadata: the [PEP 639](https://peps.python.org/pep-0639/) `License-Expression`
   field (already SPDX syntax), `License :: ...` trove classifiers, and the free-text
   `License` field. A token is trusted directly, with no text matching, once it's confirmed
   to name a real SPDX identifier. This is what PyPI serves and what `licensecheck` and
   `pip-licenses` rely on.
2. Bundled license file text, only when nothing declared resolves. Any file matching
   `LICENSE*`, `LICENCE*`, `COPYING*` or `NOTICE*` in the package's `.dist-info` directory is
   matched against the official SPDX
   [license-list-data](https://github.com/spdx/license-list-data) corpus, by a small Rust
   matcher wrapping the [`spdx`](https://github.com/EmbarkStudios/spdx) crate's word-bigram
   Sørensen–Dice text detection.

If neither resolves anything, the package reports `no license information found` and fails
any policy: an unknown license is never assumed safe.

### Free-text correction (opt-in)

PyPI's `catboost` declares `License: "Apache License, Version 2.0"`, with no
`License-Expression` field, no classifier and no bundled `LICENSE` file to match. That isn't
SPDX syntax, but it's unambiguous once reformatted. A few deterministic, validated transforms
(reformatting punctuation and a version number already in the text; see
`correct_license_statement` in `rust/core/src/detection.rs`) try to turn such text into an
SPDX id, accepted only once confirmed to be one. It never guesses a version or variant the
text doesn't state: PEP 639's appendix says tools "MUST NOT" auto-infer an SPDX id for
genuinely ambiguous classifiers (bare `"BSD License"`, bare `"GNU General Public
License"`, ...), and this follows the same rule.

This is off by default, so a project doesn't silently start passing packages it used to flag.
Opt in at whichever scope fits:

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

Unlike `ignored-packages`, a pin doesn't survive a license change: if `catboost` later
declares a different license, it is checked against your policy again.

You won't usually write these by hand: after a failing check, the interactive review offers,
where a correction applies, to verify just that package, trust that exact text everywhere,
or, when two or more current failures would resolve, enable it project-wide.

### The text-matching algorithm

The matcher is the same general family as GitHub's
[Licensee](https://github.com/licensee/licensee) and
[askalono](https://github.com/jpeddicord/askalono): word-bigram similarity against a corpus of
license texts. The `spdx` crate inlines askalono's algorithm as a maintained continuation of
it (askalono itself is unmaintained); `cargo-deny` and `cargo-about` depend on it too. It's
deliberately not ScanCode Toolkit's rule engine, which is built for finding license fragments
in arbitrary source trees ([Comparison to Alternatives](comparison.md)).

A LICENSE file that concatenates several licenses, such as a package's own permissive grant
plus a vendored dependency's copyleft notice, is segmented, so both are reported. That's why
it uses the `spdx`/askalono `TopDown` scan mode. The module doc comment in
[`matcher.rs`](https://github.com/w-martin/trustedlicenses/blob/main/rust/core/src/matcher.rs)
explains why not `Elimination` (it drops matches near the start of a document after a prior
elimination pass).

Each distinct license text is scanned once per run, across every core, and its result is
[cached](#caching), so unchanged license files aren't scanned again.

### A note on the text-matching fallback's confidence threshold

Unlike a rule engine (ScanCode) or pure metadata reading (`pip-licenses`), text similarity
matching is probabilistic: a match must clear a tunable confidence threshold to be reported
at all. `trustedlicenses` uses `0.8`, not the `spdx`/askalono library default of `0.9`.

That matters in practice. The genuine, unmodified BSD-3-Clause `LICENSE` files of two very
common, correctly licensed PyPI packages, [`jupyter`](https://pypi.org/project/jupyter/) and
[`prompt-toolkit`](https://pypi.org/project/prompt-toolkit/) (1.1.1 and 3.0.53), match
BSD-3-Clause with scores of `0.847` and `0.906`. At the library default of `0.9`, neither is
found, though `prompt-toolkit`'s reported score is above it. At `0.8`, which
[askalono's own CLI uses](https://github.com/jpeddicord/askalono) (overriding its library's
`0.9` default, evidently for the same reason), both resolve correctly, with no false
positives at nearby scores; `0.7` starts misidentifying BSD-3-Clause variants as the wrong
license. See `DEFAULT_CONFIDENCE_THRESHOLD` in
[`matcher.rs`](https://github.com/w-martin/trustedlicenses/blob/main/rust/core/src/matcher.rs).

Any similarity-based matcher, this one included, trades false negatives against false
positives and won't be right every time, which is one reason for the
[legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer).

## Reading licenses from a package index

A lock-file audit and `index-check` read license metadata from a package index. The index is
the first of:

1. the lock file's recorded source for that package (`uv.lock`, `poetry.lock`,
   `Pipfile.lock`; correct even with several indexes);
2. index settings in `pyproject.toml`/`uv.toml`/`Pipfile`;
3. `UV_DEFAULT_INDEX` / `UV_INDEX_URL` / `PIP_INDEX_URL`, then `pip.conf`;
4. pypi.org, labelled as a default, only when nothing is configured.

It says which it chose, and the review wizard asks before sending anything.

For a lock-file audit, the separate metadata file
([PEP 658](https://peps.python.org/pep-0658/)) is read first, and is enough when it names a
license. Otherwise the wheel's bundled license files are matched as for an installed package,
reading only those entries with HTTP `Range` requests. A server without `Range` support means
downloading the whole wheel, up to 25 MB. A release with no wheel has its source distribution
(`.tar.gz` or `.zip`) downloaded, and its `PKG-INFO` and license files read: the files
`PKG-INFO` names, plus those at the top of the project or in a top-level `licenses` directory,
never vendored code deeper in the tree.

A source distribution whose `pyproject.toml` sets `backend-path` builds with code of its own
at install time, and that code can download or generate what actually installs. `dbt` 2.x is
one: its source distribution is a stub whose backend fetches a prebuilt wheel from elsewhere.
What was read may then not be what installs, so the run says which packages these are and
marks their source line; check what they install.

`index-check` works with any index that speaks the standard simple API. If it offers
per-release metadata (PEP 658, as PyPI does), that's all it reads; otherwise it downloads the
wheel, up to 25 MB. The line under `Index:` in its output shows which your index supports. A
release "ships a license" if it declares a license file or a license the tool can resolve, so
a wheel that bundles a file without declaring it can be missed.

Only package names (and, for a lock file, versions) are sent, and only to that index.
Credentials come from your environment (`user:password@` in the index URL, or `.netrc`, with
`NETRC` to point elsewhere) and are never printed or forwarded if the index redirects to
another host. A private CA is trusted as described in
[An index behind a private CA](usage.md#an-index-behind-a-private-ca), and proxies come from
the usual `HTTPS_PROXY` variables.

## Caching

Results are cached per index under your platform's cache directory
(`~/Library/Caches/trustedlicenses` on macOS, `$XDG_CACHE_HOME/trustedlicenses` or
`~/.cache/trustedlicenses` on Linux, `%LOCALAPPDATA%\trustedlicenses` on Windows), or
`TRUSTEDLICENSES_CACHE_DIR`. A pinned release's metadata never changes, so nothing expires
and a repeat run needs no network. A failed lookup leaves nothing behind. Text-matching
results are cached too, so unchanged license files aren't scanned again. `--no-cache` keeps
nothing from a run, and `--offline` reads only from the cache.

## It fails closed

A package whose license can't be read fails with the reason, never passes quietly. That
happens when:

- a git, URL or local-path dependency has no index to ask;
- a release published only as a source distribution can't be read from its archive, or the
  archive is over 25 MB, or holds more than 64 license files (8 MB) or a license file over
  2 MB (the archive's `PKG-INFO` and top-level license files are read without executing
  anything);
- the index doesn't serve the package (an internal one on a different index), reported as
  "not found on this index";
- a wheel has to be downloaded whole for its license files, because the server can't send
  part of a file, and it's over 25 MB.

On the [benchmark environment](performance.md#auditing-a-lock-file), all 452 packages in the
lock file got the same verdict from the lock file as from the installed environment.

## Why the compatibility check is narrow

The [compatibility notes](usage.md#a-narrow-fsf-grounded-compatibility-check) (exact logic:
`compatibility_note` in
[`policy.rs`](https://github.com/w-martin/trustedlicenses/blob/main/rust/core/src/policy.rs))
don't attempt general project-vs-dependency compatibility checking, because categories are
too coarse for it. The FSF's
[license list](https://www.gnu.org/licenses/license-list.html#GPLv2) states: *"GPLv2 is, by
itself, not compatible with GPLv3."* Both are "Copyleft", so a category-only check would call
that pairing fine, and be wrong. MPL-2.0 ("Copyleft Limited") is outside the FSF's
[compatibility table](https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility), and its
GPL compatibility depends on its own text:
[MPL-2.0 §3.3](https://www.mozilla.org/en-US/MPL/2.0/) lets MPL code combined with GPL, LGPL
or AGPL code in a larger work also be distributed under those licenses, unless the author
marked it "Incompatible With Secondary Licenses" (Exhibit B). No category check can
represent that, and a confident-sounding wrong verdict is what the
[legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer) warns
against.
