# Comparison to Alternatives

A practical comparison of `trustedlicenses` against the other tools in this space,
for someone deciding which one to actually use. Speed numbers live on a separate
[Performance](performance.md) page — this page is about approach and tradeoffs.

## `pip-licenses`

Pure metadata reading — `License-Expression` when present (added in v5.5.0), falling
back to classifiers, falling back to the free-text `License` field. No text matching
of any kind. Very actively maintained (commits within the last day, as of this
research). It's a *lister*, not a policy-enforcement tool: it has no built-in
pass/fail concept against a set of allowed categories the way `trustedlicenses` and
`licensecheck` do — you'd need to post-process its output yourself to get that.

Use it when: you just want a license inventory, and you're comfortable writing your
own pass/fail logic on top.

## `licensecheck`

Reads `LocalPackageInfo.get_license()` as `License-Expression or classifiers or
License field` — the same metadata-priority strategy `trustedlicenses` uses for its
primary path, per its source
([`packageinforesolver.py`](https://github.com/FHPythonUtils/LicenseCheck)). No
bundled-LICENSE-file text matching anywhere in its code. When a package isn't
installed locally, it can fall back to the PyPI JSON API instead — not applicable to
`trustedlicenses`'s installed-environment-only scope. Very actively maintained
(releases every few days). It also has its own pairwise project-vs-dependency
compatibility matrix — a materially bigger undertaking than `trustedlicenses`'s own
compatibility check; see
[Usage Guide § Compatibility notes](usage.md#a-narrow-fsf-grounded-compatibility-check)
for the rationale behind that narrower scope.

`trustedlicenses`'s legal disclaimer is modeled on `licensecheck`'s — see the
[README](https://github.com/w-martin/trustedlicenses#legal-disclaimer) for the full
text.

Use it when: you want metadata-first checking plus a real project-license
compatibility matrix, and you're fine with it never looking at bundled LICENSE file
text at all.

## `liccheck`

Same metadata-only strategy, but via the deprecated `pkg_resources` API rather than
`importlib.metadata`, and with no `License-Expression` support found in its source.
Last released 2023-09-22 — over two years old as of this writing, predating PyPI's
PEP 639 rollout (November 2024) entirely. It crashes outright on a current
Python/setuptools combination (`pkg_resources` has been deprecated out of recent
`setuptools` releases) — see
[Performance § liccheck couldn't be benchmarked](performance.md#liccheck-couldnt-be-benchmarked)
for the concrete error. Treat it as unmaintained for this purpose.

## ScanCode Toolkit (and what `trustedlicenses` used to be)

`trustedlicenses` originally wrapped `scancode-toolkit-mini`: a full rule-based engine
matching against ~2,100 full license texts plus ~32,000 notice/variant rules, combined
via hash matching, an Aho-Corasick-style matcher, and sequence alignment. It requires
a system `libmagic` install (for file-type sniffing) and is significantly heavier than
this project's narrower need — auditing bundled LICENSE files of *installed Python
packages*, not scanning arbitrary source trees for embedded license fragments.

The only accuracy comparison found between ScanCode and simpler similarity-matching
tools like the one `trustedlicenses` uses is an unpublished 2019 bachelor's thesis
comparing several license scanners, which judged ScanCode correct on well under half
of the small number of disputed cases it manually reviewed against FOSSology. The
sample was tiny (25 cases) and the thesis was never peer-reviewed, so treat this as a
single low-confidence data point rather than a verdict: it does not show ScanCode's
heavier machinery buying proportionally better precision for this narrower use case,
but the evidence is too thin to support a strong claim either way.

Use it when: you need to scan arbitrary source trees for embedded license
fragments/headers, not just audit installed packages' own declared licenses — that's
a genuinely different, harder problem ScanCode is built for and `trustedlicenses`
isn't trying to solve.

## The approach `trustedlicenses` uses, briefly

`trustedlicenses`'s text-matching fallback is the same general *family* of approach
as GitHub's own [Licensee](https://github.com/licensee/licensee) and
[askalono](https://github.com/jpeddicord/askalono) (word/bigram similarity matching
against a corpus of known license texts, rather than ScanCode's rule engine) — see
[Usage Guide § How detection works](usage.md#how-detection-works) for the mechanics
and how it differs from those two specifically. That's where the algorithm-level
detail belongs; this page is about picking a tool, not implementing one.
