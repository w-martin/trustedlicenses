# Comparison to Alternatives

How `trustedlicenses` differs from other Python license tools, and when you'd pick one of
them instead. For speed, see [Performance](performance.md).

## `pip-licenses`

`pip-licenses` reads metadata only: `License-Expression` when present (since v5.5.0), then
classifiers, then the free-text `License` field. It does no text matching, and it's very
actively maintained. It lists licenses rather than enforcing a policy, with no pass/fail
against allowed categories, so you'd post-process its output yourself.

Use it when you want a license inventory and are comfortable writing your own pass/fail logic
on top.

## `licensecheck`

`licensecheck` reads `LocalPackageInfo.get_license()` as `License-Expression or classifiers
or License field`, per its source
([`packageinforesolver.py`](https://github.com/FHPythonUtils/LicenseCheck)): the same
metadata priority as `trustedlicenses`'s primary path. It never text-matches bundled LICENSE
files. For a package that isn't installed locally it can fall back to the PyPI JSON API;
`trustedlicenses` reads an index only when auditing a lock file or on request
(`index-check`), and uses the index your lock file or configuration names rather than
assuming PyPI. `licensecheck` is very actively maintained, with releases every few days.

It also has its own pairwise project-vs-dependency compatibility matrix, a much bigger
undertaking than `trustedlicenses`'s narrower
[compatibility notes](usage.md#a-narrow-fsf-grounded-compatibility-check).

Since 2026.0.0 (2026-06-12) it requires Python 3.12 or later, up from 3.9 in 2025.1.0
(2025-03-26). Python 3.10 and 3.11 were both still in security support then (end of life
2026-10-01 and 2027-10, per the [Python developer guide](https://devguide.python.org/versions/)),
so projects on them can't move to the new releases. Its commits, release notes and README give
no reason. `trustedlicenses` aims to keep its own floor and ceiling aligned with the Python
versions maintained at the time.

`trustedlicenses`'s [legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer)
is modeled on `licensecheck`'s.

Use it when you want metadata-first checking plus a real project-license compatibility
matrix, and don't need it to read bundled LICENSE file text.

## `liccheck`

`liccheck` uses the same metadata-only strategy, but through the deprecated `pkg_resources`
API rather than `importlib.metadata`, and its source shows no `License-Expression` support.
It was last released on 2023-09-22, before PyPI's PEP 639 rollout (November 2024). It crashes
on a current Python/setuptools combination, because recent `setuptools` releases have been
deprecating and dropping `pkg_resources`
([the error](performance.md#liccheck-couldnt-be-benchmarked)). Treat it as unmaintained for
this purpose.

## ScanCode Toolkit

`trustedlicenses` originally wrapped `scancode-toolkit-mini`, a full rule-based engine
matching against ~2,100 license texts plus ~32,000 notice and variant rules, combined via
hash matching, an Aho-Corasick-style matcher and sequence alignment. It needs a system
`libmagic` install for file-type sniffing, and it's much heavier than this project needs:
auditing the bundled LICENSE files of installed Python packages, not scanning arbitrary
source trees for embedded license fragments.

The only accuracy comparison found between ScanCode and simpler similarity matchers like
`trustedlicenses`'s is an unpublished 2019 bachelor's thesis comparing several license
scanners. It judged ScanCode correct on well under half of the small number of disputed cases
it reviewed by hand against FOSSology. With 25 cases and no peer review, that's too thin to
support a strong claim either way.

Use it when you need to scan arbitrary source trees for embedded license fragments or
headers. That's the harder problem ScanCode is built for, and `trustedlicenses` doesn't try
to solve it.

## The approach `trustedlicenses` uses

Its text-matching fallback is the same general family as GitHub's
[Licensee](https://github.com/licensee/licensee) and
[askalono](https://github.com/jpeddicord/askalono): word and bigram similarity against a
corpus of known license texts, not a rule engine.
[How detection works](how-it-works.md#how-detection-works) has the mechanics.
