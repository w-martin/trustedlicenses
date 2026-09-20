"""License detection for one installed distribution.

Detection strategy, per installed distribution, in priority order:

1. Declared metadata -- the ``License-Expression`` field (:pep:`639`, already SPDX
   syntax), the free-text ``License`` field, and any ``License :: ...`` trove
   classifiers. A statement is trusted directly when it already names a real SPDX
   license identifier; no text matching is involved. This is the primary source: it's
   what PyPI itself serves, and what ecosystem tools like ``licensecheck`` and
   ``pip-licenses`` rely on for installed-package auditing.
2. Only when no declared statement resolves to a known SPDX identifier, fall back to
   matching the text of any license file bundled in the distribution's ``.dist-info``
   directory (``LICENSE``, ``COPYING``, ``NOTICE``, ...) against the official SPDX
   license-list-data corpus, via a small Rust matcher (see
   :mod:`trustedlicenses.rust_matcher`) wrapping the ``spdx`` crate's word-bigram
   Sorensen-Dice text detection -- a maintained continuation of askalono's algorithm,
   the same family of approach GitHub's own Licensee uses.

Whenever neither of those resolves anything, a small set of deterministic, validated
corrections (see :func:`_correct_license_statement`) is also tried against the
declared statements -- reformatting punctuation and a version number already present
in the text, never guessing one that isn't -- and attached as
:attr:`DistributionLicence.suggested`. This is deliberately *not* folded into ``keys``
here: whether a project trusts it is a policy decision (opt-in, off by default -- see
:mod:`trustedlicenses.policy` and :mod:`trustedlicenses.wizard`), not something
detection silently decides on its own.

License *categories* (Permissive, Copyleft, Public Domain, ...) are not something SPDX
itself publishes -- they're an editorial taxonomy. The mapping bundled here
(``data/spdx_license_categories.json``) was extracted from ScanCode Toolkit's
CC-BY-4.0-licensed license database; see ``NOTICE`` for the required attribution.

This module only detects and categorizes licenses. Whether a given set of categories
passes or fails -- and whether a suggested correction is trusted -- is a policy
decision, made by :mod:`trustedlicenses.policy`.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from importlib.metadata import distribution
from pathlib import Path
from typing import TYPE_CHECKING

from trustedlicenses.rust_matcher import scan_license_text

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from importlib.metadata import Distribution

# The category assigned to ScanCode's own "there is clearly a license reference here
# but it cannot be identified" marker. It is never proof of a license.
UNSTATED_CATEGORY = "Unstated License"

LICENCE_FILE_PATTERNS = ("LICEN[CS]E*", "COPYING*", "NOTICE*")

# SPDX expression operators, stripped before looking at tokens as license identifiers.
SPDX_OPERATORS = frozenset({"and", "or", "with"})

# A bundled LICENSE-file match must clear this confidence (0.0-1.0) to be reported.
#
# Not the `spdx`/askalono library's own default (0.9) -- that default is measurably too
# strict for real-world license text. Verified directly: jupyter's and prompt-toolkit's
# genuine, unmodified BSD-3-Clause LICENSE files (both real installed PyPI packages)
# score 0.85 and 0.91 respectively against the corpus, so a 0.9 threshold produces false
# negatives on two extremely common packages. 0.8 -- which is what askalono's own CLI
# uses in practice, overriding its library's 0.9 default for exactly this reason -- finds
# both correctly without introducing false positives (0.7 starts misidentifying BSD-3
# variants; 0.8 doesn't).
TEXT_MATCH_CONFIDENCE_THRESHOLD = 0.8


@dataclass(frozen=True)
class DistributionLicence:
    """The licenses detected for one installed distribution.

    Attributes:
        name: Canonical (PEP 503 normalised) distribution name.
        keys: SPDX license identifiers detected for the distribution (e.g. ``"MIT"``,
            ``"Apache-2.0"``).
        categories: Categories of ``keys``.
        source: Where the detection came from, for a failure report.
        suggested: ``(declared statement, corrected SPDX id)`` pairs
            :func:`_correct_license_statement` produced for this distribution's
            declared statements. Populated whenever ``keys`` came back empty,
            regardless of whether anything ends up trusting it -- purely
            informational at this layer; see the module docstring.
    """

    name: str
    keys: frozenset[str]
    categories: frozenset[str]
    source: str
    suggested: frozenset[tuple[str, str]] = frozenset()


@lru_cache(maxsize=1)
def _category_table() -> dict[str, str]:
    """SPDX license identifier (canonical case) -> license category.

    Extracted from ScanCode Toolkit's ``licensedcode/data`` (CC-BY-4.0, nexB Inc. and
    others -- see ``NOTICE``), the source of the category vocabulary this project's
    own policy configuration uses (e.g. ``allowed-categories = ["Permissive", ...]``).
    """
    raw = resources.files("trustedlicenses").joinpath("data/spdx_license_categories.json").read_text("utf-8")
    return json.loads(raw)


@lru_cache(maxsize=1)
def _category_table_ci() -> dict[str, str]:
    """Lowercased-key index into :func:`_category_table`, for case-insensitive lookup.

    Declared metadata (and, in principle, differently-cased SPDX tokens) shouldn't
    fail to resolve purely over casing, but the category table itself is keyed by
    canonical SPDX case.
    """
    return {key.lower(): key for key in _category_table()}


def canonical_name(raw: str) -> str:
    """Normalise a distribution name per PEP 503.

    Args:
        raw: Distribution name as written in metadata or configuration.

    Returns:
        The lower-cased name with runs of ``-``, ``_`` and ``.`` collapsed to ``-``.
    """
    return raw.strip().lower().replace("_", "-").replace(".", "-")


def _dist_info_dir(dist: Distribution) -> Path | None:
    """Locate the ``.dist-info`` directory of an installed distribution.

    Args:
        dist: The installed distribution.

    Returns:
        The distribution's ``.dist-info`` directory, or ``None`` when it records no
        file list to derive it from.
    """
    for file in dist.files or []:
        parts = file.parts
        if parts and parts[0].endswith(".dist-info"):
            return Path(str(file.locate())).parents[len(parts) - 2]
    return None


def _licence_files(dist_info: Path | None) -> list[Path]:
    """Return the license files bundled in a ``.dist-info`` directory.

    Args:
        dist_info: The distribution's ``.dist-info`` directory, if it has one.

    Returns:
        Every bundled file whose name looks like a license file, sorted by path.
    """
    if dist_info is None or not dist_info.is_dir():
        return []
    return [
        path
        for path in sorted(dist_info.rglob("*"))
        if path.is_file() and any(fnmatch.fnmatch(path.name.upper(), pattern) for pattern in LICENCE_FILE_PATTERNS)
    ]


def _expression_tokens(expression: str) -> set[str]:
    """Split a license expression into candidate license identifier tokens.

    Also handles a classifier's trailing name, e.g. the ``MIT License`` portion of
    ``License :: OSI Approved :: MIT License``.

    Args:
        expression: A license expression such as ``MIT OR Apache-2.0``, or a trove
            classifier such as ``License :: OSI Approved :: MIT License``.

    Returns:
        The identifier tokens, with SPDX operators and brackets removed.
    """
    cleaned = expression.replace("(", " ").replace(")", " ")
    return {token for token in cleaned.split() if token.lower() not in SPDX_OPERATORS}


def _keys_from_licence_files(files: list[Path]) -> set[str]:
    """Detect license keys from bundled license text.

    Args:
        files: License files to run the SPDX-corpus text matcher over.

    Returns:
        The SPDX license identifiers matched anywhere in those files.
    """
    keys: set[str] = set()
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for spdx_id, _score in scan_license_text(text, TEXT_MATCH_CONFIDENCE_THRESHOLD):
            keys.add(spdx_id)
    return keys


def _declared_statements(dist: Distribution) -> list[str]:
    """Collect the license statements a distribution declares in its metadata.

    Args:
        dist: The installed distribution.

    Returns:
        The declared license expression or field, plus any license classifiers.
    """
    metadata = dist.metadata
    declared = [value for field in ("License-Expression", "License") for value in metadata.get_all(field) or []]
    classifiers = [
        classifier for classifier in metadata.get_all("Classifier") or [] if classifier.startswith("License ::")
    ]
    return [statement for statement in [*declared, *classifiers] if statement]


def resolve_license_expression(expression: str) -> frozenset[str]:
    """Resolve a raw license statement to known SPDX license identifiers.

    A ``License-Expression`` statement is already SPDX syntax, so a token is trusted
    directly once it's confirmed to name a real SPDX identifier -- no text matching
    involved. A free-text ``License`` field or classifier that isn't already phrased
    as one or more SPDX identifiers (e.g. prose like "Apache Software License" with
    no accompanying ``License-Expression``) resolves to nothing.

    Args:
        expression: A license expression such as ``MIT OR Apache-2.0``, or a trove
            classifier such as ``License :: OSI Approved :: MIT License``.

    Returns:
        The subset of tokens that name a real SPDX identifier.
    """
    ci_index = _category_table_ci()
    return frozenset(
        canonical
        for token in _expression_tokens(expression)
        for canonical in [ci_index.get(token.lower())]
        if canonical is not None
    )


def _keys_from_declared(statements: list[str]) -> set[str]:
    """Resolve declared license statements to SPDX license identifiers.

    Args:
        statements: Declared license statements from package metadata.

    Returns:
        The SPDX license identifiers the statements resolve to.
    """
    keys: set[str] = set()
    for statement in statements:
        keys |= resolve_license_expression(statement)
    return keys


# Structural transforms for `_correct_license_statement`: punctuation/whitespace
# cleanup, and version-number reformatting gated on a digit already present in the
# text -- never a digit invented from nothing. In particular, no transform pads a
# bare single-digit version with a fabricated ".0": several families (MPL, OSL, ...)
# have more than one real minor-version release, so "MPL 1" cannot be corrected
# without guessing between MPL-1.0 and MPL-1.1 -- exactly the kind of invented
# specificity this function otherwise refuses to produce. Applied independently to
# the original candidate (not chained): the first one whose result validates against
# a real SPDX id wins. Ported from the validated-transform tier of `spdx-correct.js`
# (jslicense, Apache-2.0 -- see NOTICE).
_CORRECTION_TRANSFORMS: tuple[Callable[[str], str], ...] = (
    lambda text: text.replace(".", ""),
    lambda text: re.sub(r"\s+", "", text),
    lambda text: re.sub(r"\s+", "-", text),
    lambda text: re.sub(r",?\s*(\d)", r"-\1", text, count=1),
    lambda text: re.sub(r",?\s*(?:V\.|v\.|V|v|Version|version)\s*(\d)", r"-\1", text, count=1),
    lambda text: text.replace("/", "-"),
)

# A single substring replacement, tried independently, before re-attempting the
# transforms above on the result. The first four spell out a license family's full
# name as its acronym, giving a version-number transform a normalized base to work
# from. The last strips the literal word "License" -- no SPDX identifier in this
# family ever contains that word, so removing it discards noise, not information; it
# is not from `spdx-correct.js` (its own transforms don't resolve e.g. "Apache
# License, Version 2.0" -- verified directly, not assumed).
_CORRECTION_TRANSPOSITIONS: tuple[tuple[str, str], ...] = (
    ("GNU Lesser General Public License", "LGPL"),
    ("GNU Affero General Public License", "AGPL"),
    ("GNU General Public License", "GPL"),
    ("Mozilla Public License", "MPL"),
    (" License", ""),
)


def _correct_license_statement(statement: str) -> str | None:
    """Try to deterministically correct a free-text statement into a real SPDX id.

    Only ever accepts a result that both changed from the input and resolves to a
    real, known SPDX identifier via the same case-insensitive table
    :func:`resolve_license_expression` already trusts -- nothing here is a new source
    of trust, just a massaged string fed to the same gate.

    Deliberately excludes `spdx-correct.js`'s "last resort" substring-guessing tier
    (e.g. any string containing "GPL" -> assume ``GPL-3.0-or-later``, any "BSD" ->
    assume ``BSD-2-Clause``): those guesses manufacture a specific version or variant
    the text never actually stated -- exactly the auto-inference :pep:`639`'s own
    appendix says tools "MUST NOT" perform for genuinely ambiguous classifiers (bare
    "BSD License", bare "GNU General Public License", ...). A statement that's
    ambiguous in this way simply stays unresolved, same as before this function
    existed.

    Only meaningful for a statement direct token resolution
    (:func:`resolve_license_expression`) already found nothing for -- a statement
    that's already a bare valid token is resolved there first and never reaches this
    function in practice.

    Args:
        statement: A single declared license statement.

    Returns:
        The corrected SPDX identifier, or ``None`` if no transform produces one.
    """
    ci_index = _category_table_ci()
    candidate = statement.strip()

    for transform in _CORRECTION_TRANSFORMS:
        corrected = transform(candidate).strip()
        if corrected != candidate and (canonical := ci_index.get(corrected.lower())):
            return canonical

    for pattern, replacement in _CORRECTION_TRANSPOSITIONS:
        if pattern not in candidate:
            continue
        transposed = candidate.replace(pattern, replacement)
        if canonical := ci_index.get(transposed.lower()):
            return canonical
        for transform in _CORRECTION_TRANSFORMS:
            corrected = transform(transposed).strip()
            if corrected != transposed and (canonical := ci_index.get(corrected.lower())):
                return canonical

    return None


def _suggested_corrections(statements: list[str]) -> frozenset[tuple[str, str]]:
    """Pair declared statements with what :func:`_correct_license_statement` resolves them to.

    Args:
        statements: Declared license statements that direct token resolution
            (:func:`_keys_from_declared`) already found nothing for.

    Returns:
        ``(statement, corrected SPDX id)`` for every statement that corrects to one.
    """
    return frozenset(
        (statement, corrected) for statement in statements if (corrected := _correct_license_statement(statement))
    )


def categories_for(keys: Iterable[str]) -> frozenset[str]:
    """Map SPDX license identifiers to their categories.

    Args:
        keys: SPDX license identifiers.

    Returns:
        The categories of every key with a known category, excluding the
        "unidentifiable license reference" marker.
    """
    table = _category_table()
    categories = {table[key] for key in keys if key in table}
    return frozenset(categories - {UNSTATED_CATEGORY})


def _categories(keys: set[str]) -> set[str]:
    """Map SPDX license identifiers to their categories.

    Args:
        keys: SPDX license identifiers.

    Returns:
        The categories of every key with a known category, excluding the
        "unidentifiable license reference" marker.
    """
    return set(categories_for(keys))


def inspect_distribution(dist: Distribution, name: str | None = None) -> DistributionLicence:
    """Detect the licenses of one installed distribution.

    Args:
        dist: The installed distribution.
        name: Its canonical name. Computed from ``dist``'s own metadata when omitted.

    Returns:
        What was detected, and where it was detected from.
    """
    resolved_name = name or canonical_name(dist.metadata["Name"] or "")

    statements = _declared_statements(dist)
    declared_keys = _keys_from_declared(statements)
    if declared_keys:
        return DistributionLicence(
            name=resolved_name,
            keys=frozenset(declared_keys),
            categories=frozenset(_categories(declared_keys)),
            source="declared metadata",
        )

    suggested = _suggested_corrections(statements)

    files = _licence_files(_dist_info_dir(dist))
    if files:
        keys = _keys_from_licence_files(files)
        source = "license files: " + ", ".join(sorted({path.name for path in files}))
    else:
        keys = set()
        source = "no license information found"
    return DistributionLicence(
        name=resolved_name,
        keys=frozenset(keys),
        categories=frozenset(_categories(keys)),
        source=source,
        suggested=suggested,
    )


def inspect_installed(name: str) -> DistributionLicence:
    """Detect the licenses of an installed distribution by name.

    Args:
        name: The distribution's project name, as installed (any case/separator).

    Returns:
        What was detected, and where it was detected from.

    Raises:
        importlib.metadata.PackageNotFoundError: No such distribution is installed.
    """
    return inspect_distribution(distribution(name), name=canonical_name(name))
