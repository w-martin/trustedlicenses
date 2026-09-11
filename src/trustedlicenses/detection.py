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

License *categories* (Permissive, Copyleft, Public Domain, ...) are not something SPDX
itself publishes -- they're an editorial taxonomy. The mapping bundled here
(``data/spdx_license_categories.json``) was extracted from ScanCode Toolkit's
CC-BY-4.0-licensed license database; see ``NOTICE`` for the required attribution.

This module only detects and categorizes licenses. Whether a given set of categories
passes or fails is a policy decision, made by :mod:`trustedlicenses.policy`.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from importlib.metadata import distribution
from pathlib import Path
from typing import TYPE_CHECKING

from trustedlicenses.rust_matcher import scan_license_text

if TYPE_CHECKING:
    from collections.abc import Iterable
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
    """

    name: str
    keys: frozenset[str]
    categories: frozenset[str]
    source: str


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

    declared_keys = _keys_from_declared(_declared_statements(dist))
    if declared_keys:
        return DistributionLicence(
            name=resolved_name,
            keys=frozenset(declared_keys),
            categories=frozenset(_categories(declared_keys)),
            source="declared metadata",
        )

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
