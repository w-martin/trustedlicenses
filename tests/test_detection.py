"""Tests for trustedlicenses.detection."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from typing import TYPE_CHECKING

import pytest

from tests.conftest import GPL2_LICENSE_TEXT, MIT_LICENSE_TEXT, make_distribution
from trustedlicenses.detection import canonical_name, inspect_distribution, inspect_installed

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Some_Package", "some-package"),
        ("Some.Package", "some-package"),
        ("  Spacey  ", "spacey"),
        ("already-canonical", "already-canonical"),
    ],
)
def test_canonical_name(raw: str, expected: str) -> None:
    """Names normalise per PEP 503 regardless of case, underscores, or dots."""
    assert canonical_name(raw) == expected


def test_inspect_distribution_detects_permissive_license_from_bundled_file(tmp_path: Path) -> None:
    """A bundled MIT LICENSE file is detected as key 'MIT', category Permissive."""
    dist = make_distribution(tmp_path, "somepkg", license_text=MIT_LICENSE_TEXT)

    result = inspect_distribution(dist, name="somepkg")

    assert result.name == "somepkg"
    assert "MIT" in result.keys
    assert "Permissive" in result.categories
    assert result.source == "license files: LICENSE"


def test_inspect_distribution_detects_copyleft_license_from_bundled_file(tmp_path: Path) -> None:
    """A bundled GPL-2.0 LICENSE file is detected as category Copyleft."""
    dist = make_distribution(tmp_path, "gplpkg", license_text=GPL2_LICENSE_TEXT)

    result = inspect_distribution(dist, name="gplpkg")

    assert "Copyleft" in result.categories


def test_inspect_distribution_detects_multiple_licenses_in_one_vendored_file(tmp_path: Path) -> None:
    """A package that concatenates vendored dependency notices into its own LICENSE.

    Mirrors the pandas case documented in the policy module: the file carries both a
    permissive grant and copyleft text from something it vendors. Detection should
    surface both -- whether that's *acceptable* is a policy decision, not this
    module's job.
    """
    concatenated = MIT_LICENSE_TEXT + "\n\n" + GPL2_LICENSE_TEXT
    dist = make_distribution(tmp_path, "vendoring-pkg", license_text=concatenated)

    result = inspect_distribution(dist, name="vendoring-pkg")

    assert "Permissive" in result.categories
    assert "Copyleft" in result.categories


def test_inspect_distribution_falls_back_to_bundled_file_without_declared_metadata(tmp_path: Path) -> None:
    """No declared metadata falls back to matching the bundled license file's text."""
    dist = make_distribution(tmp_path, "fileonly", license_text=MIT_LICENSE_TEXT)

    result = inspect_distribution(dist, name="fileonly")

    assert "MIT" in result.keys
    assert "Permissive" in result.categories
    assert result.source == "license files: LICENSE"


def test_inspect_distribution_prefers_declared_metadata_over_bundled_file(tmp_path: Path) -> None:
    """Declared metadata wins even when a (differently-licensed) file is also bundled.

    Declared metadata is the primary source, not just a fallback for when no file is
    bundled -- this is the core behaviour change from text-matching-first to
    metadata-first detection. A distribution's own ``License-Expression`` is
    authoritative; a bundled GPL file here would only ever be reached if the
    declared MIT expression were ignored.
    """
    dist = make_distribution(
        tmp_path,
        "metaonly",
        license_text=GPL2_LICENSE_TEXT,
        declared={"License-Expression": ["MIT"]},
    )

    result = inspect_distribution(dist, name="metaonly")

    assert result.keys == frozenset({"MIT"})
    assert result.categories == frozenset({"Permissive"})
    assert result.source == "declared metadata"


def test_inspect_distribution_with_no_license_information_at_all(tmp_path: Path) -> None:
    """No license file and no declared metadata detects nothing, rather than erroring."""
    dist = make_distribution(tmp_path, "bare")

    result = inspect_distribution(dist, name="bare")

    assert result.keys == frozenset()
    assert result.categories == frozenset()
    assert result.source == "no license information found"


def test_inspect_distribution_free_text_license_field_without_a_bundled_file_is_unresolved(
    tmp_path: Path,
) -> None:
    """An unresolvable free-text ``License`` field with no bundled file detects nothing.

    "Apache Software License" is prose, not an SPDX identifier -- PEP 639 introduced
    ``License-Expression`` specifically because fields like this aren't reliably
    machine-resolvable. Earlier, scancode-toolkit's own rule-based text matcher could
    resolve short prose like this against its ~32,000 notice/mention rule variants;
    the SPDX-corpus text matcher this project now uses only matches substantial
    license *text* (a bundled file), not short descriptive phrases, so this case is a
    known, deliberate limitation rather than a regression to silently paper over.
    """
    dist = make_distribution(tmp_path, "prosepkg", declared={"License": ["Apache Software License"]})

    result = inspect_distribution(dist, name="prosepkg")

    assert result.keys == frozenset()
    assert result.categories == frozenset()


def test_inspect_distribution_suggests_catboosts_real_world_free_text_license_field(tmp_path: Path) -> None:
    """The string "Apache License, Version 2.0" (catboost's actual PyPI ``License`` field) is suggested, not trusted.

    The word "License" sitting between the name and the version blocks a direct
    reformat, so this specifically exercises the "strip the word License, then
    reformat" correction path, not just a plain punctuation/whitespace transform.
    Correction is opt-in (see policy.py) -- detection surfaces the suggestion but
    never folds it into ``keys`` on its own.
    """
    dist = make_distribution(tmp_path, "catboost", declared={"License": ["Apache License, Version 2.0"]})

    result = inspect_distribution(dist, name="catboost")

    assert result.keys == frozenset()
    assert result.categories == frozenset()
    assert result.source == "no license information found"
    assert result.suggested == frozenset({("Apache License, Version 2.0", "Apache-2.0")})


def test_inspect_distribution_suggests_via_a_direct_transform_with_no_transposition_needed(
    tmp_path: Path,
) -> None:
    """A statement with no redundant "License" word is suggested via a transform alone."""
    dist = make_distribution(tmp_path, "directcase", declared={"License": ["Apache Version 2.0"]})

    result = inspect_distribution(dist, name="directcase")

    assert result.keys == frozenset()
    assert result.suggested == frozenset({("Apache Version 2.0", "Apache-2.0")})


def test_inspect_distribution_suggests_a_family_name_reformatted_via_its_acronym(tmp_path: Path) -> None:
    """A full family name (not just an acronym) is spelled out to its acronym first."""
    dist = make_distribution(tmp_path, "mozillapkg", declared={"License": ["Mozilla Public License, Version 2.0"]})

    result = inspect_distribution(dist, name="mozillapkg")

    assert result.keys == frozenset()
    assert result.suggested == frozenset({("Mozilla Public License, Version 2.0", "MPL-2.0")})


def test_inspect_distribution_suggestion_does_not_override_a_bundled_file(tmp_path: Path) -> None:
    """An untrusted suggestion never outranks an actual bundled-file match.

    Unlike declared *tokens* (which always win over a file), a free-text
    *suggestion* is a last resort that needs explicit policy-level trust to count at
    all -- at the detection layer it's purely informational, so the file match wins.
    """
    dist = make_distribution(
        tmp_path,
        "filewins",
        license_text=GPL2_LICENSE_TEXT,
        declared={"License": ["Apache License, Version 2.0"]},
    )

    result = inspect_distribution(dist, name="filewins")

    assert result.keys == frozenset({"GPL-2.0-or-later"})
    assert result.source == "license files: LICENSE"
    assert result.suggested == frozenset({("Apache License, Version 2.0", "Apache-2.0")})


def test_inspect_distribution_falls_back_to_file_when_correction_also_fails(tmp_path: Path) -> None:
    """An unresolvable free-text field with a bundled file still falls back to the file."""
    dist = make_distribution(
        tmp_path,
        "fallsback",
        license_text=MIT_LICENSE_TEXT,
        declared={"License": ["Zope Public License"]},
    )

    result = inspect_distribution(dist, name="fallsback")

    assert result.keys == frozenset({"MIT"})
    assert result.source == "license files: LICENSE"
    assert result.suggested == frozenset()


def test_inspect_distribution_does_not_guess_a_versionless_gpl_variant(tmp_path: Path) -> None:
    """No bare GPL-3.0 key exists (only -only/-or-later) -- correction must not invent one.

    PEP 639's own appendix says tools "MUST NOT" auto-infer an SPDX id for exactly
    this kind of versioned-but-variant-ambiguous classifier text.
    """
    dist = make_distribution(tmp_path, "gplfree", declared={"License": ["GNU General Public License, Version 3"]})

    result = inspect_distribution(dist, name="gplfree")

    assert result.keys == frozenset()
    assert result.suggested == frozenset()


def test_inspect_distribution_does_not_guess_an_unversioned_bsd_variant(tmp_path: Path) -> None:
    """The string "BSD License" alone has no clause count -- stays unresolved, not guessed at."""
    dist = make_distribution(tmp_path, "bsdfree", declared={"License": ["BSD License"]})

    result = inspect_distribution(dist, name="bsdfree")

    assert result.keys == frozenset()
    assert result.suggested == frozenset()


def test_inspect_distribution_does_not_fabricate_a_minor_version(tmp_path: Path) -> None:
    """A bare integer version isn't padded into a specific, possibly-wrong minor release.

    MPL has two real single-digit-major releases (MPL-1.0 and MPL-1.1) -- "MPL 1"
    doesn't say which, so correction must not guess ".0" any more than it guesses a
    GPL -only/-or-later suffix.
    """
    dist = make_distribution(tmp_path, "mplfree", declared={"License": ["MPL 1"]})

    result = inspect_distribution(dist, name="mplfree")

    assert result.keys == frozenset()
    assert result.suggested == frozenset()


def test_inspect_distribution_records_the_installed_version(tmp_path: Path) -> None:
    """The version is carried through so an opt-in index check knows what "newer" means."""
    declared = make_distribution(tmp_path, "declaredpkg", declared={"License-Expression": ["MIT"]})
    bare = make_distribution(tmp_path, "barepkg")

    assert inspect_distribution(declared, name="declaredpkg").version == "1.0"
    assert inspect_distribution(bare, name="barepkg").version == "1.0"


def test_inspect_distribution_defaults_name_from_metadata(tmp_path: Path) -> None:
    """Omitting the name argument derives it from the distribution's own metadata."""
    dist = make_distribution(tmp_path, "Some_Pkg", license_text=MIT_LICENSE_TEXT)

    result = inspect_distribution(dist)

    assert result.name == "some-pkg"


def test_inspect_distribution_finds_the_license_file_without_a_record(tmp_path: Path) -> None:
    """No RECORD (dist.files is None) doesn't hide a license file sitting in the dist-info dir.

    The dist-info directory is recovered from the distribution's own metadata path
    instead of the file list.
    """
    dist = make_distribution(tmp_path, "norecord", license_text=MIT_LICENSE_TEXT, include_record=False)
    assert dist.files is None

    result = inspect_distribution(dist, name="norecord")

    assert result.keys == frozenset({"MIT"})
    assert result.source == "license files: LICENSE"


def test_inspect_distribution_with_no_record_and_no_license_file_detects_nothing(tmp_path: Path) -> None:
    """Without a RECORD *and* without a bundled file there is still nothing to find."""
    dist = make_distribution(tmp_path, "norecord-nofile", include_record=False)

    result = inspect_distribution(dist, name="norecord-nofile")

    assert result.keys == frozenset()
    assert result.source == "no license information found"


def test_inspect_installed_raises_for_unknown_package() -> None:
    """A name with no installed distribution raises the standard stdlib error."""
    with pytest.raises(PackageNotFoundError):
        inspect_installed("definitely-not-a-real-package-xyz")


def test_inspect_installed_returns_a_result_for_a_real_dependency() -> None:
    """Looking up a genuinely installed distribution by name works end-to-end."""
    # pytest is guaranteed to be installed in this test environment, since it's what's
    # running this test.
    result = inspect_installed("pytest")

    assert result.name == "pytest"
    assert isinstance(result.keys, frozenset)
    assert isinstance(result.categories, frozenset)
