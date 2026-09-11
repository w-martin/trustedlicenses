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


def test_inspect_distribution_defaults_name_from_metadata(tmp_path: Path) -> None:
    """Omitting the name argument derives it from the distribution's own metadata."""
    dist = make_distribution(tmp_path, "Some_Pkg", license_text=MIT_LICENSE_TEXT)

    result = inspect_distribution(dist)

    assert result.name == "some-pkg"


def test_inspect_distribution_with_no_file_list_has_no_dist_info(tmp_path: Path) -> None:
    """A distribution with no RECORD file can't have its bundled LICENSE located.

    dist.files is None without a RECORD, so detection finds no license file (and has
    no declared metadata either).
    """
    dist = make_distribution(tmp_path, "norecord", license_text=MIT_LICENSE_TEXT, include_record=False)

    result = inspect_distribution(dist, name="norecord")

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
