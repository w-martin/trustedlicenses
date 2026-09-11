"""Tests for trustedlicenses.policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.conftest import GPL2_LICENSE_TEXT, MIT_LICENSE_TEXT, make_distribution
from trustedlicenses.detection import DistributionLicence
from trustedlicenses.policy import Policy, evaluate, format_failure, format_remediation

if TYPE_CHECKING:
    from pathlib import Path


def test_evaluate_passes_a_permissive_package(tmp_path: Path) -> None:
    """A package with an allowed-category license passes with no failures."""
    dist = make_distribution(tmp_path, "somepkg", license_text=MIT_LICENSE_TEXT)
    policy = Policy(allowed_categories=frozenset({"Permissive"}))

    result = evaluate(policy, distributions_=[dist])

    assert result.passed
    assert result.checked == 1
    assert result.failures == ()


def test_evaluate_fails_a_copyleft_package_when_not_allowed(tmp_path: Path) -> None:
    """A package with only a disallowed-category license fails."""
    dist = make_distribution(tmp_path, "gplpkg", license_text=GPL2_LICENSE_TEXT)
    policy = Policy(allowed_categories=frozenset({"Permissive"}))

    result = evaluate(policy, distributions_=[dist])

    assert not result.passed
    assert result.checked == 1
    assert [failure.name for failure in result.failures] == ["gplpkg"]


def test_evaluate_passes_a_vendored_package_with_at_least_one_allowed_license(tmp_path: Path) -> None:
    """The pandas case: at least one allowed license is enough to pass.

    A copyleft-tainted LICENSE file is fine if it also carries an allowed
    license -- the package's own grant, not everything it vendors.
    """
    concatenated = MIT_LICENSE_TEXT + "\n\n" + GPL2_LICENSE_TEXT
    dist = make_distribution(tmp_path, "vendoring-pkg", license_text=concatenated)
    policy = Policy(allowed_categories=frozenset({"Permissive"}))

    result = evaluate(policy, distributions_=[dist])

    assert result.passed


def test_evaluate_ignores_packages_in_the_ignore_list(tmp_path: Path) -> None:
    """An ignored package is excluded entirely, not just exempted from failure."""
    dist = make_distribution(tmp_path, "gplpkg", license_text=GPL2_LICENSE_TEXT)
    policy = Policy(allowed_categories=frozenset({"Permissive"}), ignored_packages=frozenset({"gplpkg"}))

    result = evaluate(policy, distributions_=[dist])

    assert result.passed
    assert result.checked == 0


def test_evaluate_dedupes_by_canonical_name(tmp_path: Path) -> None:
    """The same distribution appearing twice is only checked once."""
    dist = make_distribution(tmp_path, "Some_Pkg", license_text=MIT_LICENSE_TEXT)
    policy = Policy(allowed_categories=frozenset({"Permissive"}))

    result = evaluate(policy, distributions_=[dist, dist])

    assert result.checked == 1


def test_format_failure_with_no_license_detected() -> None:
    """A failure with no detected keys reports "no license detected"."""
    failure = DistributionLicence(name="bare", keys=frozenset(), categories=frozenset(), source="no source")

    assert "no license detected" in format_failure(failure)


def test_format_failure_with_detected_keys() -> None:
    """A failure with detected keys reports the keys, categories, and source."""
    failure = DistributionLicence(
        name="gplpkg",
        keys=frozenset({"gpl-2.0"}),
        categories=frozenset({"Copyleft"}),
        source="license files: LICENSE",
    )

    line = format_failure(failure)

    assert "gpl-2.0" in line
    assert "Copyleft" in line
    assert "license files: LICENSE" in line


def test_format_remediation_with_no_license_detected_suggests_manual_verification() -> None:
    """With nothing detected, there's no category to suggest -- point at manual review."""
    failure = DistributionLicence(name="bare", keys=frozenset(), categories=frozenset(), source="no source")

    line = format_remediation(failure)

    assert "bare" in line
    assert "ignored-packages" in line
    assert "allowed-categories" not in line


def test_format_remediation_with_detected_categories_suggests_config_changes() -> None:
    """With detected categories, suggest allowing them or ignoring the package."""
    failure = DistributionLicence(
        name="gplpkg",
        keys=frozenset({"GPL-2.0-only"}),
        categories=frozenset({"Copyleft"}),
        source="license files: LICENSE",
    )

    line = format_remediation(failure)

    assert '"Copyleft"' in line
    assert "allowed-categories" in line
    assert '"gplpkg"' in line
    assert "ignored-packages" in line


def test_evaluate_flags_gpl2_only_project_depending_on_gpl3_dependency(tmp_path: Path) -> None:
    """GPLv2-only and GPLv3 are mutually incompatible per the FSF, despite both being "Copyleft".

    The dependency still *passes* the category check (both Copyleft) -- this is
    exactly the case a category-only comparison would silently miss.
    """
    dist = make_distribution(tmp_path, "gpl3pkg", declared={"License-Expression": ["GPL-3.0-only"]})
    policy = Policy(
        allowed_categories=frozenset({"Copyleft"}),
        project_license_keys=frozenset({"GPL-2.0-only"}),
    )

    result = evaluate(policy, distributions_=[dist])

    assert result.passed
    assert len(result.compatibility_notes) == 1
    assert "gpl3pkg" in result.compatibility_notes[0]
    assert "GPLv2" in result.compatibility_notes[0]


def test_evaluate_flags_gpl3_project_depending_on_gpl2_only_dependency(tmp_path: Path) -> None:
    """The mismatch is symmetric: a GPLv3 project depending on GPLv2-only code too."""
    dist = make_distribution(tmp_path, "gpl2pkg", declared={"License-Expression": ["GPL-2.0-only"]})
    policy = Policy(
        allowed_categories=frozenset({"Copyleft"}),
        project_license_keys=frozenset({"GPL-3.0-only"}),
    )

    result = evaluate(policy, distributions_=[dist])

    assert len(result.compatibility_notes) == 1
    assert "gpl2pkg" in result.compatibility_notes[0]


def test_evaluate_flags_strong_copyleft_dependency_for_a_non_copyleft_project(tmp_path: Path) -> None:
    """A non-copyleft project depending on a strong-copyleft package is worth a heads-up."""
    dist = make_distribution(tmp_path, "gplpkg", declared={"License-Expression": ["GPL-3.0-or-later"]})
    policy = Policy(
        allowed_categories=frozenset({"Copyleft"}),
        project_license_keys=frozenset({"MIT"}),
    )

    result = evaluate(policy, distributions_=[dist])

    assert len(result.compatibility_notes) == 1
    assert "gplpkg" in result.compatibility_notes[0]
    assert "strong copyleft" in result.compatibility_notes[0]


def test_evaluate_has_no_compatibility_notes_when_project_license_is_unknown(tmp_path: Path) -> None:
    """With no declared project license, there's nothing to responsibly compare against."""
    dist = make_distribution(tmp_path, "gplpkg", declared={"License-Expression": ["GPL-3.0-only"]})
    policy = Policy(allowed_categories=frozenset({"Copyleft"}))

    result = evaluate(policy, distributions_=[dist])

    assert result.compatibility_notes == ()


def test_evaluate_has_no_compatibility_note_for_a_compatible_copyleft_pairing(tmp_path: Path) -> None:
    """A copyleft project depending on the exact same copyleft family triggers nothing."""
    dist = make_distribution(tmp_path, "samefamily", declared={"License-Expression": ["GPL-3.0-or-later"]})
    policy = Policy(
        allowed_categories=frozenset({"Copyleft"}),
        project_license_keys=frozenset({"GPL-3.0-or-later"}),
    )

    result = evaluate(policy, distributions_=[dist])

    assert result.compatibility_notes == ()
