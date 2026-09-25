"""Tests for trustedlicenses.policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.conftest import GPL2_LICENSE_TEXT, MIT_LICENSE_TEXT, make_distribution
from trustedlicenses.detection import DistributionLicence
from trustedlicenses.policy import (
    Policy,
    _effective_result,
    _trusted_suggestion_ids,
    detect_all,
    evaluate,
    format_failure,
    format_remediation,
    reevaluate,
)

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


@pytest.mark.parametrize("stripped_first", [True, False])
def test_detect_all_result_does_not_depend_on_duplicate_install_order(tmp_path: Path, *, stripped_first: bool) -> None:
    """Two installs of one package -- one stripped of its license file -- resolve the same either way round."""
    stripped_dir = tmp_path / "stripped"
    intact_dir = tmp_path / "intact"
    stripped_dir.mkdir()
    intact_dir.mkdir()
    stripped = make_distribution(stripped_dir, "webencodings")
    intact = make_distribution(intact_dir, "webencodings", license_text=MIT_LICENSE_TEXT)
    dists = [stripped, intact] if stripped_first else [intact, stripped]

    results = detect_all(distributions_=dists)

    assert len(results) == 1
    assert results[0].keys == frozenset({"MIT"})


def test_detect_all_keeps_the_first_copy_when_no_copy_resolves(tmp_path: Path) -> None:
    """Nothing resolves anywhere -- still exactly one result per package, not one per copy."""
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    dists = [make_distribution(first_dir, "bare"), make_distribution(second_dir, "bare")]

    results = detect_all(distributions_=dists)

    assert [result.name for result in results] == ["bare"]
    assert results[0].keys == frozenset()


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


def _suggested_only(name: str, statement: str, spdx_id: str) -> DistributionLicence:
    """A detection with nothing resolved except a free-text correction suggestion."""
    return DistributionLicence(
        name=name,
        keys=frozenset(),
        categories=frozenset(),
        source="no license information found",
        suggested=frozenset({(statement, spdx_id)}),
    )


def test_trusted_suggestion_ids_empty_by_default() -> None:
    """No trust setting at all -- an untrusted suggestion trusts nothing."""
    detected = _suggested_only("catboost", "Apache License, Version 2.0", "Apache-2.0")
    policy = Policy(allowed_categories=frozenset({"Permissive"}))

    assert _trusted_suggestion_ids(detected, policy) == frozenset()


def test_trusted_suggestion_ids_trusts_the_global_flag() -> None:
    """trust_corrected_licenses=True trusts every suggested id."""
    detected = _suggested_only("catboost", "Apache License, Version 2.0", "Apache-2.0")
    policy = Policy(allowed_categories=frozenset({"Permissive"}), trust_corrected_licenses=True)

    assert _trusted_suggestion_ids(detected, policy) == frozenset({"Apache-2.0"})


def test_trusted_suggestion_ids_trusts_a_matching_package_pin() -> None:
    """A verified_packages pin matching the current suggestion is trusted."""
    detected = _suggested_only("catboost", "Apache License, Version 2.0", "Apache-2.0")
    policy = Policy(
        allowed_categories=frozenset({"Permissive"}),
        verified_packages={"catboost": ("Apache License, Version 2.0", "Apache-2.0")},
    )

    assert _trusted_suggestion_ids(detected, policy) == frozenset({"Apache-2.0"})


def test_trusted_suggestion_ids_ignores_a_stale_package_pin() -> None:
    """A pin for text the package no longer declares doesn't apply to its new text."""
    detected = _suggested_only("catboost", "Some New License Text 3.0", "MIT")
    policy = Policy(
        allowed_categories=frozenset({"Permissive"}),
        verified_packages={"catboost": ("Apache License, Version 2.0", "Apache-2.0")},
    )

    assert _trusted_suggestion_ids(detected, policy) == frozenset()


def test_trusted_suggestion_ids_trusts_a_matching_statement_pin_for_any_package() -> None:
    """A verified_statements pin applies regardless of which package declares the text."""
    detected = _suggested_only("some-internal-pkg", "Apache License, Version 2.0", "Apache-2.0")
    policy = Policy(
        allowed_categories=frozenset({"Permissive"}),
        verified_statements={"Apache License, Version 2.0": "Apache-2.0"},
    )

    assert _trusted_suggestion_ids(detected, policy) == frozenset({"Apache-2.0"})


def test_trusted_suggestion_ids_ignores_a_statement_pin_with_a_stale_id() -> None:
    """If correction would now produce a different id than the pin recorded, don't trust it."""
    detected = _suggested_only("pkg", "Apache License, Version 2.0", "Apache-2.0")
    policy = Policy(
        allowed_categories=frozenset({"Permissive"}),
        verified_statements={"Apache License, Version 2.0": "Apache-1.0"},
    )

    assert _trusted_suggestion_ids(detected, policy) == frozenset()


def test_effective_result_folds_in_a_trusted_suggestion() -> None:
    """Trust folds a suggestion into keys/categories/source, as a copy."""
    detected = _suggested_only("catboost", "Apache License, Version 2.0", "Apache-2.0")
    policy = Policy(allowed_categories=frozenset({"Permissive"}), trust_corrected_licenses=True)

    effective = _effective_result(detected, policy)

    assert effective.keys == frozenset({"Apache-2.0"})
    assert effective.categories == frozenset({"Permissive"})
    assert effective.source == "declared metadata (corrected from free text)"
    assert detected.keys == frozenset()  # the original is untouched


def test_effective_result_is_unchanged_when_nothing_is_trusted() -> None:
    """No matching trust source -- the detection passes through as-is."""
    detected = _suggested_only("catboost", "Apache License, Version 2.0", "Apache-2.0")
    policy = Policy(allowed_categories=frozenset({"Permissive"}))

    assert _effective_result(detected, policy) == detected


def test_effective_result_does_not_override_an_existing_match_even_when_trusted() -> None:
    """A suggestion never outranks a real match (declared token or bundled file), trusted or not."""
    detected = DistributionLicence(
        name="filewins",
        keys=frozenset({"GPL-2.0-or-later"}),
        categories=frozenset({"Copyleft"}),
        source="license files: LICENSE",
        suggested=frozenset({("Apache License, Version 2.0", "Apache-2.0")}),
    )
    policy = Policy(allowed_categories=frozenset({"Permissive"}), trust_corrected_licenses=True)

    assert _effective_result(detected, policy) == detected


def test_evaluate_fails_an_untrusted_suggestion_by_default(tmp_path: Path) -> None:
    """A free-text correction is opt-in -- a plain policy doesn't trust it on its own."""
    dist = make_distribution(tmp_path, "catboost", declared={"License": ["Apache License, Version 2.0"]})
    policy = Policy(allowed_categories=frozenset({"Permissive"}))

    result = evaluate(policy, distributions_=[dist])

    assert not result.passed
    assert result.failures[0].suggested == frozenset({("Apache License, Version 2.0", "Apache-2.0")})


def test_evaluate_passes_when_trust_corrected_licenses_is_enabled(tmp_path: Path) -> None:
    """The project-wide flag trusts the correction end-to-end."""
    dist = make_distribution(tmp_path, "catboost", declared={"License": ["Apache License, Version 2.0"]})
    policy = Policy(allowed_categories=frozenset({"Permissive"}), trust_corrected_licenses=True)

    result = evaluate(policy, distributions_=[dist])

    assert result.passed


def test_evaluate_passes_with_a_matching_verified_package_pin(tmp_path: Path) -> None:
    """A package-specific pin trusts the correction end-to-end."""
    dist = make_distribution(tmp_path, "catboost", declared={"License": ["Apache License, Version 2.0"]})
    policy = Policy(
        allowed_categories=frozenset({"Permissive"}),
        verified_packages={"catboost": ("Apache License, Version 2.0", "Apache-2.0")},
    )

    result = evaluate(policy, distributions_=[dist])

    assert result.passed


def test_evaluate_fails_again_after_the_declared_text_changes_under_a_package_pin(tmp_path: Path) -> None:
    """The whole point of pinning to exact text: a changed statement needs re-review."""
    dist = make_distribution(tmp_path, "catboost", declared={"License": ["Apache Version 1.0"]})
    policy = Policy(
        allowed_categories=frozenset({"Permissive"}),
        verified_packages={"catboost": ("Apache License, Version 2.0", "Apache-2.0")},
    )

    result = evaluate(policy, distributions_=[dist])

    assert not result.passed
    assert result.failures[0].suggested == frozenset({("Apache Version 1.0", "Apache-1.0")})


def test_evaluate_passes_with_a_matching_verified_statement_pin_for_any_package(tmp_path: Path) -> None:
    """A statement-text pin applies regardless of which package declares it."""
    dist = make_distribution(tmp_path, "some-internal-pkg", declared={"License": ["Apache License, Version 2.0"]})
    policy = Policy(
        allowed_categories=frozenset({"Permissive"}),
        verified_statements={"Apache License, Version 2.0": "Apache-2.0"},
    )

    result = evaluate(policy, distributions_=[dist])

    assert result.passed


def test_evaluate_suggestion_never_overrides_a_bundled_file_match_even_when_trusted(tmp_path: Path) -> None:
    """A last-resort suggestion can't outrank a real bundled-file match."""
    dist = make_distribution(
        tmp_path,
        "filewins",
        license_text=GPL2_LICENSE_TEXT,
        declared={"License": ["Apache License, Version 2.0"]},
    )
    policy = Policy(allowed_categories=frozenset({"Permissive"}), trust_corrected_licenses=True)

    result = evaluate(policy, distributions_=[dist])

    assert not result.passed
    assert result.failures[0].keys == frozenset({"GPL-2.0-or-later"})


def test_format_remediation_with_a_suggestion_points_at_trusting_it() -> None:
    """A failure with an untrusted suggestion is told what it looks like and how to trust it."""
    failure = DistributionLicence(
        name="catboost",
        keys=frozenset(),
        categories=frozenset(),
        source="no license information found",
        suggested=frozenset({("Apache License, Version 2.0", "Apache-2.0")}),
    )

    line = format_remediation(failure)

    assert "Apache-2.0" in line
    assert "Apache License, Version 2.0" in line
    assert "trust-corrected-licenses" in line
    assert "verified-packages" in line
    assert "verified-statements" in line


def test_reevaluate_matches_evaluate_for_the_same_policy(tmp_path: Path) -> None:
    """reevaluate(detect_all(...), policy) agrees with evaluate(policy, ...) -- it's the same fold, just split."""
    dist = make_distribution(tmp_path, "somepkg", license_text=MIT_LICENSE_TEXT)
    policy = Policy(allowed_categories=frozenset({"Permissive"}))

    via_evaluate = evaluate(policy, distributions_=[dist])
    via_reevaluate = reevaluate(detect_all(distributions_=[dist]), policy)

    assert via_evaluate == via_reevaluate


def test_reevaluate_reapplies_ignored_packages_against_the_new_policy(tmp_path: Path) -> None:
    """A package not excluded by the policy that produced `detected` is still dropped if newly ignored.

    This is what makes reusing one detection pass safe across a policy change (e.g.
    the review wizard adding to ignored-packages): reevaluate doesn't trust whatever
    exclusion `detected` happened to already reflect.
    """
    dist = make_distribution(tmp_path, "gplpkg", license_text=GPL2_LICENSE_TEXT)
    detected = detect_all(distributions_=[dist])  # nothing excluded yet
    policy = Policy(allowed_categories=frozenset({"Permissive"}), ignored_packages=frozenset({"gplpkg"}))

    result = reevaluate(detected, policy)

    assert result.passed
    assert result.checked == 0


def test_format_remediation_still_suggests_manual_verification_with_no_suggestion() -> None:
    """A failure with nothing detected and no suggestion still points at manual review."""
    failure = DistributionLicence(name="bare", keys=frozenset(), categories=frozenset(), source="no source")

    line = format_remediation(failure)

    assert "ignored-packages" in line
    assert "trust-corrected-licenses" not in line
