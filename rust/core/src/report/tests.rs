use super::*;
use std::collections::BTreeMap;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn licence(name: &str, keys: &[&str]) -> DistributionLicence {
    DistributionLicence {
        name: name.to_owned(),
        keys: set(keys),
        categories: categories_for(keys.iter().copied()),
        source: "metadata".to_owned(),
        ..DistributionLicence::default()
    }
}

fn render(policy: Option<&Policy>, detected: &[DistributionLicence]) -> String {
    let reasons = BTreeMap::from([(
        "vendored".to_owned(),
        "detected LicenseRef-x -- accepted 2026-09-18".to_owned(),
    )]);
    render_report(&ReportInput {
        project: Some("demo"),
        generated: "2026-11-22 by trustedlicenses 0.4.0",
        read_from: "`uv.lock`",
        from_lock: false,
        policy_file: "pyproject.toml",
        policy,
        detected,
        ignored_reasons: &reasons,
    })
}

fn categories_policy() -> Policy {
    Policy {
        allowed_categories: set(&["Permissive", "Copyleft Limited"]),
        accepted_licenses: BTreeMap::from([("gplpkg".to_owned(), set(&["GPL-3.0-only"]))]),
        ignored_packages: set(&["vendored"]),
        use_case: Some(UseCase::Internal),
        ..Policy::default()
    }
}

fn detected() -> Vec<DistributionLicence> {
    vec![
        licence("requests", &["Apache-2.0"]),
        licence("certifi", &["MPL-2.0"]),
        licence("scipy", &["BSD-3-Clause", "GPL-3.0-or-later"]),
        licence("gplpkg", &["GPL-3.0-only"]),
        licence("agplpkg", &["AGPL-3.0-only"]),
        licence("bare", &[]),
    ]
}

#[test]
fn states_what_is_accepted_and_why() {
    let policy = categories_policy();
    let report = render(Some(&policy), &detected());
    assert!(
        report.starts_with("# License policy report: demo\n"),
        "{report}"
    );
    assert!(report.contains("- **Built for:** internal tooling or pipelines"));
    assert!(
        report.contains("- **Result:** 4 of 6 checked packages pass; 2 don't"),
        "{report}"
    );
    assert!(report.contains("every license in these categories: `Copyleft Limited`, `Permissive`."));
    assert!(
        report.contains("| MPL-2.0 | Copyleft Limited | 1: certifi |"),
        "{report}"
    );
    // scipy passes on BSD-3-Clause; the GPL text it bundles isn't what the policy accepts.
    assert!(
        report.contains("| BSD-3-Clause | Permissive | 1: scipy |"),
        "{report}"
    );
    assert!(!report.contains("| GPL-3.0-or-later |"), "{report}");
    assert!(report
        .contains("| gplpkg | GPL-3.0-only for this package only (`accepted-licenses`) | — |"));
    assert!(report.contains(
        "| vendored | listed in `ignored-packages`, not installed | detected LicenseRef-x -- accepted 2026-09-18 |"
    ));
    assert!(report.contains("not legal advice"));
}

#[test]
fn lists_what_could_be_accepted_but_isnt() {
    let policy = categories_policy();
    let report = render(Some(&policy), &detected());
    assert!(report.contains("## What we could accept but don't"));
    assert!(report
        .contains("| agplpkg | AGPL-3.0-only | Copyleft | license not allowed by the policy |"));
    assert!(
        report.contains("| bare | — | — | no license found |"),
        "{report}"
    );
    // Copyleft Limited is allowed, so its outliers are flagged; Copyleft isn't, so Parity isn't.
    assert!(
        report.contains("| RPL-1.5 | Copyleft Limited |"),
        "{report}"
    );
    assert!(!report.contains("| Parity-7.0.0 |"), "{report}");
}

#[test]
fn a_pinned_policy_names_its_licenses_and_flags_no_category_outliers() {
    let policy = Policy {
        allowed_licenses: set(&["Apache-2.0", "MPL-2.0"]),
        ..Policy::default()
    };
    let found = [
        licence("requests", &["Apache-2.0"]),
        licence("certifi", &["MPL-2.0"]),
    ];
    let report = render(Some(&policy), &found);
    assert!(report.contains("The policy is **pinned**"), "{report}");
    assert!(report.contains("`Apache-2.0`, `MPL-2.0`"), "{report}");
    assert!(report.contains("- **Built for:** not recorded"), "{report}");
    assert!(!report.contains("could accept but don't"), "{report}");
}

#[test]
fn without_a_policy_it_lists_what_was_found() {
    let report = render(None, &detected());
    assert!(report.contains("No policy is configured yet"), "{report}");
    assert!(
        report.contains("| AGPL-3.0-only | Copyleft | 1: agplpkg |"),
        "{report}"
    );
    assert!(report.contains("No license detected: bare."), "{report}");
}

#[test]
fn every_license_flagged_for_individual_review_has_a_category() {
    for (id, _) in CHECK_INDIVIDUALLY {
        assert!(!categories_for([id]).is_empty(), "{id}");
    }
}

#[test]
fn counts_installed_ignored_packages_and_says_doesnt_for_one() {
    let policy = Policy {
        allowed_categories: set(&["Permissive"]),
        ignored_packages: set(&["vendored"]),
        ..Policy::default()
    };
    let found = [
        licence("requests", &["Apache-2.0"]),
        licence("gplpkg", &["GPL-3.0-only"]),
        licence("vendored", &["LicenseRef-x"]),
    ];
    let report = render(Some(&policy), &found);
    assert!(
        report.contains(
            "- **Result:** 1 of 2 checked packages pass; 1 doesn't (1 more in `ignored-packages` aren't checked)"
        ),
        "{report}"
    );
    assert!(
        report.contains("| vendored | not checked at all (`ignored-packages`) |"),
        "{report}"
    );
}

#[test]
fn flags_outliers_listed_in_allowed_licenses_as_accepted() {
    let policy = Policy {
        allowed_categories: set(&["Copyleft Limited"]),
        allowed_licenses: set(&["EUPL-1.2", "MIT"]),
        ..Policy::default()
    };
    let found = [licence("eupkg", &["EUPL-1.2"])];
    let report = render(Some(&policy), &found);
    let accepted = report
        .split("## What we could accept but don't")
        .next()
        .expect("section");
    assert!(
        accepted.contains("These allowed licenses ask more than their category suggests"),
        "{report}"
    );
    assert!(accepted.contains("| EUPL-1.2 | covers"), "{report}");
    assert!(accepted.contains("| yes: eupkg |"), "{report}");
    // Not listed twice: it's accepted, not merely let in by its category.
    assert_eq!(report.matches("| EUPL-1.2 | covers").count(), 1, "{report}");
    assert!(
        !report.contains("| EUPL-1.2 | Copyleft Limited | covers"),
        "{report}"
    );
    assert_eq!(needs_individual_check("MIT"), None);
}
