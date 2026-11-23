//! A Markdown summary of a project's license policy, for whoever reviews it: what is
//! accepted and why, and what the policy could let in but doesn't today.

use crate::config::UseCase;
use crate::detection::{categories_for, DistributionLicence};
use crate::policy::{effective_result, is_allowed, reevaluate, Policy, PolicyException};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// Licenses whose category understates what they ask, with why. Kept in step with the
/// "Licenses to check individually" table in docs/choosing-a-policy.md, which cites the
/// clauses.
const CHECK_INDIVIDUALLY: [(&str, &str); 10] = [
    (
        "RPL-1.5",
        "internal use within your organisation counts as deploying it",
    ),
    (
        "APSL-2.0",
        "providing a service with modified code requires releasing its source",
    ),
    (
        "RPSL-1.0",
        "using it to provide services to others brings in its copyleft",
    ),
    (
        "EUPL-1.2",
        "covers \"Communication\" as well as distribution; reach to hosting is disputed",
    ),
    (
        "QPL-1.0",
        "software that links with it must ship with its source when distributed",
    ),
    (
        "CECILL-2.1",
        "modules in the same address space count as contributions",
    ),
    (
        "CC-BY-SA-4.0",
        "a content license with no notion of linking; share-alike applies to adaptations",
    ),
    (
        "Parity-7.0.0",
        "software you develop, operate or analyse with it must be contributed",
    ),
    (
        "OSL-3.0",
        "use over a network by others counts like distribution",
    ),
    (
        "CPAL-1.0",
        "use over a network by others counts like distribution",
    ),
];

/// Why `id` asks more than its category suggests, if it's one of those licenses.
#[must_use]
pub fn needs_individual_check(id: &str) -> Option<&'static str> {
    CHECK_INDIVIDUALLY
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, why)| *why)
}

fn in_use_cell(in_use: &BTreeMap<String, BTreeSet<String>>, id: &str) -> String {
    in_use.get(id).map_or_else(
        || "no".to_owned(),
        |packages| format!("yes: {}", joined(packages)),
    )
}

const CHOOSING_URL: &str = "https://trustedlicenses.readthedocs.io/en/latest/choosing-a-policy/";
const DISCLAIMER_URL: &str = "https://github.com/w-martin/trustedlicenses#legal-disclaimer";

/// Everything the report states, gathered by the caller.
pub struct ReportInput<'a> {
    pub project: Option<&'a str>,
    /// e.g. `2026-11-22 by trustedlicenses 0.4.0`.
    pub generated: &'a str,
    /// What was audited, as Markdown, e.g. `` `uv.lock` `` or `the installed environment`.
    pub read_from: &'a str,
    /// Audited from a lock file rather than an installed environment.
    pub from_lock: bool,
    /// Where the policy lives, e.g. `pyproject.toml`.
    pub policy_file: &'a str,
    pub policy: Option<&'a Policy>,
    pub detected: &'a [DistributionLicence],
    /// `ignored-packages` entry -> the reason recorded beside it.
    pub ignored_reasons: &'a BTreeMap<String, String>,
}

fn use_case_label(use_case: UseCase) -> &'static str {
    match use_case {
        UseCase::Internal => "internal tooling or pipelines",
        UseCase::OpenSource => "an open-source package or tool",
        UseCase::Product => "a product shipped to customers or hosted for them",
    }
}

fn joined<'a>(items: impl IntoIterator<Item = &'a String>) -> String {
    items
        .into_iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn code_list<'a>(items: impl IntoIterator<Item = &'a String>) -> String {
    items
        .into_iter()
        .map(|item| format!("`{item}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// License -> the packages it lets pass.
fn licenses_in_use(
    detected: &[DistributionLicence],
    policy: &Policy,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut in_use: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for result in detected
        .iter()
        .filter(|result| !policy.ignored_packages.contains(&result.name))
        .map(|result| effective_result(result, policy))
        .filter(|result| is_allowed(result, policy))
    {
        for key in result.keys.iter().filter(|key| {
            policy.allowed_licenses.contains(*key)
                || !categories_for([key.as_str()]).is_disjoint(&policy.allowed_categories)
        }) {
            in_use
                .entry(key.clone())
                .or_default()
                .insert(result.name.clone());
        }
    }
    in_use
}

fn license_table(out: &mut String, licenses: &BTreeMap<String, BTreeSet<String>>) {
    let _ = writeln!(out, "| License | Category | Packages |");
    let _ = writeln!(out, "|---|---|---|");
    for (license, packages) in licenses {
        let category = joined(&categories_for([license.as_str()]));
        let _ = writeln!(
            out,
            "| {license} | {} | {}: {} |",
            if category.is_empty() {
                "—"
            } else {
                &category
            },
            packages.len(),
            joined(packages)
        );
    }
}

fn why_failing(failure: &DistributionLicence) -> &'static str {
    if failure.unreadable {
        "license couldn't be read"
    } else if failure.keys.is_empty() && failure.declares_license {
        "a license is declared but couldn't be identified"
    } else if failure.keys.is_empty() {
        "no license found"
    } else {
        "license not allowed by the policy"
    }
}

fn header(out: &mut String, input: &ReportInput<'_>) {
    let _ = writeln!(
        out,
        "# License policy report{}\n",
        input
            .project
            .map(|name| format!(": {name}"))
            .unwrap_or_default()
    );
    let _ = writeln!(out, "- **Generated:** {}", input.generated);
    let _ = writeln!(out, "- **Packages read from:** {}", input.read_from);
    let _ = writeln!(out, "- **Policy:** `{}`", input.policy_file);
    let use_case = input.policy.and_then(|policy| policy.use_case);
    let _ = writeln!(
        out,
        "- **Built for:** {}",
        use_case.map_or("not recorded (`use-case` isn't set)", use_case_label)
    );
}

fn unconfigured(out: &mut String, detected: &[DistributionLicence]) {
    let _ = writeln!(
        out,
        "\nNo policy is configured yet, so nothing is accepted or rejected. These are the \
         licenses found.\n"
    );
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut without: BTreeSet<String> = BTreeSet::new();
    for result in detected {
        if result.keys.is_empty() {
            without.insert(result.name.clone());
        }
        for key in &result.keys {
            found
                .entry(key.clone())
                .or_default()
                .insert(result.name.clone());
        }
    }
    license_table(out, &found);
    if !without.is_empty() {
        let _ = writeln!(out, "\nNo license detected: {}.", joined(&without));
    }
}

/// Render the report as Markdown.
#[must_use]
pub fn render_report(input: &ReportInput<'_>) -> String {
    let mut out = String::new();
    header(&mut out, input);
    let Some(policy) = input.policy else {
        unconfigured(&mut out, input.detected);
        footer(&mut out);
        return out;
    };
    let result = reevaluate(input.detected, policy);
    let passing = result.checked - result.failures.len();
    let failing = match result.failures.len() {
        0 => String::new(),
        1 => "; 1 doesn't".to_owned(),
        n => format!("; {n} don't"),
    };
    let installed: BTreeSet<&String> = input.detected.iter().map(|d| &d.name).collect();
    let ignored = policy
        .ignored_packages
        .iter()
        .filter(|name| installed.contains(name))
        .count();
    let ignored = match ignored {
        0 => String::new(),
        n => format!(" ({n} more in `ignored-packages` aren't checked)"),
    };
    let _ = writeln!(
        out,
        "- **Result:** {passing} of {} checked packages pass{failing}{ignored}",
        result.checked
    );

    let _ = writeln!(out, "\n## What we accept\n");
    if policy.allowed_categories.is_empty() {
        let _ = writeln!(
            out,
            "The policy is **pinned**: it allows exactly these licenses, for any package. A \
             license new to the project fails until someone accepts it.\n\n{}\n",
            code_list(&policy.allowed_licenses)
        );
    } else {
        let _ = writeln!(
            out,
            "The policy allows every license in these categories: {}.",
            code_list(&policy.allowed_categories)
        );
        if !policy.allowed_licenses.is_empty() {
            let _ = writeln!(
                out,
                "It also allows these licenses for any package: {}.",
                code_list(&policy.allowed_licenses)
            );
        }
        let _ = writeln!(out);
    }
    let in_use = licenses_in_use(input.detected, policy);
    if !in_use.is_empty() {
        let _ = writeln!(out, "Licenses in use under the policy:\n");
        license_table(&mut out, &in_use);
    }
    let listed: Vec<(&String, &str)> = policy
        .allowed_licenses
        .iter()
        .filter_map(|id| needs_individual_check(id).map(|why| (id, why)))
        .collect();
    if !listed.is_empty() {
        let _ = writeln!(
            out,
            "\nThese allowed licenses ask more than their category suggests; see \
             [Choosing a policy]({CHOOSING_URL}#licenses-to-check-individually).\n"
        );
        let _ = writeln!(out, "| License | Why to look closer | In use |");
        let _ = writeln!(out, "|---|---|---|");
        for (id, why) in listed {
            let _ = writeln!(out, "| {id} | {why} | {} |", in_use_cell(&in_use, id));
        }
    }

    exceptions(
        &mut out,
        policy,
        &result.exceptions,
        input.ignored_reasons,
        &installed,
        input.from_lock,
    );
    not_accepted(&mut out, policy, &result.failures, &in_use);
    footer(&mut out);
    out
}

fn exceptions(
    out: &mut String,
    policy: &Policy,
    excepted: &[PolicyException],
    reasons: &BTreeMap<String, String>,
    installed: &BTreeSet<&String>,
    from_lock: bool,
) {
    if excepted.is_empty() && policy.ignored_packages.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "\n### Exceptions\n\nThese packages pass only because the policy names them.\n"
    );
    let _ = writeln!(out, "| Package | Accepted as | Recorded reason |");
    let _ = writeln!(out, "|---|---|---|");
    for exception in excepted {
        match exception {
            PolicyException::AcceptedLicense { package, licenses } => {
                let _ = writeln!(
                    out,
                    "| {package} | {} for this package only (`accepted-licenses`) | — |",
                    joined(licenses)
                );
            }
            PolicyException::Unlicensed { package } => {
                let _ = writeln!(out, "| {package} | no license (`allow-unlicensed`) | — |");
            }
        }
    }
    for package in &policy.ignored_packages {
        let status = if installed.contains(package) {
            "not checked at all (`ignored-packages`)"
        } else if from_lock {
            "listed in `ignored-packages`, not in the lock file"
        } else {
            "listed in `ignored-packages`, not installed"
        };
        let _ = writeln!(
            out,
            "| {package} | {status} | {} |",
            reasons.get(package).map_or("—", String::as_str)
        );
    }
}

fn not_accepted(
    out: &mut String,
    policy: &Policy,
    failures: &[DistributionLicence],
    in_use: &BTreeMap<String, BTreeSet<String>>,
) {
    let review: Vec<(&str, &str, String)> = CHECK_INDIVIDUALLY
        .iter()
        .filter_map(|(id, why)| {
            let categories = categories_for([*id]);
            (!categories.is_disjoint(&policy.allowed_categories)
                && !policy.allowed_licenses.contains(*id))
            .then(|| (*id, *why, joined(&categories)))
        })
        .collect();
    if failures.is_empty() && review.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n## What we could accept but don't\n");
    if !failures.is_empty() {
        let _ = writeln!(
            out,
            "These packages fail the policy today. Each could be accepted on its own \
             (`accepted-licenses`) once someone has checked what its license asks.\n"
        );
        let _ = writeln!(out, "| Package | Detected | Category | Why it fails |");
        let _ = writeln!(out, "|---|---|---|---|");
        for failure in failures {
            let detected = if failure.keys.is_empty() {
                "—".to_owned()
            } else {
                joined(&failure.keys)
            };
            let category = if failure.categories.is_empty() {
                "—".to_owned()
            } else {
                joined(&failure.categories)
            };
            let _ = writeln!(
                out,
                "| {} | {detected} | {category} | {} |",
                failure.name,
                why_failing(failure)
            );
        }
        let _ = writeln!(out);
    }
    if !review.is_empty() {
        let _ = writeln!(
            out,
            "The allowed categories would also let in these licenses, which ask more than \
             their category suggests. Pinning the policy (`trustedlicenses pin`) stops a new \
             one passing unnoticed. See [Choosing a policy]({CHOOSING_URL}#licenses-to-check-individually).\n"
        );
        let _ = writeln!(out, "| License | Category | Why to look closer | In use |");
        let _ = writeln!(out, "|---|---|---|---|");
        for (id, why, category) in review {
            let _ = writeln!(
                out,
                "| {id} | {category} | {why} | {} |",
                in_use_cell(in_use, id)
            );
        }
    }
}

fn footer(out: &mut String) {
    let _ = writeln!(
        out,
        "\n---\n\nGenerated by trustedlicenses from each package's declared metadata and \
         bundled license files. This is a technical summary to support a review, not legal \
         advice; see the [legal disclaimer]({DISCLAIMER_URL})."
    );
}

#[cfg(test)]
mod tests;
