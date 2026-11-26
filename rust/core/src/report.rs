//! A Markdown summary of a project's license policy, for whoever reviews it: what is
//! accepted and why, and what the policy could let in but doesn't today.

use crate::config::UseCase;
use crate::detection::{categories_for, DistributionLicence};
use crate::policy::{
    effective_result, is_allowed, reevaluate, Policy, PolicyException, PolicyResult,
};
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
    /// Where the policy comes from, as Markdown, e.g. `` `pyproject.toml` ``; unused without
    /// a policy.
    pub policy_from: &'a str,
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

/// `#` repeated for a heading `depth` levels down.
fn heading(depth: usize) -> String {
    "#".repeat(depth)
}

/// What was audited and under which policy, as bullets.
fn details(out: &mut String, input: &ReportInput<'_>) {
    let _ = writeln!(out, "- **Packages read from:** {}", input.read_from);
    let built: Vec<String> = input
        .detected
        .iter()
        .filter_map(|result| {
            result
                .in_tree_backend
                .as_ref()
                .map(|backend| format!("{} (`{backend}`)", result.name))
        })
        .collect();
    if !built.is_empty() {
        let _ = writeln!(
            out,
            "- **Built at install time:** {}. Each was read from a source archive whose own \
             build backend may download or generate what actually installs, so its license \
             here may not be the installed one; check what it installs.",
            built.join(", ")
        );
    }
    let Some(policy) = input.policy else {
        let _ = writeln!(out, "- **Policy:** none configured");
        return;
    };
    let _ = writeln!(out, "- **Policy:** {}", input.policy_from);
    let _ = writeln!(
        out,
        "- **Built for:** {}",
        policy
            .use_case
            .map_or("not recorded (`use-case` isn't set)", use_case_label)
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
    let _ = writeln!(
        out,
        "# License policy report{}\n",
        input
            .project
            .map(|name| format!(": {name}"))
            .unwrap_or_default()
    );
    let _ = writeln!(out, "- **Generated:** {}", input.generated);
    render_project(&mut out, input, 2);
    footer(&mut out);
    out
}

/// One project's details and findings, with its sections as headings `depth` levels down.
fn render_project(out: &mut String, input: &ReportInput<'_>, depth: usize) {
    details(out, input);
    let Some(policy) = input.policy else {
        unconfigured(out, input.detected);
        return;
    };
    let result = reevaluate(input.detected, policy);
    let _ = writeln!(out, "- **Result:** {}", result_line(input, policy, &result));

    let _ = writeln!(out, "\n{} What we accept\n", heading(depth));
    if policy.allowed_categories.is_empty() {
        let _ = writeln!(
            out,
            "The policy is **pinned**: it allows exactly these licenses, for any package. A \
             license new to the project fails until someone accepts it.\n\n{}\n",
            code_list(&policy.allowed_licenses)
        );
        if !policy.pinned_categories.is_empty() {
            let _ = writeln!(
                out,
                "Pinned from these categories: {}.\n",
                code_list(&policy.pinned_categories)
            );
        }
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
        if !policy.pinned_categories.is_empty() {
            let _ = writeln!(
                out,
                "These categories are **pinned**: {}. Only their licenses listed above are \
                 allowed, so a new one fails until someone accepts it.",
                code_list(&policy.pinned_categories)
            );
        }
        let _ = writeln!(out);
    }
    let in_use = licenses_in_use(input.detected, policy);
    if !in_use.is_empty() {
        let _ = writeln!(out, "Licenses in use under the policy:\n");
        license_table(out, &in_use);
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

    let installed: BTreeSet<&String> = input.detected.iter().map(|d| &d.name).collect();
    exceptions(
        out,
        policy,
        &result.exceptions,
        input.ignored_reasons,
        &installed,
        input.from_lock,
        depth + 1,
    );
    not_accepted(out, policy, &result.failures, &in_use, depth);
}

/// e.g. `4 of 6 checked packages pass; 2 don't (1 more in `ignored-packages` aren't checked)`.
fn result_line(input: &ReportInput<'_>, policy: &Policy, result: &PolicyResult) -> String {
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
    format!(
        "{passing} of {} checked packages pass{failing}{ignored}",
        result.checked
    )
}

fn exceptions(
    out: &mut String,
    policy: &Policy,
    excepted: &[PolicyException],
    reasons: &BTreeMap<String, String>,
    installed: &BTreeSet<&String>,
    from_lock: bool,
    depth: usize,
) {
    if excepted.is_empty() && policy.ignored_packages.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "\n{} Exceptions\n\nThese packages pass only because the policy names them.\n",
        heading(depth)
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
            PolicyException::TrustedIndex { package, index } => {
                let _ = writeln!(
                    out,
                    "| {package} | no identified license, from `{index}` (`trusted-indexes`) | — |"
                );
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
    depth: usize,
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
    let _ = writeln!(out, "\n{} What we could accept but don't\n", heading(depth));
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
             their category suggests. Pinning the category (`trustedlicenses pin --category \
             <name>`) stops a new one passing unnoticed. See [Choosing a policy]({CHOOSING_URL}#licenses-to-check-individually).\n"
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

/// One codebase in an audit: what it says about itself, or why it couldn't be read.
pub struct AuditProject<'a> {
    /// The path it was given as, e.g. `../billing`.
    pub path: &'a str,
    pub name: &'a str,
    pub outcome: Result<ReportInput<'a>, String>,
}

/// Render an audit of several codebases as Markdown: a summary row each, which licenses
/// they use between them, then each one's report.
#[must_use]
pub fn render_audit(
    generated: &str,
    fallback_policy: Option<&str>,
    projects: &[AuditProject<'_>],
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# License audit\n");
    let _ = writeln!(out, "- **Generated:** {generated}");
    let _ = writeln!(out, "- **Codebases:** {}", projects.len());
    if let Some(fallback) = fallback_policy {
        let _ = writeln!(
            out,
            "- **Policy for codebases without their own:** {fallback}"
        );
    }

    let _ = writeln!(out, "\n## Summary\n");
    let _ = writeln!(
        out,
        "| Codebase | Path | Packages read from | Policy | Packages | Result |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    for project in projects {
        let label = format!("{} | `{}`", project.name, project.path);
        match &project.outcome {
            Err(error) => {
                let _ = writeln!(
                    out,
                    "| {label} | — | — | — | couldn't be read: {} |",
                    table_cell(error)
                );
            }
            Ok(input) => {
                let (policy, result) = match input.policy {
                    None => ("none".to_owned(), "not judged".to_owned()),
                    Some(policy) => {
                        let result = reevaluate(input.detected, policy);
                        let line = if result.passed() {
                            format!("all {} pass", result.checked)
                        } else {
                            result_line(input, policy, &result)
                                .replace(" checked packages pass", " pass")
                        };
                        (input.policy_from.to_owned(), line)
                    }
                };
                let _ = writeln!(
                    out,
                    "| {label} | {} | {policy} | {} | {result} |",
                    input.read_from,
                    input.detected.len()
                );
            }
        }
    }

    across_projects(&mut out, projects);

    for project in projects {
        let _ = writeln!(out, "\n## {}\n", project.name);
        match &project.outcome {
            Err(error) => {
                let _ = writeln!(out, "- **Path:** `{}`", project.path);
                let _ = writeln!(out, "\nCouldn't be read: {error}");
            }
            Ok(input) => {
                let _ = writeln!(out, "- **Path:** `{}`", project.path);
                render_project(&mut out, input, 3);
            }
        }
    }
    footer(&mut out);
    out
}

/// Which licenses the codebases use between them, and where one fails its codebase's policy.
fn across_projects(out: &mut String, projects: &[AuditProject<'_>]) {
    let mut used: BTreeMap<String, BTreeMap<&str, usize>> = BTreeMap::new();
    let mut failing: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    const NONE: &str = "(no license detected)";
    const UNREAD: &str = "(license couldn't be read)";
    for project in projects {
        let Ok(input) = &project.outcome else {
            continue;
        };
        for result in input.detected {
            let keys: Vec<String> = if result.unreadable {
                vec![UNREAD.to_owned()]
            } else if result.keys.is_empty() {
                vec![NONE.to_owned()]
            } else {
                result.keys.iter().cloned().collect()
            };
            for key in keys {
                *used
                    .entry(key)
                    .or_default()
                    .entry(project.name)
                    .or_default() += 1;
            }
        }
        if let Some(policy) = input.policy {
            for failure in reevaluate(input.detected, policy).failures {
                let label = if failure.unreadable { UNREAD } else { NONE };
                if failure.keys.is_empty() {
                    failing
                        .entry(label.to_owned())
                        .or_default()
                        .insert(project.name);
                }
                for key in failure.keys {
                    failing.entry(key).or_default().insert(project.name);
                }
            }
        }
    }
    if used.is_empty() {
        return;
    }
    let _ = writeln!(out, "\n## Licenses across codebases\n");
    let _ = writeln!(
        out,
        "| License | Category | Used in (packages) | Fails the policy in |"
    );
    let _ = writeln!(out, "|---|---|---|---|");
    for (license, counts) in &used {
        let category = joined(&categories_for([license.as_str()]));
        let used_in = counts
            .iter()
            .map(|(name, count)| format!("{name}: {count}"))
            .collect::<Vec<_>>()
            .join("; ");
        let fails = failing.get(license).map_or_else(
            || "—".to_owned(),
            |names| names.iter().copied().collect::<Vec<_>>().join("; "),
        );
        let _ = writeln!(
            out,
            "| {license} | {} | {used_in} | {fails} |",
            if category.is_empty() {
                "—"
            } else {
                &category
            }
        );
    }
}

/// Text safe inside a Markdown table cell: one line, no column breaks.
fn table_cell(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
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
