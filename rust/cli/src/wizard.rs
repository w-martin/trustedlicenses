//! Interactive setup: guide a user through configuring a policy, with explanations.
//!
//! Two independent flows:
//!
//! - [`Wizard::run`]: initial `allowed-categories` setup, offered when no policy is
//!   configured yet.
//! - [`Wizard::review_failures`]: walks a failing check's failures one at a time, offering
//!   to ignore each, allow its category, or, where a free-text correction is available,
//!   trust that correction (for the package, for that exact text anywhere, or project-wide
//!   if enough failures would actually pass once it is enabled).
//!
//! Both run only when the session looks interactive; neither launches on its own in CI,
//! pre-commit or piped input. Every prompt is time-boxed (see [`crate::prompt`]), and a
//! timeout ends either flow the way a declined one does.

use crate::context::{Color, Style};
use crate::prompt::{timeout_notice, PromptError, Prompter};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use trustedlicenses_core::config::{add_to_policy, write_policy, CorrectionTrust, PolicyAdditions};
use trustedlicenses_core::detection::{categories_for, DistributionLicence};
use trustedlicenses_core::index::{audit_package, format_audit, AuditOptions, Client};
use trustedlicenses_core::index_discovery::{discover_index, redact_url, DiscoveryContext};
use trustedlicenses_core::policy::{format_failure, Policy, PolicyResult};

/// What a wizard needs from the outside world beyond the terminal.
pub struct Services<'a> {
    pub client: &'a dyn Client,
    pub env: &'a HashMap<String, String>,
}

pub trait Wizard {
    /// Offer guided setup for a project with no policy, given what was detected. Returns the
    /// file written, or `None` when nothing was written.
    ///
    /// # Errors
    ///
    /// [`PromptError::Aborted`] when input ends mid-flow.
    fn run(
        &mut self,
        io: &mut dyn Prompter,
        pyproject: &Path,
        detected: &[DistributionLicence],
    ) -> Result<Option<PathBuf>, PromptError>;

    /// Offer to review failures and record decisions in `policy_path`. Returns whether the
    /// policy file changed.
    ///
    /// # Errors
    ///
    /// [`PromptError::Aborted`] when input ends mid-flow.
    fn review_failures(
        &mut self,
        io: &mut dyn Prompter,
        services: &Services<'_>,
        policy_path: &Path,
        result: &PolicyResult,
        policy: &Policy,
    ) -> Result<bool, PromptError>;
}

/// No interactive flows: behaves as if the user always declines.
pub struct NoWizard;

impl Wizard for NoWizard {
    fn run(
        &mut self,
        _io: &mut dyn Prompter,
        _pyproject: &Path,
        _detected: &[DistributionLicence],
    ) -> Result<Option<PathBuf>, PromptError> {
        Ok(None)
    }

    fn review_failures(
        &mut self,
        _io: &mut dyn Prompter,
        _services: &Services<'_>,
        _path: &Path,
        _result: &PolicyResult,
        _policy: &Policy,
    ) -> Result<bool, PromptError> {
        Ok(false)
    }
}

// (category, explanation, default answer): the vocabulary the docs and examples already
// treat as the common case. The defaults mirror the
// `allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]` example.
const PRIMARY_CATEGORIES: [(&str, &str, bool); 4] = [
    (
        "Permissive",
        "MIT, BSD, Apache-2.0, ISC, ... -- minimal restrictions: use, modify, and redistribute freely, \
         usually with just an attribution/copyright notice.",
        true,
    ),
    (
        "Public Domain",
        "CC0, Unlicense, ... -- copyright is waived entirely. No restrictions at all.",
        true,
    ),
    (
        "Copyleft Limited",
        "LGPL, MPL-2.0, ... -- changes to the licensed code itself must be shared back, but you can still \
         use it inside a project under a different license (e.g. dynamic linking is fine). Doesn't \
         require your whole project to adopt the same license.",
        true,
    ),
    (
        "Copyleft",
        "GPL, AGPL, ... -- a much bigger commitment: distributing a work that includes this code \
         generally requires your entire project to also be released under a compatible copyleft license.",
        false,
    ),
];

/// Above this many matches in one category, list a count only: naming every package stops
/// being skimmable.
const NAME_INDIVIDUALLY_UP_TO: usize = 2;

/// Below this many failures a correction would resolve, per-case pinning is the expected
/// path; at or above it, offering project-wide correction saves repetitive pinning.
const OFFER_BLANKET_CORRECTION_AT: usize = NAME_INDIVIDUALLY_UP_TO;

const ACCEPT_LICENSE: &str = "l";
const ALLOW_UNLICENSED: &str = "u";
const IGNORE: &str = "i";
const ALLOW_CATEGORY: &str = "a";
const BULK_IGNORE: &str = "b";
const VERIFY_PACKAGE: &str = "v";
const TRUST_TEXT: &str = "t";
const CHECK_INDEX: &str = "c";
const SKIP: &str = "s";
const QUIT: &str = "q";

/// Describe how many detected packages still need one category allowed, and which.
///
/// A package with more than one detected category (its own BSD-3-Clause grant alongside a
/// vendored GPL notice) needs only one of them allowed. Counting it against every category
/// it touches would make allowing Copyleft look mandatory for a package Permissive already
/// covers, so a package covered by an earlier answer is excluded outright.
fn category_summary(
    detected: &[DistributionLicence],
    category: &str,
    already_allowed: &BTreeSet<String>,
) -> String {
    let matches: Vec<&DistributionLicence> = detected
        .iter()
        .filter(|result| {
            result.categories.contains(category) && result.categories.is_disjoint(already_allowed)
        })
        .collect();
    if matches.is_empty() {
        return "(none detected in your environment)".to_owned();
    }
    if matches.len() <= NAME_INDIVIDUALLY_UP_TO {
        let named = matches
            .iter()
            .map(|result| {
                let keys = if result.keys.is_empty() {
                    "unknown".to_owned()
                } else {
                    result.keys.iter().cloned().collect::<Vec<_>>().join(", ")
                };
                format!("{} ({keys})", result.name)
            })
            .collect::<Vec<_>>()
            .join("; ");
        return format!("({} detected: {named})", matches.len());
    }
    format!("({} detected)", matches.len())
}

/// Decisions accumulated across one review, written once at the end. Ordered like a
/// Python dict: setting an existing key keeps its position.
#[derive(Default)]
struct ReviewDecisions {
    ignored: Vec<(String, String)>,
    /// Package -> the licenses accepted for that package alone.
    accepted: Vec<(String, Vec<String>)>,
    allow_unlicensed: bool,
    allowed_categories: BTreeSet<String>,
    verified_packages: Vec<(String, (String, String))>,
    verified_statements: Vec<(String, String)>,
    trust_corrected_licenses: bool,
}

fn set_ordered<V>(entries: &mut Vec<(String, V)>, key: String, value: V) {
    match entries.iter_mut().find(|(existing, _)| *existing == key) {
        Some(slot) => slot.1 = value,
        None => entries.push((key, value)),
    }
}

impl ReviewDecisions {
    fn has_decisions(&self) -> bool {
        !(self.ignored.is_empty()
            && self.accepted.is_empty()
            && !self.allow_unlicensed
            && self.allowed_categories.is_empty()
            && self.verified_packages.is_empty()
            && self.verified_statements.is_empty()
            && !self.trust_corrected_licenses)
    }
}

/// The `YYYY-MM-DD` date `days` days after 1970-01-01 (Howard Hinnant's civil-from-days).
fn civil_date(days: i64) -> String {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_phase = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_phase + 2) / 5 + 1;
    let month = if month_phase < 10 {
        month_phase + 3
    } else {
        month_phase - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Today's UTC date, for the "accepted <date>" reason on a new ignored-packages entry.
fn today_utc() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    civil_date(i64::try_from(seconds / 86_400).unwrap_or(0))
}

fn reason_for(failure: &DistributionLicence, today: &str) -> String {
    if failure.keys.is_empty() {
        format!("no license detected -- accepted {today}")
    } else {
        format!(
            "detected {} -- accepted {today}",
            failure.keys.iter().cloned().collect::<Vec<_>>().join(", ")
        )
    }
}

/// The `(statement, spdx id)` pair to show or pin for a failure with more than one: the
/// lexicographically first, since a sub-menu for an edge case isn't worth it.
fn primary_suggestion(failure: &DistributionLicence) -> Option<&(String, String)> {
    failure.suggested.iter().next()
}

fn failure_options(failure: &DistributionLicence) -> String {
    let mut options = Vec::new();
    if !failure.keys.is_empty() {
        let licenses = failure.keys.iter().cloned().collect::<Vec<_>>().join(", ");
        options.push(format!(
            "[{ACCEPT_LICENSE}]ccept {licenses} for this package only"
        ));
    }
    if failure.is_unlicensed() {
        options.push(format!(
            "[{ALLOW_UNLICENSED}]nlicensed packages are fine (every package with no license)"
        ));
    }
    options.push(format!(
        "[{IGNORE}]gnore this package (trusts the package, whatever its license)"
    ));
    if failure.categories.is_empty() {
        options.push(format!(
            "[{BULK_IGNORE}]ulk-ignore every remaining undetectable package"
        ));
    } else {
        let categories = failure
            .categories
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        options.push(format!(
            "[{ALLOW_CATEGORY}]llow \"{categories}\" (every package in it, not just this one)"
        ));
    }
    if let Some((statement, spdx_id)) = primary_suggestion(failure) {
        options.push(format!(
            "[{VERIFY_PACKAGE}]erify this package as {spdx_id} (re-checked if its text changes)"
        ));
        options.push(format!(
            "[{TRUST_TEXT}]rust \"{statement}\" -> {spdx_id} for any package"
        ));
    }
    if failure.keys.is_empty() {
        options.push(format!(
            "[{CHECK_INDEX}]heck the package index for a version that ships a license"
        ));
    }
    options.push(format!("[{SKIP}]kip"));
    options.push(format!("[{QUIT}]uit reviewing"));
    format!("  {}", options.join("; "))
}

/// Apply one prompted choice, returning `(quit_requested, bulk_ignore_requested)`.
fn apply_choice(
    io: &mut dyn Prompter,
    choice: &str,
    failure: &DistributionLicence,
    today: &str,
    decisions: &mut ReviewDecisions,
) -> (bool, bool) {
    if choice == QUIT {
        return (true, false);
    }
    if choice == BULK_IGNORE && failure.categories.is_empty() {
        set_ordered(
            &mut decisions.ignored,
            failure.name.clone(),
            reason_for(failure, today),
        );
        return (false, true);
    }
    let suggestion = primary_suggestion(failure);
    if choice == ACCEPT_LICENSE && !failure.keys.is_empty() {
        set_ordered(
            &mut decisions.accepted,
            failure.name.clone(),
            failure.keys.iter().cloned().collect(),
        );
    } else if choice == ALLOW_UNLICENSED && failure.is_unlicensed() {
        decisions.allow_unlicensed = true;
    } else if choice == IGNORE {
        set_ordered(
            &mut decisions.ignored,
            failure.name.clone(),
            reason_for(failure, today),
        );
    } else if choice == ALLOW_CATEGORY && !failure.categories.is_empty() {
        decisions
            .allowed_categories
            .extend(failure.categories.iter().cloned());
    } else if choice == VERIFY_PACKAGE && suggestion.is_some() {
        if let Some(pair) = suggestion {
            set_ordered(
                &mut decisions.verified_packages,
                failure.name.clone(),
                pair.clone(),
            );
        }
    } else if choice == TRUST_TEXT && suggestion.is_some() {
        if let Some((statement, spdx_id)) = suggestion {
            set_ordered(
                &mut decisions.verified_statements,
                statement.clone(),
                spdx_id.clone(),
            );
        }
    } else if choice != SKIP {
        io.secho(
            &format!(
                "  \"{choice}\" isn't one of the options above -- skipping {}.",
                failure.name
            ),
            Style {
                color: Some(Color::Yellow),
                ..Style::default()
            },
        );
    }
    (false, false)
}

fn summarize_and_write(
    io: &mut dyn Prompter,
    source: &Path,
    decisions: &ReviewDecisions,
) -> Result<bool, PromptError> {
    if !decisions.has_decisions() {
        io.echo("\nNothing selected -- nothing to write.");
        return Ok(false);
    }
    io.secho("\nAbout to update:", Style::bold(Color::Green));
    if decisions.trust_corrected_licenses {
        io.echo("  enable free-text license correction project-wide");
    }
    for category in &decisions.allowed_categories {
        io.echo(&format!("  allow category \"{category}\""));
    }
    if decisions.allow_unlicensed {
        io.echo("  allow packages that have no license (allow-unlicensed = true)");
    }
    let mut accepted = decisions.accepted.clone();
    accepted.sort();
    for (name, licenses) in accepted {
        io.echo(&format!("  accept {} for {name} only", licenses.join(", ")));
    }
    let sorted = |entries: &[(String, String)]| {
        let mut entries = entries.to_vec();
        entries.sort();
        entries
    };
    for (name, reason) in sorted(&decisions.ignored) {
        io.echo(&format!("  ignore {name}  # {reason}"));
    }
    let mut packages = decisions.verified_packages.clone();
    packages.sort();
    for (name, (statement, spdx_id)) in packages {
        io.echo(&format!(
            "  verify {name} as {spdx_id} (text: \"{statement}\")"
        ));
    }
    for (statement, spdx_id) in sorted(&decisions.verified_statements) {
        io.echo(&format!(
            "  trust \"{statement}\" -> {spdx_id} for any package"
        ));
    }
    io.echo(&format!("\n  -> {}", source.display()));

    if !io.confirm("\nWrite these changes?", true)? {
        return Ok(false);
    }
    let additions = PolicyAdditions {
        ignored_packages: decisions
            .ignored
            .iter()
            .map(|(name, _)| name.clone())
            .collect(),
        allowed_categories: decisions.allowed_categories.iter().cloned().collect(),
        accepted_licenses: decisions
            .accepted
            .iter()
            .flat_map(|(name, licenses)| {
                licenses
                    .iter()
                    .map(move |license| (name.clone(), license.clone()))
            })
            .collect(),
        allow_unlicensed: decisions.allow_unlicensed,
        reasons: decisions.ignored.iter().cloned().collect(),
        trust: Some(CorrectionTrust {
            enabled: decisions.trust_corrected_licenses.then_some(true),
            verified_packages: decisions.verified_packages.clone(),
            verified_statements: decisions.verified_statements.clone(),
        }),
    };
    if let Err(error) = add_to_policy(source, &additions) {
        io.secho(
            &format!("\ntrustedlicenses: {error}"),
            Style::bold(Color::Red),
        );
        return Ok(false);
    }
    io.secho(
        &format!("\nUpdated {}.", source.display()),
        Style::bold(Color::Green),
    );
    Ok(true)
}

/// Whether trusting any of a failure's suggestions would land it in an allowed category.
/// Having a suggestion is not enough: the corrected id must map to a category the policy
/// accepts, exactly as a declared id would. Otherwise the blanket offer would overcount.
fn would_pass_if_corrected(failure: &DistributionLicence, policy: &Policy) -> bool {
    let ids: Vec<&str> = failure
        .suggested
        .iter()
        .map(|(_, id)| id.as_str())
        .collect();
    !categories_for(ids).is_disjoint(&policy.allowed_categories)
}

fn offer_blanket_correction(
    io: &mut dyn Prompter,
    remaining: Vec<DistributionLicence>,
    decisions: &mut ReviewDecisions,
    policy: &Policy,
) -> Result<Vec<DistributionLicence>, PromptError> {
    let correctable: Vec<&DistributionLicence> = remaining
        .iter()
        .filter(|failure| would_pass_if_corrected(failure, policy))
        .collect();
    if correctable.len() < OFFER_BLANKET_CORRECTION_AT {
        return Ok(remaining);
    }
    let named = if correctable.len() <= NAME_INDIVIDUALLY_UP_TO {
        correctable
            .iter()
            .map(|failure| failure.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        format!("{} packages", correctable.len())
    };
    let accepted = io.confirm(
        &format!(
            "\n{} failure(s) would resolve if free-text license correction were enabled project-wide \
             ({named}). Enable it now?",
            correctable.len()
        ),
        false,
    )?;
    if !accepted {
        return Ok(remaining);
    }
    decisions.trust_corrected_licenses = true;
    let resolved: Vec<String> = correctable
        .iter()
        .map(|failure| failure.name.clone())
        .collect();
    Ok(remaining
        .into_iter()
        .filter(|failure| !resolved.contains(&failure.name))
        .collect())
}

/// Ask the index whether a newer release of one failing package ships a license.
///
/// Purely informational: writes nothing. The index, and why it was chosen, is confirmed
/// before anything is sent, since guessing wrong could send an internal package's name to a
/// public host.
fn run_index_check(
    io: &mut dyn Prompter,
    services: &Services<'_>,
    failure: &DistributionLicence,
    project_dir: &Path,
) -> Result<(), PromptError> {
    let discovery = DiscoveryContext {
        env: services.env.clone(),
        home: services.env.get("HOME").map(PathBuf::from),
        include_system: true,
    };
    let choice = discover_index(project_dir, &failure.name, &discovery);
    let shown = redact_url(&choice.url);
    if !io.confirm(
        &format!(
            "\nAsk {shown} (from {}) about \"{}\"? Only its name is sent.",
            choice.origin, failure.name
        ),
        false,
    )? {
        return Ok(());
    }
    match audit_package(
        services.client,
        &choice.url,
        &failure.name,
        &failure.version,
        AuditOptions::default(),
    ) {
        Ok(audit) => io.echo(&format_audit(&audit)),
        Err(error) => io.secho(
            &format!("  {error}"),
            Style {
                color: Some(Color::Yellow),
                ..Style::default()
            },
        ),
    }
    Ok(())
}

/// Show one failure's menu and read the answer, re-asking after an informational index check.
fn ask_choice(
    io: &mut dyn Prompter,
    services: &Services<'_>,
    failure: &DistributionLicence,
    project_dir: &Path,
) -> Result<String, PromptError> {
    loop {
        io.echo(&format!("\n{}", format_failure(failure)));
        io.echo(&failure_options(failure));
        let choice = io.prompt("  Choice", SKIP)?.trim().to_lowercase();
        if choice != CHECK_INDEX || !failure.keys.is_empty() {
            return Ok(choice);
        }
        run_index_check(io, services, failure, project_dir)?;
    }
}

/// The production wizard.
#[derive(Default)]
pub struct InteractiveWizard {
    /// Fixed date for the "accepted" reason, so tests are deterministic.
    pub today: Option<String>,
}

impl InteractiveWizard {
    fn run_flow(
        io: &mut dyn Prompter,
        pyproject: &Path,
        detected: &[DistributionLicence],
    ) -> Result<Option<PathBuf>, PromptError> {
        let with_license = detected
            .iter()
            .filter(|result| !result.keys.is_empty())
            .count();
        io.echo(&format!(
            "Detected licenses for {with_license} of {} installed packages.\n",
            detected.len()
        ));

        if !io.confirm(
            "No policy configured yet -- would you like to run the guided setup?",
            true,
        )? {
            return Ok(None);
        }
        io.echo("");

        let mut allowed: Vec<String> = Vec::new();
        for (category, explanation, default) in PRIMARY_CATEGORIES {
            io.echo(&format!("{category}: {explanation}"));
            let already: BTreeSet<String> = allowed.iter().cloned().collect();
            io.echo(&format!(
                "  {}",
                category_summary(detected, category, &already)
            ));
            if io.confirm(&format!("Allow {category} licenses?"), default)? {
                allowed.push(category.to_owned());
            }
            io.echo("");
        }

        // Same principle as the summary: don't suggest a category some earlier answer
        // already covers.
        let already: BTreeSet<String> = allowed.iter().cloned().collect();
        let primary: BTreeSet<&str> = PRIMARY_CATEGORIES
            .iter()
            .map(|(name, _, _)| *name)
            .collect();
        let other_categories: BTreeSet<&String> = detected
            .iter()
            .filter(|result| result.categories.is_disjoint(&already))
            .flat_map(|result| result.categories.iter())
            .filter(|category| !primary.contains(category.as_str()))
            .collect();
        if !other_categories.is_empty() {
            let listed = other_categories
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            io.echo(&format!("Also detected in your environment: {listed}."));
            let extra = io.prompt(
                "Allow any of these too? Comma-separated exact names, or Enter to skip",
                "",
            )?;
            allowed.extend(
                extra
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned),
            );
        }

        if allowed.is_empty() {
            io.echo("\nNo categories selected -- nothing to write. Run `trustedlicenses` again when you're ready.");
            return Ok(None);
        }
        io.secho(
            &format!("\nAllowed categories: {}", allowed.join(", ")),
            Style::bold(Color::Green),
        );

        let standalone = if pyproject.is_file() {
            io.confirm(
                &format!(
                    "\nSave to a separate trustedlicenses.toml instead of adding to {}?",
                    pyproject.display()
                ),
                false,
            )?
        } else {
            io.echo(&format!(
                "\n{} doesn't exist -- writing a separate trustedlicenses.toml.",
                pyproject.display()
            ));
            true
        };

        if !io.confirm("\nWrite this configuration?", true)? {
            return Ok(None);
        }
        match write_policy(pyproject, &allowed, &[], standalone) {
            Ok(written) => {
                io.secho(
                    &format!("\nWrote policy to {}.", written.display()),
                    Style::bold(Color::Green),
                );
                Ok(Some(written))
            }
            Err(error) => {
                io.secho(
                    &format!("\ntrustedlicenses: {error}"),
                    Style::bold(Color::Red),
                );
                Ok(None)
            }
        }
    }

    fn review_flow(
        &self,
        io: &mut dyn Prompter,
        services: &Services<'_>,
        source: &Path,
        result: &PolicyResult,
        policy: &Policy,
    ) -> Result<bool, PromptError> {
        if !io.confirm(
            &format!(
                "Review these {} failing package(s) now?",
                result.failures.len()
            ),
            false,
        )? {
            return Ok(false);
        }
        let mut decisions = ReviewDecisions::default();
        let today = self.today.clone().unwrap_or_else(today_utc);
        let remaining =
            offer_blanket_correction(io, result.failures.clone(), &mut decisions, policy)?;
        let project_dir = source
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        let mut bulk_ignore_undetectable = false;
        for failure in &remaining {
            if bulk_ignore_undetectable && failure.categories.is_empty() {
                set_ordered(
                    &mut decisions.ignored,
                    failure.name.clone(),
                    reason_for(failure, &today),
                );
                continue;
            }
            if decisions.allow_unlicensed && failure.is_unlicensed() {
                continue;
            }
            let choice = ask_choice(io, services, failure, project_dir)?;
            let (quit, bulk) = apply_choice(io, &choice, failure, &today, &mut decisions);
            bulk_ignore_undetectable = bulk_ignore_undetectable || bulk;
            if quit {
                break;
            }
        }
        summarize_and_write(io, source, &decisions)
    }
}

impl Wizard for InteractiveWizard {
    fn run(
        &mut self,
        io: &mut dyn Prompter,
        pyproject: &Path,
        detected: &[DistributionLicence],
    ) -> Result<Option<PathBuf>, PromptError> {
        match Self::run_flow(io, pyproject, detected) {
            Err(PromptError::Timeout) => {
                timeout_notice(
                    io,
                    "aborting setup",
                    "(Running non-interactively? Pass --quiet to skip this wizard entirely.)",
                );
                Ok(None)
            }
            other => other,
        }
    }

    fn review_failures(
        &mut self,
        io: &mut dyn Prompter,
        services: &Services<'_>,
        policy_path: &Path,
        result: &PolicyResult,
        policy: &Policy,
    ) -> Result<bool, PromptError> {
        match self.review_flow(io, services, policy_path, result, policy) {
            Err(PromptError::Timeout) => {
                timeout_notice(io, "stopping the review", "Nothing has been written.");
                Ok(false)
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests;
