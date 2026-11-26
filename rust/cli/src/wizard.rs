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
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use trustedlicenses_core::config::{
    add_to_policy, policy_source, rewrite_policy, write_new_policy, CorrectionTrust, NewPolicy,
    PolicyAdditions, UseCase,
};
use trustedlicenses_core::detection::{categories_for, DistributionLicence};
use trustedlicenses_core::index::{audit_package, format_audit, AuditOptions, Client};
use trustedlicenses_core::index_discovery::{discover_index, redact_url, DiscoveryContext};
use trustedlicenses_core::policy::{
    format_failure, is_public_index, pinnable_licenses, trusted_by_index, Policy, PolicyResult,
};

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

    /// Run guided setup because it was asked for, over `prior` when a policy exists: each
    /// answer defaults to what it says now. Returns the file written, or `None`.
    ///
    /// # Errors
    ///
    /// [`PromptError::Aborted`] when input ends mid-flow.
    fn setup(
        &mut self,
        _io: &mut dyn Prompter,
        _pyproject: &Path,
        _detected: &[DistributionLicence],
        _prior: Option<&Policy>,
    ) -> Result<Option<PathBuf>, PromptError> {
        Ok(None)
    }

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
        "LGPL, MPL-2.0, ... -- changes to the licensed code must be shared with anyone you \
         distribute it to; the rest of your project can keep its own license. A few licenses here \
         (RPL, APSL, EUPL, ...) also count internal or network use, so check any you see.",
        true,
    ),
    (
        "Copyleft",
        "GPL, AGPL, ... -- a much bigger commitment: distributing a work that includes this code \
         generally requires the combined work to be distributed under that license, so your own \
         code needs a compatible one.",
        false,
    ),
];

const COPYLEFT: &str = "Copyleft";
const SOURCE_AVAILABLE: &str = "Source-available";

/// Whether the code leaves the organisation, and how, decides what a copyleft license asks
/// of it; the categories themselves can't tell. Pre-wrapped: `echo` doesn't wrap, and a
/// terminal breaks mid-word.
fn copyleft_hint(use_case: UseCase) -> &'static [&'static str] {
    match use_case {
        UseCase::Internal => &[
            "For internal use: GPL has no conditions while the code stays in your organisation;",
            "AGPL does if you modify it and people use it over a network. Others here (OSL,",
            "Parity, ...) are triggered by use, so answer n and accept GPL packages one at a",
            "time in the review after the check.",
        ],
        UseCase::OpenSource => &[
            "For an open-source package: fine if your own project is GPL. Declare your license",
            "in pyproject.toml ([project.license]) and the check flags GPL version mismatches.",
        ],
        UseCase::Product => &[
            "For a product: shipping copies brings in GPL's full terms; hosting only doesn't,",
            "but AGPL does if you modify it. Answer n and accept individual packages in the",
            "review after the check.",
        ],
    }
}

/// Up to this many licenses are named when offering to pin; the rest are counted.
const NAME_PINNED_UP_TO: usize = 8;

fn abbreviated(licenses: &BTreeSet<String>) -> String {
    let named = licenses
        .iter()
        .take(NAME_PINNED_UP_TO)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    match licenses.len().saturating_sub(NAME_PINNED_UP_TO) {
        0 => named,
        rest => format!("{named} and {rest} more"),
    }
}

/// Categories whose licenses differ most in what they ask; pinning them is suggested.
const PIN_BY_DEFAULT: [&str; 2] = ["Copyleft Limited", "Copyleft"];

/// Ask, category by category, which to pin to the licenses they allow today. A category the
/// prior policy already pins keeps the licenses it's pinned to, so re-running changes nothing
/// unless asked; one newly pinned takes those its packages use today. A category with no
/// license in use and not pinned before isn't offered: pinning it would just disallow it.
fn ask_pins(
    io: &mut dyn Prompter,
    detected: &[DistributionLicence],
    allowed: &[String],
    prior: Option<&Policy>,
) -> Result<(Vec<String>, BTreeSet<String>), PromptError> {
    // The prior policy's corrections and ignored packages decide what passes today, so they
    // decide what pinning would list.
    let policy = Policy {
        allowed_categories: allowed.iter().cloned().collect(),
        ..prior.cloned().unwrap_or_default()
    };
    let offers: Vec<(&String, BTreeSet<String>, bool)> = allowed
        .iter()
        .map(|category| {
            let pinned_before =
                prior.is_some_and(|prior| prior.pinned_categories.contains(category));
            let licenses = if pinned_before {
                prior
                    .map(|prior| {
                        prior
                            .allowed_licenses
                            .iter()
                            .filter(|id| categories_for([id.as_str()]).contains(category))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                pinnable_licenses(detected, &policy, &BTreeSet::from([category.clone()]))
            };
            (category, licenses, pinned_before)
        })
        .filter(|(_, licenses, pinned_before)| *pinned_before || !licenses.is_empty())
        .collect();
    let mut pinned_categories = Vec::new();
    let mut pinned_licenses = BTreeSet::new();
    if offers.is_empty() {
        return Ok((pinned_categories, pinned_licenses));
    }
    io.echo("\nPinning a category lists the licenses it allows in your environment now, so a");
    io.echo("  license from it that's new to the project fails until you accept it. Worth it");
    io.echo("  where a category's licenses ask different things (Copyleft Limited: LGPL, MPL,");
    io.echo("  EUPL, ...); `trustedlicenses pin --category` can pin one later.");
    for (category, licenses, pinned_before) in offers {
        if pinned_before {
            let to = if licenses.is_empty() {
                "no license".to_owned()
            } else {
                abbreviated(&licenses)
            };
            io.echo(&format!("  {category}: pinned now, to {to}"));
        } else {
            let packages = detected
                .iter()
                .filter(|result| result.categories.contains(category.as_str()))
                .count();
            io.echo(&format!(
                "  {category}: {} ({packages} package(s))",
                abbreviated(&licenses)
            ));
        }
        let default = prior.map_or_else(
            || PIN_BY_DEFAULT.contains(&category.as_str()),
            |_| pinned_before,
        );
        if io.confirm(&format!("Pin {category}?"), default)? {
            pinned_categories.push(category.clone());
            pinned_licenses.extend(licenses);
        }
    }
    Ok((pinned_categories, pinned_licenses))
}

/// Offer to trust each non-PyPI index serving packages with no identifiable license, then ask
/// about any package with no license that's left. Returns `(trusted indexes, allow-unlicensed)`.
fn ask_unlicensed(
    io: &mut dyn Prompter,
    detected: &[DistributionLicence],
    prior: Option<&Policy>,
) -> Result<(Vec<String>, bool), PromptError> {
    let mut by_index: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for result in detected
        .iter()
        .filter(|result| result.keys.is_empty() && !result.unreadable)
    {
        if let Some(index) = result.index.as_deref().filter(|i| !is_public_index(i)) {
            by_index
                .entry(index)
                .or_default()
                .insert(result.name.clone());
        }
    }
    let mut trusted: Vec<String> = Vec::new();
    for (index, names) in &by_index {
        io.echo(&format!(
            "\nNo identifiable license, from {index}: {}.",
            abbreviated(names)
        ));
        let licensed = detected
            .iter()
            .filter(|result| result.index.as_deref() == Some(*index) && !result.keys.is_empty())
            .count();
        if licensed > 0 {
            io.echo(&format!(
                "  It also serves {licensed} package(s) that do have a license, so it may proxy PyPI:"
            ));
            io.echo("  trusting it would pass any unlicensed package that comes through it.");
        } else {
            io.echo(
                "  If this is your own internal index, its packages are your code: trusting it",
            );
            io.echo("  passes those with no license, and still judges any that have one.");
        }
        let default = prior.map_or(licensed == 0, |prior| {
            prior.trusted_indexes.contains(*index)
        });
        if io.confirm(
            &format!("Trust packages with no license from {index}?"),
            default,
        )? {
            trusted.push((*index).to_owned());
        }
    }
    // An index trusted before but serving nothing this run isn't asked about, so it stays.
    if let Some(prior) = prior {
        for index in &prior.trusted_indexes {
            if !by_index.contains_key(index.as_str()) {
                trusted.push(index.clone());
            }
        }
    }
    let trusted_set: BTreeSet<String> = trusted.iter().cloned().collect();
    let unlicensed: BTreeSet<String> = detected
        .iter()
        .filter(|result| result.is_unlicensed() && !trusted_by_index(result, &trusted_set))
        .map(|result| result.name.clone())
        .collect();
    let current = prior.is_some_and(|prior| prior.allow_unlicensed);
    if unlicensed.is_empty() {
        return Ok((trusted, current));
    }
    io.echo(&format!(
        "\nNo license at all: {}.",
        abbreviated(&unlicensed)
    ));
    io.echo("  Copyright applies without a notice, so with no license stated you'd be relying");
    io.echo("  on an implied permission from publishing it: arguable for installing and using,");
    io.echo("  weaker for redistributing. Often it's just missing metadata, so check each one;");
    io.echo("  answering n lets you accept them one at a time in the review after the check.");
    let allow = io.confirm("Allow packages with no license?", current)?;
    Ok((trusted, allow))
}

/// The prior policy as setup sees it: a category whose licenses are listed in
/// `allowed-licenses` but which isn't allowed whole counts as pinned, whether `pin` recorded it
/// in `pinned-categories` (older versions didn't) or the list was written by hand. Without
/// this, re-running setup over such a policy would offer to drop those licenses.
fn as_seen_by_setup(prior: &Policy) -> Policy {
    let mut seen = prior.clone();
    for license in &prior.allowed_licenses {
        for category in categories_for([license.as_str()]) {
            if !prior.allowed_categories.contains(&category) {
                seen.pinned_categories.insert(category);
            }
        }
    }
    seen
}

/// What a write came to, said to the user.
fn report_written(
    io: &mut dyn Prompter,
    written: Result<PathBuf, trustedlicenses_core::config::ConfigError>,
) -> Option<PathBuf> {
    match written {
        Ok(written) => {
            io.secho(
                &format!("\nWrote policy to {}.", written.display()),
                Style::bold(Color::Green),
            );
            Some(written)
        }
        Err(error) => {
            io.secho(
                &format!("\ntrustedlicenses: {error}"),
                Style::bold(Color::Red),
            );
            None
        }
    }
}

/// List the decisions earlier reviews recorded package by package, and ask whether to keep
/// them. Not asked when there are none.
fn ask_keep_package_entries(io: &mut dyn Prompter, prior: &Policy) -> Result<bool, PromptError> {
    let names = |items: Vec<String>| -> String {
        abbreviated(&items.into_iter().collect::<BTreeSet<String>>())
    };
    let mut lines = Vec::new();
    if !prior.accepted_licenses.is_empty() {
        lines.push(format!(
            "accepted-licenses: {}",
            names(prior.accepted_licenses.keys().cloned().collect())
        ));
    }
    if !prior.ignored_packages.is_empty() {
        lines.push(format!(
            "ignored-packages: {}",
            names(prior.ignored_packages.iter().cloned().collect())
        ));
    }
    if !prior.verified_packages.is_empty() {
        lines.push(format!(
            "verified-packages: {}",
            names(prior.verified_packages.keys().cloned().collect())
        ));
    }
    if !prior.verified_statements.is_empty() {
        lines.push(format!(
            "verified-statements: {} statement(s)",
            prior.verified_statements.len()
        ));
    }
    if prior.trust_corrected_licenses {
        lines.push("trust-corrected-licenses = true".to_owned());
    }
    if lines.is_empty() {
        return Ok(true);
    }
    io.echo("\nThe policy also has decisions recorded package by package:");
    for line in &lines {
        io.echo(&format!("  {line}"));
    }
    io.echo("  Dropping them makes those packages fail again until reviewed.");
    io.confirm("Keep these?", true)
}

/// No default: the answer changes what is suggested, so it has to be the user's.
/// `optional`: a re-run over a policy that never recorded one may leave it unrecorded.
fn ask_use_case(
    io: &mut dyn Prompter,
    current: Option<UseCase>,
    optional: bool,
) -> Result<Option<UseCase>, PromptError> {
    io.echo("What are you building?");
    io.echo("  [i] internal tooling or pipelines -- nothing leaves your organisation");
    io.echo("  [o] an open-source package or tool others install (e.g. from PyPI)");
    io.echo("  [p] a product you ship to customers or host for them");
    io.echo("  Not sure, or it may ship later? Choose p.");
    let default = current.map_or("", |case| &case.as_str()[..1]);
    let skippable = optional && current.is_none();
    if skippable {
        io.echo("  Your policy doesn't record one: press Enter to leave it that way.");
    }
    loop {
        let answer = io.prompt("Choice (i/o/p)", default)?;
        if skippable && answer.trim().is_empty() {
            return Ok(None);
        }
        let answer = if answer.trim().is_empty() {
            default.to_owned()
        } else {
            answer
        };
        match answer.trim().to_lowercase().chars().next() {
            Some('i') => return Ok(Some(UseCase::Internal)),
            Some('o') => return Ok(Some(UseCase::OpenSource)),
            Some('p') => return Ok(Some(UseCase::Product)),
            _ => io.echo("  Type i, o or p (not sure? p)."),
        }
    }
}

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
const TRUST_INDEX: &str = "o";
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
    /// For a pinned policy: licenses to allow for every package.
    allowed_licenses: BTreeSet<String>,
    verified_packages: Vec<(String, (String, String))>,
    verified_statements: Vec<(String, String)>,
    trust_corrected_licenses: bool,
    trusted_indexes: BTreeSet<String>,
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
            && self.allowed_licenses.is_empty()
            && self.verified_packages.is_empty()
            && self.verified_statements.is_empty()
            && !self.trust_corrected_licenses
            && self.trusted_indexes.is_empty())
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
pub(crate) fn today_utc() -> String {
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

/// `pinned`: the policy names licenses, not categories, so offering a category would undo
/// the pin; offer the license instead.
fn failure_options(failure: &DistributionLicence, pinned: bool) -> String {
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
    if failure.keys.is_empty() {
        options.push(format!(
            "[{BULK_IGNORE}]ulk-ignore every remaining undetectable package"
        ));
    } else if pinned || failure.categories.is_empty() {
        // No category to allow (a `WITH` license, an unknown id), or one that would undo a pin.
        let licenses = failure.keys.iter().cloned().collect::<Vec<_>>().join(", ");
        options.push(format!(
            "[{ALLOW_CATEGORY}]dd {licenses} to allowed-licenses (every package with it, not just this one)"
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
    if let Some(index) = own_index(failure) {
        options.push(format!(
            "[{TRUST_INDEX}]ur index: pass every package with no identified license from {index} \
             (trusted-indexes)"
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

/// The non-PyPI index a failure with no identifiable license came from, if any: the one a
/// `trusted-indexes` entry would cover.
fn own_index(failure: &DistributionLicence) -> Option<&str> {
    if !failure.keys.is_empty() || failure.unreadable {
        return None;
    }
    failure
        .index
        .as_deref()
        .filter(|index| !is_public_index(index))
}

/// Apply one prompted choice, returning `(quit_requested, bulk_ignore_requested)`.
fn apply_choice(
    io: &mut dyn Prompter,
    choice: &str,
    failure: &DistributionLicence,
    today: &str,
    decisions: &mut ReviewDecisions,
    pinned: bool,
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
    } else if let (TRUST_INDEX, Some(index)) = (choice, own_index(failure)) {
        decisions.trusted_indexes.insert(index.to_owned());
    } else if choice == IGNORE {
        set_ordered(
            &mut decisions.ignored,
            failure.name.clone(),
            reason_for(failure, today),
        );
    } else if choice == ALLOW_CATEGORY
        && (pinned || failure.categories.is_empty())
        && !failure.keys.is_empty()
    {
        decisions
            .allowed_licenses
            .extend(failure.keys.iter().cloned());
    } else if choice == ALLOW_CATEGORY && !pinned && !failure.categories.is_empty() {
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
    for license in &decisions.allowed_licenses {
        io.echo(&format!(
            "  allow {license} for every package (allowed-licenses)"
        ));
    }
    if decisions.allow_unlicensed {
        io.echo("  allow packages that have no license (allow-unlicensed = true)");
    }
    for index in &decisions.trusted_indexes {
        io.echo(&format!(
            "  pass packages with no identified license from {index} (trusted-indexes)"
        ));
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
        allowed_licenses: decisions.allowed_licenses.iter().cloned().collect(),
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
        trusted_indexes: decisions.trusted_indexes.iter().cloned().collect(),
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
    ids.iter().any(|id| policy.allowed_licenses.contains(*id))
        || !categories_for(ids).is_disjoint(&policy.allowed_categories)
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
    pinned: bool,
) -> Result<String, PromptError> {
    loop {
        io.echo(&format!("\n{}", format_failure(failure)));
        io.echo(&failure_options(failure, pinned));
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
    #[allow(clippy::too_many_lines)]
    fn run_flow(
        io: &mut dyn Prompter,
        pyproject: &Path,
        detected: &[DistributionLicence],
        prior: Option<&Policy>,
        explicit: bool,
    ) -> Result<Option<PathBuf>, PromptError> {
        let seen = prior.map(as_seen_by_setup);
        let prior = seen.as_ref();
        let with_license = detected
            .iter()
            .filter(|result| !result.keys.is_empty())
            .count();
        io.echo(&format!(
            "Detected licenses for {with_license} of {} installed packages.\n",
            detected.len()
        ));

        if !explicit
            && !io.confirm(
                "No policy configured yet -- would you like to run the guided setup?",
                true,
            )?
        {
            return Ok(None);
        }
        if prior.is_some() {
            io.echo(&format!(
                "Each answer defaults to what {} says now: press Enter to keep it.",
                policy_source(pyproject).display()
            ));
        }
        io.echo("");
        let use_case = ask_use_case(io, prior.and_then(|prior| prior.use_case), prior.is_some())?;
        io.echo("");
        let hint_case = use_case.unwrap_or(UseCase::Product);

        let allowed_before = |category: &str| {
            prior.map(|prior| {
                prior.allowed_categories.contains(category)
                    || prior.pinned_categories.contains(category)
            })
        };
        let mut allowed: Vec<String> = Vec::new();
        for (category, explanation, default) in PRIMARY_CATEGORIES {
            io.echo(&format!("{category}: {explanation}"));
            if category == COPYLEFT {
                for line in copyleft_hint(hint_case) {
                    io.echo(&format!("  {line}"));
                }
            }
            let already: BTreeSet<String> = allowed.iter().cloned().collect();
            io.echo(&format!(
                "  {}",
                category_summary(detected, category, &already)
            ));
            let default = allowed_before(category).unwrap_or(default);
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
        let previously: BTreeSet<String> = prior
            .map(|prior| {
                prior
                    .allowed_categories
                    .union(&prior.pinned_categories)
                    .filter(|category| !primary.contains(category.as_str()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut other_categories: BTreeSet<String> = detected
            .iter()
            .filter(|result| result.categories.is_disjoint(&already))
            .flat_map(|result| result.categories.iter())
            .filter(|category| !primary.contains(category.as_str()))
            .cloned()
            .collect();
        other_categories.extend(previously.iter().cloned());
        if !other_categories.is_empty() {
            let listed = other_categories
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            if previously.is_empty() {
                io.echo(&format!("Also detected in your environment: {listed}."));
            } else {
                io.echo(&format!("Also detected or allowed before: {listed}."));
            }
            if other_categories.contains(SOURCE_AVAILABLE) {
                io.echo(
                    "Source-available licenses vary: some (BUSL, CC-BY-NC) restrict use even \
                     internally, others (SSPL, Elastic) restrict offering the software to others as \
                     a service. Read the terms, then leave this blank and accept the package in the \
                     review after the check.",
                );
            }
            let default = previously.iter().cloned().collect::<Vec<_>>().join(", ");
            let question = if default.is_empty() {
                "Allow any of these too? Comma-separated exact names, or Enter to skip".to_owned()
            } else {
                format!(
                    "Allow any of these too? Comma-separated exact names, or Enter for [{default}]"
                )
            };
            let extra = io.prompt(&question, &default)?;
            let extra = if extra.trim().is_empty() {
                default
            } else {
                extra
            };
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
        let (pinned_categories, mut pinned_licenses) = ask_pins(io, detected, &allowed, prior)?;
        let (trusted_indexes, allow_unlicensed) = ask_unlicensed(io, detected, prior)?;

        let Some(prior) = prior else {
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
            let written = write_new_policy(
                pyproject,
                &NewPolicy {
                    allowed_categories: &allowed,
                    pinned_categories: &pinned_categories,
                    pinned_licenses: &pinned_licenses,
                    allow_unlicensed,
                    trusted_indexes: &trusted_indexes,
                    ignored_packages: &[],
                    use_case,
                },
                standalone,
            );
            return Ok(report_written(io, written));
        };

        // allowed-licenses: a license goes only when a category it was pinned under is
        // unpinned now; everything else listed stays as it was.
        let unpinned: BTreeSet<&String> = prior
            .pinned_categories
            .iter()
            .filter(|category| !pinned_categories.contains(category))
            .collect();
        let mut dropped = BTreeSet::new();
        for license in &prior.allowed_licenses {
            let released = categories_for([license.as_str()])
                .iter()
                .any(|category| unpinned.contains(category));
            if released && !pinned_licenses.contains(license) {
                dropped.insert(license.clone());
            } else {
                pinned_licenses.insert(license.clone());
            }
        }
        if !dropped.is_empty() {
            io.echo(&format!(
                "\nNo longer listed in allowed-licenses, as your answers above decide them: {}.",
                abbreviated(&dropped)
            ));
        }
        let keep = ask_keep_package_entries(io, prior)?;
        let source = policy_source(pyproject);
        if !io.confirm(
            &format!("\nRewrite the policy in {}?", source.display()),
            true,
        )? {
            return Ok(None);
        }
        let written = rewrite_policy(
            &source,
            &NewPolicy {
                allowed_categories: &allowed,
                pinned_categories: &pinned_categories,
                pinned_licenses: &pinned_licenses,
                allow_unlicensed,
                trusted_indexes: &trusted_indexes,
                ignored_packages: &[],
                use_case,
            },
            keep,
        )
        .map(|()| source);
        Ok(report_written(io, written))
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
            let pinned = policy.allowed_categories.is_empty()
                || !failure.categories.is_disjoint(&policy.pinned_categories);
            if bulk_ignore_undetectable && failure.keys.is_empty() {
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
            if trusted_by_index(failure, &decisions.trusted_indexes) {
                continue;
            }
            let choice = ask_choice(io, services, failure, project_dir, pinned)?;
            let (quit, bulk) = apply_choice(io, &choice, failure, &today, &mut decisions, pinned);
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
        match Self::run_flow(io, pyproject, detected, None, false) {
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

    fn setup(
        &mut self,
        io: &mut dyn Prompter,
        pyproject: &Path,
        detected: &[DistributionLicence],
        prior: Option<&Policy>,
    ) -> Result<Option<PathBuf>, PromptError> {
        match Self::run_flow(io, pyproject, detected, prior, true) {
            Err(PromptError::Timeout) => {
                timeout_notice(io, "aborting setup", "Nothing has been written.");
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
