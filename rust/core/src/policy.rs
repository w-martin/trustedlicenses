//! Policy evaluation: which detected licenses are acceptable, and for which packages.
//!
//! Separate from detection on purpose: detection says what a package carries, policy says
//! whether that is acceptable for this project.

use crate::detection::{
    canonical_name, categories_for, inspect_distribution, Distribution, DistributionLicence,
};
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};

// Plain strong-copyleft licenses: no linking exception (unlike LGPL) and no conditional
// compatibility grant (unlike MPL-2.0). Used only for the generic "your project isn't
// copyleft, this dependency is" heads-up.
const STRONG_COPYLEFT_IDS: [&str; 6] = [
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
];

// GPLv2-only is not by itself compatible with GPLv3 or AGPL-3.0, per the FSF. "GPL-2.0-or-later"
// grants permission to relicense under GPLv3, so it is deliberately excluded.
const GPL3_FAMILY_IDS: [&str; 4] = [
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
];
const GPL2_ONLY_ID: &str = "GPL-2.0-only";
const GPL_FAQ_URL: &str = "https://www.gnu.org/licenses/gpl-faq.html#AllCompatibility";
/// Where the FSF says, in these words, that GPLv2 is not by itself compatible with GPLv3.
const GPLV2_ENTRY_URL: &str = "https://www.gnu.org/licenses/license-list.html#GPLv2";

/// A project's license policy.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// A distribution passes when at least one detected license is in one of these.
    pub allowed_categories: BTreeSet<String>,
    /// SPDX ids allowed for every package, whatever their category.
    pub allowed_licenses: BTreeSet<String>,
    /// Categories replaced by the licenses they allowed when pinned: a license new to the
    /// project in one of them fails, and its fix is to list the license, not the category.
    pub pinned_categories: BTreeSet<String>,
    /// Indexes, as [`index_key`] spells them, whose packages pass when they have no license or
    /// one that can't be identified: an internal index serving the organisation's own code.
    pub trusted_indexes: BTreeSet<String>,
    /// Canonical names exempted from the check entirely. Trusts the package, whatever its license;
    /// prefer `accepted_licenses`.
    pub ignored_packages: BTreeSet<String>,
    /// Package -> the SPDX ids accepted for that package alone, though their categories are not
    /// allowed. A package passes if any license detected for it is listed here.
    pub accepted_licenses: BTreeMap<String, BTreeSet<String>>,
    /// Let a package with no license at all pass. A license that is detected, or a free-text
    /// statement awaiting review, is not "no license" and is judged as usual.
    pub allow_unlicensed: bool,
    /// SPDX ids of the consuming project's own license; only feeds informational notes.
    pub project_license_keys: BTreeSet<String>,
    /// Trust every free-text correction project-wide. Off by default so detection getting
    /// smarter never silently starts passing packages that were previously flagged.
    pub trust_corrected_licenses: bool,
    /// Package -> the exact `(declared statement, corrected id)` pair a human verified. The
    /// pin stops applying if the declared statement changes.
    pub verified_packages: HashMap<String, (String, String)>,
    /// Declared statement -> the id a human verified it corrects to, for any package.
    pub verified_statements: HashMap<String, String>,
    /// What the project is for; informational only.
    pub use_case: Option<crate::config::UseCase>,
}

/// The outcome of evaluating a [`Policy`].
#[derive(Clone, Debug, Default)]
pub struct PolicyResult {
    pub failures: Vec<DistributionLicence>,
    /// Distributions evaluated, ignored ones excluded.
    pub checked: usize,
    /// Informational, never pass/fail-affecting FSF-documented compatibility concerns.
    pub compatibility_notes: Vec<String>,
    /// Packages that pass only because the policy makes an exception for them, so a reviewer can
    /// see what is being relied on.
    pub exceptions: Vec<PolicyException>,
    /// The policy names licenses, not categories, so a fix should too: suggesting a category
    /// would undo the pin.
    pub pinned: bool,
    /// Categories pinned while others are still allowed whole: a failure in one of these is
    /// fixed by listing its license, as under a full pin.
    pub pinned_categories: BTreeSet<String>,
}

/// Why a package that fails the categories passes anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyException {
    /// The policy accepts these licenses for this package.
    AcceptedLicense {
        package: String,
        licenses: BTreeSet<String>,
    },
    /// The package has no license and the policy allows that.
    Unlicensed { package: String },
    /// The package has no identifiable license and comes from a trusted index.
    TrustedIndex { package: String, index: String },
}

/// How an index URL is compared and written: without credentials or a trailing slash.
#[must_use]
pub fn index_key(url: &str) -> String {
    crate::index_discovery::redact_url(url.trim())
        .trim_end_matches('/')
        .to_owned()
}

/// PyPI and its test instance: never offered as a trusted index, since everyone publishes there.
#[must_use]
pub fn is_public_index(url: &str) -> bool {
    let host = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split(['/', ':', '?'])
        .next()
        .unwrap_or("")
        .to_lowercase();
    [
        "pypi.org",
        "test.pypi.org",
        "pypi.python.org",
        "files.pythonhosted.org",
    ]
    .contains(&host.as_str())
}

/// Whether a trusted index would let `detected` pass: it came from one, its license is absent or
/// unrecognised, and it was read (a failed lookup isn't "no license").
#[must_use]
pub fn trusted_by_index(detected: &DistributionLicence, trusted: &BTreeSet<String>) -> bool {
    detected.keys.is_empty()
        && !detected.unreadable
        && detected
            .index
            .as_ref()
            .is_some_and(|index| trusted.contains(index))
}

impl PolicyException {
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::AcceptedLicense { package, licenses } => format!(
                "  {package}: {} (accepted for this package in accepted-licenses)",
                licenses
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Unlicensed { package } => {
                format!("  {package}: no license (allowed by allow-unlicensed)")
            }
            Self::TrustedIndex { package, index } => {
                format!("  {package}: no identified license, from {index} (trusted-indexes)")
            }
        }
    }
}

impl PolicyResult {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// Whether the fix for `failure` should name its license rather than its category.
    #[must_use]
    pub fn pinned_for(&self, failure: &DistributionLicence) -> bool {
        self.pinned || !failure.categories.is_disjoint(&self.pinned_categories)
    }
}

pub(crate) fn is_allowed(detected: &DistributionLicence, policy: &Policy) -> bool {
    detected
        .categories
        .intersection(&policy.allowed_categories)
        .next()
        .is_some()
        || detected
            .keys
            .intersection(&policy.allowed_licenses)
            .next()
            .is_some()
}

/// The licenses that let packages pass through `allowed-categories` today, plus any
/// `allowed-licenses` already listed: allowing exactly these instead of the categories keeps
/// every current result while failing any license that is new to the project.
///
/// Only a passing package's licenses that are themselves in an allowed category count: scipy
/// passing on BSD-3-Clause doesn't pin the GPL text it also bundles.
#[must_use]
pub fn pin_licenses(detected: &[DistributionLicence], policy: &Policy) -> BTreeSet<String> {
    let mut pinned = policy.allowed_licenses.clone();
    pinned.extend(pinnable_licenses(
        detected,
        policy,
        &policy.allowed_categories,
    ));
    pinned
}

/// The licenses that let packages pass through `categories` today: what pinning just those
/// categories adds to `allowed-licenses`.
#[must_use]
pub fn pinnable_licenses(
    detected: &[DistributionLicence],
    policy: &Policy,
    categories: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut pinned = BTreeSet::new();
    for result in detected
        .iter()
        .filter(|result| !policy.ignored_packages.contains(&result.name))
        .map(|result| effective_result(result, policy))
    {
        pinned.extend(
            result
                .keys
                .iter()
                .filter(|key| {
                    categories_for([key.as_str()])
                        .intersection(categories)
                        .next()
                        .is_some()
                })
                .cloned(),
        );
    }
    pinned
}

enum Verdict {
    Allowed,
    Excepted(PolicyException),
    Failed,
}

fn judge(detected: &DistributionLicence, policy: &Policy) -> Verdict {
    if is_allowed(detected, policy) {
        return Verdict::Allowed;
    }
    if let Some(accepted) = policy.accepted_licenses.get(&detected.name) {
        let licenses: BTreeSet<String> = detected.keys.intersection(accepted).cloned().collect();
        if !licenses.is_empty() {
            return Verdict::Excepted(PolicyException::AcceptedLicense {
                package: detected.name.clone(),
                licenses,
            });
        }
    }
    if policy.allow_unlicensed && detected.is_unlicensed() {
        return Verdict::Excepted(PolicyException::Unlicensed {
            package: detected.name.clone(),
        });
    }
    if trusted_by_index(detected, &policy.trusted_indexes) {
        return Verdict::Excepted(PolicyException::TrustedIndex {
            package: detected.name.clone(),
            index: detected.index.clone().unwrap_or_default(),
        });
    }
    Verdict::Failed
}

/// Which of a detection's suggested corrections the policy trusts: the project-wide flag,
/// then a package pin, then a statement pin. Pins are matched against `suggested` as it
/// stands now, so a pin for one statement stops applying the moment the statement changes.
fn trusted_suggestion_ids(detected: &DistributionLicence, policy: &Policy) -> BTreeSet<String> {
    if detected.suggested.is_empty() {
        return BTreeSet::new();
    }
    if policy.trust_corrected_licenses {
        return detected
            .suggested
            .iter()
            .map(|(_, id)| id.clone())
            .collect();
    }
    if let Some(pinned) = policy.verified_packages.get(&detected.name) {
        if detected.suggested.contains(pinned) {
            return BTreeSet::from([pinned.1.clone()]);
        }
    }
    detected
        .suggested
        .iter()
        .filter(|(statement, id)| policy.verified_statements.get(statement) == Some(id))
        .map(|(_, id)| id.clone())
        .collect()
}

/// Fold a trusted correction into a detection that otherwise resolved to nothing. It never
/// overrides an existing declared-metadata or license-file match.
pub(crate) fn effective_result(
    detected: &DistributionLicence,
    policy: &Policy,
) -> DistributionLicence {
    if !detected.keys.is_empty() || detected.suggested.is_empty() {
        return detected.clone();
    }
    let trusted = trusted_suggestion_ids(detected, policy);
    if trusted.is_empty() {
        return detected.clone();
    }
    DistributionLicence {
        categories: categories_for(trusted.iter().map(String::as_str)),
        keys: trusted,
        source: "declared metadata (corrected from free text)".to_owned(),
        ..detected.clone()
    }
}

fn joined_intersection(keys: &BTreeSet<String>, ids: &[&str]) -> Option<String> {
    let hits: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| keys.contains(*id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    (!hits.is_empty()).then(|| hits.join(", "))
}

/// A narrow, FSF-documented copyleft note, if one applies. Not a compatibility engine:
/// category-level comparisons get real cases wrong (GPLv2-only vs GPLv3 are mutually
/// incompatible despite both being "copyleft"). Reported as a note, never a verdict.
fn compatibility_note(detected: &DistributionLicence, policy: &Policy) -> Option<String> {
    let project = &policy.project_license_keys;
    if project.is_empty() {
        return None;
    }
    let name = &detected.name;

    if project.contains(GPL2_ONLY_ID) {
        if let Some(other) = joined_intersection(&detected.keys, &GPL3_FAMILY_IDS) {
            return Some(format!(
                "  {name}: your project is GPL-2.0-only; {name} is {other} -- the FSF states GPLv2 is \
                 not, by itself, compatible with GPLv3 ({GPLV2_ENTRY_URL})"
            ));
        }
    }
    if detected.keys.contains(GPL2_ONLY_ID) {
        if let Some(mine) = joined_intersection(project, &GPL3_FAMILY_IDS) {
            return Some(format!(
                "  {name}: your project is {mine}; {name} is GPL-2.0-only -- the FSF states GPLv2 is \
                 not, by itself, compatible with GPLv3 ({GPLV2_ENTRY_URL})"
            ));
        }
    }
    let project_is_copyleft =
        categories_for(project.iter().map(String::as_str)).contains("Copyleft");
    if !project_is_copyleft {
        if let Some(matched) = joined_intersection(&detected.keys, &STRONG_COPYLEFT_IDS) {
            return Some(format!(
                "  {name}: detected {matched} (strong copyleft); your project's own declared license \
                 isn't copyleft -- distributing this combination may require your project to also be \
                 GPL-compatible, see the FSF's GPL FAQ ({GPL_FAQ_URL})"
            ));
        }
    }
    None
}

/// The most informative of several installs of one package: the first that resolved a
/// license, else the first with a suggested correction, else the first.
fn best_result(copies: Vec<DistributionLicence>) -> DistributionLicence {
    let pick = copies
        .iter()
        .position(|copy| !copy.keys.is_empty())
        .or_else(|| copies.iter().position(|copy| !copy.suggested.is_empty()))
        .unwrap_or(0);
    copies.into_iter().nth(pick).unwrap_or_default()
}

/// Detect the license of every distribution with no policy applied, sorted by name.
///
/// The same package can appear more than once and the copies can differ (one stripped of
/// its license file); all copies are inspected and the best kept, so the outcome does not
/// depend on discovery order.
#[must_use]
pub fn detect_all(
    distributions: &[Distribution],
    exclude: &BTreeSet<String>,
) -> Vec<DistributionLicence> {
    let jobs: Vec<(String, &Distribution)> = distributions
        .iter()
        .filter_map(|dist| {
            let name = canonical_name(dist.metadata.get("Name").unwrap_or(""));
            (!name.is_empty() && !exclude.contains(&name)).then_some((name, dist))
        })
        .collect();

    crate::detection::prescan_licence_files(jobs.iter().map(|(_, dist)| *dist));
    let inspected: Vec<DistributionLicence> = jobs
        .par_iter()
        .map(|(name, dist)| inspect_distribution(dist, Some(name)))
        .collect();

    let mut by_name: BTreeMap<String, Vec<DistributionLicence>> = BTreeMap::new();
    for result in inspected {
        by_name.entry(result.name.clone()).or_default().push(result);
    }
    by_name.into_values().map(best_result).collect()
}

/// Detect every distribution and evaluate it against a policy.
#[must_use]
pub fn evaluate(policy: &Policy, distributions: &[Distribution]) -> PolicyResult {
    let detected = detect_all(distributions, &policy.ignored_packages);
    reevaluate(&detected, policy)
}

/// Evaluate already-detected results without re-running detection, so one detection pass
/// can be judged against more than one policy (e.g. after the wizard edits it).
///
/// Many distributions concatenate the license texts of what they vendor into their own
/// LICENSE: pandas ships BSD-3-Clause alongside notices that include GPL text. Failing on
/// any disallowed match would reject pandas, whose actual grant is BSD-3-Clause. Requiring
/// a positive allowed match still fails a dependency offering only a disallowed license,
/// or none.
#[must_use]
pub fn reevaluate(detected: &[DistributionLicence], policy: &Policy) -> PolicyResult {
    let results: Vec<DistributionLicence> = detected
        .iter()
        .filter(|result| !policy.ignored_packages.contains(&result.name))
        .map(|result| effective_result(result, policy))
        .collect();
    let mut failures = Vec::new();
    let mut exceptions = Vec::new();
    for result in &results {
        match judge(result, policy) {
            Verdict::Allowed => {}
            Verdict::Excepted(exception) => exceptions.push(exception),
            Verdict::Failed => failures.push(result.clone()),
        }
    }
    // Checked against every result, not just failures: both being "Copyleft" does not
    // guarantee the specific licenses are compatible.
    let compatibility_notes = results
        .iter()
        .filter_map(|result| compatibility_note(result, policy))
        .collect();
    PolicyResult {
        failures,
        checked: results.len(),
        compatibility_notes,
        exceptions,
        pinned: policy.allowed_categories.is_empty(),
        pinned_categories: policy.pinned_categories.clone(),
    }
}

/// Render one policy failure as a human-readable line.
#[must_use]
pub fn format_failure(failure: &DistributionLicence) -> String {
    let detail = if failure.keys.is_empty() {
        "no license detected".to_owned()
    } else {
        let categories = failure
            .categories
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "detected {} (categories: {})",
            failure
                .keys
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            if categories.is_empty() {
                "none"
            } else {
                &categories
            }
        )
    };
    format!("  {}: {} -- from {}", failure.name, detail, failure.source)
}

/// Suggest a policy change that would let one failure pass.
///
/// For a detected license the narrowest option comes first: the exact `accepted-licenses` line for
/// this package, then the whole category.
#[must_use]
pub fn format_remediation(failure: &DistributionLicence, pinned: bool) -> String {
    if failure.unreadable {
        return "    -> its license could not be read, so this is not an unlicensed package and \
                allow-unlicensed doesn't apply; fix the problem above, or trust the package outright \
                with ignored-packages"
            .to_owned();
    }
    if failure.categories.is_empty() {
        if !failure.suggested.is_empty() {
            return format_suggestion(failure);
        }
        let from_own_index = failure
            .index
            .as_ref()
            .filter(|index| !is_public_index(index))
            .map_or_else(String::new, |index| {
                format!(
                    "; or, if every such package from {index} is your own, add \"{index}\" to \
                     trusted-indexes"
                )
            });
        if failure.declares_license && failure.keys.is_empty() {
            return format!(
                "    -> a license is declared or shipped but could not be identified; read it yourself, \
                 then trust \"{}\" outright with ignored-packages if it is acceptable (allow-unlicensed \
                 covers only packages with no license at all){from_own_index}",
                failure.name
            );
        }
        if failure.keys.is_empty() {
            return format!(
                "    -> no license could be detected; verify \"{}\" manually, then set \
                 allow-unlicensed = true (or pass --allow-unlicensed) to allow packages that have \
                 none{from_own_index}",
                failure.name
            );
        }
    }
    let categories = failure
        .categories
        .iter()
        .map(|category| format!("\"{category}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let licenses = failure
        .keys
        .iter()
        .map(|key| format!("\"{key}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let accept = format!(
        "to accept only this license for this package, add `{} = [{licenses}]` under \
         [tool.trustedlicenses.accepted-licenses]",
        toml_key(&failure.name)
    );
    if pinned {
        return format!(
            "    -> {accept}; or add {licenses} to allowed-licenses to allow it for every package"
        );
    }
    if failure.categories.is_empty() {
        return format!("    -> {accept}");
    }
    format!(
        "    -> {accept}; or add {categories} to allowed-categories to allow every package in it"
    )
}

/// A TOML key, quoted only when it has to be.
fn toml_key(name: &str) -> String {
    let bare = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if bare {
        name.to_owned()
    } else {
        format!("\"{name}\"")
    }
}

/// Describe an untrusted free-text correction and how to trust it.
#[must_use]
pub fn format_suggestion(failure: &DistributionLicence) -> String {
    let Some((statement, spdx_id)) = failure.suggested.iter().next() else {
        return String::new();
    };
    format!(
        "    -> looks like {spdx_id} from its declared metadata (\"{statement}\"), not trusted by \
         default -- review interactively, or add trust-corrected-licenses / verified-packages / \
         verified-statements to your policy"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::test_support::{make_distribution, GPL_2_0, MIT};
    use tempfile::tempdir;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn pair(statement: &str, id: &str) -> (String, String) {
        (statement.to_owned(), id.to_owned())
    }

    fn allowing(categories: &[&str]) -> Policy {
        Policy {
            allowed_categories: set(categories),
            ..Policy::default()
        }
    }

    fn licence(
        name: &str,
        keys: &[&str],
        categories: &[&str],
        source: &str,
    ) -> DistributionLicence {
        DistributionLicence {
            name: name.to_owned(),
            keys: set(keys),
            categories: set(categories),
            source: source.to_owned(),
            ..DistributionLicence::default()
        }
    }

    fn suggested_only(name: &str, statement: &str, id: &str) -> DistributionLicence {
        DistributionLicence {
            suggested: BTreeSet::from([pair(statement, id)]),
            ..licence(name, &[], &[], "no license information found")
        }
    }

    const APACHE_TEXT: &str = "Apache License, Version 2.0";

    #[test]
    fn passes_a_permissive_package() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "somepkg", Some(MIT), &[]);
        let result = evaluate(&allowing(&["Permissive"]), &[dist]);
        assert!(result.passed());
        assert_eq!(result.checked, 1);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn fails_a_copyleft_package_when_not_allowed() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "gplpkg", Some(GPL_2_0), &[]);
        let result = evaluate(&allowing(&["Permissive"]), &[dist]);
        assert!(!result.passed());
        assert_eq!(result.checked, 1);
        let names: Vec<&str> = result.failures.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["gplpkg"]);
    }

    #[test]
    fn passes_a_vendored_package_with_at_least_one_allowed_license() {
        let tmp = tempdir().expect("tempdir");
        let concatenated = format!("{MIT}\n\n{GPL_2_0}");
        let dist = make_distribution(tmp.path(), "vendoring-pkg", Some(&concatenated), &[]);
        assert!(evaluate(&allowing(&["Permissive"]), &[dist]).passed());
    }

    #[test]
    fn ignores_packages_in_the_ignore_list() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "gplpkg", Some(GPL_2_0), &[]);
        let policy = Policy {
            ignored_packages: set(&["gplpkg"]),
            ..allowing(&["Permissive"])
        };
        let result = evaluate(&policy, &[dist]);
        assert!(result.passed());
        assert_eq!(result.checked, 0);
    }

    #[test]
    fn detect_all_does_not_depend_on_duplicate_install_order() {
        for stripped_first in [true, false] {
            let tmp = tempdir().expect("tempdir");
            let (stripped_dir, intact_dir) =
                (tmp.path().join("stripped"), tmp.path().join("intact"));
            std::fs::create_dir_all(&stripped_dir).expect("mkdir");
            std::fs::create_dir_all(&intact_dir).expect("mkdir");
            let stripped = make_distribution(&stripped_dir, "webencodings", None, &[]);
            let intact = make_distribution(&intact_dir, "webencodings", Some(MIT), &[]);
            let dists = if stripped_first {
                vec![stripped, intact]
            } else {
                vec![intact, stripped]
            };
            let results = detect_all(&dists, &BTreeSet::new());
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].keys, set(&["MIT"]));
        }
    }

    #[test]
    fn detect_all_keeps_one_result_when_no_copy_resolves() {
        let tmp = tempdir().expect("tempdir");
        let (first, second) = (tmp.path().join("first"), tmp.path().join("second"));
        std::fs::create_dir_all(&first).expect("mkdir");
        std::fs::create_dir_all(&second).expect("mkdir");
        let dists = [
            make_distribution(&first, "bare", None, &[]),
            make_distribution(&second, "bare", None, &[]),
        ];
        let results = detect_all(&dists, &BTreeSet::new());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "bare");
        assert!(results[0].keys.is_empty());
    }

    #[test]
    fn dedupes_by_canonical_name() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "Some_Pkg", Some(MIT), &[]);
        let result = evaluate(&allowing(&["Permissive"]), &[dist.clone(), dist]);
        assert_eq!(result.checked, 1);
    }

    #[test]
    fn format_failure_with_no_license_detected() {
        let failure = licence("bare", &[], &[], "no source");
        assert!(format_failure(&failure).contains("no license detected"));
    }

    #[test]
    fn format_failure_with_detected_keys() {
        let failure = licence(
            "gplpkg",
            &["gpl-2.0"],
            &["Copyleft"],
            "license files: LICENSE",
        );
        let line = format_failure(&failure);
        assert_eq!(
            line,
            "  gplpkg: detected gpl-2.0 (categories: Copyleft) -- from license files: LICENSE"
        );
    }

    #[test]
    fn format_failure_names_none_when_keys_have_no_category() {
        let failure = licence("odd", &["x"], &[], "src");
        assert_eq!(
            format_failure(&failure),
            "  odd: detected x (categories: none) -- from src"
        );
    }

    #[test]
    fn remediation_with_no_license_suggests_manual_verification() {
        let line = format_remediation(&licence("bare", &[], &[], "no source"), false);
        assert!(line.contains("\"bare\""));
        assert!(line.contains("allow-unlicensed"));
        assert!(!line.contains("ignored-packages"));
        assert!(!line.contains("allowed-categories"));
        assert!(!line.contains("trust-corrected-licenses"));
    }

    #[test]
    fn remediation_with_categories_suggests_config_changes() {
        let failure = licence(
            "gplpkg",
            &["GPL-2.0-only"],
            &["Copyleft"],
            "license files: LICENSE",
        );
        assert_eq!(
            format_remediation(&failure, false),
            "    -> to accept only this license for this package, add `gplpkg = [\"GPL-2.0-only\"]` under \
             [tool.trustedlicenses.accepted-licenses]; or add \"Copyleft\" to allowed-categories to \
             allow every package in it"
        );
    }

    #[test]
    fn remediation_quotes_a_key_that_needs_it_and_lists_every_detected_license() {
        let failure = licence(
            "odd.name",
            &["GPL-2.0-only", "MPL-2.0"],
            &["Copyleft"],
            "src",
        );
        assert!(format_remediation(&failure, false)
            .contains("`\"odd.name\" = [\"GPL-2.0-only\", \"MPL-2.0\"]`"));
    }

    fn evaluated(policy: &Policy, found: &[DistributionLicence]) -> PolicyResult {
        reevaluate(found, policy)
    }

    fn accepting(package: &str, ids: &[&str]) -> Policy {
        Policy {
            allowed_categories: set(&["Permissive"]),
            accepted_licenses: BTreeMap::from([(package.to_owned(), set(ids))]),
            ..Policy::default()
        }
    }

    #[test]
    fn an_accepted_license_passes_that_package_and_is_reported() {
        let found = [licence(
            "certifi",
            &["MPL-2.0"],
            &["Copyleft Limited"],
            "src",
        )];
        let result = evaluated(&accepting("certifi", &["MPL-2.0"]), &found);
        assert!(result.passed());
        assert_eq!(
            result.exceptions,
            [PolicyException::AcceptedLicense {
                package: "certifi".to_owned(),
                licenses: set(&["MPL-2.0"]),
            }]
        );
    }

    #[test]
    fn an_accepted_license_does_not_pass_another_package_with_the_same_license() {
        let found = [licence("other", &["MPL-2.0"], &["Copyleft Limited"], "src")];
        assert!(!evaluated(&accepting("certifi", &["MPL-2.0"]), &found).passed());
    }

    #[test]
    fn an_accepted_license_does_not_pass_a_different_license_on_the_same_package() {
        let found = [licence("certifi", &["GPL-3.0-only"], &["Copyleft"], "src")];
        assert!(!evaluated(&accepting("certifi", &["MPL-2.0"]), &found).passed());
    }

    #[test]
    fn an_exception_is_not_reported_for_a_package_that_passes_anyway() {
        let found = [licence("certifi", &["MIT"], &["Permissive"], "src")];
        let result = evaluated(&accepting("certifi", &["MIT"]), &found);
        assert!(result.passed() && result.exceptions.is_empty());
    }

    #[test]
    fn allow_unlicensed_passes_only_a_package_with_no_license_at_all() {
        let policy = Policy {
            allowed_categories: set(&["Permissive"]),
            allow_unlicensed: true,
            ..Policy::default()
        };
        let bare = licence("internal", &[], &[], "no source");
        let mut free_text = licence("wordy", &[], &[], "src");
        free_text.suggested = BTreeSet::from([pair("Apache License, Version 2.0", "Apache-2.0")]);
        let gpl = licence("gplpkg", &["GPL-2.0-only"], &["Copyleft"], "src");

        let result = evaluated(&policy, &[bare, free_text, gpl]);
        let failed: Vec<&str> = result.failures.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(failed, ["wordy", "gplpkg"]);
        assert_eq!(
            result.exceptions,
            [PolicyException::Unlicensed {
                package: "internal".to_owned()
            }]
        );
    }

    #[test]
    fn allow_unlicensed_does_not_pass_a_package_whose_license_could_not_be_read() {
        let policy = Policy {
            allowed_categories: set(&["Permissive"]),
            allow_unlicensed: true,
            ..Policy::default()
        };
        let mut unread = licence("gitdep", &[], &[], "lock file: git source");
        unread.unreadable = true;
        let result = evaluated(&policy, &[unread.clone()]);
        assert!(!result.passed() && result.exceptions.is_empty());
        let line = format_remediation(&unread, false);
        assert!(
            line.contains("could not be read") && !line.contains("set allow-unlicensed"),
            "{line}"
        );
    }

    #[test]
    fn unlicensed_packages_fail_unless_the_policy_allows_them() {
        let policy = Policy {
            allowed_categories: set(&["Permissive"]),
            ..Policy::default()
        };
        assert!(!evaluated(&policy, &[licence("internal", &[], &[], "none")]).passed());
    }

    #[test]
    fn remediation_with_a_suggestion_points_at_trusting_it() {
        let line = format_remediation(
            &suggested_only("catboost", APACHE_TEXT, "Apache-2.0"),
            false,
        );
        for needle in [
            "Apache-2.0",
            APACHE_TEXT,
            "trust-corrected-licenses",
            "verified-packages",
            "verified-statements",
        ] {
            assert!(line.contains(needle), "{needle} missing from {line}");
        }
    }

    fn gpl_note_policy(project: &[&str], allowed: &[&str]) -> Policy {
        Policy {
            project_license_keys: set(project),
            ..allowing(allowed)
        }
    }

    #[test]
    fn flags_gpl2_only_project_depending_on_gpl3_dependency() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "gpl3pkg",
            None,
            &[("License-Expression", "GPL-3.0-only")],
        );
        let result = evaluate(&gpl_note_policy(&["GPL-2.0-only"], &["Copyleft"]), &[dist]);
        assert!(result.passed());
        assert_eq!(result.compatibility_notes.len(), 1);
        assert!(result.compatibility_notes[0].contains("gpl3pkg"));
        assert!(result.compatibility_notes[0].contains("GPLv2"));
    }

    #[test]
    fn flags_gpl3_project_depending_on_gpl2_only_dependency() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "gpl2pkg",
            None,
            &[("License-Expression", "GPL-2.0-only")],
        );
        let result = evaluate(&gpl_note_policy(&["GPL-3.0-only"], &["Copyleft"]), &[dist]);
        assert_eq!(result.compatibility_notes.len(), 1);
        assert!(result.compatibility_notes[0].contains("gpl2pkg"));
    }

    #[test]
    fn flags_strong_copyleft_dependency_for_a_non_copyleft_project() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "gplpkg",
            None,
            &[("License-Expression", "GPL-3.0-or-later")],
        );
        let result = evaluate(&gpl_note_policy(&["MIT"], &["Copyleft"]), &[dist]);
        assert_eq!(result.compatibility_notes.len(), 1);
        assert!(result.compatibility_notes[0].contains("gplpkg"));
        assert!(result.compatibility_notes[0].contains("strong copyleft"));
    }

    #[test]
    fn no_compatibility_notes_when_project_license_is_unknown() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "gplpkg",
            None,
            &[("License-Expression", "GPL-3.0-only")],
        );
        assert!(evaluate(&allowing(&["Copyleft"]), &[dist])
            .compatibility_notes
            .is_empty());
    }

    #[test]
    fn no_compatibility_note_for_a_compatible_copyleft_pairing() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "samefamily",
            None,
            &[("License-Expression", "GPL-3.0-or-later")],
        );
        let policy = gpl_note_policy(&["GPL-3.0-or-later"], &["Copyleft"]);
        assert!(evaluate(&policy, &[dist]).compatibility_notes.is_empty());
    }

    #[test]
    fn trusted_ids_empty_by_default() {
        let detected = suggested_only("catboost", APACHE_TEXT, "Apache-2.0");
        assert!(trusted_suggestion_ids(&detected, &allowing(&["Permissive"])).is_empty());
    }

    #[test]
    fn trusted_ids_trusts_the_global_flag() {
        let detected = suggested_only("catboost", APACHE_TEXT, "Apache-2.0");
        let policy = Policy {
            trust_corrected_licenses: true,
            ..allowing(&["Permissive"])
        };
        assert_eq!(
            trusted_suggestion_ids(&detected, &policy),
            set(&["Apache-2.0"])
        );
    }

    fn pinned(name: &str, statement: &str, id: &str) -> Policy {
        Policy {
            verified_packages: HashMap::from([(name.to_owned(), pair(statement, id))]),
            ..allowing(&["Permissive"])
        }
    }

    #[test]
    fn trusted_ids_trusts_a_matching_package_pin() {
        let detected = suggested_only("catboost", APACHE_TEXT, "Apache-2.0");
        let policy = pinned("catboost", APACHE_TEXT, "Apache-2.0");
        assert_eq!(
            trusted_suggestion_ids(&detected, &policy),
            set(&["Apache-2.0"])
        );
    }

    #[test]
    fn trusted_ids_ignores_a_stale_package_pin() {
        let detected = suggested_only("catboost", "Some New License Text 3.0", "MIT");
        let policy = pinned("catboost", APACHE_TEXT, "Apache-2.0");
        assert!(trusted_suggestion_ids(&detected, &policy).is_empty());
    }

    fn statement_pin(statement: &str, id: &str) -> Policy {
        Policy {
            verified_statements: HashMap::from([(statement.to_owned(), id.to_owned())]),
            ..allowing(&["Permissive"])
        }
    }

    #[test]
    fn trusted_ids_trusts_a_matching_statement_pin_for_any_package() {
        let detected = suggested_only("some-internal-pkg", APACHE_TEXT, "Apache-2.0");
        let policy = statement_pin(APACHE_TEXT, "Apache-2.0");
        assert_eq!(
            trusted_suggestion_ids(&detected, &policy),
            set(&["Apache-2.0"])
        );
    }

    #[test]
    fn trusted_ids_ignores_a_statement_pin_with_a_stale_id() {
        let detected = suggested_only("pkg", APACHE_TEXT, "Apache-2.0");
        let policy = statement_pin(APACHE_TEXT, "Apache-1.0");
        assert!(trusted_suggestion_ids(&detected, &policy).is_empty());
    }

    #[test]
    fn effective_result_folds_in_a_trusted_suggestion() {
        let detected = suggested_only("catboost", APACHE_TEXT, "Apache-2.0");
        let policy = Policy {
            trust_corrected_licenses: true,
            ..allowing(&["Permissive"])
        };
        let effective = effective_result(&detected, &policy);
        assert_eq!(effective.keys, set(&["Apache-2.0"]));
        assert_eq!(effective.categories, set(&["Permissive"]));
        assert_eq!(
            effective.source,
            "declared metadata (corrected from free text)"
        );
        assert!(detected.keys.is_empty());
    }

    #[test]
    fn effective_result_is_unchanged_when_nothing_is_trusted() {
        let detected = suggested_only("catboost", APACHE_TEXT, "Apache-2.0");
        assert_eq!(
            effective_result(&detected, &allowing(&["Permissive"])),
            detected
        );
    }

    #[test]
    fn effective_result_does_not_override_an_existing_match_even_when_trusted() {
        let detected = DistributionLicence {
            suggested: BTreeSet::from([pair(APACHE_TEXT, "Apache-2.0")]),
            ..licence(
                "filewins",
                &["GPL-2.0-or-later"],
                &["Copyleft"],
                "license files: LICENSE",
            )
        };
        let policy = Policy {
            trust_corrected_licenses: true,
            ..allowing(&["Permissive"])
        };
        assert_eq!(effective_result(&detected, &policy), detected);
    }

    #[test]
    fn fails_an_untrusted_suggestion_by_default() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "catboost", None, &[("License", APACHE_TEXT)]);
        let result = evaluate(&allowing(&["Permissive"]), &[dist]);
        assert!(!result.passed());
        assert_eq!(
            result.failures[0].suggested,
            BTreeSet::from([pair(APACHE_TEXT, "Apache-2.0")])
        );
    }

    #[test]
    fn passes_when_trust_corrected_licenses_is_enabled() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "catboost", None, &[("License", APACHE_TEXT)]);
        let policy = Policy {
            trust_corrected_licenses: true,
            ..allowing(&["Permissive"])
        };
        assert!(evaluate(&policy, &[dist]).passed());
    }

    #[test]
    fn passes_with_a_matching_verified_package_pin() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "catboost", None, &[("License", APACHE_TEXT)]);
        assert!(evaluate(&pinned("catboost", APACHE_TEXT, "Apache-2.0"), &[dist]).passed());
    }

    #[test]
    fn fails_again_after_the_declared_text_changes_under_a_package_pin() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "catboost",
            None,
            &[("License", "Apache Version 1.0")],
        );
        let result = evaluate(&pinned("catboost", APACHE_TEXT, "Apache-2.0"), &[dist]);
        assert!(!result.passed());
        assert_eq!(
            result.failures[0].suggested,
            BTreeSet::from([pair("Apache Version 1.0", "Apache-1.0")])
        );
    }

    #[test]
    fn passes_with_a_matching_verified_statement_pin_for_any_package() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "some-internal-pkg",
            None,
            &[("License", APACHE_TEXT)],
        );
        assert!(evaluate(&statement_pin(APACHE_TEXT, "Apache-2.0"), &[dist]).passed());
    }

    #[test]
    fn suggestion_never_overrides_a_bundled_file_match_even_when_trusted() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "filewins",
            Some(GPL_2_0),
            &[("License", APACHE_TEXT)],
        );
        let policy = Policy {
            trust_corrected_licenses: true,
            ..allowing(&["Permissive"])
        };
        let result = evaluate(&policy, &[dist]);
        assert!(!result.passed());
        assert_eq!(result.failures[0].keys, set(&["GPL-2.0-or-later"]));
    }

    #[test]
    fn reevaluate_matches_evaluate_for_the_same_policy() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "somepkg", Some(MIT), &[]);
        let policy = allowing(&["Permissive"]);
        let via_evaluate = evaluate(&policy, std::slice::from_ref(&dist));
        let via_reevaluate = reevaluate(&detect_all(&[dist], &BTreeSet::new()), &policy);
        assert_eq!(via_evaluate.checked, via_reevaluate.checked);
        assert_eq!(via_evaluate.failures, via_reevaluate.failures);
        assert_eq!(
            via_evaluate.compatibility_notes,
            via_reevaluate.compatibility_notes
        );
    }

    #[test]
    fn reevaluate_reapplies_ignored_packages_against_the_new_policy() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "gplpkg", Some(GPL_2_0), &[]);
        let detected = detect_all(&[dist], &BTreeSet::new());
        let policy = Policy {
            ignored_packages: set(&["gplpkg"]),
            ..allowing(&["Permissive"])
        };
        let result = reevaluate(&detected, &policy);
        assert!(result.passed());
        assert_eq!(result.checked, 0);
    }

    #[test]
    fn allowed_licenses_pass_a_package_whatever_its_category() {
        let policy = Policy {
            allowed_licenses: set(&["MPL-2.0"]),
            ..Policy::default()
        };
        let found = [
            licence("certifi", &["MPL-2.0"], &["Copyleft Limited"], "metadata"),
            licence(
                "other",
                &["LGPL-3.0-only"],
                &["Copyleft Limited"],
                "metadata",
            ),
        ];
        let result = evaluated(&policy, &found);
        assert_eq!(result.failures.len(), 1);
        assert_eq!(result.failures[0].name, "other");
        assert!(result.pinned);
    }

    #[test]
    fn pinning_keeps_only_the_licenses_that_pass_through_a_category() {
        let policy = Policy {
            allowed_licenses: set(&["MPL-2.0"]),
            ignored_packages: set(&["skipped"]),
            ..allowing(&["Permissive"])
        };
        let found = [
            licence(
                "scipy",
                &["BSD-3-Clause", "GPL-3.0-or-later"],
                &["Permissive", "Copyleft"],
                "files",
            ),
            licence("gplpkg", &["GPL-2.0-only"], &["Copyleft"], "metadata"),
            licence("skipped", &["ISC"], &["Permissive"], "metadata"),
            licence("mit", &["MIT"], &["Permissive"], "metadata"),
        ];
        assert_eq!(
            pin_licenses(&found, &policy),
            set(&["BSD-3-Clause", "MIT", "MPL-2.0"])
        );
    }

    #[test]
    fn a_pinned_policy_judges_todays_packages_exactly_as_the_categories_did() {
        let policy = allowing(&["Permissive", "Copyleft Limited"]);
        let found = [
            licence(
                "scipy",
                &["BSD-3-Clause", "GPL-3.0-or-later"],
                &["Permissive", "Copyleft"],
                "files",
            ),
            licence("certifi", &["MPL-2.0"], &["Copyleft Limited"], "metadata"),
            licence("gplpkg", &["GPL-2.0-only"], &["Copyleft"], "metadata"),
            licence("bare", &[], &[], "no source"),
        ];
        let pinned = Policy {
            allowed_categories: BTreeSet::new(),
            allowed_licenses: pin_licenses(&found, &policy),
            ..policy.clone()
        };
        let names = |result: &PolicyResult| {
            result
                .failures
                .iter()
                .map(|f| f.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&evaluated(&pinned, &found)),
            names(&evaluated(&policy, &found))
        );
        // A license new to the project now fails, though its category is still "allowed".
        let newcomer = [licence(
            "newpkg",
            &["EPL-2.0"],
            &["Copyleft Limited"],
            "metadata",
        )];
        assert!(evaluated(&policy, &newcomer).passed());
        assert!(!evaluated(&pinned, &newcomer).passed());
    }

    #[test]
    fn a_pinned_policy_suggests_a_license_not_a_category() {
        let failure = licence("newpkg", &["EPL-2.0"], &["Copyleft Limited"], "metadata");
        let pinned = format_remediation(&failure, true);
        assert!(
            pinned.contains("add \"EPL-2.0\" to allowed-licenses"),
            "{pinned}"
        );
        assert!(!pinned.contains("allowed-categories"), "{pinned}");
        assert!(format_remediation(&failure, false).contains("to allowed-categories"));
    }

    #[test]
    fn pinning_one_category_keeps_todays_results_and_fails_only_its_newcomers() {
        let policy = allowing(&["Permissive", "Copyleft Limited"]);
        let found = [
            licence("requests", &["Apache-2.0"], &["Permissive"], "metadata"),
            licence("certifi", &["MPL-2.0"], &["Copyleft Limited"], "metadata"),
        ];
        let chosen = set(&["Copyleft Limited"]);
        assert_eq!(
            pinnable_licenses(&found, &policy, &chosen),
            set(&["MPL-2.0"])
        );
        let pinned = Policy {
            allowed_categories: set(&["Permissive"]),
            allowed_licenses: pinnable_licenses(&found, &policy, &chosen),
            pinned_categories: chosen,
            ..Policy::default()
        };
        assert!(evaluated(&pinned, &found).passed());
        let newcomers = [
            licence("newmit", &["0BSD"], &["Permissive"], "metadata"),
            licence(
                "chardet",
                &["LGPL-2.1-or-later"],
                &["Copyleft Limited"],
                "files",
            ),
            licence("gplpkg", &["GPL-3.0-only"], &["Copyleft"], "metadata"),
        ];
        let result = evaluated(&pinned, &newcomers);
        let failed: Vec<&str> = result.failures.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(failed, ["chardet", "gplpkg"]);
        // Only the pinned category's failure is told to list its license.
        assert!(result.pinned_for(&result.failures[0]));
        assert!(!result.pinned_for(&result.failures[1]));
    }

    #[test]
    fn a_trusted_index_passes_only_its_packages_with_no_identified_license() {
        let nexus = "https://nexus.example.com/simple";
        let policy = Policy {
            trusted_indexes: set(&[nexus]),
            ..allowing(&["Permissive"])
        };
        let from = |mut result: DistributionLicence, index: &str| {
            result.index = Some(index.to_owned());
            result
        };
        let mut unreadable = from(licence("broken", &[], &[], "package index: 401"), nexus);
        unreadable.unreadable = true;
        let found = [
            from(
                licence("acme-core", &[], &[], "no license information found"),
                nexus,
            ),
            from(
                licence("acme-gpl", &["GPL-3.0-only"], &["Copyleft"], "metadata"),
                nexus,
            ),
            unreadable,
            from(
                licence("stray", &[], &[], "no license information found"),
                "https://idx/simple",
            ),
        ];
        let result = evaluated(&policy, &found);
        let failed: Vec<&str> = result.failures.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(failed, ["acme-gpl", "broken", "stray"]);
        assert_eq!(
            result.exceptions,
            [PolicyException::TrustedIndex {
                package: "acme-core".to_owned(),
                index: nexus.to_owned(),
            }]
        );
        assert_eq!(index_key("https://u:p@nexus.example.com/simple/"), nexus);
        assert!(is_public_index("https://pypi.org/simple"));
        assert!(!is_public_index(nexus));
    }

    #[test]
    fn a_with_license_passes_only_when_accepted_explicitly() {
        use crate::detection::resolve_license_expression;
        let keys = resolve_license_expression("GPL-3.0-only WITH LLVM-exception");
        let found = [DistributionLicence {
            name: "llvmpkg".to_owned(),
            categories: categories_for(keys.iter().map(String::as_str)),
            keys,
            source: "metadata".to_owned(),
            ..DistributionLicence::default()
        }];
        let base = allowing(&["Permissive", "Public Domain", "Copyleft Limited"]);
        assert!(!evaluated(&base, &found).passed());
        assert!(pin_licenses(&found, &base).is_empty());
        let listed = Policy {
            allowed_licenses: set(&["GPL-3.0-only WITH LLVM-exception"]),
            ..base.clone()
        };
        assert!(evaluated(&listed, &found).passed());
        let accepted = Policy {
            accepted_licenses: BTreeMap::from([(
                "llvmpkg".to_owned(),
                set(&["GPL-3.0-only WITH LLVM-exception"]),
            )]),
            ..base
        };
        assert!(evaluated(&accepted, &found).passed());
    }
}
