//! Wizard tests, driven with scripted answers like the Python suite's `typer.confirm` stubs.

use super::*;
use crate::context::Terminal;
use crate::prompt::LineSource;
use std::collections::VecDeque;
use std::fs;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use trustedlicenses_core::config::load_policy;
use trustedlicenses_core::index::{IndexError, Response};

/// Feeds pre-scripted answers to `confirm`/`prompt` calls, in order, and records the output.
#[derive(Default)]
struct Script {
    output: Vec<String>,
    confirms: VecDeque<bool>,
    prompts: Option<VecDeque<String>>,
    extra_prompt: String,
}

impl Script {
    fn confirming(confirms: &[bool]) -> Self {
        Self {
            confirms: confirms.iter().copied().collect(),
            ..Self::default()
        }
    }

    fn choosing(confirms: &[bool], prompts: &[&str]) -> Self {
        Self {
            confirms: confirms.iter().copied().collect(),
            prompts: Some(prompts.iter().map(|p| (*p).to_owned()).collect()),
            ..Self::default()
        }
    }

    fn text(&self) -> String {
        self.output.join("\n")
    }
}

impl Prompter for Script {
    fn echo(&mut self, text: &str) {
        self.output.push(text.to_owned());
    }

    fn secho(&mut self, text: &str, _style: Style) {
        self.output.push(text.to_owned());
    }

    fn confirm(&mut self, text: &str, default: bool) -> Result<bool, PromptError> {
        self.output.push(text.to_owned());
        Ok(self.confirms.pop_front().unwrap_or(default))
    }

    fn prompt(&mut self, _text: &str, default: &str) -> Result<String, PromptError> {
        match &mut self.prompts {
            Some(prompts) => Ok(prompts.pop_front().unwrap_or_else(|| default.to_owned())),
            None => Ok(self.extra_prompt.clone()),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

/// A prompter nobody ever answers.
#[derive(Default)]
struct NeverAnswers {
    output: Vec<String>,
}

impl Prompter for NeverAnswers {
    fn echo(&mut self, text: &str) {
        self.output.push(text.to_owned());
    }

    fn secho(&mut self, text: &str, _style: Style) {
        self.output.push(text.to_owned());
    }

    fn confirm(&mut self, _text: &str, _default: bool) -> Result<bool, PromptError> {
        Err(PromptError::Timeout)
    }

    fn prompt(&mut self, _text: &str, _default: &str) -> Result<String, PromptError> {
        Err(PromptError::Timeout)
    }
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn licence(name: &str, keys: &[&str], categories: &[&str]) -> DistributionLicence {
    DistributionLicence {
        name: name.to_owned(),
        keys: set(keys),
        categories: set(categories),
        source: "x".to_owned(),
        ..DistributionLicence::default()
    }
}

fn failure(name: &str) -> DistributionLicence {
    licence(name, &[], &[])
}

fn suggesting(name: &str, statement: &str, spdx_id: &str) -> DistributionLicence {
    DistributionLicence {
        suggested: BTreeSet::from([(statement.to_owned(), spdx_id.to_owned())]),
        ..failure(name)
    }
}

fn wizard() -> InteractiveWizard {
    InteractiveWizard {
        today: Some("2026-09-18".to_owned()),
    }
}

fn setup(io: &mut Script, pyproject: &Path, detected: &[DistributionLicence]) -> Option<PathBuf> {
    wizard().run(io, pyproject, detected).expect("no abort")
}

fn project(body: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempdir().expect("tempdir");
    let path = tmp.path().join("pyproject.toml");
    fs::write(&path, body).expect("write");
    (tmp, path)
}

const BARE: &str = "[project]\nname = 'x'\n";

// ---------------------------------------------------------------------------------
// Initial setup.
// ---------------------------------------------------------------------------------

#[test]
fn run_writes_the_selected_categories_to_pyproject() {
    let (_tmp, pyproject) = project(BARE);
    // setup? yes; Permissive, Public Domain, Copyleft Limited yes; Copyleft no;
    // standalone? no; write? yes.
    let mut io = Script::confirming(&[true, true, true, true, false, false, true]);
    assert_eq!(setup(&mut io, &pyproject, &[]), Some(pyproject.clone()));
    let text = fs::read_to_string(&pyproject).expect("read");
    assert!(text.contains("[tool.trustedlicenses]"));
    for category in ["Permissive", "Public Domain", "Copyleft Limited"] {
        assert!(text.contains(category), "{category}");
    }
    assert!(!text.contains("\"Copyleft\""));
}

#[test]
fn run_asks_about_additional_detected_categories() {
    let (_tmp, pyproject) = project(BARE);
    let detected = [licence("somepkg", &["LicenseRef-x"], &["Proprietary Free"])];
    let mut io = Script::confirming(&[true, true, true, true, false, false, true]);
    io.extra_prompt = "Proprietary Free".to_owned();
    assert_eq!(
        setup(&mut io, &pyproject, &detected),
        Some(pyproject.clone())
    );
    assert!(fs::read_to_string(&pyproject)
        .expect("read")
        .contains("Proprietary Free"));
    assert!(io
        .text()
        .contains("Also detected in your environment: Proprietary Free."));
}

#[test]
fn run_reports_the_detected_license_count_before_asking_anything() {
    let (_tmp, pyproject) = project(BARE);
    let detected = [
        licence("haslicense", &["MIT"], &["Permissive"]),
        failure("nolicense"),
    ];
    let mut io = Script::confirming(&[false]);
    setup(&mut io, &pyproject, &detected);
    assert!(io.output[0].contains("Detected licenses for 1 of 2 installed packages"));
}

#[test]
fn run_reports_per_category_counts_naming_one_or_two() {
    let (_tmp, pyproject) = project(BARE);
    let mut detected = vec![licence("gplpkg", &["GPL-3.0-only"], &["Copyleft"])];
    detected.extend((0..5).map(|i| licence(&format!("pkg{i}"), &["MIT"], &["Permissive"])));
    let mut io = Script::confirming(&[true, false, false, false, false]);
    setup(&mut io, &pyproject, &detected);
    assert!(io.text().contains("(5 detected)"));
    assert!(io.text().contains("(1 detected: gplpkg (GPL-3.0-only))"));
}

#[test]
fn run_does_not_count_a_package_already_covered_by_an_earlier_allowance() {
    let (_tmp, pyproject) = project(BARE);
    let scipy_like = licence(
        "scipy",
        &["BSD-3-Clause", "GPL-3.0-or-later"],
        &["Permissive", "Copyleft"],
    );
    let mut io = Script::confirming(&[true, true, false, false, false]);
    setup(&mut io, &pyproject, &[scipy_like]);
    let copyleft_section = io
        .text()
        .split("Copyleft:")
        .nth(1)
        .expect("section")
        .to_owned();
    assert!(!copyleft_section.contains("scipy"));
    assert!(copyleft_section.contains("(none detected in your environment)"));
}

#[test]
fn run_returns_none_and_writes_nothing_when_declined_or_empty() {
    for confirms in [
        vec![false],
        vec![true, false, false, false, false],
        vec![true, true, false, false, false, false, false],
    ] {
        let (_tmp, pyproject) = project(BARE);
        let mut io = Script::confirming(&confirms);
        assert_eq!(setup(&mut io, &pyproject, &[]), None, "{confirms:?}");
        assert!(!fs::read_to_string(&pyproject)
            .expect("read")
            .contains("[tool.trustedlicenses]"));
    }
}

#[test]
fn run_forces_a_standalone_file_when_pyproject_is_missing() {
    let tmp = tempdir().expect("tempdir");
    let pyproject = tmp.path().join("pyproject.toml");
    // No "save to standalone?" question: setup + 4 categories + write.
    let mut io = Script::confirming(&[true, true, false, false, false, true]);
    let written = setup(&mut io, &pyproject, &[]).expect("written");
    assert_eq!(written, tmp.path().join("trustedlicenses.toml"));
    assert!(written.is_file());
    assert!(!pyproject.is_file());
    assert!(io
        .text()
        .contains("doesn't exist -- writing a separate trustedlicenses.toml."));
}

#[test]
fn run_writes_a_standalone_file_when_explicitly_chosen() {
    let (tmp, pyproject) = project(BARE);
    let original = fs::read_to_string(&pyproject).expect("read");
    let mut io = Script::confirming(&[true, true, false, false, false, true, true]);
    let written = setup(&mut io, &pyproject, &[]).expect("written");
    assert_eq!(written, tmp.path().join("trustedlicenses.toml"));
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), original);
    assert!(fs::read_to_string(&written)
        .expect("read")
        .contains("Permissive"));
}

#[test]
fn run_aborts_gracefully_when_a_prompt_is_never_answered() {
    let (_tmp, pyproject) = project(BARE);
    let mut io = NeverAnswers::default();
    let written = wizard()
        .run(&mut io, &pyproject, &[])
        .expect("not an abort");
    assert_eq!(written, None);
    let output = io.output.join("\n");
    assert!(output.contains("No answer received within"));
    assert!(output.contains("--quiet"));
    assert!(!fs::read_to_string(&pyproject)
        .expect("read")
        .contains("[tool.trustedlicenses]"));
}

// ---------------------------------------------------------------------------------
// Reviewing failures.
// ---------------------------------------------------------------------------------

const POLICY_FILE: &str =
    "[project]\nname = \"x\"\n# keep me\n\n[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n";

/// A stub index: `webencodings` has a newer release that declares MIT. Records requests.
#[derive(Default)]
struct FakeIndex {
    requests: Mutex<Vec<String>>,
    error: Option<IndexError>,
}

impl Client for FakeIndex {
    fn credentials_for(&self, _url: &str) -> String {
        "none".to_owned()
    }

    fn get(
        &self,
        url: &str,
        _accept: Option<&str>,
        _max: Option<usize>,
    ) -> Result<Response, IndexError> {
        self.requests.lock().expect("lock").push(url.to_owned());
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        if url.ends_with(".metadata") {
            return Ok(Response {
                url: url.to_owned(),
                content_type: "text/plain".to_owned(),
                body: b"Name: webencodings\nVersion: 0.6.0\nLicense-Expression: MIT\n".to_vec(),
            });
        }
        let files = serde_json::json!({"files": [
            {"filename": "webencodings-0.5.1-py3-none-any.whl", "url": "https://idx/a.whl", "core-metadata": true},
            {"filename": "webencodings-0.6.0-py3-none-any.whl", "url": "https://idx/b.whl", "core-metadata": true},
        ]});
        Ok(Response {
            url: url.to_owned(),
            content_type: "application/vnd.pypi.simple.v1+json".to_owned(),
            body: serde_json::to_vec(&files).expect("json"),
        })
    }
}

fn review(
    io: &mut Script,
    pyproject: &Path,
    failures: Vec<DistributionLicence>,
    index: &FakeIndex,
) -> bool {
    let policy = load_policy(pyproject).expect("policy");
    let result = PolicyResult {
        checked: failures.len(),
        failures,
        compatibility_notes: Vec::new(),
        exceptions: Vec::new(),
    };
    let env = HashMap::new();
    let services = Services {
        client: index,
        env: &env,
    };
    wizard()
        .review_failures(io, &services, pyproject, &result, &policy)
        .expect("no abort")
}

fn reviewed(io: &mut Script, pyproject: &Path, failures: Vec<DistributionLicence>) -> bool {
    review(io, pyproject, failures, &FakeIndex::default())
}

#[test]
fn review_declines_up_front() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::confirming(&[false]);
    assert!(!reviewed(&mut io, &pyproject, vec![failure("catboost")]));
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), POLICY_FILE);
}

#[test]
fn review_ignoring_one_writes_its_name_and_a_dated_reason() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, true], &["i"]);
    assert!(reviewed(&mut io, &pyproject, vec![failure("catboost")]));
    let text = fs::read_to_string(&pyproject).expect("read");
    assert!(
        text.contains("# no license detected -- accepted 2026-09-18"),
        "{text}"
    );
    assert!(text.contains("# keep me"));
    assert!(load_policy(&pyproject)
        .expect("policy")
        .ignored_packages
        .contains("catboost"));
}

#[test]
fn review_ignoring_a_detected_but_disallowed_package_records_its_keys() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, true], &["i"]);
    let gpl = licence("gplpkg", &["GPL-3.0-only"], &["Copyleft"]);
    assert!(reviewed(&mut io, &pyproject, vec![gpl]));
    assert!(fs::read_to_string(&pyproject)
        .expect("read")
        .contains("detected GPL-3.0-only -- accepted"));
}

#[test]
fn review_allowing_a_category_writes_it_not_the_package() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, true], &["a"]);
    let cons = licence("cons", &["LGPL-3.0-or-later"], &["Copyleft Limited"]);
    assert!(reviewed(&mut io, &pyproject, vec![cons]));
    let policy = load_policy(&pyproject).expect("policy");
    assert_eq!(
        policy.allowed_categories,
        set(&["Permissive", "Copyleft Limited"])
    );
    assert!(!policy.ignored_packages.contains("cons"));
}

#[test]
fn review_verifying_a_package_pins_its_exact_statement() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, true], &["v"]);
    let catboost = suggesting("catboost", "Apache License, Version 2.0", "Apache-2.0");
    assert!(reviewed(&mut io, &pyproject, vec![catboost]));
    let policy = load_policy(&pyproject).expect("policy");
    assert_eq!(
        policy.verified_packages.get("catboost"),
        Some(&(
            "Apache License, Version 2.0".to_owned(),
            "Apache-2.0".to_owned()
        ))
    );
    assert!(!policy.trust_corrected_licenses);
}

#[test]
fn review_trusting_a_statement_pins_it_for_any_package() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, true], &["t"]);
    let catboost = suggesting("catboost", "Apache License, Version 2.0", "Apache-2.0");
    assert!(reviewed(&mut io, &pyproject, vec![catboost]));
    let policy = load_policy(&pyproject).expect("policy");
    assert_eq!(
        policy
            .verified_statements
            .get("Apache License, Version 2.0")
            .map(String::as_str),
        Some("Apache-2.0")
    );
    assert!(policy.verified_packages.is_empty());
}

#[test]
fn review_offers_the_blanket_toggle_at_the_threshold_and_sweeps_both() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    // review? yes; blanket? yes; write? yes. No per-failure prompts: both are swept.
    let mut io = Script::confirming(&[true, true, true]);
    let failures = vec![
        suggesting("catboost", "Apache License, Version 2.0", "Apache-2.0"),
        suggesting("apachepkg2", "Apache Version 2.0", "Apache-2.0"),
    ];
    assert!(reviewed(&mut io, &pyproject, failures));
    let policy = load_policy(&pyproject).expect("policy");
    assert!(policy.trust_corrected_licenses);
    assert!(policy.verified_packages.is_empty());
    assert!(policy.verified_statements.is_empty());
    assert!(io.text().contains("2 failure(s) would resolve if free-text license correction were enabled project-wide (catboost, apachepkg2)"));
}

#[test]
fn review_blanket_offer_excludes_a_suggestion_in_a_disallowed_category() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    // Only catboost's Apache-2.0 (Permissive) is correctable under this policy, so there is
    // no blanket offer: review? yes, then straight to per-failure prompts, then write? yes.
    let mut io = Script::choosing(&[true, true], &["v", "s"]);
    let failures = vec![
        suggesting("catboost", "Apache License, Version 2.0", "Apache-2.0"),
        suggesting(
            "mozillapkg",
            "Mozilla Public License, Version 2.0",
            "MPL-2.0",
        ),
    ];
    assert!(reviewed(&mut io, &pyproject, failures));
    let policy = load_policy(&pyproject).expect("policy");
    assert!(!policy.trust_corrected_licenses);
    assert!(policy.verified_packages.contains_key("catboost"));
}

#[test]
fn review_blanket_offer_names_a_count_above_the_naming_threshold() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::confirming(&[true, true, true]);
    let failures = vec![
        suggesting("pkg-a", "Apache License, Version 2.0", "Apache-2.0"),
        suggesting("pkg-b", "Apache Version 2.0", "Apache-2.0"),
        suggesting("pkg-c", "Zlib License", "Zlib"),
    ];
    reviewed(&mut io, &pyproject, failures);
    let text = io.text();
    assert!(text.contains("3 failure(s)"));
    assert!(text.contains("(3 packages)"));
    assert!(!text.contains("pkg-a, pkg-b, pkg-c"));
}

#[test]
fn review_declining_the_blanket_toggle_falls_through_to_per_case_choices() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, false, true], &["v", "s"]);
    let failures = vec![
        suggesting("catboost", "Apache License, Version 2.0", "Apache-2.0"),
        suggesting("apachepkg2", "Apache Version 2.0", "Apache-2.0"),
    ];
    assert!(reviewed(&mut io, &pyproject, failures));
    let policy = load_policy(&pyproject).expect("policy");
    assert!(!policy.trust_corrected_licenses);
    assert!(policy.verified_packages.contains_key("catboost"));
    assert!(!policy.verified_packages.contains_key("apachepkg2"));
}

#[test]
fn review_bulk_ignore_sweeps_only_the_remaining_undetectable_packages() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    // "b" for pkg-a sweeps pkg-b without a prompt; "s" for pkg-c, which has a category.
    let mut io = Script::choosing(&[true, true], &["b", "s"]);
    let failures = vec![
        failure("pkg-a"),
        failure("pkg-b"),
        licence("pkg-c", &[], &["Copyleft"]),
    ];
    assert!(reviewed(&mut io, &pyproject, failures));
    let policy = load_policy(&pyproject).expect("policy");
    assert_eq!(policy.ignored_packages, set(&["pkg-a", "pkg-b"]));
    assert_eq!(policy.allowed_categories, set(&["Permissive"]));
}

#[test]
fn review_quit_stops_early_but_keeps_prior_decisions() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, true], &["i", "q"]);
    assert!(reviewed(
        &mut io,
        &pyproject,
        vec![failure("pkg-a"), failure("pkg-b"), failure("pkg-c")]
    ));
    assert_eq!(
        load_policy(&pyproject).expect("policy").ignored_packages,
        set(&["pkg-a"])
    );
}

#[test]
fn review_warns_and_skips_on_a_choice_not_offered_for_that_failure() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    // "a" (allow category) isn't offered for a failure with no detected category.
    let mut io = Script::choosing(&[true], &["a"]);
    assert!(!reviewed(&mut io, &pyproject, vec![failure("catboost")]));
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), POLICY_FILE);
    assert!(io
        .text()
        .contains("\"a\" isn't one of the options above -- skipping catboost."));
}

#[test]
fn review_with_nothing_selected_asks_no_final_confirmation() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true], &["s"]);
    assert!(!reviewed(&mut io, &pyproject, vec![failure("catboost")]));
    assert!(io.text().contains("Nothing selected -- nothing to write."));
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), POLICY_FILE);
}

#[test]
fn review_declining_the_final_confirmation_writes_nothing() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, false], &["i"]);
    assert!(!reviewed(&mut io, &pyproject, vec![failure("catboost")]));
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), POLICY_FILE);
}

#[test]
fn review_summary_lists_every_pending_change() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, true], &["i", "a", "v", "t"]);
    let failures = vec![
        failure("catboost"),
        licence("cons", &["LGPL-3.0-or-later"], &["Copyleft Limited"]),
        suggesting("vpkg", "Apache License, Version 2.0", "Apache-2.0"),
        suggesting("tpkg", "Mozilla Public License, Version 2.0", "MPL-2.0"),
    ];
    assert!(reviewed(&mut io, &pyproject, failures));
    let text = io.text();
    for line in [
        "About to update:",
        "  allow category \"Copyleft Limited\"",
        "  ignore catboost  # no license detected -- accepted 2026-09-18",
        "  verify vpkg as Apache-2.0 (text: \"Apache License, Version 2.0\")",
        "  trust \"Mozilla Public License, Version 2.0\" -> MPL-2.0 for any package",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    assert!(text.contains(&format!("  -> {}", pyproject.display())));
    assert!(text.contains(&format!("Updated {}.", pyproject.display())));
}

#[test]
fn review_aborts_gracefully_when_a_prompt_is_never_answered() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let policy = load_policy(&pyproject).expect("policy");
    let result = PolicyResult {
        failures: vec![failure("catboost")],
        checked: 1,
        compatibility_notes: Vec::new(),
        exceptions: Vec::new(),
    };
    let index = FakeIndex::default();
    let env = HashMap::new();
    let services = Services {
        client: &index,
        env: &env,
    };
    let mut io = NeverAnswers::default();
    let changed = wizard()
        .review_failures(&mut io, &services, &pyproject, &result, &policy)
        .expect("not an abort");
    assert!(!changed);
    assert!(io
        .output
        .join("\n")
        .contains("stopping the review. Nothing has been written."));
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), POLICY_FILE);
}

// ---------------------------------------------------------------------------------
// The index check offered from a review.
// ---------------------------------------------------------------------------------

fn webencodings() -> DistributionLicence {
    DistributionLicence {
        version: "0.5.1".to_owned(),
        ..failure("webencodings")
    }
}

#[test]
fn only_undetected_failures_are_offered_the_index_check() {
    assert!(failure_options(&failure("webencodings")).contains("[c]heck"));
    assert!(!failure_options(&licence("mitpkg", &["MIT"], &[])).contains("[c]heck"));
}

#[test]
fn index_check_declined_sends_nothing_and_asks_again() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let index = FakeIndex::default();
    let mut io = Script::choosing(&[true, false], &["c", "s"]);
    assert!(!review(&mut io, &pyproject, vec![webencodings()], &index));
    assert!(index.requests.lock().expect("lock").is_empty());
    assert!(io
        .text()
        .contains("about \"webencodings\"? Only its name is sent."));
}

#[test]
fn index_check_accepted_reports_then_asks_again_and_writes_nothing() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let index = FakeIndex::default();
    let mut io = Script::choosing(&[true, true], &["c", "s"]);
    assert!(!review(&mut io, &pyproject, vec![webencodings()], &index));
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), POLICY_FILE);
    assert!(!index.requests.lock().expect("lock").is_empty());
    assert!(
        io.text()
            .contains("0.6.0 is the first newer release that ships a license (declares MIT)"),
        "{}",
        io.text()
    );
}

#[test]
fn index_check_can_be_followed_by_a_real_decision() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let index = FakeIndex::default();
    let mut io = Script::choosing(&[true, true, true], &["c", "i"]);
    assert!(review(&mut io, &pyproject, vec![webencodings()], &index));
    assert!(load_policy(&pyproject)
        .expect("policy")
        .ignored_packages
        .contains("webencodings"));
}

#[test]
fn index_check_failure_is_shown_not_raised() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let index = FakeIndex {
        error: Some(IndexError::Http {
            status: 401,
            message:
                "https://nexus rejected the request (401). Credentials come from your environment."
                    .to_owned(),
        }),
        ..FakeIndex::default()
    };
    let mut io = Script::choosing(&[true, true], &["c", "s"]);
    assert!(!review(&mut io, &pyproject, vec![webencodings()], &index));
    assert!(io.text().contains("rejected the request (401)"));
}

#[test]
fn the_index_check_choice_is_invalid_for_a_detected_package() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let index = FakeIndex::default();
    let mut io = Script::choosing(&[true], &["c"]);
    let gpl = licence("gplpkg", &["GPL-3.0-only"], &["Copyleft"]);
    review(&mut io, &pyproject, vec![gpl], &index);
    assert!(index.requests.lock().expect("lock").is_empty());
    assert!(io.text().contains("isn't one of the options"));
}

// ---------------------------------------------------------------------------------
// Small pieces, and the real terminal prompts.
// ---------------------------------------------------------------------------------

#[test]
fn civil_dates_match_python() {
    for (days, expected) in [
        (0, "1970-01-01"),
        (59, "1970-03-01"),
        (60, "1970-03-02"),
        (365, "1971-01-01"),
        (11_016, "2000-02-29"),
        (19_000, "2022-01-08"),
        (20_000, "2024-10-04"),
        (25_000, "2038-06-13"),
        (-1, "1969-12-31"),
    ] {
        assert_eq!(civil_date(days), expected, "{days}");
    }
}

#[test]
fn a_mixed_batch_keeps_first_seen_order_and_replaces_in_place() {
    let mut entries = vec![("a".to_owned(), 1), ("b".to_owned(), 2)];
    set_ordered(&mut entries, "a".to_owned(), 9);
    set_ordered(&mut entries, "c".to_owned(), 3);
    assert_eq!(
        entries,
        [
            ("a".to_owned(), 9),
            ("b".to_owned(), 2),
            ("c".to_owned(), 3)
        ]
    );
}

#[derive(Clone, Default)]
struct Out(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Out {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn terminal(input: &str, tty: bool) -> (Terminal, Out) {
    let out = Out::default();
    let term = Terminal {
        out: Box::new(out.clone()),
        err: Box::new(Out::default()),
        input: LineSource::Direct(Box::new(Cursor::new(input.as_bytes().to_vec()))),
        prompt_timeout: Duration::from_millis(50),
        color: false,
        stdin_is_tty: tty,
    };
    (term, out)
}

fn written(out: &Out) -> String {
    String::from_utf8_lossy(&out.0.lock().expect("lock")).into_owned()
}

#[test]
fn terminal_confirm_follows_click_conventions() {
    let (mut term, out) = terminal("y\n\nNO\nmaybe\nyes\n", false);
    assert_eq!(term.confirm("Go?", true), Ok(true));
    assert_eq!(
        term.confirm("Go?", false),
        Ok(false),
        "empty answer takes the default"
    );
    assert_eq!(term.confirm("Go?", true), Ok(false));
    assert_eq!(
        term.confirm("Go?", false),
        Ok(true),
        "invalid input is re-asked"
    );
    let text = written(&out);
    assert!(text.starts_with("Go? [Y/n]: y\n"), "{text}");
    assert!(text.contains("Go? [y/N]: \n"));
    assert!(
        text.contains("Error: invalid input\nGo? [y/N]: yes\n"),
        "{text}"
    );
}

#[test]
fn terminal_prompt_returns_the_default_for_an_empty_answer() {
    let (mut term, out) = terminal("\ntext, more\n", true);
    assert_eq!(term.prompt("  Choice", "s"), Ok("s".to_owned()));
    assert_eq!(term.prompt("  Choice", "s"), Ok("text, more".to_owned()));
    assert_eq!(
        written(&out),
        "  Choice: ".to_owned() + "  Choice: ",
        "a real terminal echoes its own input"
    );
}

#[test]
fn terminal_input_that_ends_aborts() {
    let (mut term, _out) = terminal("", false);
    assert_eq!(term.confirm("Go?", true), Err(PromptError::Aborted));
    assert_eq!(term.prompt("Name", ""), Err(PromptError::Aborted));
}

#[test]
fn a_prompt_nobody_answers_times_out_instead_of_hanging() {
    let (_keep_open, receiver) = {
        let (sender, receiver) = std::sync::mpsc::channel::<String>();
        (sender, receiver)
    };
    let mut term = terminal("", false).0;
    term.input = LineSource::Threaded(receiver);
    assert_eq!(term.confirm("Go?", true), Err(PromptError::Timeout));
    assert_eq!(term.prompt("Name", ""), Err(PromptError::Timeout));
}

#[test]
fn a_threaded_reader_delivers_lines_in_order() {
    let mut term = terminal("", false).0;
    term.prompt_timeout = Duration::from_secs(5);
    term.input = LineSource::threaded(Box::new(Cursor::new(b"one\ntwo\n".to_vec())));
    assert_eq!(term.prompt("a", ""), Ok("one".to_owned()));
    assert_eq!(term.prompt("b", ""), Ok("two".to_owned()));
    assert_eq!(
        term.prompt("c", ""),
        Err(PromptError::Aborted),
        "end of input once the reader finishes"
    );
}

#[test]
fn review_accepting_a_license_writes_that_package_and_license_only() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true, true], &["l"]);
    let certifi = licence("certifi", &["MPL-2.0"], &["Copyleft Limited"]);
    assert!(reviewed(&mut io, &pyproject, vec![certifi]));
    let policy = load_policy(&pyproject).expect("policy");
    assert_eq!(policy.accepted_licenses["certifi"], set(&["MPL-2.0"]));
    assert!(policy.ignored_packages.is_empty() || !policy.ignored_packages.contains("certifi"));
    assert!(!policy.allowed_categories.contains("Copyleft Limited"));
    assert!(
        io.text().contains("accept MPL-2.0 for certifi only"),
        "{}",
        io.text()
    );
}

#[test]
fn review_offers_the_license_option_only_for_a_detected_license() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true], &["s"]);
    reviewed(&mut io, &pyproject, vec![failure("bare")]);
    assert!(!io.text().contains("[l]ccept"), "{}", io.text());
    assert!(
        io.text().contains("[u]nlicensed packages are fine"),
        "{}",
        io.text()
    );

    let mut io = Script::choosing(&[true], &["s"]);
    let certifi = licence("certifi", &["MPL-2.0"], &["Copyleft Limited"]);
    reviewed(&mut io, &pyproject, vec![certifi]);
    assert!(
        io.text().contains("[l]ccept MPL-2.0 for this package only"),
        "{}",
        io.text()
    );
    assert!(!io.text().contains("[u]nlicensed"), "{}", io.text());
}

#[test]
fn review_allowing_unlicensed_writes_the_key_and_stops_asking_about_the_rest() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    // One answer: the second unlicensed package must not prompt.
    let mut io = Script::choosing(&[true, true], &["u"]);
    assert!(reviewed(
        &mut io,
        &pyproject,
        vec![failure("internal-a"), failure("internal-b")]
    ));
    let policy = load_policy(&pyproject).expect("policy");
    assert!(policy.allow_unlicensed);
    assert!(policy.ignored_packages.is_empty());
}

#[test]
fn review_unlicensed_is_not_offered_for_a_free_text_statement() {
    let (_tmp, pyproject) = project(POLICY_FILE);
    let mut io = Script::choosing(&[true], &["u"]);
    let wordy = suggesting("wordy", "Apache License, Version 2.0", "Apache-2.0");
    assert!(!reviewed(&mut io, &pyproject, vec![wordy]));
    assert!(!load_policy(&pyproject).expect("policy").allow_unlicensed);
}
