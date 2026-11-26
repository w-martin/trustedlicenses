//! CLI tests, driven through `run` with a captured terminal, a stub index and resolver.

use super::*;
use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::{tempdir, TempDir};
use trustedlicenses_core::config::{add_to_policy, PolicyAdditions};
use trustedlicenses_core::detection::DistributionLicence;
use trustedlicenses_core::index::{Client, IndexError, Response};
use trustedlicenses_core::policy::{Policy, PolicyResult};

const MIT_TEXT: &str = include_str!("../../tests/fixtures/mit.txt");
const GPL_TEXT: &str = include_str!("../../tests/fixtures/gpl-2.0.txt");
const PERMISSIVE: &str = "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n";

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }
}

/// A scripted index: `files[name]` lists `(version, METADATA text)`. Records every request.
type Releases = HashMap<String, Vec<(String, String)>>;

#[derive(Clone, Default)]
struct StubIndex {
    files: Arc<Mutex<Releases>>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl StubIndex {
    fn publish(&self, name: &str, version: &str, license_expression: &str) {
        let metadata = format!(
            "Metadata-Version: 2.4\nName: {name}\nVersion: {version}\nLicense-Expression: {license_expression}\n"
        );
        self.files
            .lock()
            .expect("lock")
            .entry(name.to_owned())
            .or_default()
            .push((version.to_owned(), metadata));
    }

    fn request_count(&self) -> usize {
        self.requests.lock().expect("lock").len()
    }
}

impl Client for StubIndex {
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
        let files = self.files.lock().expect("lock");
        let not_found = || {
            IndexError::Http {
            status: 404,
            message: format!("{url} not found on this index (a package that isn't published there, e.g. an internal one)."),
        }
        };
        if let Some(metadata_for) = url.strip_suffix(".metadata") {
            let file = metadata_for.rsplit('/').next().expect("file");
            let (name, rest) = file.split_once('-').expect("name-version");
            let version = rest.split("-py3").next().expect("version");
            let text = files
                .get(name)
                .and_then(|releases| releases.iter().find(|(v, _)| v == version))
                .map(|(_, text)| text.clone())
                .ok_or_else(not_found)?;
            return Ok(Response {
                url: url.to_owned(),
                content_type: "text/plain".to_owned(),
                body: text.into_bytes(),
            });
        }
        let name = url.trim_end_matches('/').rsplit('/').next().expect("name");
        let releases = files.get(name).ok_or_else(not_found)?;
        let entries: Vec<serde_json::Value> = releases
            .iter()
            .map(|(version, _)| {
                let file = format!("{name}-{version}-py3-none-any.whl");
                serde_json::json!({"filename": file, "url": format!("https://idx/files/{file}"), "core-metadata": true})
            })
            .collect();
        Ok(Response {
            url: url.to_owned(),
            content_type: "application/vnd.pypi.simple.v1+json".to_owned(),
            body: serde_json::to_vec(&serde_json::json!({ "files": entries })).expect("json"),
        })
    }
}

/// Writes a fixed set of distributions into the resolve target.
struct StubResolver {
    distributions: Vec<(&'static str, Option<&'static str>, Option<&'static str>)>,
    error: Option<String>,
}

impl Resolver for StubResolver {
    fn resolve(
        &self,
        _packages: &[String],
        target: &Path,
        _python: Option<&Path>,
    ) -> Result<(), String> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        for (name, declared, license_text) in &self.distributions {
            write_dist(target, name, *declared, *license_text);
        }
        Ok(())
    }
}

fn write_dist(site: &Path, name: &str, declared: Option<&str>, license_text: Option<&str>) {
    let dist_info = site.join(format!("{name}-1.0.dist-info"));
    fs::create_dir_all(&dist_info).expect("mkdir");
    let mut metadata = format!("Metadata-Version: 2.4\nName: {name}\nVersion: 1.0\n");
    if let Some(declared) = declared {
        metadata.push_str(&format!("License-Expression: {declared}\n"));
    }
    fs::write(dist_info.join("METADATA"), metadata).expect("write");
    if let Some(text) = license_text {
        fs::write(dist_info.join("LICENSE"), text).expect("write");
    }
}

/// A scripted wizard standing in for the interactive flows.
#[derive(Default)]
struct ScriptedWizard {
    setup_policy: Option<String>,
    ignore_on_review: Option<String>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl Wizard for ScriptedWizard {
    fn run(
        &mut self,
        _io: &mut dyn Prompter,
        pyproject: &Path,
        _detected: &[DistributionLicence],
    ) -> Result<Option<PathBuf>, PromptError> {
        self.calls.lock().expect("lock").push("run");
        let Some(body) = self.setup_policy.clone() else {
            return Ok(None);
        };
        let existing = fs::read_to_string(pyproject).unwrap_or_default();
        fs::write(pyproject, format!("{existing}{body}")).expect("write");
        Ok(Some(pyproject.to_path_buf()))
    }

    fn review_failures(
        &mut self,
        _io: &mut dyn Prompter,
        _services: &Services<'_>,
        path: &Path,
        _result: &PolicyResult,
        _policy: &Policy,
    ) -> Result<bool, PromptError> {
        self.calls.lock().expect("lock").push("review");
        let Some(name) = self.ignore_on_review.clone() else {
            return Ok(false);
        };
        add_to_policy(
            path,
            &PolicyAdditions {
                ignored_packages: vec![name],
                ..PolicyAdditions::default()
            },
        )
        .expect("add");
        Ok(true)
    }
}

struct Harness {
    tmp: TempDir,
    index: StubIndex,
    tty: bool,
    resolver: Option<StubResolver>,
    wizard: ScriptedWizard,
    cache: Option<PathBuf>,
    env: HashMap<String, String>,
}

struct Outcome {
    _tmp: TempDir,
    code: i32,
    out: String,
    err: String,
}

impl Harness {
    fn new() -> Self {
        let tmp = tempdir().expect("tempdir");
        Self {
            index: StubIndex::default(),
            tty: false,
            resolver: None,
            wizard: ScriptedWizard::default(),
            cache: Some(tmp.path().join("cache")),
            env: HashMap::from([(
                "HOME".to_owned(),
                tmp.path().join("home").display().to_string(),
            )]),
            tmp,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    fn pyproject(&self, body: &str) -> PathBuf {
        let path = self.path("pyproject.toml");
        fs::write(&path, body).expect("write");
        path
    }

    /// An installed environment under `venv/`, one entry per `(name, declared license)`.
    fn venv(&self, packages: &[(&str, Option<&str>, Option<&str>)]) -> PathBuf {
        let site = self.path("venv/lib/python3.13/site-packages");
        fs::create_dir_all(&site).expect("mkdir");
        for (name, declared, text) in packages {
            write_dist(&site, name, *declared, *text);
        }
        self.path("venv")
    }

    fn run(self, args: &[&str]) -> Outcome {
        // The scan-result cache directory is process-wide, as the process is the unit that has one, so
        // the invocations in these tests must not overlap.
        static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
        let _serial = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Self {
            tmp,
            index,
            tty,
            resolver,
            wizard,
            cache,
            env,
        } = self;
        let out = Shared::default();
        let err = Shared::default();
        let mut context = Context {
            term: Terminal {
                out: Box::new(out.clone()),
                err: Box::new(err.clone()),
                input: LineSource::Direct(Box::new(Cursor::new(Vec::new()))),
                prompt_timeout: std::time::Duration::from_millis(50),
                color: false,
                stdin_is_tty: tty,
            },
            env,
            client: Box::new(index.clone()),
            resolver: Box::new(resolver.unwrap_or(StubResolver {
                distributions: Vec::new(),
                error: Some("no resolver configured".to_owned()),
            })),
            wizard: Box::new(wizard),
            cache_dir: cache,
        };
        let mut argv: Vec<OsString> = vec!["trustedlicenses".into()];
        argv.extend(args.iter().map(OsString::from));
        let code = run(&argv, &mut context);
        Outcome {
            _tmp: tmp,
            code,
            out: out.text(),
            err: err.text(),
        }
    }
}

fn s(path: &Path) -> String {
    path.display().to_string()
}

// ---------------------------------------------------------------------------------
// The default command: the installed environment.
// ---------------------------------------------------------------------------------

#[test]
fn returns_zero_when_everything_passes() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[
        ("a", Some("MIT"), None),
        ("b", Some("BSD-3-Clause"), None),
        ("c", None, Some(MIT_TEXT)),
    ]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("All 3 packages passed."), "{}", r.out);
}

#[test]
fn returns_one_when_a_package_fails() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[
        ("a", Some("MIT"), None),
        ("gplpkg", Some("GPL-2.0-only"), None),
        ("c", Some("MIT"), None),
    ]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 1);
    assert!(
        r.out
            .contains("Disallowed or undetectable licenses in 1 of 3 packages"),
        "{}",
        r.out
    );
    assert!(r.out.contains(
        "gplpkg: detected GPL-2.0-only (categories: Copyleft) -- from declared metadata"
    ));
    assert!(r.out.contains(
        "to accept only this license for this package, add `gplpkg = [\"GPL-2.0-only\"]` under [tool.trustedlicenses.accepted-licenses]"
    ));
    assert!(r.out.contains("or add \"Copyleft\" to allowed-categories"));
}

#[test]
fn prints_compatibility_notes_without_affecting_the_exit_code() {
    let h = Harness::new();
    let pyproject = h.pyproject(
        &format!("[project]\nname = \"x\"\nlicense = \"MIT\"\n{PERMISSIVE}").replace(
            "allowed-categories = [\"Permissive\"]",
            "allowed-categories = [\"Copyleft\"]",
        ),
    );
    let venv = h.venv(&[("gplpkg", Some("GPL-3.0-or-later"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("1 compatibility note(s)"));
    assert!(r
        .out
        .contains("gplpkg: detected GPL-3.0-or-later (strong copyleft)"));
    assert!(r.out.contains("All 1 packages passed."));
}

#[test]
fn a_broken_config_exits_one_and_reports_it() {
    let h = Harness::new();
    let pyproject = h.pyproject("[tool.trustedlicenses]\nallowed-categories = []\n");
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("trustedlicenses: "));
    assert!(r.out.contains("allowed-categories"));
}

#[test]
fn falls_back_to_report_mode_when_not_interactive() {
    let h = Harness::new();
    let pyproject = h.pyproject("[project]\nname = 'unconfigured'\n");
    let venv = h.venv(&[("somepkg", Some("MIT"), None), ("nolicense", None, None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("no policy configured"));
    assert!(r.out.contains("  somepkg: MIT (Permissive)"), "{}", r.out);
    assert!(
        r.out.contains("  nolicense: no license detected (none)"),
        "{}",
        r.out
    );
    assert!(r.out.contains("Add a policy"));
}

#[test]
fn quiet_forces_report_mode_even_on_a_terminal_and_never_calls_the_wizard() {
    let mut h = Harness::new();
    h.tty = true;
    let calls = Arc::clone(&h.wizard.calls);
    let pyproject = h.pyproject("[project]\nname = 'unconfigured'\n");
    let venv = h.venv(&[]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--quiet",
    ]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("no policy configured"));
    assert!(calls.lock().expect("lock").is_empty());
}

#[test]
fn runs_the_wizard_when_there_is_no_policy_and_a_terminal() {
    let mut h = Harness::new();
    h.tty = true;
    h.wizard.setup_policy =
        Some("\n[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n".to_owned());
    let pyproject = h.pyproject("[project]\nname = 'consuming-project'\n");
    let venv = h.venv(&[("a", Some("MIT"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("All 1 packages passed."));
    assert!(fs::read_to_string(&pyproject)
        .expect("read")
        .contains("[tool.trustedlicenses]"));
}

#[test]
fn reports_no_policy_when_the_wizard_is_declined() {
    let mut h = Harness::new();
    h.tty = true;
    let pyproject = h.pyproject("[project]\nname = 'consuming-project'\n");
    let venv = h.venv(&[]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("no policy configured"));
    assert!(!fs::read_to_string(&pyproject)
        .expect("read")
        .contains("[tool.trustedlicenses]"));
}

#[test]
fn never_offers_a_review_when_not_interactive_or_quiet() {
    for (tty, extra) in [(false, None), (true, Some("--quiet"))] {
        let mut h = Harness::new();
        h.tty = tty;
        let calls = Arc::clone(&h.wizard.calls);
        let pyproject = h.pyproject(PERMISSIVE);
        let venv = h.venv(&[("catboost", None, None)]);
        let mut args = vec![
            "--pyproject".to_owned(),
            s(&pyproject),
            "--venv".to_owned(),
            s(&venv),
        ];
        args.extend(extra.map(str::to_owned));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = h.run(&args);
        assert_eq!(r.code, 1);
        assert!(!r.out.contains("Review"));
        assert!(calls.lock().expect("lock").is_empty());
    }
}

#[test]
fn offers_a_review_after_a_failing_check_and_re_evaluates() {
    let mut h = Harness::new();
    h.tty = true;
    h.wizard.ignore_on_review = Some("catboost".to_owned());
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[("catboost", None, None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("Re-checking against the updated policy"));
    assert!(r.out.contains("All 0 packages passed."), "{}", r.out);
    assert!(fs::read_to_string(&pyproject)
        .expect("read")
        .contains("catboost"));
}

#[test]
fn keeps_the_failing_exit_code_when_the_review_is_declined() {
    let mut h = Harness::new();
    h.tty = true;
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[("catboost", None, None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 1);
    assert!(!r.out.contains("Re-checking"));
    assert!(!fs::read_to_string(&pyproject)
        .expect("read")
        .contains("catboost"));
}

#[test]
fn a_plain_installed_check_makes_no_network_requests() {
    let h = Harness::new();
    let index = h.index.clone();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[("a", Some("MIT"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0);
    assert_eq!(index.request_count(), 0);
}

// ---------------------------------------------------------------------------------
// check <package>: resolve into an isolated directory first.
// ---------------------------------------------------------------------------------

fn resolving(
    distributions: Vec<(&'static str, Option<&'static str>, Option<&'static str>)>,
) -> StubResolver {
    StubResolver {
        distributions,
        error: None,
    }
}

#[test]
fn check_passes_a_resolved_package() {
    let mut h = Harness::new();
    h.resolver = Some(resolving(vec![("requests", None, Some(MIT_TEXT))]));
    let pyproject = h.pyproject(PERMISSIVE);
    let r = h.run(&["--pyproject", &s(&pyproject), "check", "requests"]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r
        .out
        .contains("Resolving requests and its transitive dependencies..."));
    assert!(r
        .out
        .contains("Checking 1 package(s) (requested plus transitive dependencies)..."));
    assert!(r.out.contains("All 1 packages passed."));
}

#[test]
fn check_fails_a_disallowed_transitive_dependency() {
    let mut h = Harness::new();
    h.resolver = Some(resolving(vec![("gplpkg", None, Some(GPL_TEXT))]));
    let pyproject = h.pyproject(PERMISSIVE);
    let r = h.run(&["--pyproject", &s(&pyproject), "check", "gplpkg"]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("gplpkg"));
}

#[test]
fn check_reports_a_resolution_failure() {
    let mut h = Harness::new();
    h.resolver = Some(StubResolver {
        distributions: Vec::new(),
        error: Some(
            "could not resolve definitely-not-a-real-package-xyz: no matching distribution"
                .to_owned(),
        ),
    });
    let pyproject = h.pyproject(PERMISSIVE);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "check",
        "definitely-not-a-real-package-xyz",
    ]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("could not resolve"));
}

#[test]
fn check_needs_a_configured_policy_when_not_interactive() {
    let h = Harness::new();
    let pyproject = h.pyproject("[project]\nname = 'unconfigured'\n");
    let r = h.run(&["--pyproject", &s(&pyproject), "check", "requests"]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("no policy configured"));
}

#[test]
fn check_reports_a_broken_config() {
    let h = Harness::new();
    let pyproject = h.pyproject("[tool.trustedlicenses]\nallowed-categories = []\n");
    let r = h.run(&["--pyproject", &s(&pyproject), "check", "requests"]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("allowed-categories"));
}

// ---------------------------------------------------------------------------------
// index-check
// ---------------------------------------------------------------------------------

#[test]
fn index_check_uses_the_lock_files_index_and_the_installed_version() {
    let h = Harness::new();
    let pyproject = h.pyproject("[project]\nname = 'x'\n");
    fs::write(
        h.path("uv.lock"),
        "[[package]]\nname = \"pytest\"\nversion = \"1\"\nsource = { registry = \"https://nexus.example.com/simple\" }\n",
    )
    .expect("write");
    h.index.publish("pytest", "1.0", "MIT");
    h.index.publish("pytest", "2.0", "MIT");
    let venv = h.venv(&[("pytest", Some("MIT"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "index-check",
        "pytest",
    ]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(
        r.out
            .contains("Asking https://nexus.example.com/simple (from uv.lock) about 'pytest'..."),
        "{}",
        r.out
    );
    assert!(r.out.contains("pytest 1.0:"), "{}", r.out);
    assert!(
        r.out
            .contains("2.0 is the first newer release that ships a license (declares MIT)"),
        "{}",
        r.out
    );
}

#[test]
fn index_check_reports_an_unreachable_index_and_exits_one() {
    let h = Harness::new();
    let pyproject = h.pyproject("[project]\nname = 'x'\n");
    let r = h.run(&["--pyproject", &s(&pyproject), "index-check", "webencodings"]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("not found on this index"), "{}", r.out);
}

#[test]
fn index_check_handles_a_package_that_is_not_installed() {
    let h = Harness::new();
    let pyproject = h.pyproject("[project]\nname = 'x'\n");
    h.index
        .publish("definitely-not-installed-xyz", "1.0", "MIT");
    let venv = h.venv(&[]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "index-check",
        "definitely-not-installed-xyz",
    ]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("(not installed)"), "{}", r.out);
}

// ---------------------------------------------------------------------------------
// Lock-file mode.
// ---------------------------------------------------------------------------------

fn uv_lock(packages: &[(&str, &str)]) -> String {
    packages
        .iter()
        .map(|(name, version)| {
            format!(
                "[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = {{ registry = \"https://idx/simple\" }}\n\n"
            )
        })
        .collect()
}

#[test]
fn a_lock_file_beside_pyproject_is_audited_through_the_index() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(
        h.path("uv.lock"),
        uv_lock(&[("alpha", "1.0"), ("beta", "2.0")]),
    )
    .expect("write");
    h.index.publish("alpha", "1.0", "MIT");
    h.index.publish("beta", "2.0", "Apache-2.0");
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains(
        "Reading 2 package(s) pinned in uv.lock; license metadata comes from the package index."
    ));
    assert!(r.out.contains("All 2 packages passed."));
}

#[test]
fn a_disallowed_license_in_a_lock_file_fails() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(
        h.path("uv.lock"),
        uv_lock(&[("alpha", "1.0"), ("gplpkg", "3.0")]),
    )
    .expect("write");
    h.index.publish("alpha", "1.0", "MIT");
    h.index.publish("gplpkg", "3.0", "GPL-3.0-only");
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 1);
    assert!(
        r.out
            .contains("gplpkg: detected GPL-3.0-only (categories: Copyleft)"),
        "{}",
        r.out
    );
}

#[test]
fn a_git_dependency_fails_closed_with_the_reason() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(
        h.path("uv.lock"),
        "[[package]]\nname = \"gitdep\"\nversion = \"0.1\"\nsource = { git = \"https://user:pw@github.com/x/y?rev=abc#abc\" }\n",
    )
    .expect("write");
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 1);
    assert!(
        r.out.contains(
            "gitdep: no license detected -- from lock file: git source https://github.com/x/y"
        ),
        "{}",
        r.out
    );
    assert!(
        !r.out.contains("pw@"),
        "credentials must not be printed: {}",
        r.out
    );
}

#[test]
fn a_package_missing_from_the_index_fails_closed() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(h.path("uv.lock"), uv_lock(&[("internal", "1.0")])).expect("write");
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 1);
    assert!(
        r.out
            .contains("internal: no license detected -- from package index:"),
        "{}",
        r.out
    );
}

#[test]
fn ignored_packages_are_not_looked_up() {
    let h = Harness::new();
    let index = h.index.clone();
    let pyproject = h.pyproject(
        "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\nignored-packages = [\"internal\"]\n",
    );
    fs::write(
        h.path("uv.lock"),
        uv_lock(&[("alpha", "1.0"), ("internal", "1.0")]),
    )
    .expect("write");
    index.publish("alpha", "1.0", "MIT");
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("All 1 packages passed."));
    assert!(!index
        .requests
        .lock()
        .expect("lock")
        .iter()
        .any(|u| u.contains("internal")));
}

#[test]
fn installed_flag_ignores_the_lock_file() {
    let h = Harness::new();
    let index = h.index.clone();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(h.path("uv.lock"), uv_lock(&[("alpha", "1.0")])).expect("write");
    let venv = h.venv(&[("local", Some("MIT"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--installed",
        "--venv",
        &s(&venv),
    ]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("All 1 packages passed."));
    assert_eq!(index.request_count(), 0);
}

#[test]
fn an_explicit_requirements_file_is_audited_but_loose_ranges_are_refused() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    h.index.publish("alpha", "1.0", "MIT");
    fs::write(h.path("requirements.txt"), "alpha==1.0\n").expect("write");
    let requirements = h.path("requirements.txt");
    let index = h.index.clone();
    let r = h.run(&["--pyproject", &s(&pyproject), "--lock", &s(&requirements)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("All 1 packages passed."));

    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(h.path("requirements.txt"), "alpha>=1\n").expect("write");
    let requirements = h.path("requirements.txt");
    let r = h.run(&["--pyproject", &s(&pyproject), "--lock", &s(&requirements)]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("not pinned with =="), "{}", r.out);
    drop(index);
}

#[test]
fn a_loose_requirements_file_is_never_picked_up_automatically() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(h.path("requirements.txt"), "alpha>=1\n").expect("write");
    let venv = h.venv(&[("a", Some("MIT"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
}

#[test]
fn a_second_run_is_served_from_the_cache_and_offline_uses_only_the_cache() {
    let h = Harness::new();
    let cache = h.cache.clone();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(h.path("uv.lock"), uv_lock(&[("alpha", "1.0")])).expect("write");
    h.index.publish("alpha", "1.0", "MIT");
    let first_index = h.index.clone();
    let tmp_root = h.tmp.path().to_path_buf();
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(first_index.request_count() > 0);

    // Same project and cache, but an index that knows nothing: only the cache can answer.
    let mut second = Harness::new();
    second.cache = cache;
    let pyproject2 = tmp_root.join("pyproject.toml");
    let r = second.run(&["--pyproject", &s(&pyproject2), "--offline"]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("(--offline: local cache only)"));
    assert!(r.out.contains("All 1 packages passed."));
}

#[test]
fn offline_with_an_empty_cache_fails_closed() {
    let h = Harness::new();
    let index = h.index.clone();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(h.path("uv.lock"), uv_lock(&[("alpha", "1.0")])).expect("write");
    index.publish("alpha", "1.0", "MIT");
    let r = h.run(&["--pyproject", &s(&pyproject), "--offline"]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("--offline"), "{}", r.out);
    assert_eq!(index.request_count(), 0, "offline must not reach the index");
}

#[test]
fn no_cache_fetches_every_time() {
    let h = Harness::new();
    let index = h.index.clone();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(h.path("uv.lock"), uv_lock(&[("alpha", "1.0")])).expect("write");
    index.publish("alpha", "1.0", "MIT");
    let cache = h.cache.clone().expect("cache");
    let r = h.run(&["--pyproject", &s(&pyproject), "--no-cache"]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(index.request_count() > 0);
    assert!(
        !cache.exists(),
        "--no-cache must not write to the cache directory"
    );
}

#[test]
fn report_mode_works_from_a_lock_file_too() {
    let h = Harness::new();
    let pyproject = h.pyproject("[project]\nname = 'x'\n");
    fs::write(h.path("uv.lock"), uv_lock(&[("alpha", "1.0")])).expect("write");
    h.index.publish("alpha", "1.0", "MIT");
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(r.out.contains("  alpha: MIT (Permissive)"), "{}", r.out);
}

// ---------------------------------------------------------------------------------
// Argument handling.
// ---------------------------------------------------------------------------------

#[test]
fn usage_errors_exit_two_on_stderr_and_help_exits_zero_on_stdout() {
    let r = Harness::new().run(&["--no-such-flag"]);
    assert_eq!(r.code, 2);
    assert!(r.err.contains("--no-such-flag"));

    let r = Harness::new().run(&["--lock", "uv.lock", "--installed"]);
    assert_eq!(r.code, 2);

    let r = Harness::new().run(&["--lock", "mystery.bin"]);
    assert_eq!(r.code, 1);
    assert!(r.out.contains("cannot tell what kind of lock file"));

    let r = Harness::new().run(&["--help"]);
    assert_eq!(r.code, 0);
    assert!(r.out.contains("--pyproject"));
    assert!(r.out.contains("index-check"));

    let r = Harness::new().run(&["check"]);
    assert_eq!(r.code, 2);
}

// ---------------------------------------------------------------------------------
// The persistent scan-result cache.
// ---------------------------------------------------------------------------------

fn entries_under(dir: &Path) -> usize {
    let mut count = 0;
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            count += entries_under(&path);
        } else {
            count += 1;
        }
    }
    count
}

/// A license text no other test scans, so the in-process cache cannot answer for the disk one.
fn unique_license(tag: &str) -> String {
    format!("{MIT_TEXT}\n\nlocal notice {tag}\n")
}

#[test]
fn scanned_license_text_is_cached_on_disk_beside_the_other_caches() {
    let h = Harness::new();
    let cache = h.cache.clone().expect("cache");
    let pyproject = h.pyproject(PERMISSIVE);
    let text = unique_license("disk-cache-test");
    let venv = h.venv(&[("filepkg", None, Some(text.as_str()))]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        entries_under(&cache.join("matches")) >= 1,
        "no scan result was cached"
    );
}

#[test]
fn no_cache_leaves_no_scan_results_behind() {
    let h = Harness::new();
    let cache = h.cache.clone().expect("cache");
    let pyproject = h.pyproject(PERMISSIVE);
    let text = unique_license("no-cache-test");
    let venv = h.venv(&[("filepkg", None, Some(text.as_str()))]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--no-cache",
    ]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        !cache.exists(),
        "--no-cache must not create the cache directory"
    );
}

const GROUPED_LOCK: &str = r#"
[[package]]
name = "me"
version = "0.1"
source = { editable = "." }
dependencies = [{ name = "alpha" }]
[package.dev-dependencies]
dev = [{ name = "gplpkg" }]

[[package]]
name = "alpha"
version = "1.0"
source = { registry = "https://idx/simple" }

[[package]]
name = "gplpkg"
version = "3.0"
source = { registry = "https://idx/simple" }
"#;

fn grouped_harness() -> (Harness, std::path::PathBuf) {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(h.path("uv.lock"), GROUPED_LOCK).expect("write");
    h.index.publish("alpha", "1.0", "MIT");
    h.index.publish("gplpkg", "3.0", "GPL-3.0-only");
    (h, pyproject)
}

#[test]
fn a_dev_dependency_fails_the_audit_when_its_group_is_not_excluded() {
    let (h, pyproject) = grouped_harness();
    let r = h.run(&["--pyproject", &s(&pyproject)]);
    assert_eq!(r.code, 1, "{}", r.out);
}

#[test]
fn excluding_the_dev_group_leaves_out_its_packages() {
    let (h, pyproject) = grouped_harness();
    let r = h.run(&["--pyproject", &s(&pyproject), "--exclude-group", "dev"]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        r.out
            .contains("Left out 1 package(s) reached only through dev."),
        "{}",
        r.out
    );
    assert!(r.out.contains("All 1 packages passed."), "{}", r.out);
}

#[test]
fn an_unknown_group_name_is_reported_with_the_ones_that_exist() {
    let (h, pyproject) = grouped_harness();
    let r = h.run(&["--pyproject", &s(&pyproject), "--exclude-group", "tests"]);
    assert_ne!(r.code, 0);
    assert!(
        r.out.contains("no dependency group or extra named 'tests'"),
        "{}",
        r.out
    );
    assert!(r.out.contains("dev"), "{}", r.out);
}

#[test]
fn exclude_group_is_refused_for_an_installed_environment() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--installed",
        "--exclude-group",
        "dev",
    ]);
    assert_ne!(r.code, 0);
    assert!(
        r.out.contains("--exclude-group needs a lock file"),
        "{}",
        r.out
    );
}

const ACCEPTING_CERTIFI: &str = "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n\n\
     [tool.trustedlicenses.accepted-licenses]\ncertifi = [\"MPL-2.0\"]\n";

#[test]
fn a_failure_prints_the_exact_line_that_would_accept_just_that_license() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[("certifi", Some("MPL-2.0"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("`certifi = [\"MPL-2.0\"]`"), "{}", r.out);
}

#[test]
fn an_accepted_license_passes_that_package_and_is_listed_as_an_exception() {
    let h = Harness::new();
    let pyproject = h.pyproject(ACCEPTING_CERTIFI);
    let venv = h.venv(&[("certifi", Some("MPL-2.0"), None), ("a", Some("MIT"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        r.out.contains("1 package(s) pass only by an exception"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("certifi: MPL-2.0 (accepted for this package in accepted-licenses)"),
        "{}",
        r.out
    );
    assert!(r.out.contains("All 2 packages passed."), "{}", r.out);
}

#[test]
fn the_accepted_license_does_not_cover_another_package_with_it() {
    let h = Harness::new();
    let pyproject = h.pyproject(ACCEPTING_CERTIFI);
    let venv = h.venv(&[
        ("certifi", Some("MPL-2.0"), None),
        ("other", Some("MPL-2.0"), None),
    ]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("other: detected MPL-2.0"), "{}", r.out);
}

#[test]
fn unlicensed_packages_fail_until_the_flag_or_the_config_key_allows_them() {
    let packages = [("internal", None, None), ("a", Some("MIT"), None)];
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&packages);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("allow-unlicensed"), "{}", r.out);

    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&packages);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--allow-unlicensed",
    ]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        r.out
            .contains("internal: no license (allowed by allow-unlicensed)"),
        "{}",
        r.out
    );

    let h = Harness::new();
    let pyproject = h.pyproject(&format!("{PERMISSIVE}allow-unlicensed = true\n"));
    let venv = h.venv(&packages);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
}

#[test]
fn allow_unlicensed_does_not_hide_a_disallowed_license() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[
        ("gplpkg", Some("GPL-2.0-only"), None),
        ("internal", None, None),
    ]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--allow-unlicensed",
    ]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("gplpkg: detected GPL-2.0-only"), "{}", r.out);
    assert!(
        !r.out.contains("internal: no license detected"),
        "{}",
        r.out
    );
}

#[test]
fn using_ignored_packages_says_it_trusts_the_package_not_the_license() {
    let h = Harness::new();
    let pyproject = h.pyproject(&format!("{PERMISSIVE}ignored-packages = [\"gplpkg\"]\n"));
    let venv = h.venv(&[("gplpkg", Some("GPL-2.0-only"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        r.out
            .contains("ignored-packages trusts 1 package(s) whatever their license (gplpkg)"),
        "{}",
        r.out
    );
}

#[test]
fn allow_unlicensed_does_not_pass_a_dependency_whose_license_could_not_be_read() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    fs::write(
        h.path("uv.lock"),
        "[[package]]\nname = \"gitdep\"\nversion = \"1.0\"\nsource = { git = \"https://example.com/x.git?rev=abc#abc\" }\n",
    )
    .expect("write");
    let r = h.run(&["--pyproject", &s(&pyproject), "--allow-unlicensed"]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("could not be read"), "{}", r.out);
}

// ---------------------------------------------------------------------------------
// --prefer-installed.
// ---------------------------------------------------------------------------------

fn lock_with(h: &Harness, packages: &[(&str, &str)]) {
    fs::write(h.path("uv.lock"), uv_lock(packages)).expect("write");
}

#[test]
fn a_lock_audit_reads_the_index_only_unless_installed_copies_are_preferred() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    lock_with(&h, &[("alpha", "1.0")]);
    let venv = h.venv(&[("alpha", Some("MIT"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 1, "alpha isn't on the index: {}", r.out);
}

#[test]
fn prefer_installed_reads_a_matching_name_and_version_from_the_environment() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    lock_with(&h, &[("alpha", "1.0"), ("beta", "2.0")]);
    h.index.publish("beta", "2.0", "Apache-2.0");
    let venv = h.venv(&[("alpha", Some("MIT"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--prefer-installed",
    ]);
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        r.out
            .contains("Read 1 of 2 package(s) from the installed environment (--prefer-installed)"),
        "{}",
        r.out
    );
}

#[test]
fn prefer_installed_does_not_use_a_copy_at_another_version() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    lock_with(&h, &[("alpha", "2.0")]);
    h.index.publish("alpha", "2.0", "Apache-2.0");
    let venv = h.venv(&[("alpha", Some("GPL-3.0-only"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--prefer-installed",
    ]);
    assert_eq!(
        r.code, 0,
        "the index's Apache-2.0 decides, not the venv's 1.0: {}",
        r.out
    );
    assert!(
        !r.out.contains("from the installed environment"),
        "{}",
        r.out
    );
}

#[test]
fn prefer_installed_ignores_a_copy_installed_from_a_url() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    lock_with(&h, &[("alpha", "1.0")]);
    let venv = h.venv(&[("alpha", Some("MIT"), None)]);
    fs::write(
        venv.join("lib/python3.13/site-packages/alpha-1.0.dist-info/direct_url.json"),
        r#"{"url": "file:///somewhere"}"#,
    )
    .expect("write");
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--prefer-installed",
    ]);
    assert_eq!(r.code, 1, "{}", r.out);
}

#[test]
fn prefer_installed_marks_where_a_failing_license_was_read_from() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    lock_with(&h, &[("gplpkg", "1.0")]);
    let venv = h.venv(&[("gplpkg", Some("GPL-3.0-only"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--prefer-installed",
    ]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out.contains("declared metadata [installed environment]"),
        "{}",
        r.out
    );
}

#[test]
fn prefer_installed_with_offline_needs_no_network_for_installed_packages() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    lock_with(&h, &[("alpha", "1.0")]);
    let venv = h.venv(&[("alpha", Some("MIT"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--prefer-installed",
        "--offline",
    ]);
    assert_eq!(r.code, 0, "{}", r.out);
}

#[test]
fn allow_unlicensed_does_not_pass_a_license_file_that_could_not_be_identified() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[(
        "closed",
        None,
        Some("Proprietary. All rights reserved. Do not copy or redistribute."),
    )]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--allow-unlicensed",
    ]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("could not be identified"), "{}", r.out);
    assert!(!r.out.contains("allowed by allow-unlicensed"), "{}", r.out);
}

#[test]
fn allow_unlicensed_does_not_pass_a_declared_license_it_cannot_parse() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let venv = h.venv(&[("closed", Some("Proprietary - internal use only"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--allow-unlicensed",
    ]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(r.out.contains("could not be identified"), "{}", r.out);
    assert!(!r.out.contains("allowed by allow-unlicensed"), "{}", r.out);
}

#[test]
fn prefer_installed_ignores_a_legacy_egg_info_copy() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    lock_with(&h, &[("alpha", "1.0")]);
    h.index.publish("alpha", "1.0", "MIT");
    let venv = h.venv(&[]);
    let egg = venv.join("lib/python3.13/site-packages/alpha-1.0.egg-info");
    fs::create_dir_all(&egg).expect("mkdir");
    fs::write(
        egg.join("PKG-INFO"),
        "Metadata-Version: 2.1\nName: alpha\nVersion: 1.0\n",
    )
    .expect("write");
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "--prefer-installed",
    ]);
    assert_eq!(r.code, 0, "the index's MIT decides: {}", r.out);
    assert!(
        !r.out.contains("from the installed environment"),
        "{}",
        r.out
    );
}

#[test]
fn the_ca_cert_flag_beats_the_environment_and_system_certs_ignores_both() {
    let parse = |args: &[&str]| {
        Cli::try_parse_from(std::iter::once("trustedlicenses").chain(args.iter().copied()))
    };
    let env = HashMap::from([("SSL_CERT_FILE".to_owned(), "/env.pem".to_owned())]);
    let extra = |path: &str, origin: &str| {
        Trust::WithExtra(CaBundle {
            path: PathBuf::from(path),
            origin: origin.to_owned(),
        })
    };

    let cli = parse(&[]).expect("parse");
    assert_eq!(trust(&cli, &env), extra("/env.pem", "SSL_CERT_FILE"));
    assert_eq!(trust(&cli, &HashMap::new()), Trust::Bundled);
    let cli = parse(&["--ca-cert", "/flag.pem"]).expect("parse");
    assert_eq!(trust(&cli, &env), extra("/flag.pem", "--ca-cert"));
    let cli = parse(&["--system-certs"]).expect("parse");
    assert_eq!(trust(&cli, &env), Trust::System);
    assert!(parse(&["--system-certs", "--ca-cert", "/flag.pem"]).is_err());
}

const PERMISSIVE_POLICY: &str =
    "[project]\nname = 'x'\n\n[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n";

#[test]
fn pin_dry_run_lists_the_licenses_and_writes_nothing() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE_POLICY);
    let venv = h.venv(&[("a", Some("MIT"), None), ("b", Some("MPL-2.0"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "pin",
        "--dry-run",
    ]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r
        .out
        .contains("allowed-categories (Permissive) becomes allowed-licenses with 1 license(s):"));
    assert!(r.out.contains("  MIT\n"), "{}", r.out);
    assert!(!r.out.contains("MPL-2.0"), "{}", r.out);
    assert!(r.out.contains("Dry run -- nothing written."));
    assert_eq!(
        fs::read_to_string(&pyproject).expect("read"),
        PERMISSIVE_POLICY
    );
}

#[test]
fn pin_replaces_the_categories_and_a_second_run_says_so() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE_POLICY);
    let venv = h.venv(&[("a", Some("MIT"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv), "pin"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r
        .out
        .contains("A license new to the project now fails until you accept it."));
    let written = fs::read_to_string(&pyproject).expect("read");
    assert!(
        written.contains("allowed-licenses = [\n    \"MIT\",\n]"),
        "{written}"
    );
    assert!(!written.contains("allowed-categories"), "{written}");

    let again = Harness::new();
    let pyproject = again.pyproject(&written);
    let r = again.run(&["--pyproject", &s(&pyproject), "pin"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("is already pinned"), "{}", r.out);
}

#[test]
fn pin_without_a_policy_says_how_to_make_one() {
    let h = Harness::new();
    let pyproject = h.pyproject("[project]\nname = 'x'\n");
    let r = h.run(&["--pyproject", &s(&pyproject), "pin"]);
    assert_eq!(r.code, 1);
    assert!(
        format!("{}{}", r.out, r.err).contains("there's no policy to pin yet"),
        "{}{}",
        r.out,
        r.err
    );
}

#[test]
fn report_is_markdown_on_stdout_and_exits_zero_even_with_failures() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE_POLICY);
    let venv = h.venv(&[("a", Some("MIT"), None), ("b", Some("GPL-3.0-only"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv), "report"]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(
        r.out.starts_with("# License policy report: x\n"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("- **Result:** 1 of 2 checked packages pass; 1 doesn't"),
        "{}",
        r.out
    );
    assert!(r.out.contains("| MIT | Permissive | 1: a |"), "{}", r.out);
    assert!(r
        .out
        .contains("| b | GPL-3.0-only | Copyleft | license not allowed by the policy |"));
    assert!(!r.out.contains("Checking dependency licenses"), "{}", r.out);
}

#[test]
fn report_writes_to_a_file_with_output() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE_POLICY);
    let venv = h.venv(&[("a", Some("MIT"), None)]);
    let target = pyproject.with_file_name("licenses.md");
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "report",
        "--output",
        &s(&target),
    ]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.err.contains("Wrote the report to"), "{}", r.err);
    assert!(r.out.is_empty(), "{}", r.out);
    let written = fs::read_to_string(&target).expect("read");
    assert!(written.contains("## What we accept"), "{written}");
}

#[test]
fn report_errors_go_to_stderr_not_into_the_report() {
    let h = Harness::new();
    let pyproject = h.pyproject("[tool.trustedlicenses]\nallowed-categories = \"Permissive\"\n");
    let r = h.run(&["--pyproject", &s(&pyproject), "report"]);
    assert_eq!(r.code, 1);
    assert!(r.out.is_empty(), "{}", r.out);
    assert!(
        r.err.contains("allowed-categories must be a list"),
        "{}",
        r.err
    );
}

#[test]
fn pin_marks_licenses_that_need_a_closer_look() {
    let h = Harness::new();
    let pyproject = h.pyproject(
        "[project]\nname = 'x'\n\n[tool.trustedlicenses]\nallowed-categories = [\"Copyleft Limited\"]\n",
    );
    let venv = h.venv(&[("eupkg", Some("EUPL-1.2"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "pin",
        "--dry-run",
    ]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(
        r.out.contains("  EUPL-1.2 (check individually: covers"),
        "{}",
        r.out
    );
}

#[test]
fn pin_category_pins_only_that_category() {
    let h = Harness::new();
    let pyproject = h.pyproject(
        "[project]\nname = 'x'\n\n[tool.trustedlicenses]\nallowed-categories = [\"Permissive\", \"Copyleft Limited\"]\n",
    );
    let venv = h.venv(&[("a", Some("MIT"), None), ("b", Some("MPL-2.0"), None)]);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "--venv",
        &s(&venv),
        "pin",
        "--category",
        "Copyleft Limited",
    ]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(
        r.out.contains(
            "\"Copyleft Limited\" becomes 1 license(s) in allowed-licenses; \"Permissive\" stays allowed whole:"
        ),
        "{}",
        r.out
    );
    assert!(r.out.contains("  MPL-2.0\n"), "{}", r.out);
    assert!(!r.out.contains("MIT"), "{}", r.out);
    let written = fs::read_to_string(&pyproject).expect("read");
    assert!(
        written.contains(
            "allowed-categories = [\"Permissive\"]\nallowed-licenses = [\n    \"MPL-2.0\",\n]\npinned-categories = [\"Copyleft Limited\"]\n"
        ),
        "{written}"
    );

    let again = Harness::new();
    let pyproject = again.pyproject(&written);
    let r = again.run(&[
        "--pyproject",
        &s(&pyproject),
        "pin",
        "--category",
        "Copyleft Limited",
    ]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.contains("is already pinned"), "{}", r.out);
}

#[test]
fn a_new_license_in_a_pinned_category_is_fixed_by_listing_the_license() {
    let h = Harness::new();
    let pyproject = h.pyproject(
        "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\nallowed-licenses = [\"MPL-2.0\"]\npinned-categories = [\"Copyleft Limited\"]\n",
    );
    let venv = h.venv(&[("a", Some("MIT"), None), ("c", Some("EPL-2.0"), None)]);
    let r = h.run(&["--pyproject", &s(&pyproject), "--venv", &s(&venv)]);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out.contains("or add \"EPL-2.0\" to allowed-licenses"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("to allowed-categories"), "{}", r.out);
}

#[test]
fn pin_category_refuses_a_category_the_policy_doesnt_allow() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE_POLICY);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "pin",
        "--category",
        "Copyleft",
    ]);
    assert_eq!(r.code, 1);
    assert!(
        r.err
            .contains("\"Copyleft\" isn't in allowed-categories, so there's nothing to pin"),
        "{}",
        r.err
    );
    assert_eq!(
        fs::read_to_string(&pyproject).expect("read"),
        PERMISSIVE_POLICY
    );
}

#[test]
fn audit_covers_several_codebases_with_and_without_a_policy() {
    let h = Harness::new();
    let covered = h.path("covered");
    let uncovered = h.path("uncovered");
    let unlocked = h.path("unlocked");
    for dir in [&covered, &uncovered, &unlocked] {
        fs::create_dir_all(dir).expect("mkdir");
    }
    fs::write(
        covered.join("pyproject.toml"),
        "[project]\nname = 'api'\n\n[tool.trustedlicenses]\nallowed-categories = [\"Permissive\", \"Copyleft Limited\"]\n",
    )
    .expect("write");
    fs::write(
        covered.join("uv.lock"),
        uv_lock(&[("alpha", "1.0"), ("mpl", "1.0")]),
    )
    .expect("write");
    fs::write(uncovered.join("requirements.txt"), "mpl==1.0\nbare==1.0\n").expect("write");
    let shared = h.path("org.toml");
    fs::write(&shared, "allowed-categories = [\"Permissive\"]\n").expect("write");
    h.index.publish("alpha", "1.0", "MIT");
    h.index.publish("mpl", "1.0", "MPL-2.0");
    h.index.publish("bare", "1.0", "MIT");
    let r = h.run(&[
        "audit",
        &s(&covered),
        &s(&uncovered),
        &s(&unlocked),
        "--policy",
        &s(&shared),
    ]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    assert!(r.out.starts_with("# License audit\n"), "{}", r.out);
    assert!(
        r.out.contains("| api | ")
            && r.out
                .contains("| its own (`pyproject.toml`) | 2 | all 2 pass |"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("| uncovered | ")
            && r.out.contains("| `requirements.txt` | ")
            && r.out
                .contains("(`--policy`) | 2 | 1 of 2 pass; 1 doesn't |"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("| unlocked | ") && r.out.contains("couldn't be read: no uv.lock"),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains("| MPL-2.0 | Copyleft Limited | api: 1; uncovered: 1 | uncovered |"),
        "{}",
        r.out
    );
    assert!(r.err.contains("Auditing"), "{}", r.err);
}

#[test]
fn audit_takes_its_codebases_as_paths_not_lock_flags() {
    let h = Harness::new();
    let r = h.run(&["--lock", "uv.lock", "audit", "."]);
    assert_eq!(r.code, 1);
    assert!(r.err.contains("doesn't take --lock"), "{}", r.err);
    let r = Harness::new().run(&["audit"]);
    assert_eq!(r.code, 2);
}

#[test]
fn packages_with_no_license_from_a_trusted_index_pass_and_are_listed() {
    let nexus = "https://nexus.example.com/repository/pypi-internal/simple";
    let lock = format!(
        "{}[[package]]\nname = \"acmecore\"\nversion = \"1.0\"\nsource = {{ registry = \"{nexus}\" }}\n\n",
        uv_lock(&[("alpha", "1.0")])
    );
    // The internal package is read from its installed copy, so the stub index needn't serve it.
    let run = |policy: &str| {
        let h = Harness::new();
        let pyproject = h.pyproject(policy);
        fs::write(h.path("uv.lock"), &lock).expect("write");
        let venv = h.venv(&[("acmecore", None, None)]);
        h.index.publish("alpha", "1.0", "MIT");
        h.run(&[
            "--pyproject",
            &s(&pyproject),
            "--prefer-installed",
            "--venv",
            &s(&venv),
        ])
    };
    let r = run(PERMISSIVE);
    assert_eq!(r.code, 1, "{}", r.out);
    assert!(
        r.out
            .contains(&format!("add \"{nexus}\" to trusted-indexes")),
        "{}",
        r.out
    );
    let r = run(&format!("{PERMISSIVE}trusted-indexes = [\"{nexus}/\"]\n"));
    assert_eq!(r.code, 0, "{}", r.out);
    assert!(
        r.out.contains(&format!(
            "acmecore: no identified license, from {nexus} (trusted-indexes)"
        )),
        "{}",
        r.out
    );
}

#[test]
fn setup_needs_a_terminal() {
    let h = Harness::new();
    let pyproject = h.pyproject(PERMISSIVE);
    let r = h.run(&["--pyproject", &s(&pyproject), "setup"]);
    assert_eq!(r.code, 1);
    assert!(
        format!("{}{}", r.out, r.err).contains("setup asks questions, so it needs a terminal"),
        "{}{}",
        r.out,
        r.err
    );
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), PERMISSIVE);
}

#[test]
fn audit_finds_the_policy_above_a_lock_file_in_a_subdirectory_and_skips_repeats() {
    let h = Harness::new();
    let project = h.path("b");
    fs::create_dir_all(project.join("sub")).expect("mkdir");
    fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = 'b'\n\n[tool.trustedlicenses]\nallowed-categories = [\"Public Domain\"]\n",
    )
    .expect("write");
    let lock = project.join("sub").join("requirements.txt");
    fs::write(&lock, "six==1.0\n").expect("write");
    let shared = h.path("org.toml");
    fs::write(&shared, "allowed-categories = [\"Permissive\"]\n").expect("write");
    h.index.publish("six", "1.0", "MIT");
    let r = h.run(&["audit", &s(&lock), &s(&lock), "--policy", &s(&shared)]);
    assert_eq!(r.code, 0, "{}{}", r.out, r.err);
    // b's own policy, which allows only Public Domain, judges it, not --policy.
    assert!(
        r.out.contains("| 1 | 0 of 1 pass; 1 doesn't |"),
        "{}",
        r.out
    );
    assert!(r.out.contains("pyproject.toml`) |"), "{}", r.out);
    assert_eq!(r.out.matches("\n## b\n").count(), 1, "{}", r.out);
    assert!(r.err.contains("it's already in this audit"), "{}", r.err);
}

#[test]
fn pin_rejects_an_unknown_category_even_on_a_pinned_policy() {
    let h = Harness::new();
    let body = "[tool.trustedlicenses]\nallowed-licenses = [\"MIT\"]\n";
    let pyproject = h.pyproject(body);
    let r = h.run(&[
        "--pyproject",
        &s(&pyproject),
        "pin",
        "--category",
        "Permisive",
    ]);
    assert_eq!(r.code, 1, "{}{}", r.out, r.err);
    assert!(
        r.err.contains("\"Permisive\" isn't a license category"),
        "{}",
        r.err
    );
    assert_eq!(fs::read_to_string(&pyproject).expect("read"), body);
}
