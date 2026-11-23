//! Tests for the index logic (fake client) and the wire (a real local HTTP server).

use super::*;
use crate::detection::{inspect_distribution, DistributionLicence};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

const JSON_TYPE: &str = "application/vnd.pypi.simple.v1+json";
const HTML_TYPE: &str = "text/html";
const MIT: &str = include_str!("../../../tests/fixtures/mit.txt");
const GPL_2_0_TEXT: &str = include_str!("../../../tests/fixtures/gpl-2.0.txt");

fn with_license(version: &str) -> String {
    format!("Metadata-Version: 2.5\nName: pkg\nVersion: {version}\nLicense-File: LICENSE\n")
}

fn without_license(version: &str) -> String {
    format!(
        "Metadata-Version: 2.0\nName: pkg\nVersion: {version}\nLicense: BSD\n\
         Classifier: License :: OSI Approved :: BSD License\n"
    )
}

/// A minimal real wheel. `declare` controls whether METADATA carries `License-File`.
fn make_wheel(version: &str, license_text: Option<&str>, declare: bool) -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let metadata = if license_text.is_some() && declare {
        with_license(version)
    } else {
        without_license(version)
    };
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut buffer);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        archive
            .start_file(format!("pkg-{version}.dist-info/METADATA"), options)
            .expect("start");
        archive.write_all(metadata.as_bytes()).expect("write");
        if let Some(text) = license_text {
            archive
                .start_file(format!("pkg-{version}.dist-info/licenses/LICENSE"), options)
                .expect("start");
            archive.write_all(text.as_bytes()).expect("write");
        }
        archive.finish().expect("finish");
    }
    buffer.into_inner()
}

/// A wheel whose payload dwarfs its metadata, as real wheels do. The payload entry comes first.
fn make_padded_wheel(version: &str, license_text: &str, padding: usize) -> Vec<u8> {
    use zip::write::SimpleFileOptions;
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut buffer);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        archive
            .start_file("pkg/payload.bin", options)
            .expect("start");
        let block: Vec<u8> = (0..1024)
            .map(|i| u8::try_from(i % 251).expect("byte"))
            .collect();
        for _ in 0..padding / 1024 {
            archive.write_all(&block).expect("write");
        }
        archive
            .start_file(format!("pkg-{version}.dist-info/METADATA"), options)
            .expect("start");
        archive
            .write_all(without_license(version).as_bytes())
            .expect("write");
        archive
            .start_file(format!("pkg-{version}.dist-info/licenses/LICENSE"), options)
            .expect("start");
        archive.write_all(license_text.as_bytes()).expect("write");
        archive.finish().expect("finish");
    }
    buffer.into_inner()
}

fn found(audit: &Audit) -> &VersionFinding {
    audit.first_with_license.as_ref().expect("a finding")
}

fn latest(audit: &Audit) -> &VersionFinding {
    audit.latest.as_ref().expect("a latest release")
}

// --------------------------------------------------------------------------------------
// Logic, against a fake client.
// --------------------------------------------------------------------------------------

#[derive(Default)]
struct FakeClient {
    versions: Vec<(String, String)>,
    sdist_only: Vec<String>,
    yanked: Vec<String>,
    extra_filenames: Vec<String>,
    fetched: Mutex<Vec<String>>,
}

impl FakeClient {
    fn new(versions: &[(&str, String)]) -> Self {
        Self {
            versions: versions
                .iter()
                .map(|(v, t)| ((*v).to_owned(), t.clone()))
                .collect(),
            ..Self::default()
        }
    }

    fn fetched(&self) -> Vec<String> {
        self.fetched.lock().expect("lock").clone()
    }
}

impl Client for FakeClient {
    fn credentials_for(&self, _url: &str) -> String {
        "none".to_owned()
    }

    fn get(
        &self,
        url: &str,
        _accept: Option<&str>,
        _max: Option<usize>,
    ) -> Result<Response, IndexError> {
        self.fetched.lock().expect("lock").push(url.to_owned());
        if url.ends_with("/pkg/") {
            let mut files: Vec<Json> = self
                .extra_filenames
                .iter()
                .map(|name| serde_json::json!({"filename": name, "url": format!("https://idx/files/{name}")}))
                .collect();
            for (version, _) in &self.versions {
                let name = if self.sdist_only.contains(version) {
                    format!("pkg-{version}.tar.gz")
                } else {
                    format!("pkg-{version}-py3-none-any.whl")
                };
                files.push(serde_json::json!({
                    "filename": name,
                    "url": format!("https://idx/files/{name}"),
                    "core-metadata": true,
                    "yanked": self.yanked.contains(version),
                }));
            }
            return Ok(Response {
                url: url.to_owned(),
                content_type: JSON_TYPE.to_owned(),
                body: serde_json::to_vec(&serde_json::json!({ "files": files })).expect("json"),
            });
        }
        let version = url
            .rsplit_once("pkg-")
            .expect("pkg-")
            .1
            .split("-py3")
            .next()
            .expect("split")
            .trim_end_matches(".tar.gz");
        let text = &self
            .versions
            .iter()
            .find(|(v, _)| v == version)
            .expect("known version")
            .1;
        Ok(Response {
            url: url.to_owned(),
            content_type: "text/plain".to_owned(),
            body: text.clone().into_bytes(),
        })
    }
}

fn audit_with(client: &FakeClient, installed: &str) -> Audit {
    audit_package(
        client,
        "https://idx/simple",
        "pkg",
        installed,
        AuditOptions::default(),
    )
    .expect("audit")
}

fn audit_of(versions: &[(&str, String)], installed: &str) -> (Audit, FakeClient) {
    let client = FakeClient::new(versions);
    (audit_with(&client, installed), client)
}

#[test]
fn finds_the_first_newer_release_that_ships_a_license() {
    let (audit, _) = audit_of(
        &[
            ("0.5.1", without_license("0.5.1")),
            ("0.6.0", with_license("0.6.0")),
            ("0.6.1", with_license("0.6.1")),
        ],
        "0.5.1",
    );
    assert_eq!(found(&audit).version.to_string(), "0.6.0");
    assert_eq!(
        found(&audit).evidence.as_deref(),
        Some("License-File: LICENSE")
    );
    assert_eq!(latest(&audit).version.to_string(), "0.6.1");
    assert!(audit.served_json);
    assert!(audit.has_metadata);
    let rendered = format_audit(&audit);
    assert!(rendered.contains("0.6.0 is the first newer release"));
    assert!(rendered.contains("The latest release is 0.6.1"));
}

#[test]
fn only_newer_releases_are_considered() {
    let (audit, client) = audit_of(
        &[
            ("0.4", with_license("0.4")),
            ("0.5.1", without_license("0.5.1")),
        ],
        "0.5.1",
    );
    assert!(audit.first_with_license.is_none());
    assert_eq!(audit.newer_count, 0);
    assert!(!client.fetched().iter().any(|url| url.contains("0.4")));
    assert!(format_audit(&audit).contains("no newer release, so an upgrade isn't available"));
}

#[test]
fn an_unparseable_installed_version_still_considers_every_release() {
    let (audit, _) = audit_of(&[("1.0", with_license("1.0"))], "not-a-real-version");
    assert_eq!(found(&audit).version.to_string(), "1.0");
}

#[test]
fn yanked_releases_are_skipped_in_the_json_index() {
    let mut client = FakeClient::new(&[
        ("1.0", without_license("1.0")),
        ("1.1", with_license("1.1")),
    ]);
    client.yanked = vec!["1.1".to_owned()];
    let audit = audit_with(&client, "1.0");
    assert!(audit.first_with_license.is_none());
    assert_eq!(audit.newer_count, 0);
}

#[test]
fn unparseable_filenames_on_the_index_are_skipped() {
    let mut client = FakeClient::new(&[("1.0", with_license("1.0"))]);
    client.extra_filenames = vec!["pkg-nonsense.egg".to_owned()];
    assert_eq!(
        found(&audit_with(&client, "0.9")).version.to_string(),
        "1.0"
    );
}

#[test]
fn reports_when_no_newer_release_declares_a_license() {
    let (audit, _) = audit_of(
        &[
            ("1.0", without_license("1.0")),
            ("1.1", without_license("1.1")),
        ],
        "1.0",
    );
    assert!(audit.first_with_license.is_none());
    assert_eq!(audit.checked, 1);
    assert!(format_audit(&audit).contains("won't help"));
}

#[test]
fn prereleases_are_skipped_unless_the_installed_one_is_a_prerelease() {
    let versions = [
        ("1.0", without_license("1.0")),
        ("1.1rc1", with_license("1.1rc1")),
    ];
    let (stable, _) = audit_of(&versions, "1.0");
    let (pre, _) = audit_of(&versions, "1.0rc1");
    assert!(stable.first_with_license.is_none());
    assert_eq!(found(&pre).version.to_string(), "1.1rc1");
}

#[test]
fn an_sdist_only_release_is_reported_not_guessed() {
    let mut client = FakeClient::new(&[("1.0", without_license("1.0")), ("1.1", String::new())]);
    client.sdist_only = vec!["1.1".to_owned()];
    let audit = audit_with(&client, "1.0");
    assert!(audit.first_with_license.is_none());
    assert!(latest(&audit)
        .note
        .as_deref()
        .expect("note")
        .contains("source distribution"));
    assert!(format_audit(&audit).contains("couldn't be inspected"));
}

#[test]
fn the_window_is_bounded_but_the_latest_is_still_checked() {
    let owned: Vec<(String, String)> = (0..6)
        .map(|i| (format!("1.{i}"), without_license(&format!("1.{i}"))))
        .collect();
    let versions: Vec<(&str, String)> =
        owned.iter().map(|(v, t)| (v.as_str(), t.clone())).collect();
    let client = FakeClient::new(&versions);
    let audit = audit_package(
        &client,
        "https://idx/simple",
        "pkg",
        "1.0",
        AuditOptions {
            max_versions: 2,
            ..AuditOptions::default()
        },
    )
    .expect("audit");
    assert_eq!(audit.checked, 2);
    assert_eq!(audit.newer_count, 5);
    assert_eq!(latest(&audit).version.to_string(), "1.5");
    assert!(format_audit(&audit).contains("not checked"));
}

#[test]
fn no_installed_version_considers_every_release() {
    let (audit, _) = audit_of(&[("1.0", with_license("1.0"))], "");
    assert_eq!(found(&audit).version.to_string(), "1.0");
    assert!(format_audit(&audit).contains("(not installed)"));
}

#[test]
fn a_declared_resolvable_license_counts_without_a_license_file() {
    let (audit, _) = audit_of(
        &[(
            "1.0",
            "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\nLicense-Expression: MIT\n".to_owned(),
        )],
        "",
    );
    assert_eq!(found(&audit).evidence.as_deref(), Some("declares MIT"));
}

#[test]
fn filename_versions_come_from_wheels_and_sdists_only() {
    for (name, expected) in [
        ("pkg-1.0-py3-none-any.whl", Some("1.0")),
        ("pkg-1.0-1-py3-none-any.whl", Some("1.0")),
        ("pkg-1.0.tar.gz", Some("1.0")),
        ("my-pkg-2.0.zip", Some("2.0")),
        ("pkg-1.0.egg", None),
        ("pkg-1.0-py3.whl", None),
        ("pkg-1.0-x-py3-none-any.whl", None),
        ("nonsense.tar.gz", None),
        ("pkg-notaversion.tar.gz", None),
    ] {
        assert_eq!(
            filename_version(name).map(|v| v.to_string()).as_deref(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn the_html_scanner_reads_anchors_only_and_unescapes_attributes() {
    let anchors = anchor_attributes(
        "<abbr title=x>no</abbr><A HREF='a&amp;b' data-yanked>one</A><a href=\"c\" data-core-metadata=true/><a>",
    );
    assert_eq!(anchors.len(), 3);
    assert_eq!(anchors[0][0], ("href".to_owned(), Some("a&b".to_owned())));
    assert_eq!(anchors[0][1], ("data-yanked".to_owned(), None));
    assert_eq!(anchors[1][1].0, "data-core-metadata");
}

// --------------------------------------------------------------------------------------
// The wire, against a real local HTTP server.
// --------------------------------------------------------------------------------------

#[derive(Default)]
struct SiteState {
    wheels: BTreeMap<String, Vec<u8>>,
    metadata: BTreeMap<String, String>,
    require_auth: Option<String>,
    seen_auth: Vec<Option<String>>,
    requests: Vec<String>,
    redirect_files_to: Option<String>,
    json: bool,
    yanked_html_files: BTreeSet<String>,
    hang: bool,
    /// Serve `Range` requests for files (206), as pythonhosted.org does.
    ranges: bool,
    range_headers: Vec<String>,
}

struct Site {
    port: u16,
    state: Arc<Mutex<SiteState>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

fn reply(stream: &mut TcpStream, status: u16, headers: &[(&str, String)], body: &[u8]) {
    let mut head = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
}

fn serve(mut stream: TcpStream, state: &Mutex<SiteState>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    let mut authorization = None;
    let mut range: Option<String> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
            if name.eq_ignore_ascii_case("range") {
                range = Some(value.trim().to_owned());
            }
        }
    }
    let mut state = state.lock().expect("lock");
    state.seen_auth.push(authorization.clone());
    state.requests.push(path.clone());
    if let Some(range) = &range {
        state.range_headers.push(range.clone());
    }
    if state.hang {
        drop(state);
        thread::sleep(Duration::from_secs(5));
        return;
    }
    if state.require_auth.is_some() && state.require_auth != authorization {
        reply(&mut stream, 401, &[], b"");
        return;
    }
    if path == "/simple/pkg/" {
        let names: Vec<String> = state.wheels.keys().cloned().collect();
        if state.json {
            let files: Vec<Json> = names
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "filename": n,
                        "url": format!("/files/{n}"),
                        "core-metadata": state.metadata.contains_key(&format!("{n}.metadata")),
                        "yanked": state.yanked_html_files.contains(n),
                        "size": state.wheels.get(n).map(Vec::len),
                    })
                })
                .collect();
            let body = serde_json::to_vec(&serde_json::json!({ "files": files })).expect("json");
            reply(
                &mut stream,
                200,
                &[("Content-Type", JSON_TYPE.to_owned())],
                &body,
            );
        } else {
            let links: String = names
                .iter()
                .map(|n| {
                    let yanked = if state.yanked_html_files.contains(n) {
                        " data-yanked=\"\""
                    } else {
                        ""
                    };
                    let meta = if state.metadata.contains_key(&format!("{n}.metadata")) {
                        " data-core-metadata=\"true\""
                    } else {
                        ""
                    };
                    format!("<a href=\"../../files/{n}#sha256=x\"{yanked}{meta}>{n}</a><br>")
                })
                .collect();
            let body = format!("<html><body>{links}</body></html>");
            reply(
                &mut stream,
                200,
                &[("Content-Type", HTML_TYPE.to_owned())],
                body.as_bytes(),
            );
        }
    } else if let Some(file) = path.strip_prefix("/files/") {
        if let Some(target) = state.redirect_files_to.clone() {
            reply(
                &mut stream,
                302,
                &[("Location", format!("{target}{path}"))],
                b"",
            );
        } else if let (Some(wheel), true, Some(range)) =
            (state.wheels.get(file), state.ranges, range.as_deref())
        {
            let total = wheel.len();
            let spec = range.trim_start_matches("bytes=");
            if let Some(("", suffix)) = spec.split_once('-') {
                // As files.pythonhosted.org does: a suffix longer than the file is unsatisfiable.
                if suffix.parse::<usize>().unwrap_or(0) > total {
                    reply(
                        &mut stream,
                        416,
                        &[("Content-Range", format!("bytes */{total}"))],
                        b"",
                    );
                    return;
                }
            }
            let (start, end) = match spec.split_once('-') {
                Some(("", suffix)) => {
                    (total.saturating_sub(suffix.parse().unwrap_or(0)), total - 1)
                }
                Some((first, "")) => (first.parse().unwrap_or(0), total - 1),
                Some((first, last)) => (
                    first.parse().unwrap_or(0),
                    last.parse::<usize>().unwrap_or(total - 1).min(total - 1),
                ),
                None => (0, total - 1),
            };
            reply(
                &mut stream,
                206,
                &[
                    ("Content-Type", "application/octet-stream".to_owned()),
                    ("Content-Range", format!("bytes {start}-{end}/{total}")),
                ],
                &wheel[start..=end],
            );
        } else if let Some(wheel) = state.wheels.get(file) {
            reply(
                &mut stream,
                200,
                &[("Content-Type", "application/octet-stream".to_owned())],
                wheel,
            );
        } else if let Some(text) = state.metadata.get(file) {
            reply(
                &mut stream,
                200,
                &[("Content-Type", "text/plain".to_owned())],
                text.as_bytes(),
            );
        } else {
            reply(&mut stream, 404, &[], b"");
        }
    } else {
        reply(&mut stream, 404, &[], b"");
    }
}

fn site() -> Site {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let state = Arc::new(Mutex::new(SiteState::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (thread_state, thread_stop) = (Arc::clone(&state), Arc::clone(&stop));
    thread::spawn(move || {
        for stream in listener.incoming() {
            if thread_stop.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(stream) = stream {
                let state = Arc::clone(&thread_state);
                thread::spawn(move || serve(stream, &state));
            }
        }
    });
    Site { port, state, stop }
}

impl Site {
    fn url(&self, userinfo: &str) -> String {
        format!("http://{userinfo}127.0.0.1:{}/simple", self.port)
    }

    fn set(&self, configure: impl FnOnce(&mut SiteState)) {
        configure(&mut self.state.lock().expect("lock"));
    }

    fn add_wheel(&self, version: &str, license: Option<&str>, declare: bool) {
        let name = format!("pkg-{version}-py3-none-any.whl");
        self.set(|s| {
            s.wheels.insert(name, make_wheel(version, license, declare));
        });
    }

    fn requests(&self) -> Vec<String> {
        self.state.lock().expect("lock").requests.clone()
    }
}

fn client() -> HttpClient {
    HttpClient::with_options(Duration::from_secs(10), None)
}

fn audit_site(client: &HttpClient, url: &str, installed: &str) -> Result<Audit, IndexError> {
    audit_package(client, url, "pkg", installed, AuditOptions::default())
}

#[test]
fn yanked_releases_are_skipped_in_an_html_index() {
    let site = site();
    site.add_wheel("1.1", Some("text"), true);
    site.set(|s| {
        s.yanked_html_files
            .insert("pkg-1.1-py3-none-any.whl".to_owned());
    });
    let audit = audit_site(&client(), &site.url(""), "1.0").expect("audit");
    assert!(audit.first_with_license.is_none());
    assert_eq!(audit.newer_count, 0);
}

#[test]
fn an_html_index_without_pep_658_downloads_the_wheel_to_inspect_it() {
    let site = site();
    site.add_wheel("0.5.1", None, true);
    site.add_wheel("0.6.0", Some("text"), true);
    let audit = audit_site(&client(), &site.url(""), "0.5.1").expect("audit");
    assert!(!audit.served_json);
    assert!(!audit.has_metadata);
    assert_eq!(found(&audit).version.to_string(), "0.6.0");
    assert!(found(&audit)
        .evidence
        .as_deref()
        .expect("evidence")
        .contains("License-File"));
    assert!(format_audit(&audit).contains("wheels are downloaded"));
}

#[test]
fn a_wheel_bundling_a_license_without_declaring_it_is_still_seen() {
    let site = site();
    site.add_wheel("0.6.0", Some("text"), false);
    let audit = audit_site(&client(), &site.url(""), "0.5.1").expect("audit");
    assert_eq!(found(&audit).evidence.as_deref(), Some("bundles LICENSE"));
}

#[test]
fn a_json_index_is_used_when_offered() {
    let site = site();
    site.set(|s| s.json = true);
    site.add_wheel("0.6.0", Some("text"), true);
    let audit = audit_site(&client(), &site.url(""), "0.5.1").expect("audit");
    assert!(audit.served_json);
    assert!(audit.first_with_license.is_some());
}

#[test]
fn credentials_in_the_url_are_sent_and_never_shown() {
    let site = site();
    site.set(|s| s.require_auth = Some("Basic dXNlcjpzM2NyZXQ=".to_owned()));
    site.add_wheel("0.6.0", Some("text"), true);
    let url = site.url("user:s3cret@");
    let audit = audit_site(&client(), &url, "0.5.1").expect("audit");
    assert_eq!(audit.credentials, "in the index URL");
    assert!(!format_audit(&audit).contains("s3cret"));
    assert!(audit.first_with_license.is_some());
}

#[test]
fn credentials_come_from_netrc_when_the_url_has_none() {
    let tmp = tempdir().expect("tempdir");
    let netrc = tmp.path().join("netrc");
    fs::write(&netrc, "machine 127.0.0.1 login user password s3cret\n").expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&netrc, fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let site = site();
    site.set(|s| s.require_auth = Some("Basic dXNlcjpzM2NyZXQ=".to_owned()));
    site.add_wheel("0.6.0", Some("text"), true);
    let client = HttpClient::with_options(Duration::from_secs(10), Some(netrc));
    let audit = audit_site(&client, &site.url(""), "0.5.1").expect("audit");
    assert_eq!(audit.credentials, ".netrc");
    assert!(audit.first_with_license.is_some());
}

#[test]
fn rejected_credentials_explain_where_they_come_from() {
    let site = site();
    site.set(|s| s.require_auth = Some("Basic never-matches".to_owned()));
    let error = audit_site(&client(), &site.url(""), "0.5.1").expect_err("error");
    assert_eq!(error.status(), Some(401));
    assert!(error.to_string().contains(".netrc"));
}

#[test]
fn an_unknown_package_says_it_is_not_on_this_index() {
    let site = site();
    let error = client()
        .get(&format!("{}/nope/", site.url("")), None, None)
        .expect_err("error");
    assert_eq!(error.status(), Some(404));
    assert!(error.to_string().contains("not found on this index"));
}

#[test]
fn a_request_that_times_out_is_an_explained_error() {
    let site = site();
    site.set(|s| s.hang = true);
    let client = HttpClient::with_options(Duration::from_millis(300), None);
    let error = client
        .get(&format!("{}/pkg/", site.url("")), None, None)
        .expect_err("error");
    assert!(error.to_string().contains("Timed out after"), "{error}");
}

#[test]
fn credentials_are_not_forwarded_to_another_host() {
    let target = site();
    let origin = site();
    origin.set(|s| s.redirect_files_to = Some(format!("http://localhost:{}", target.port)));
    target.add_wheel("1.0", None, true);
    target.set(|s| {
        s.wheels.insert("probe".to_owned(), b"ok".to_vec());
    });
    let url = format!("http://user:s3cret@127.0.0.1:{}/files/probe", origin.port);
    let response = client().get(&url, None, None).expect("get");
    assert_eq!(response.body, b"ok");
    assert_eq!(
        origin.state.lock().expect("lock").seen_auth,
        [Some("Basic dXNlcjpzM2NyZXQ=".to_owned())]
    );
    assert_eq!(target.state.lock().expect("lock").seen_auth, [None]);
}

#[test]
fn an_oversized_wheel_is_not_downloaded() {
    let site = site();
    site.add_wheel("0.6.0", Some("text"), true);
    let audit = audit_package(
        &client(),
        &site.url(""),
        "pkg",
        "0.5.1",
        AuditOptions {
            max_wheel_bytes: 50,
            ..AuditOptions::default()
        },
    )
    .expect("audit");
    assert!(audit.first_with_license.is_none());
    assert!(latest(&audit)
        .note
        .as_deref()
        .expect("note")
        .contains("larger than"));
}

#[test]
fn an_unreachable_index_is_an_explained_error() {
    let error = client()
        .get("http://127.0.0.1:1/simple/pkg/", None, None)
        .expect_err("error");
    assert!(error.to_string().contains("Could not reach"), "{error}");
}

// --------------------------------------------------------------------------------------
// Fetching a pinned release's license metadata.
// --------------------------------------------------------------------------------------

fn options(cache: &Path) -> FetchOptions<'_> {
    FetchOptions {
        cache_dir: cache,
        max_wheel_bytes: MAX_WHEEL_BYTES,
    }
}

fn fetch(site: &Site, cache: &Path, version: &str) -> Result<Distribution, FetchError> {
    fetch_distribution(&client(), &site.url(""), "pkg", version, &options(cache))
}

#[test]
fn declared_metadata_is_read_from_the_separate_metadata_file_without_downloading_the_wheel() {
    let site = site();
    let cache = tempdir().expect("tempdir");
    site.set(|s| s.json = true);
    site.add_wheel("1.0", None, true);
    site.set(|s| {
        s.metadata.insert(
            "pkg-1.0-py3-none-any.whl.metadata".to_owned(),
            "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\nLicense-Expression: MIT\n".to_owned(),
        );
    });
    let dist = fetch(&site, cache.path(), "1.0").expect("fetch");
    let detected = inspect_distribution(&dist, Some("pkg"));
    assert_eq!(detected.keys, BTreeSet::from(["MIT".to_owned()]));
    assert_eq!(detected.source, "declared metadata");
    assert_eq!(detected.version, "1.0");
    assert!(
        !site.requests().iter().any(|p| p.ends_with(".whl")),
        "the wheel must not be downloaded: {:?}",
        site.requests()
    );
}

#[test]
fn a_wheel_is_downloaded_for_its_license_text_when_nothing_is_declared() {
    let site = site();
    let cache = tempdir().expect("tempdir");
    site.add_wheel("1.0", Some(MIT), false);
    let dist = fetch(&site, cache.path(), "1.0").expect("fetch");
    let detected = inspect_distribution(&dist, Some("pkg"));
    assert_eq!(detected.keys, BTreeSet::from(["MIT".to_owned()]));
    assert_eq!(detected.source, "license files: LICENSE");
}

#[test]
fn a_second_fetch_is_served_from_the_cache_with_no_requests() {
    let site = site();
    let cache = tempdir().expect("tempdir");
    site.add_wheel("1.0", Some(MIT), false);
    fetch(&site, cache.path(), "1.0").expect("first");
    let before = site.requests().len();
    let dist = fetch(&site, cache.path(), "1.0").expect("second");
    assert_eq!(site.requests().len(), before);
    assert_eq!(
        inspect_distribution(&dist, Some("pkg")).source,
        "license files: LICENSE"
    );
}

#[test]
fn the_cache_is_keyed_by_index_so_another_index_is_asked_again() {
    let (first, second) = (site(), site());
    let cache = tempdir().expect("tempdir");
    first.add_wheel("1.0", Some(MIT), false);
    second.add_wheel("1.0", Some(MIT), false);
    fetch(&first, cache.path(), "1.0").expect("first");
    fetch(&second, cache.path(), "1.0").expect("second");
    assert!(!second.requests().is_empty());
}

#[test]
fn an_unlisted_version_is_an_error() {
    let site = site();
    let cache = tempdir().expect("tempdir");
    site.add_wheel("1.0", None, true);
    let error = fetch(&site, cache.path(), "2.0").expect_err("error");
    assert!(error.0.contains("pkg 2.0 is not listed"), "{error}");
}

#[test]
fn a_yanked_release_can_still_be_fetched_when_a_lock_pins_it() {
    let site = site();
    let cache = tempdir().expect("tempdir");
    site.set(|s| s.json = true);
    site.add_wheel("1.0", Some(MIT), false);
    site.set(|s| {
        s.yanked_html_files
            .insert("pkg-1.0-py3-none-any.whl".to_owned());
    });
    let audit = audit_site(&client(), &site.url(""), "0.9").expect("audit");
    assert_eq!(
        audit.newer_count, 0,
        "the audit must still skip a yanked release"
    );
    let dist = fetch(&site, cache.path(), "1.0").expect("fetch");
    assert_eq!(inspect_distribution(&dist, Some("pkg")).keys.len(), 1);
}

#[test]
fn equivalent_version_spellings_match() {
    let site = site();
    let cache = tempdir().expect("tempdir");
    site.add_wheel("1.0", Some(MIT), false);
    assert!(fetch(&site, cache.path(), "1.0.0").is_ok());
}

#[test]
fn a_network_failure_during_fetch_is_an_error_not_a_pass() {
    let cache = tempdir().expect("tempdir");
    let error = fetch_distribution(
        &client(),
        "http://127.0.0.1:1/simple",
        "pkg",
        "1.0",
        &options(cache.path()),
    )
    .expect_err("error");
    assert!(error.0.contains("Could not reach"), "{error}");
}

#[test]
fn a_failed_fetch_leaves_nothing_in_the_cache() {
    let site = site();
    let cache = tempdir().expect("tempdir");
    site.set(|s| {
        s.wheels
            .insert("pkg-1.0-py3-none-any.whl".to_owned(), b"not a zip".to_vec());
    });
    assert!(fetch(&site, cache.path(), "1.0").is_err());
    let leftovers: Vec<_> = walk_files(cache.path());
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk_files(&path));
        } else {
            found.push(path);
        }
    }
    found
}

#[test]
fn bundled_files_are_extracted_without_escaping_the_cache_entry() {
    use zip::write::SimpleFileOptions;
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut buffer);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, body) in [
            ("pkg-1.0.dist-info/METADATA", "Name: pkg\nVersion: 1.0\n"),
            ("pkg-1.0.dist-info/../../escape/LICENSE", "bad"),
            ("pkg-1.0.dist-info/licenses/COPYING.txt", "ok"),
            ("pkg/LICENSE", "not in dist-info"),
        ] {
            archive.start_file(name, options).expect("start");
            archive.write_all(body.as_bytes()).expect("write");
        }
        archive.finish().expect("finish");
    }
    let tmp = tempdir().expect("tempdir");
    let dist_info = tmp.path().join("pkg-1.0.dist-info");
    fs::create_dir_all(&dist_info).expect("mkdir");
    extract_wheel(
        WheelSource::Memory(std::io::Cursor::new(buffer.into_inner())),
        &dist_info,
    )
    .expect("extract");
    let mut names: Vec<String> = walk_files(tmp.path())
        .iter()
        .map(|p| {
            p.strip_prefix(tmp.path())
                .expect("prefix")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "pkg-1.0.dist-info/METADATA",
            "pkg-1.0.dist-info/licenses/COPYING.txt"
        ]
    );
}

/// Talks to the real pypi.org: `cargo test -p trustedlicenses-core live -- --ignored`.
#[test]
#[ignore = "needs network access to pypi.org"]
fn live_pypi_serves_license_metadata_for_pinned_releases() {
    let cache = tempdir().expect("tempdir");
    let options = options(cache.path());
    let real = HttpClient::new();
    let index = "https://pypi.org/simple";

    let requests =
        fetch_distribution(&real, index, "requests", "2.32.3", &options).expect("requests");
    let detected = inspect_distribution(&requests, Some("requests"));
    assert!(detected.keys.contains("Apache-2.0"), "{detected:?}");

    let again = fetch_distribution(&real, index, "requests", "2.32.3", &options).expect("cached");
    assert_eq!(inspect_distribution(&again, Some("requests")), detected);

    let missing =
        fetch_distribution(&real, index, "requests", "0.0.0.0.1", &options).expect_err("missing");
    assert!(missing.0.contains("is not listed"), "{missing}");
}

// --------------------------------------------------------------------------------------
// Reading wheels by byte ranges.
// --------------------------------------------------------------------------------------

const PAYLOAD: usize = 3 * 1024 * 1024;

fn big_wheel_site(ranges: bool) -> Site {
    let site = site();
    site.set(|s| {
        s.ranges = ranges;
        s.wheels.insert(
            "pkg-1.0-py3-none-any.whl".to_owned(),
            make_padded_wheel("1.0", MIT, PAYLOAD),
        );
    });
    site
}

#[test]
fn a_wheel_is_read_by_ranges_and_only_a_fraction_of_it_is_downloaded() {
    let site = big_wheel_site(true);
    let cache = tempdir().expect("tempdir");
    let client = client();
    let dist = fetch_distribution(&client, &site.url(""), "pkg", "1.0", &options(cache.path()))
        .expect("fetch");
    let detected = inspect_distribution(&dist, Some("pkg"));
    assert_eq!(
        detected.keys,
        BTreeSet::from(["MIT".to_owned()]),
        "{detected:?}"
    );
    assert_eq!(detected.source, "license files: LICENSE");

    let downloaded = client.traffic().expect("traffic").bytes;
    assert!(
        downloaded < (PAYLOAD / 4) as u64,
        "downloaded {downloaded} bytes of a {PAYLOAD}-byte wheel"
    );
    let headers = site.state.lock().expect("lock").range_headers.clone();
    // Everything wanted sits in the tail, so the tail is the only request.
    assert_eq!(headers, ["bytes=-131072"]);
}

#[test]
fn a_server_that_ignores_ranges_gets_a_full_download_and_is_not_asked_again() {
    let site = big_wheel_site(false);
    let cache = tempdir().expect("tempdir");
    let client = client();
    let dist = fetch_distribution(&client, &site.url(""), "pkg", "1.0", &options(cache.path()))
        .expect("fetch");
    assert_eq!(inspect_distribution(&dist, Some("pkg")).keys.len(), 1);
    assert!(
        client.traffic().expect("traffic").bytes >= PAYLOAD as u64,
        "the whole wheel was fetched"
    );

    let attempts = site.state.lock().expect("lock").range_headers.len();
    assert_eq!(
        attempts, 1,
        "one probe, then the host is remembered as not supporting ranges"
    );
    let other_cache = tempdir().expect("tempdir");
    fetch_distribution(
        &client,
        &site.url(""),
        "pkg",
        "1.0",
        &options(other_cache.path()),
    )
    .expect("again");
    assert_eq!(
        site.state.lock().expect("lock").range_headers.len(),
        1,
        "not probed again"
    );
}

#[test]
fn a_wheel_too_big_to_download_whole_is_still_readable_by_ranges() {
    let site = big_wheel_site(true);
    let cache = tempdir().expect("tempdir");
    let small_cap = FetchOptions {
        cache_dir: cache.path(),
        max_wheel_bytes: 50,
    };
    let dist =
        fetch_distribution(&client(), &site.url(""), "pkg", "1.0", &small_cap).expect("fetch");
    assert_eq!(inspect_distribution(&dist, Some("pkg")).keys.len(), 1);
}

#[test]
fn the_index_audit_also_reads_wheels_by_ranges() {
    let site = site();
    site.set(|s| {
        s.ranges = true;
        s.wheels.insert(
            "pkg-0.6.0-py3-none-any.whl".to_owned(),
            make_padded_wheel("0.6.0", MIT, PAYLOAD),
        );
    });
    let client = client();
    let audit = audit_site(&client, &site.url(""), "0.5.1").expect("audit");
    assert_eq!(found(&audit).evidence.as_deref(), Some("bundles LICENSE"));
    assert!(client.traffic().expect("traffic").bytes < (PAYLOAD / 4) as u64);
}

#[test]
fn only_the_wanted_entries_of_a_range_read_wheel_are_fetched() {
    use zip::write::SimpleFileOptions;
    // Many unrelated files between the start and the license: a loop that touches every entry would
    // fetch the whole wheel.
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut buffer);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        let chunk = vec![7u8; 8 * 1024];
        for number in 0..400 {
            archive
                .start_file(format!("pkg/module_{number}.py"), options)
                .expect("start");
            archive.write_all(&chunk).expect("write");
        }
        archive
            .start_file("pkg-1.0.dist-info/METADATA", options)
            .expect("start");
        archive
            .write_all(without_license("1.0").as_bytes())
            .expect("write");
        archive
            .start_file("pkg-1.0.dist-info/licenses/LICENSE", options)
            .expect("start");
        archive.write_all(MIT.as_bytes()).expect("write");
        archive.finish().expect("finish");
    }
    let wheel = buffer.into_inner();
    let site = site();
    site.set(|s| {
        s.ranges = true;
        s.wheels
            .insert("pkg-1.0-py3-none-any.whl".to_owned(), wheel.clone());
    });
    let cache = tempdir().expect("tempdir");
    let client = client();
    fetch_distribution(&client, &site.url(""), "pkg", "1.0", &options(cache.path()))
        .expect("fetch");
    let downloaded = client.traffic().expect("traffic").bytes;
    assert!(
        downloaded < (wheel.len() / 5) as u64,
        "downloaded {downloaded} bytes of a {}-byte wheel with 400 unrelated files",
        wheel.len()
    );
}

#[test]
fn only_dist_info_metadata_and_licenses_are_wanted_and_paths_stay_inside() {
    for (name, expected) in [
        ("pkg-1.0.dist-info/METADATA", Some("METADATA")),
        (
            "pkg-1.0.dist-info/licenses/LICENSE",
            Some("licenses/LICENSE"),
        ),
        ("pkg-1.0.dist-info/COPYING.txt", Some("COPYING.txt")),
        (
            "pkg-1.0.dist-info/licenses/deep/NOTICE",
            Some("licenses/deep/NOTICE"),
        ),
        ("pkg-1.0.dist-info/RECORD", None),
        ("pkg-1.0.dist-info/sub/METADATA", None),
        ("pkg/LICENSE", None),
        ("pkg-1.0.dist-info/", None),
        ("pkg-1.0.dist-info/../../escape/LICENSE", None),
        ("/abs/pkg-1.0.dist-info/LICENSE", None),
        ("pkg-1.0.dist-info/licenses//LICENSE", None),
        ("pkg-1.0.dist-info\\LICENSE", None),
    ] {
        assert_eq!(
            wanted_entry(name).map(|path| path.to_string_lossy().replace('\\', "/")),
            expected.map(str::to_owned),
            "{name}"
        );
    }
}

// --------------------------------------------------------------------------------------
// pypi.org's release JSON, used instead of the (huge) project listing.
// --------------------------------------------------------------------------------------

/// Serves only what pypi.org's release endpoint and metadata files would; any other request, such as
/// the project listing, is a test failure.
#[derive(Default)]
struct PypiFake {
    requests: Mutex<Vec<String>>,
    release_json: Option<String>,
}

impl Client for PypiFake {
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
        let reply = |body: String| Response {
            url: url.to_owned(),
            content_type: "application/json".to_owned(),
            body: body.into_bytes(),
        };
        if url == "https://pypi.org/pypi/pkg/1.0/json" {
            return match &self.release_json {
                Some(json) => Ok(reply(json.clone())),
                None => Err(IndexError::Http {
                    status: 404,
                    message: "not found".to_owned(),
                }),
            };
        }
        if url == "https://pypi.org/simple/pkg/" {
            let listing = serde_json::json!({"files": [{
                "filename": "pkg-1.0-py3-none-any.whl",
                "url": "https://files.example/pkg-1.0-py3-none-any.whl",
                "core-metadata": true
            }]});
            return Ok(Response {
                url: url.to_owned(),
                content_type: "application/vnd.pypi.simple.v1+json".to_owned(),
                body: serde_json::to_vec(&listing).expect("json"),
            });
        }
        assert!(url.ends_with(".metadata"), "unexpected request: {url}");
        Ok(reply(
            "Name: pkg\nVersion: 1.0\nLicense-Expression: MIT\n".to_owned(),
        ))
    }
}

fn release_json() -> String {
    serde_json::json!({
        "info": {"name": "pkg", "version": "1.0"},
        "urls": [
            {"filename": "pkg-1.0.tar.gz", "url": "https://files.example/pkg-1.0.tar.gz", "yanked": false},
            {"filename": "pkg-1.0-py3-none-any.whl", "url": "https://files.example/pkg-1.0-py3-none-any.whl", "yanked": false}
        ]
    })
    .to_string()
}

#[test]
fn pypi_org_is_asked_for_the_release_not_the_project_listing() {
    let cache = tempdir().expect("tempdir");
    let fake = PypiFake {
        release_json: Some(release_json()),
        ..PypiFake::default()
    };
    let dist = fetch_distribution(
        &fake,
        "https://pypi.org/simple",
        "pkg",
        "1.0",
        &options(cache.path()),
    )
    .expect("fetch");
    assert_eq!(
        inspect_distribution(&dist, Some("pkg")).keys,
        BTreeSet::from(["MIT".to_owned()])
    );
    let requests = fake.requests.lock().expect("lock").clone();
    assert_eq!(
        requests,
        [
            "https://pypi.org/pypi/pkg/1.0/json",
            "https://files.example/pkg-1.0-py3-none-any.whl.metadata"
        ]
    );
}

#[test]
fn a_missing_release_document_falls_back_to_the_project_listing() {
    let cache = tempdir().expect("tempdir");
    let fake = PypiFake::default();
    fetch_distribution(
        &fake,
        "https://pypi.org/simple/",
        "pkg",
        "1.0",
        &options(cache.path()),
    )
    .expect("fetch");
    let requests = fake.requests.lock().expect("lock").clone();
    assert_eq!(requests[0], "https://pypi.org/pypi/pkg/1.0/json");
    assert_eq!(requests[1], "https://pypi.org/simple/pkg/");
}

#[test]
fn only_the_default_index_uses_the_release_endpoint() {
    for index in [
        "https://nexus.example.com/repository/pypi/simple",
        "https://pypi.org.evil.example/simple",
        "https://test.pypi.org/simple",
        "http://127.0.0.1:1234/simple",
        "https://pypi.org/other",
    ] {
        assert_eq!(pypi_release_json_url(index, "pkg", "1.0"), None, "{index}");
    }
    assert_eq!(
        pypi_release_json_url("https://pypi.org/simple", "Some_Pkg", "1.0").as_deref(),
        Some("https://pypi.org/pypi/some-pkg/1.0/json")
    );
}

#[test]
fn release_json_parsing_handles_odd_documents() {
    assert!(files_from_release_json(b"not json").is_none());
    assert!(files_from_release_json(br#"{"urls": []}"#).is_none());
    assert!(files_from_release_json(br#"{"info": {}}"#).is_none());
    let files = files_from_release_json(
        br#"{"urls": [{"filename": "a.whl", "url": "u", "yanked": true}, {"filename": "a.tar.gz"}]}"#,
    )
    .expect("one usable file");
    assert_eq!(files.len(), 1);
    assert!(files[0].yanked && files[0].has_metadata);
}

#[test]
fn a_wheel_smaller_than_one_fetch_is_read_even_when_the_server_refuses_a_long_suffix() {
    let site = site();
    site.set(|s| s.ranges = true);
    site.add_wheel("1.0", Some(MIT), false);
    let cache = tempdir().expect("tempdir");
    let client = client();
    let dist = fetch_distribution(&client, &site.url(""), "pkg", "1.0", &options(cache.path()))
        .expect("fetch");
    assert_eq!(
        inspect_distribution(&dist, Some("pkg")).keys,
        BTreeSet::from(["MIT".to_owned()])
    );
    // The 416 did not make the host look range-incapable: a bigger wheel is still read by ranges.
    site.state.lock().expect("lock").wheels.insert(
        "pkg-2.0-py3-none-any.whl".to_owned(),
        make_padded_wheel("2.0", MIT, PAYLOAD),
    );
    let other = tempdir().expect("tempdir");
    let before = client.traffic().expect("traffic").bytes;
    fetch_distribution(&client, &site.url(""), "pkg", "2.0", &options(other.path())).expect("big");
    let used = client.traffic().expect("traffic").bytes - before;
    assert!(used < (PAYLOAD / 4) as u64, "used {used} bytes");
}

#[test]
fn a_known_small_size_skips_the_range_probe_entirely() {
    let site = site();
    site.set(|s| {
        s.ranges = true;
        s.json = true;
        s.wheels.insert(
            "pkg-1.0-py3-none-any.whl".to_owned(),
            make_wheel("1.0", Some(MIT), false),
        );
    });
    let cache = tempdir().expect("tempdir");
    fetch_distribution(
        &client(),
        &site.url(""),
        "pkg",
        "1.0",
        &options(cache.path()),
    )
    .expect("fetch");
    assert!(
        site.state.lock().expect("lock").range_headers.is_empty(),
        "no range request for a small wheel"
    );
}

// --------------------------------------------------------------------------------------
// Releases published only as a source distribution.
// --------------------------------------------------------------------------------------

fn sdist_tar_gz(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, body) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, body.as_bytes())
            .expect("append");
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(&builder.into_inner().expect("tar"))
        .expect("gzip");
    encoder.finish().expect("finish")
}

fn site_with_sdist(filename: &str, body: Vec<u8>) -> Site {
    let site = site();
    site.set(|s| {
        s.wheels.insert(filename.to_owned(), body);
    });
    site
}

fn fetched_sdist(site: &Site) -> Result<DistributionLicence, FetchError> {
    let cache = tempdir().expect("tempdir");
    fetch(site, cache.path(), "1.0").map(|dist| inspect_distribution(&dist, Some("pkg")))
}

#[test]
fn an_sdist_only_release_is_read_from_its_pkg_info() {
    let info = "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\nLicense-Expression: MIT\n";
    let site = site_with_sdist(
        "pkg-1.0.tar.gz",
        sdist_tar_gz(&[("pkg-1.0/PKG-INFO", info)]),
    );
    let detected = fetched_sdist(&site).expect("fetch");
    assert_eq!(detected.keys, BTreeSet::from(["MIT".to_owned()]));
    assert_eq!(detected.source, "declared metadata");
    assert_eq!(detected.version, "1.0");
}

#[test]
fn an_sdist_with_no_declared_license_is_matched_on_its_license_file() {
    let info = "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n";
    let site = site_with_sdist(
        "pkg-1.0.tar.gz",
        sdist_tar_gz(&[("pkg-1.0/PKG-INFO", info), ("pkg-1.0/LICENSE", MIT)]),
    );
    let detected = fetched_sdist(&site).expect("fetch");
    assert_eq!(detected.keys, BTreeSet::from(["MIT".to_owned()]));
    assert_eq!(detected.source, "license files: LICENSE");
}

#[test]
fn a_vendored_license_deep_in_an_sdist_is_not_mistaken_for_the_packages_own() {
    let info = "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n";
    let site = site_with_sdist(
        "pkg-1.0.tar.gz",
        sdist_tar_gz(&[
            ("pkg-1.0/PKG-INFO", info),
            ("pkg-1.0/LICENSE", MIT),
            ("pkg-1.0/third_party/other/LICENSE", GPL_2_0_TEXT),
        ]),
    );
    let detected = fetched_sdist(&site).expect("fetch");
    assert_eq!(
        detected.keys,
        BTreeSet::from(["MIT".to_owned()]),
        "{detected:?}"
    );
}

#[test]
fn a_license_file_named_in_pkg_info_is_found_wherever_it_is() {
    let info = "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\nLicense-File: src/pkg/COPYING.md\n";
    let site = site_with_sdist(
        "pkg-1.0.tar.gz",
        sdist_tar_gz(&[
            ("pkg-1.0/PKG-INFO", info),
            ("pkg-1.0/src/pkg/COPYING.md", MIT),
        ]),
    );
    assert_eq!(
        fetched_sdist(&site).expect("fetch").keys,
        BTreeSet::from(["MIT".to_owned()])
    );
}

#[test]
fn a_zip_sdist_is_read_too() {
    use zip::write::SimpleFileOptions;
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut buffer);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        archive
            .start_file("pkg-1.0/PKG-INFO", options)
            .expect("start");
        archive
            .write_all(b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n")
            .expect("write");
        archive
            .start_file("pkg-1.0/LICENSE", options)
            .expect("start");
        archive.write_all(MIT.as_bytes()).expect("write");
        archive.finish().expect("finish");
    }
    let site = site_with_sdist("pkg-1.0.zip", buffer.into_inner());
    assert_eq!(
        fetched_sdist(&site).expect("fetch").keys,
        BTreeSet::from(["MIT".to_owned()])
    );
}

#[test]
fn an_sdist_that_cannot_be_read_fails_closed_with_the_reason() {
    let site = site_with_sdist("pkg-1.0.tar.gz", b"not an archive".to_vec());
    let error = fetched_sdist(&site).expect_err("error");
    assert!(
        error
            .0
            .contains("pkg-1.0.tar.gz: not a valid sdist archive"),
        "{error}"
    );

    let cache = tempdir().expect("tempdir");
    assert!(
        walk_files(cache.path()).is_empty(),
        "nothing is cached for a failed read"
    );
}

#[test]
fn an_sdist_over_the_size_cap_is_not_downloaded() {
    let site = site_with_sdist(
        "pkg-1.0.tar.gz",
        sdist_tar_gz(&[("pkg-1.0/PKG-INFO", "Name: pkg\n")]),
    );
    let cache = tempdir().expect("tempdir");
    let tiny = FetchOptions {
        cache_dir: cache.path(),
        max_wheel_bytes: 10,
    };
    let error =
        fetch_distribution(&client(), &site.url(""), "pkg", "1.0", &tiny).expect_err("error");
    assert!(error.0.contains("larger than"), "{error}");
}

#[test]
fn index_check_inspects_an_sdist_only_release() {
    let info = "Metadata-Version: 2.4\nName: pkg\nVersion: 1.1\nLicense-Expression: MIT\n";
    let site = site_with_sdist(
        "pkg-1.1.tar.gz",
        sdist_tar_gz(&[("pkg-1.1/PKG-INFO", info)]),
    );
    let audit = audit_site(&client(), &site.url(""), "1.0").expect("audit");
    assert_eq!(found(&audit).evidence.as_deref(), Some("declares MIT"));
}

#[test]
fn a_reuse_style_licenses_directory_in_an_sdist_is_matched() {
    let info = "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n";
    let site = site_with_sdist(
        "pkg-1.0.tar.gz",
        sdist_tar_gz(&[
            ("pkg-1.0/PKG-INFO", info),
            ("pkg-1.0/LICENSES/MIT.txt", MIT),
        ]),
    );
    assert_eq!(
        fetched_sdist(&site).expect("fetch").keys,
        BTreeSet::from(["MIT".to_owned()])
    );
}

const TLS_CA: &str = include_str!("../../../tests/fixtures/tls/ca.pem");
const TLS_SERVER_CERT: &str = include_str!("../../../tests/fixtures/tls/server.pem");
const TLS_SERVER_KEY: &str = include_str!("../../../tests/fixtures/tls/server.key");
const TLS_INDEX_PAGE: &str = "<a href=\"pkg-1.0.tar.gz\">pkg-1.0.tar.gz</a>";

/// An HTTPS index whose certificate is signed by the fixture CA, not by a public root.
fn private_ca_index() -> u16 {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::Read;

    let certs = CertificateDer::pem_slice_iter(TLS_SERVER_CERT.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("server certificate");
    let key = PrivateKeyDer::from_pem_slice(TLS_SERVER_KEY.as_bytes()).expect("server key");
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            thread::spawn(move || {
                let Ok(connection) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(read) => request.extend_from_slice(&chunk[..read]),
                    }
                }
                let _ = write!(
                    tls,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{TLS_INDEX_PAGE}",
                    TLS_INDEX_PAGE.len()
                );
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    port
}

#[test]
fn a_private_ca_index_is_trusted_only_with_its_ca_bundle() {
    let url = format!("https://127.0.0.1:{}/simple/pkg/", private_ca_index());
    let mut client = client();

    let refused = client.get(&url, None, None).expect_err("untrusted CA");
    let message = refused.to_string();
    assert!(message.starts_with("TLS verification failed"), "{message}");
    assert!(message.contains("--ca-cert"), "{message}");

    let tmp = tempdir().expect("tempdir");
    let bundle = tmp.path().join("ca.pem");
    std::fs::write(&bundle, TLS_CA).expect("write");
    client.set_trust(&Trust::WithExtra(CaBundle {
        path: bundle,
        origin: "--ca-cert".to_owned(),
    }));
    let page = client.get(&url, None, None).expect("trusted CA");
    assert_eq!(String::from_utf8_lossy(&page.body), TLS_INDEX_PAGE);
}
