//! The real network layer.
//!
//! Credentials come from the user's environment only: `user:pass@` in the index URL, or
//! `.netrc`. They are never forwarded to a different host on a redirect and never shown;
//! a URL's credentials are remembered per host because file links on an index page come
//! back without them but need them to download from that host.

use super::ranged::parse_content_range;
use super::{ByteRange, Client, IndexError, RangeResponse, Response, Traffic, TIMEOUT_SECONDS};
use crate::index_discovery::redact_url;
use base64::Engine;
use percent_encoding::percent_decode_str;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};
use url::Url;

const HTTP_UNAUTHORIZED: u16 = 401;
const HTTP_FORBIDDEN: u16 = 403;
const HTTP_NOT_FOUND: u16 = 404;

#[must_use]
pub fn http_message(status: u16, url: &str) -> String {
    let shown = redact_url(url);
    match status {
        HTTP_UNAUTHORIZED | HTTP_FORBIDDEN => format!(
            "{shown} rejected the request ({status}). Credentials are read from your environment \
             (user:pass@ in the index URL, or .netrc) -- this tool doesn't manage them."
        ),
        HTTP_NOT_FOUND => format!(
            "{shown} not found on this index (a package that isn't published there, e.g. an internal one)."
        ),
        _ => format!("{shown} returned HTTP {status}."),
    }
}

/// A PEM file of extra CA certificates to trust, and where its path came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaBundle {
    pub path: PathBuf,
    /// Shown in messages, e.g. `--ca-cert` or `SSL_CERT_FILE`.
    pub origin: String,
}

/// Which certificate authorities an index's TLS certificate may chain to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Trust {
    /// Mozilla's roots, built into the binary.
    #[default]
    Bundled,
    /// The bundled roots plus every certificate in a PEM file, e.g. a private CA.
    WithExtra(CaBundle),
    /// The operating system's certificate store.
    System,
}

impl Trust {
    fn describe(&self) -> String {
        match self {
            Self::Bundled => "the bundled Mozilla roots".to_owned(),
            Self::WithExtra(bundle) => format!(
                "the bundled Mozilla roots plus {} (from {})",
                bundle.path.display(),
                bundle.origin
            ),
            Self::System => "the operating system's certificate store (--system-certs)".to_owned(),
        }
    }
}

fn pem_certificates(bytes: &[u8]) -> Result<Vec<Certificate<'static>>, String> {
    let mut certificates = Vec::new();
    for item in ureq::tls::parse_pem(bytes) {
        if let PemItem::Certificate(certificate) = item.map_err(|error| error.to_string())? {
            certificates.push(certificate);
        }
    }
    Ok(certificates)
}

fn load_ca_bundle(bundle: &CaBundle) -> Result<Vec<Certificate<'static>>, String> {
    let shown = format!("{} (from {})", bundle.path.display(), bundle.origin);
    let unreadable = |error: std::io::Error| format!("Cannot read CA bundle {shown}: {error}.");
    let certificates = if bundle.path.is_dir() {
        // A certificate directory, as OpenSSL and requests accept: every PEM file in it.
        // Anything else there (an index, a README) is skipped rather than fatal.
        let mut files: Vec<PathBuf> = fs::read_dir(&bundle.path)
            .map_err(unreadable)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        files
            .iter()
            .filter_map(|path| fs::read(path).ok())
            .filter_map(|bytes| pem_certificates(&bytes).ok())
            .flatten()
            .collect()
    } else {
        let bytes = fs::read(&bundle.path).map_err(unreadable)?;
        pem_certificates(&bytes)
            .map_err(|error| format!("CA bundle {shown} is not valid PEM: {error}."))?
    };
    if certificates.is_empty() {
        return Err(format!(
            "CA bundle {shown} holds no PEM certificates (-----BEGIN CERTIFICATE-----)."
        ));
    }
    Ok(certificates)
}

fn root_certs(trust: &Trust) -> Result<RootCerts, String> {
    Ok(match trust {
        Trust::Bundled => RootCerts::WebPki,
        Trust::System => RootCerts::PlatformVerifier,
        Trust::WithExtra(bundle) => {
            let extra = load_ca_bundle(bundle)?;
            let mozilla = webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|der| Certificate::from_der(der.as_ref()));
            RootCerts::from(mozilla.chain(extra))
        }
    })
}

fn build_agent(timeout: Duration, trust: &Trust) -> Result<ureq::Agent, String> {
    let tls = TlsConfig::builder().root_certs(root_certs(trust)?).build();
    Ok(ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .user_agent("trustedlicenses")
        .redirect_auth_headers(ureq::config::RedirectAuthHeaders::SameHost)
        .tls_config(tls)
        .build()
        .into())
}

/// rustls reports a failed handshake as an I/O error, so look inside those too.
fn is_tls_error(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Rustls(_) | ureq::Error::Pem(_) | ureq::Error::Tls(_) => true,
        ureq::Error::Io(io) => io
            .get_ref()
            .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some()),
        _ => false,
    }
}

#[must_use]
pub fn network_message(error: &ureq::Error, url: &str, trust: &Trust) -> String {
    if is_tls_error(error) {
        let reason = match error {
            ureq::Error::Io(io) => io.to_string(),
            other => other.to_string(),
        };
        return tls_message(&reason, url, trust);
    }
    format!("Could not reach {}: {error}.", redact_url(url))
}

fn tls_message(reason: &str, url: &str, trust: &Trust) -> String {
    let advice = match trust {
        Trust::Bundled => {
            "If your index uses a private CA, pass its certificate with --ca-cert FILE (or set \
             SSL_CERT_FILE), or use --system-certs to trust your operating system's store."
        }
        Trust::WithExtra(_) => {
            "Check that the file holds the CA that issued this index's certificate, plus any \
             intermediate certificate the server does not send."
        }
        Trust::System => {
            "Check that your operating system trusts this index's CA, or pass it with --ca-cert \
             FILE instead of --system-certs."
        }
    };
    format!(
        "TLS verification failed for {}: {reason}. Trusting {}. {advice}",
        redact_url(url),
        trust.describe()
    )
}

#[derive(Clone, Debug, Default)]
struct NetrcEntry {
    machine: Option<String>,
    login: Option<String>,
    password: Option<String>,
}

/// Parse `.netrc` content: `machine`/`default` blocks with `login` and `password`.
fn parse_netrc(text: &str) -> Vec<NetrcEntry> {
    let mut entries: Vec<NetrcEntry> = Vec::new();
    let mut tokens = text.split_whitespace();
    while let Some(token) = tokens.next() {
        match token {
            "machine" => entries.push(NetrcEntry {
                machine: tokens.next().map(str::to_owned),
                ..NetrcEntry::default()
            }),
            "default" => entries.push(NetrcEntry::default()),
            "login" | "user" | "account" | "password" => {
                let value = tokens.next().map(str::to_owned);
                if let Some(entry) = entries.last_mut() {
                    match token {
                        "login" | "user" => entry.login = value,
                        "password" => entry.password = value,
                        _ => {}
                    }
                }
            }
            "macdef" => {
                // A macro runs to the next blank line, which whitespace-splitting cannot see;
                // stop here rather than misread its body as credentials.
                break;
            }
            _ => {}
        }
    }
    entries
}

fn netrc_login(path: Option<&PathBuf>, host: &str) -> Option<(String, String)> {
    let path = path?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).ok()?.permissions().mode();
        // Like Python's `netrc`, refuse a credentials file other users can read.
        if mode & 0o077 != 0 {
            return None;
        }
    }
    let entries = parse_netrc(&fs::read_to_string(path).ok()?);
    let entry = entries
        .iter()
        .find(|entry| entry.machine.as_deref() == Some(host))
        .or_else(|| entries.iter().find(|entry| entry.machine.is_none()))?;
    Some((
        entry.login.clone()?,
        entry.password.clone().unwrap_or_default(),
    ))
}

fn default_netrc_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("NETRC") {
        return Some(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let home = PathBuf::from(home);
    let unix = home.join(".netrc");
    Some(if unix.is_file() {
        unix
    } else {
        home.join("_netrc")
    })
}

fn netloc(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// The real network layer, honouring proxy settings from the environment.
pub struct HttpClient {
    /// An unusable CA bundle is reported by the first request, so a run that never touches the
    /// network is not failed by a stale `SSL_CERT_FILE`.
    agent: Result<ureq::Agent, String>,
    trust: Trust,
    timeout: Duration,
    netrc: Option<PathBuf>,
    url_credentials: Mutex<HashMap<String, (String, String)>>,
    /// Hosts that answered a range request with the whole file, so they are not asked again.
    range_unsupported: Mutex<HashSet<String>>,
    requests: AtomicU64,
    bytes: AtomicU64,
    /// Print each request's time and size to stderr (`TRUSTEDLICENSES_TRACE=1`).
    trace: bool,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient {
    #[must_use]
    pub fn new() -> Self {
        Self::with_options(Duration::from_secs(TIMEOUT_SECONDS), default_netrc_path())
    }

    /// A client with an explicit timeout and `.netrc` location, so tests need not touch the
    /// process environment.
    #[must_use]
    pub fn with_options(timeout: Duration, netrc: Option<PathBuf>) -> Self {
        let trust = Trust::Bundled;
        Self {
            agent: build_agent(timeout, &trust),
            trust,
            timeout,
            netrc,
            url_credentials: Mutex::new(HashMap::new()),
            range_unsupported: Mutex::new(HashSet::new()),
            requests: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            trace: std::env::var_os("TRUSTEDLICENSES_TRACE").is_some_and(|value| !value.is_empty()),
        }
    }

    fn remembered(&self) -> std::sync::MutexGuard<'_, HashMap<String, (String, String)>> {
        self.url_credentials
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn range_unsupported(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.range_unsupported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn credentials(&self, url: &Url) -> Option<(String, String)> {
        let key = netloc(url);
        if !url.username().is_empty() {
            let decode = |text: &str| percent_decode_str(text).decode_utf8_lossy().into_owned();
            self.remembered().insert(
                key.clone(),
                (decode(url.username()), decode(url.password().unwrap_or(""))),
            );
        }
        let remembered = self.remembered().get(&key).cloned();
        remembered.or_else(|| netrc_login(self.netrc.as_ref(), url.host_str().unwrap_or("")))
    }
}

fn basic(user: &str, password: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {encoded}")
}

impl Client for HttpClient {
    fn set_trust(&mut self, trust: &Trust) {
        self.agent = build_agent(self.timeout, trust);
        self.trust = trust.clone();
    }

    fn traffic(&self) -> Option<Traffic> {
        Some(Traffic {
            requests: self.requests.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        })
    }

    fn credentials_for(&self, url: &str) -> String {
        let Ok(parsed) = Url::parse(url) else {
            return "none".to_owned();
        };
        if !parsed.username().is_empty() || self.remembered().contains_key(&netloc(&parsed)) {
            return "in the index URL".to_owned();
        }
        if netrc_login(self.netrc.as_ref(), parsed.host_str().unwrap_or("")).is_some() {
            ".netrc".to_owned()
        } else {
            "none".to_owned()
        }
    }

    fn get(
        &self,
        url: &str,
        accept: Option<&str>,
        max_bytes: Option<usize>,
    ) -> Result<Response, IndexError> {
        self.fetch(url, accept, None, max_bytes)
            .map(|fetched| fetched.response)
    }

    fn get_range(&self, url: &str, range: ByteRange) -> Result<Option<RangeResponse>, IndexError> {
        let host = Url::parse(url)
            .map(|parsed| netloc(&parsed))
            .unwrap_or_default();
        if self.range_unsupported().contains(&host) {
            return Ok(None);
        }
        let wanted = match range {
            ByteRange::Suffix(count) => count,
            ByteRange::Span { start, end } => end.saturating_sub(start) + 1,
        };
        let slack = 1024;
        let max = usize::try_from(wanted)
            .unwrap_or(usize::MAX)
            .saturating_add(slack);
        let fetched = match self.fetch(url, None, Some(range), Some(max)) {
            Ok(fetched) => fetched,
            // The file is shorter than the range asked for, which some servers refuse rather than
            // answering with all of it. Ranges work; this file just is not worth them.
            Err(IndexError::Http { status: 416, .. }) => return Ok(None),
            Err(error) => return Err(error),
        };
        let unsupported = || {
            self.range_unsupported().insert(host.clone());
            Ok(None)
        };
        if fetched.status != 206 {
            return unsupported();
        }
        let Some((start, end, total)) = fetched
            .content_range
            .as_deref()
            .and_then(parse_content_range)
        else {
            return unsupported();
        };
        if end < start || (end - start + 1) != fetched.response.body.len() as u64 {
            return unsupported();
        }
        Ok(Some(RangeResponse {
            start,
            total,
            body: fetched.response.body,
        }))
    }
}

/// A completed request: the response, plus the parts a range request needs.
struct Fetched {
    response: Response,
    status: u16,
    content_range: Option<String>,
}

impl HttpClient {
    /// One request, with the credential, redirect, timeout and error handling both `get` and
    /// `get_range` share. With a `range`, a server that answers 200 (ignoring it) has its body left
    /// unread: the caller falls back to a plain `get`.
    fn fetch(
        &self,
        url: &str,
        accept: Option<&str>,
        range: Option<ByteRange>,
        max_bytes: Option<usize>,
    ) -> Result<Fetched, IndexError> {
        let query = |message: String| IndexError::Query(message);
        let parsed =
            Url::parse(url).map_err(|_| query(format!("Not a valid URL: {}", redact_url(url))))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(query(format!(
                "Refusing to fetch non-http(s) URL: {}",
                redact_url(url)
            )));
        }
        let agent = self
            .agent
            .as_ref()
            .map_err(|message| query(message.clone()))?;
        let credentials = self.credentials(&parsed);
        let mut clean = parsed.clone();
        let _ = clean.set_username("");
        let _ = clean.set_password(None);
        let clean = clean.to_string();

        self.requests.fetch_add(1, Ordering::Relaxed);
        let started = std::time::Instant::now();
        let mut request = agent.get(&clean);
        if let Some(accept) = accept {
            request = request.header("Accept", accept);
        }
        if let Some(range) = range {
            request = request.header("Range", range.header());
        }
        if let Some((user, password)) = &credentials {
            request = request.header("Authorization", basic(user, password));
        }
        let too_large = |max: usize| {
            query(format!(
                "{} is larger than {} MB; not downloading it.",
                redact_url(&clean),
                max / (1024 * 1024)
            ))
        };
        let mut response = request.call().map_err(|error| match error {
            ureq::Error::StatusCode(status) => IndexError::Http {
                status,
                message: http_message(status, &clean),
            },
            ureq::Error::Timeout(_) => query(format!(
                "Timed out after {:.0}s waiting for {}.",
                self.timeout.as_secs_f64(),
                redact_url(&clean)
            )),
            other => query(network_message(&other, &clean, &self.trust)),
        })?;

        let status = response.status().as_u16();
        let content_range = response
            .headers()
            .get("content-range")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let final_url = ureq::ResponseExt::get_uri(&response).to_string();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        if range.is_some() && status == 200 {
            return Ok(Fetched {
                response: Response {
                    url: final_url,
                    content_type,
                    body: Vec::new(),
                },
                status,
                content_range,
            });
        }
        let body = match max_bytes {
            Some(max) => {
                let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
                let body = response
                    .body_mut()
                    .with_config()
                    .limit(limit)
                    .read_to_vec()
                    .map_err(|error| match error {
                        ureq::Error::BodyExceedsLimit(_) => too_large(max),
                        ureq::Error::Timeout(_) => query(format!(
                            "Timed out after {:.0}s waiting for {}.",
                            self.timeout.as_secs_f64(),
                            redact_url(&clean)
                        )),
                        other => query(network_message(&other, &clean, &self.trust)),
                    })?;
                if body.len() > max {
                    return Err(too_large(max));
                }
                body
            }
            None => response
                .body_mut()
                .with_config()
                .limit(u64::MAX)
                .read_to_vec()
                .map_err(|error| query(network_message(&error, &clean, &self.trust)))?,
        };
        self.bytes.fetch_add(body.len() as u64, Ordering::Relaxed);
        if self.trace {
            eprintln!(
                "trace {:>7.1}ms {:>10} bytes {}{}",
                started.elapsed().as_secs_f64() * 1000.0,
                body.len(),
                if range.is_some() { "[range] " } else { "" },
                redact_url(&clean)
            );
        }
        Ok(Fetched {
            response: Response {
                url: final_url,
                content_type,
                body,
            },
            status,
            content_range,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn a_generic_http_status_is_reported_plainly() {
        assert!(http_message(500, "https://idx/pkg/").contains("HTTP 500"));
    }

    #[test]
    fn rejected_credentials_explain_where_they_come_from() {
        let message = http_message(401, "https://user:pw@idx/pkg/");
        assert!(message.contains(".netrc"));
        assert!(!message.contains("pw@"));
    }

    #[test]
    fn a_tls_failure_with_bundled_roots_suggests_the_ca_options() {
        let message = tls_message("UnknownIssuer", "https://idx/pkg/", &Trust::Bundled);
        assert!(message.contains("--ca-cert"));
        assert!(message.contains("SSL_CERT_FILE"));
        assert!(message.contains("--system-certs"));
    }

    #[test]
    fn a_tls_failure_with_a_ca_bundle_names_the_bundle() {
        let trust = Trust::WithExtra(CaBundle {
            path: PathBuf::from("/certs/corp.pem"),
            origin: "PIP_CERT".to_owned(),
        });
        let message = tls_message("UnknownIssuer", "https://idx/pkg/", &trust);
        assert!(message.contains("/certs/corp.pem (from PIP_CERT)"));
        assert!(message.contains("intermediate"));
    }

    #[test]
    fn a_rustls_error_wrapped_in_io_counts_as_tls() {
        let wrapped = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        let message = network_message(
            &ureq::Error::Io(wrapped),
            "https://idx/pkg/",
            &Trust::Bundled,
        );
        assert!(message.starts_with("TLS verification failed"), "{message}");
    }

    #[test]
    fn a_plain_connection_failure_does_not_mention_certificates() {
        let message = network_message(
            &ureq::Error::ConnectionFailed,
            "https://idx/pkg/",
            &Trust::Bundled,
        );
        assert!(!message.contains("SSL_CERT_FILE"));
        assert!(message.contains("Could not reach"));
    }

    fn bundle(path: PathBuf) -> CaBundle {
        CaBundle {
            path,
            origin: "--ca-cert".to_owned(),
        }
    }

    #[test]
    fn an_unusable_ca_bundle_fails_the_first_request_not_construction() {
        let tmp = tempdir().expect("tempdir");
        let empty = tmp.path().join("empty.pem");
        fs::write(&empty, "not a certificate\n").expect("write");
        for (path, expected) in [
            (tmp.path().join("missing.pem"), "Cannot read CA bundle"),
            (empty, "holds no PEM certificates"),
        ] {
            let mut client = HttpClient::new();
            client.set_trust(&Trust::WithExtra(bundle(path)));
            let error = client
                .get("https://idx.invalid/simple/", None, None)
                .expect_err("error");
            assert!(error.to_string().contains(expected), "{error}");
            assert!(error.to_string().contains("(from --ca-cert)"), "{error}");
        }
    }

    #[test]
    fn a_ca_directory_adds_every_pem_file_in_it() {
        let tmp = tempdir().expect("tempdir");
        let ca = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/tls/ca.pem");
        fs::copy(&ca, tmp.path().join("corp.pem")).expect("copy");
        fs::write(tmp.path().join("README"), "not a certificate\n").expect("write");
        let RootCerts::Specific(certs) =
            root_certs(&Trust::WithExtra(bundle(tmp.path().to_path_buf()))).expect("roots")
        else {
            panic!("expected specific roots");
        };
        assert_eq!(
            certs.len(),
            webpki_root_certs::TLS_SERVER_ROOT_CERTS.len() + 1
        );
        let empty = tempdir().expect("tempdir");
        let error = root_certs(&Trust::WithExtra(bundle(empty.path().to_path_buf())))
            .expect_err("no certificates");
        assert!(error.contains("holds no PEM certificates"), "{error}");
    }

    #[test]
    fn a_ca_bundle_adds_to_the_mozilla_roots() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/tls/ca.pem");
        let RootCerts::Specific(certs) =
            root_certs(&Trust::WithExtra(bundle(path))).expect("roots")
        else {
            panic!("expected specific roots");
        };
        assert_eq!(
            certs.len(),
            webpki_root_certs::TLS_SERVER_ROOT_CERTS.len() + 1
        );
    }

    #[test]
    fn non_http_urls_are_refused() {
        let error = HttpClient::new()
            .get("file:///etc/passwd", None, None)
            .expect_err("error");
        assert!(error.to_string().contains("non-http"));
    }

    #[test]
    fn netrc_picks_the_machine_then_default_and_ignores_world_readable_files() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("netrc");
        fs::write(
            &path,
            "machine a.example login ua password pa\nmachine b.example\n  login ub\n  password pb\ndefault login ud password pd\n",
        )
        .expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
            assert_eq!(netrc_login(Some(&path), "a.example"), None);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert_eq!(
            netrc_login(Some(&path), "a.example"),
            Some(("ua".to_owned(), "pa".to_owned()))
        );
        assert_eq!(
            netrc_login(Some(&path), "b.example"),
            Some(("ub".to_owned(), "pb".to_owned()))
        );
        assert_eq!(
            netrc_login(Some(&path), "other"),
            Some(("ud".to_owned(), "pd".to_owned()))
        );
        assert_eq!(netrc_login(None, "a.example"), None);
    }
}
