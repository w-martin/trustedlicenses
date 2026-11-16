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

#[must_use]
pub fn network_message(error: &ureq::Error, url: &str) -> String {
    let is_tls = matches!(
        error,
        ureq::Error::Rustls(_) | ureq::Error::Pem(_) | ureq::Error::Tls(_)
    );
    if is_tls {
        return tls_message(&error.to_string(), url);
    }
    format!("Could not reach {}: {error}.", redact_url(url))
}

fn tls_message(reason: &str, url: &str) -> String {
    format!(
        "TLS verification failed for {}: {reason}. If your index uses a private CA, \
         point SSL_CERT_FILE at its certificate bundle.",
        redact_url(url)
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

/// The real network layer, honouring proxy and CA settings from the environment.
pub struct HttpClient {
    agent: ureq::Agent,
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
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .user_agent("trustedlicenses")
            .redirect_auth_headers(ureq::config::RedirectAuthHeaders::SameHost)
            .build();
        Self {
            agent: config.into(),
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
        let credentials = self.credentials(&parsed);
        let mut clean = parsed.clone();
        let _ = clean.set_username("");
        let _ = clean.set_password(None);
        let clean = clean.to_string();

        self.requests.fetch_add(1, Ordering::Relaxed);
        let started = std::time::Instant::now();
        let mut request = self.agent.get(&clean);
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
            other => query(network_message(&other, &clean)),
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
                        other => query(network_message(&other, &clean)),
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
                .map_err(|error| query(network_message(&error, &clean)))?,
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
    fn a_tls_failure_names_ssl_cert_file() {
        assert!(
            tls_message("certificate verify failed", "https://idx/pkg/").contains("SSL_CERT_FILE")
        );
    }

    #[test]
    fn a_plain_connection_failure_does_not_mention_ssl_cert_file() {
        let message = network_message(&ureq::Error::ConnectionFailed, "https://idx/pkg/");
        assert!(!message.contains("SSL_CERT_FILE"));
        assert!(message.contains("Could not reach"));
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
