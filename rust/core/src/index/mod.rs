//! Ask a package index about a package's releases.
//!
//! Two uses share this machinery. [`audit_package`] answers "does a newer release ship a
//! license?" for the opt-in `index-check`. [`fetch_distribution`] reads a pinned release's
//! license metadata for a package that is in a lock file but not installed.
//!
//! Works against any index speaking the standard "simple" API (PEP 503), preferring the
//! JSON form (PEP 691) and, per release, the small separate metadata file (PEP 658) over
//! downloading a whole wheel. Only the package *name* is ever sent.

pub mod http;
pub mod ranged;
pub mod sdist;

#[cfg(test)]
mod tests;

pub use http::{CaBundle, HttpClient, Trust};
pub use ranged::{open_wheel, ByteRange, RangeResponse, WheelSource};

use crate::detection::{declared_keys, resolve_license_expression, Distribution};
use crate::index_discovery::redact_url;
use crate::sources::installed::parse_metadata;
use pep440_rs::Version;
use percent_encoding::percent_decode_str;
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

pub const TIMEOUT_SECONDS: u64 = 20;
pub const MAX_WHEEL_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_VERSIONS_CHECKED: usize = 10;
/// Cap on one extracted license file; real license texts are a few tens of kilobytes.
const MAX_LICENCE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const ACCEPT: &str =
    "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.1";
const LICENCE_NAME_PREFIXES: [&str; 4] = ["LICENSE", "LICENCE", "COPYING", "NOTICE"];

/// A query failed in a way the user can act on; the `Display` text is the explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexError {
    /// The index answered with an HTTP error status.
    Http {
        status: u16,
        message: String,
    },
    Query(String),
}

impl IndexError {
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Http { status, .. } => Some(*status),
            Self::Query(_) => None,
        }
    }
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { message, .. } | Self::Query(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for IndexError {}

/// A fetched document.
#[derive(Clone, Debug)]
pub struct Response {
    /// The final URL after any redirects; relative links resolve against this.
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// What the index logic needs from a network layer; fakeable in tests.
pub trait Client: Sync {
    /// Fetch `url`, failing with an [`IndexError`] on any problem.
    ///
    /// # Errors
    ///
    /// On network failure, a non-success status, or a body over `max_bytes`.
    fn get(
        &self,
        url: &str,
        accept: Option<&str>,
        max_bytes: Option<usize>,
    ) -> Result<Response, IndexError>;

    /// Describe where credentials for `url` come from, for the report.
    fn credentials_for(&self, url: &str) -> String;

    /// Which certificate authorities HTTPS may chain to. Only a real network layer has any.
    fn set_trust(&mut self, _trust: &Trust) {}

    /// What this client has fetched so far, when it keeps count.
    fn traffic(&self) -> Option<Traffic> {
        None
    }

    /// Fetch part of a file. `Ok(None)` when the server does not honour range requests, in which
    /// case the caller falls back to a plain `get`.
    ///
    /// # Errors
    ///
    /// On network failure or a non-success status.
    fn get_range(
        &self,
        _url: &str,
        _range: ByteRange,
    ) -> Result<Option<RangeResponse>, IndexError> {
        Ok(None)
    }
}

/// How much a client has fetched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub requests: u64,
    /// Response body bytes received.
    pub bytes: u64,
}

/// One downloadable file listed on an index page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexFile {
    pub filename: String,
    pub url: String,
    /// Whether the index advertises a separate metadata file (PEP 658).
    pub has_metadata: bool,
    pub yanked: bool,
    /// The file's size in bytes, when the index says (PEP 700).
    pub size: Option<u64>,
}

fn canonicalize_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut in_separator = false;
    for ch in name.chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !in_separator {
                result.push('-');
            }
            in_separator = true;
        } else {
            in_separator = false;
            result.extend(ch.to_lowercase());
        }
    }
    result
}

/// Python truthiness of a JSON value, for fields an index may give as a bool or an object.
fn truthy(value: Option<&Json>) -> bool {
    match value {
        None | Some(Json::Null) => false,
        Some(Json::Bool(flag)) => *flag,
        Some(Json::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0),
        Some(Json::String(text)) => !text.is_empty(),
        Some(Json::Array(items)) => !items.is_empty(),
        Some(Json::Object(map)) => !map.is_empty(),
    }
}

fn join_url(base: &str, reference: &str) -> String {
    Url::parse(base)
        .and_then(|base| base.join(reference))
        .map_or_else(|_| reference.to_owned(), |joined| joined.to_string())
}

fn files_from_json(response: &Response) -> Result<Vec<IndexFile>, IndexError> {
    let document: Json = serde_json::from_slice(&response.body).map_err(|error| {
        IndexError::Query(format!(
            "{} returned invalid JSON: {error}.",
            redact_url(&response.url)
        ))
    })?;
    let mut files = Vec::new();
    for entry in document
        .get("files")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(filename), Some(url)) = (
            entry.get("filename").and_then(Json::as_str),
            entry.get("url").and_then(Json::as_str),
        ) else {
            continue;
        };
        files.push(IndexFile {
            filename: filename.to_owned(),
            url: join_url(&response.url, url),
            has_metadata: truthy(entry.get("core-metadata"))
                || truthy(entry.get("dist-info-metadata")),
            yanked: truthy(entry.get("yanked")),
            size: entry.get("size").and_then(Json::as_u64),
        });
    }
    Ok(files)
}

fn unescape_html(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        result.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let replaced = after.find(';').and_then(|end| {
            let entity = &after[..end];
            let ch = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => entity.strip_prefix('#').and_then(|number| {
                    let code = match number.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => number.parse().ok()?,
                    };
                    char::from_u32(code)
                }),
            }?;
            Some((ch, end + 2))
        });
        match replaced {
            Some((ch, consumed)) => {
                result.push(ch);
                rest = &rest[start + consumed..];
            }
            None => {
                result.push('&');
                rest = after;
            }
        }
    }
    result.push_str(rest);
    result
}

/// The attributes of every `<a ...>` tag, names lowercased, values unescaped. A bare
/// attribute has the value `None`.
fn anchor_attributes(html: &str) -> Vec<Vec<(String, Option<String>)>> {
    let bytes = html.as_bytes();
    let mut anchors = Vec::new();
    let mut position = 0;
    while let Some(offset) = html[position..].find('<') {
        let start = position + offset + 1;
        position = start;
        let is_anchor = bytes
            .get(start)
            .is_some_and(|b| b.eq_ignore_ascii_case(&b'a'))
            && bytes
                .get(start + 1)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'>' || *b == b'/');
        if !is_anchor {
            continue;
        }
        let mut index = start + 1;
        let mut attributes = Vec::new();
        loop {
            while bytes
                .get(index)
                .is_some_and(|b| b.is_ascii_whitespace() || *b == b'/')
            {
                index += 1;
            }
            match bytes.get(index) {
                None => break,
                Some(b'>') => {
                    index += 1;
                    break;
                }
                _ => {}
            }
            let name_start = index;
            while bytes
                .get(index)
                .is_some_and(|b| !b.is_ascii_whitespace() && !matches!(*b, b'=' | b'>' | b'/'))
            {
                index += 1;
            }
            let name = html[name_start..index].to_lowercase();
            while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
                index += 1;
            }
            let mut value = None;
            if bytes.get(index) == Some(&b'=') {
                index += 1;
                while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
                    index += 1;
                }
                match bytes.get(index) {
                    Some(&quote) if quote == b'"' || quote == b'\'' => {
                        let value_start = index + 1;
                        let end = html[value_start..]
                            .find(quote as char)
                            .map_or(html.len(), |e| value_start + e);
                        value = Some(unescape_html(&html[value_start..end]));
                        index = (end + 1).min(html.len());
                    }
                    _ => {
                        let value_start = index;
                        while bytes
                            .get(index)
                            .is_some_and(|b| !b.is_ascii_whitespace() && *b != b'>')
                        {
                            index += 1;
                        }
                        value = Some(unescape_html(&html[value_start..index]));
                    }
                }
            }
            if !name.is_empty() {
                attributes.push((name, value));
            }
        }
        position = index;
        anchors.push(attributes);
    }
    anchors
}

fn files_from_html(response: &Response) -> Vec<IndexFile> {
    let html = String::from_utf8_lossy(&response.body);
    let mut files = Vec::new();
    for attributes in anchor_attributes(&html) {
        let attribute = |name: &str| {
            attributes
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
        };
        let Some(Some(href)) = attribute("href")
            .map(|value| value.as_deref())
            .filter(|href| href.is_some_and(|h| !h.is_empty()))
        else {
            continue;
        };
        if attribute("data-yanked").is_some() {
            continue;
        }
        // Python's `a or b`: an empty first attribute falls through to the second, and
        // only a missing one counts as "not advertised".
        let text = |name: &str| attribute(name).map(|value| value.clone().unwrap_or_default());
        let advertised = match text("data-core-metadata") {
            Some(value) if !value.is_empty() => Some(value),
            _ => text("data-dist-info-metadata"),
        };
        let path = href.split(['#', '?']).next().unwrap_or(href);
        let filename = percent_decode_str(path.rsplit('/').next().unwrap_or(path))
            .decode_utf8_lossy()
            .into_owned();
        files.push(IndexFile {
            filename,
            url: join_url(&response.url, href),
            has_metadata: advertised.is_some(),
            yanked: false,
            size: None,
        });
    }
    files
}

fn project_files(
    client: &dyn Client,
    index_url: &str,
    package: &str,
) -> Result<(Vec<IndexFile>, bool), IndexError> {
    let page_url = format!(
        "{}/{}/",
        index_url.trim_end_matches('/'),
        canonicalize_name(package)
    );
    let response = client.get(&page_url, Some(ACCEPT), None)?;
    if response.content_type.contains("json") {
        Ok((files_from_json(&response)?, true))
    } else {
        Ok((files_from_html(&response), false))
    }
}

fn is_valid_wheel_name_part(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

/// The version in a wheel or sdist filename, or `None` when it is neither.
fn filename_version(filename: &str) -> Option<Version> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let parts: Vec<&str> = stem.split('-').collect();
        if !(parts.len() == 5 || parts.len() == 6) || !is_valid_wheel_name_part(parts[0]) {
            return None;
        }
        if parts.len() == 6 && !parts[2].starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        return Version::from_str(parts[1]).ok();
    }
    let stem = filename
        .strip_suffix(".tar.gz")
        .or_else(|| filename.strip_suffix(".zip"))?;
    let (name, version) = stem.rsplit_once('-')?;
    if name.is_empty() {
        return None;
    }
    Version::from_str(version).ok()
}

fn releases(files: &[IndexFile]) -> BTreeMap<Version, Vec<&IndexFile>> {
    let mut by_version: BTreeMap<Version, Vec<&IndexFile>> = BTreeMap::new();
    for file in files {
        if let Some(version) = filename_version(&file.filename) {
            by_version.entry(version).or_default().push(file);
        }
    }
    by_version
}

fn pick_wheel<'a>(files: &[&'a IndexFile]) -> Option<&'a IndexFile> {
    let wheels: Vec<&IndexFile> = files
        .iter()
        .copied()
        .filter(|f| f.filename.ends_with(".whl"))
        .collect();
    wheels
        .iter()
        .copied()
        .find(|f| f.filename.ends_with("-none-any.whl"))
        .or_else(|| wheels.first().copied())
}

/// The source distribution among a release's files, preferring a `.tar.gz` to the older `.zip`.
fn pick_sdist<'a>(files: &[&'a IndexFile]) -> Option<&'a IndexFile> {
    let ends = |suffix: &str| files.iter().copied().find(|f| f.filename.ends_with(suffix));
    ends(".tar.gz").or_else(|| ends(".zip"))
}

fn is_licence_file_name(name: &str) -> bool {
    let upper = name.rsplit('/').next().unwrap_or(name).to_uppercase();
    LICENCE_NAME_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
}

/// Say why a release counts as shipping a detectable license, or `None`.
fn evidence(metadata_text: &str, dist_info_names: &[String]) -> Option<String> {
    let metadata = parse_metadata(metadata_text);
    let license_files: Vec<&str> = metadata.get_all("License-File").collect();
    if !license_files.is_empty() {
        return Some(format!("License-File: {}", license_files.join(", ")));
    }
    let statements = metadata
        .get_all("License-Expression")
        .chain(
            metadata
                .get_all("License")
                .filter(|value| !value.contains('\n')),
        )
        .chain(
            metadata
                .get_all("Classifier")
                .filter(|value| value.starts_with("License ::")),
        );
    let resolved: std::collections::BTreeSet<String> =
        statements.flat_map(resolve_license_expression).collect();
    if !resolved.is_empty() {
        return Some(format!(
            "declares {}",
            resolved.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    dist_info_names
        .iter()
        .find(|name| is_licence_file_name(name))
        .map(|name| format!("bundles {}", name.rsplit('/').next().unwrap_or(name)))
}

fn metadata_url(file_url: &str) -> String {
    match Url::parse(file_url) {
        Ok(mut url) => {
            let path = format!("{}.metadata", url.path());
            url.set_path(&path);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => format!("{file_url}.metadata"),
    }
}

/// What one release of the package declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionFinding {
    pub version: Version,
    /// Why it counts as shipping a detectable license, or `None`.
    pub evidence: Option<String>,
    /// Why it could not be inspected, if it could not.
    pub note: Option<String>,
}

/// Names and METADATA text of a wheel's `.dist-info` entries.
fn read_wheel(source: WheelSource<'_>) -> Result<(Vec<String>, String), String> {
    let mut archive = zip::ZipArchive::new(source)
        .map_err(|error| format!("not a valid wheel archive: {error}"))?;
    let names: Vec<String> = (0..archive.len())
        .filter_map(|index| {
            archive
                .name_for_index(index)
                .and_then(Result::ok)
                .map(std::borrow::Cow::into_owned)
        })
        .filter(|name| name.contains(".dist-info/"))
        .collect();
    let metadata = names
        .iter()
        .find(|name| name.ends_with(".dist-info/METADATA"));
    let text = match metadata {
        Some(name) => {
            let mut entry = archive
                .by_name(name)
                .map_err(|error| format!("unreadable METADATA in wheel: {error}"))?;
            let mut bytes = Vec::new();
            entry
                .by_ref()
                .take(MAX_LICENCE_FILE_BYTES)
                .read_to_end(&mut bytes)
                .map_err(|error| format!("unreadable METADATA in wheel: {error}"))?;
            String::from_utf8_lossy(&bytes).into_owned()
        }
        None => String::new(),
    };
    Ok((names, text))
}

fn inspect(
    client: &dyn Client,
    version: &Version,
    files: &[&IndexFile],
    max_wheel_bytes: usize,
) -> Result<VersionFinding, IndexError> {
    let finding = |evidence, note| VersionFinding {
        version: version.clone(),
        evidence,
        note,
    };
    let Some(wheel) = pick_wheel(files) else {
        let Some(sdist) = pick_sdist(files) else {
            return Ok(finding(
                None,
                Some("no wheel or source distribution is published".to_owned()),
            ));
        };
        let read = client
            .get(&sdist.url, None, Some(max_wheel_bytes))
            .map_err(|error| error.to_string())
            .and_then(|response| sdist::read_sdist(&response.body, &sdist.filename));
        return Ok(match read {
            Ok(contents) => {
                let names: Vec<String> = contents
                    .licences
                    .iter()
                    .map(|(path, _)| {
                        sdist::stored_path(path)
                            .to_string_lossy()
                            .replace('\\', "/")
                    })
                    .collect();
                finding(evidence(&contents.pkg_info, &names), None)
            }
            Err(error) => finding(
                None,
                Some(format!(
                    "only a source distribution is published, and it could not be read: {error}"
                )),
            ),
        });
    };
    if wheel.has_metadata {
        match client.get(&metadata_url(&wheel.url), None, None) {
            Ok(response) => {
                let text = String::from_utf8_lossy(&response.body);
                return Ok(finding(evidence(&text, &[]), None));
            }
            Err(IndexError::Http { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    let source = match open_wheel(client, &wheel.url, wheel.size, max_wheel_bytes) {
        Ok(source) => source,
        Err(error) => return Ok(finding(None, Some(error.to_string()))),
    };
    match read_wheel(source) {
        Ok((names, text)) => Ok(finding(evidence(&text, &names), None)),
        Err(note) => Ok(finding(None, Some(note))),
    }
}

/// The outcome of asking an index about one package.
#[derive(Clone, Debug)]
pub struct Audit {
    pub index_url: String,
    pub package: String,
    /// The installed version string ("" if unknown).
    pub installed: String,
    /// Whether the index answered in JSON (PEP 691).
    pub served_json: bool,
    /// Whether any release advertises separate metadata (PEP 658).
    pub has_metadata: bool,
    /// Where credentials came from.
    pub credentials: String,
    /// The oldest *newer* release that ships a license, if any.
    pub first_with_license: Option<VersionFinding>,
    /// The newest release inspected; `None` when nothing is newer.
    pub latest: Option<VersionFinding>,
    pub newer_count: usize,
    pub checked: usize,
}

/// Limits for [`audit_package`].
#[derive(Clone, Copy, Debug)]
pub struct AuditOptions {
    pub max_versions: usize,
    pub max_wheel_bytes: usize,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            max_versions: MAX_VERSIONS_CHECKED,
            max_wheel_bytes: MAX_WHEEL_BYTES,
        }
    }
}

/// Find the first release newer than the installed one that ships a license.
///
/// `installed_version` may be `""` to consider every release, or unparseable, which does
/// the same. Newer releases are inspected oldest first, up to `max_versions`; the latest is
/// inspected regardless so the report can say what it found.
///
/// # Errors
///
/// When the index cannot be queried.
pub fn audit_package(
    client: &dyn Client,
    index_url: &str,
    package: &str,
    installed_version: &str,
    options: AuditOptions,
) -> Result<Audit, IndexError> {
    let (files, served_json) = project_files(client, index_url, package)?;
    let live: Vec<IndexFile> = files.iter().filter(|file| !file.yanked).cloned().collect();
    let by_version = releases(&live);
    let installed = if installed_version.is_empty() {
        None
    } else {
        Version::from_str(installed_version).ok()
    };
    let allow_pre = installed.as_ref().is_some_and(Version::any_prerelease);
    let newer: Vec<&Version> = by_version
        .keys()
        .filter(|version| {
            installed
                .as_ref()
                .is_none_or(|installed| *version > installed)
        })
        .filter(|version| allow_pre || !version.any_prerelease())
        .collect();

    let mut first = None;
    let mut inspected: BTreeMap<&Version, VersionFinding> = BTreeMap::new();
    for version in newer.iter().take(options.max_versions) {
        let finding = inspect(
            client,
            version,
            &by_version[*version],
            options.max_wheel_bytes,
        )?;
        let found = finding.evidence.is_some();
        inspected.insert(version, finding.clone());
        if found {
            first = Some(finding);
            break;
        }
    }

    let latest = match newer.last() {
        Some(version) => Some(match inspected.get(version) {
            Some(finding) => finding.clone(),
            None => inspect(
                client,
                version,
                &by_version[*version],
                options.max_wheel_bytes,
            )?,
        }),
        None => None,
    };
    Ok(Audit {
        index_url: index_url.to_owned(),
        package: package.to_owned(),
        installed: installed_version.to_owned(),
        served_json,
        has_metadata: files.iter().any(|file| file.has_metadata),
        credentials: client.credentials_for(index_url),
        first_with_license: first,
        latest,
        newer_count: newer.len(),
        checked: inspected.len(),
    })
}

/// Render an [`Audit`] for a terminal: what the index supports, then the finding and what
/// to do about it.
#[must_use]
pub fn format_audit(audit: &Audit) -> String {
    let yes_no = |flag: bool, yes: &'static str, no: &'static str| if flag { yes } else { no };
    let mut lines = vec![
        format!("  Index: {}", redact_url(&audit.index_url)),
        format!(
            "    credentials: {}; JSON API: {}; separate metadata (PEP 658): {}",
            audit.credentials,
            yes_no(audit.served_json, "yes", "no"),
            yes_no(audit.has_metadata, "yes", "no (wheels are downloaded)")
        ),
        format!(
            "  {} {}:",
            audit.package,
            if audit.installed.is_empty() {
                "(not installed)"
            } else {
                &audit.installed
            }
        ),
    ];
    if let Some(found) = &audit.first_with_license {
        lines.push(format!(
            "    {} is the first newer release that ships a license ({}).",
            found.version,
            found.evidence.as_deref().unwrap_or("")
        ));
        if let Some(latest) = audit
            .latest
            .as_ref()
            .filter(|latest| latest.version != found.version)
        {
            lines.push(format!("    The latest release is {}.", latest.version));
        }
        lines.push(format!(
            "    -> upgrading to {}>={} would let this be detected. Whether your other dependencies allow \
             that is up to your resolver.",
            audit.package, found.version
        ));
    } else if audit.newer_count == 0 {
        lines.push(
            "    This index lists no newer release, so an upgrade isn't available here.".to_owned(),
        );
    } else {
        lines.push(format!(
            "    None of the {} newer release(s) checked declares a license, so upgrading won't help by itself.",
            audit.checked
        ));
        if let Some(latest) = &audit.latest {
            if let Some(note) = &latest.note {
                lines.push(format!(
                    "    Latest release ({}) couldn't be inspected: {note}",
                    latest.version
                ));
            }
        }
        if audit.checked < audit.newer_count {
            lines.push(format!(
                "    ({} newer release(s) were not checked.)",
                audit.newer_count - audit.checked
            ));
        }
    }
    lines.push(
        "    Detected by what the release declares -- a wheel can bundle a license without declaring it."
            .to_owned(),
    );
    lines.join("\n")
}

/// A pinned release's license metadata could not be obtained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchError(pub String);

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FetchError {}

impl From<IndexError> for FetchError {
    fn from(error: IndexError) -> Self {
        Self(error.to_string())
    }
}

/// Where fetched metadata is cached, and the size cap for a wheel download.
#[derive(Clone, Copy, Debug)]
pub struct FetchOptions<'a> {
    pub cache_dir: &'a Path,
    pub max_wheel_bytes: usize,
}

/// The per-user cache directory: `TRUSTEDLICENSES_CACHE_DIR`, else the platform default.
#[must_use]
pub fn default_cache_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("TRUSTEDLICENSES_CACHE_DIR").filter(|dir| !dir.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    if cfg!(target_os = "macos") {
        return home().map(|home| home.join("Library/Caches/trustedlicenses"));
    }
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA")
            .map(|dir| PathBuf::from(dir).join("trustedlicenses"));
    }
    std::env::var_os("XDG_CACHE_HOME")
        .filter(|dir| !dir.is_empty())
        .map(|dir| PathBuf::from(dir).join("trustedlicenses"))
        .or_else(|| home().map(|home| home.join(".cache/trustedlicenses")))
}

fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn safe_component(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn cache_entry(options: &FetchOptions<'_>, index_url: &str, name: &str, version: &str) -> PathBuf {
    options
        .cache_dir
        .join(format!("v{CACHE_FORMAT}"))
        .join(format!("{:016x}", fnv1a(&redact_url(index_url))))
        .join(safe_component(name))
        .join(safe_component(version))
}

/// Part of each entry's path, so an entry an older layout wrote is never read, nor replaced in
/// place where another process might be reading it.
const CACHE_FORMAT: &str = "2";

/// Beside a cached `METADATA`: the in-tree build backend of the sdist it was read from.
const IN_TREE_BACKEND_FILE: &str = "in-tree-build-backend";

/// The in-tree build backend of the sdist a fetched distribution was read from, if any: what
/// installs is whatever that backend produces, which may not be what was read.
#[must_use]
pub fn in_tree_backend(distribution: &Distribution) -> Option<String> {
    let path = distribution.dist_info.as_ref()?.join(IN_TREE_BACKEND_FILE);
    fs::read_to_string(path)
        .ok()
        .map(|text| text.trim().to_owned())
}

fn load_cached(entry: &Path, name: &str, version: &str) -> Option<Distribution> {
    if !entry.join(".complete").is_file() {
        return None;
    }
    let dist_info = entry.join(format!(
        "{}-{}.dist-info",
        safe_component(name),
        safe_component(version)
    ));
    let text = fs::read(dist_info.join("METADATA")).ok()?;
    let metadata = parse_metadata(&String::from_utf8_lossy(&text));
    Some(Distribution {
        version: metadata.get("Version").unwrap_or(version).to_owned(),
        metadata,
        dist_info: Some(dist_info),
    })
}

/// The path of a wheel entry relative to its top-level `.dist-info` directory, if the entry is
/// something to copy: `METADATA`, or a license-like file at any depth below it. Decided from the
/// name alone, so choosing costs no reads: over a range-read wheel, touching an entry means fetching
/// the bytes around it.
fn wanted_entry(name: &str) -> Option<PathBuf> {
    if name.ends_with('/') || name.starts_with('/') || name.contains('\\') {
        return None;
    }
    let mut parts = name.split('/');
    let top = parts.next()?;
    let rest: Vec<&str> = parts.collect();
    let safe = rest
        .iter()
        .all(|part| !part.is_empty() && *part != "." && *part != "..");
    if !top.ends_with(".dist-info") || rest.is_empty() || !safe {
        return None;
    }
    let base = rest.last()?;
    let is_metadata = rest.len() == 1 && *base == "METADATA";
    (is_metadata || is_licence_file_name(base)).then(|| rest.iter().collect())
}

/// Copy `METADATA` and any license-like files out of a wheel into `dist_info`.
fn extract_wheel(source: WheelSource<'_>, dist_info: &Path) -> Result<(), FetchError> {
    let mut archive = zip::ZipArchive::new(source)
        .map_err(|error| FetchError(format!("not a valid wheel archive: {error}")))?;
    let io_error =
        |error: std::io::Error| FetchError(format!("could not cache wheel metadata: {error}"));
    let wanted: Vec<(usize, PathBuf)> = (0..archive.len())
        .filter_map(|index| {
            let name = archive.name_for_index(index)?.ok()?;
            wanted_entry(&name).map(|relative| (index, relative))
        })
        .collect();
    for (index, relative) in wanted {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| FetchError(format!("unreadable wheel entry: {error}")))?;
        let target = dist_info.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(MAX_LICENCE_FILE_BYTES)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        fs::write(target, bytes).map_err(io_error)?;
    }
    Ok(())
}

/// The release-level JSON document pypi.org serves for one version, which lists only that version's
/// files. Only for the default index: other indexes speak the simple API and nothing else is assumed.
fn pypi_release_json_url(index_url: &str, name: &str, version: &str) -> Option<String> {
    let parsed = Url::parse(index_url).ok()?;
    let is_pypi =
        parsed.host_str() == Some("pypi.org") && parsed.path().trim_end_matches('/') == "/simple";
    is_pypi.then(|| {
        format!(
            "https://pypi.org/pypi/{}/{version}/json",
            canonicalize_name(name)
        )
    })
}

/// The files of one release from pypi.org's release JSON. Wheels are assumed to have a separate
/// metadata file (PEP 658): pypi.org serves one for every wheel, and a miss just falls through to
/// reading the wheel.
fn files_from_release_json(body: &[u8]) -> Option<Vec<IndexFile>> {
    let document: Json = serde_json::from_slice(body).ok()?;
    let files: Vec<IndexFile> = document
        .get("urls")?
        .as_array()?
        .iter()
        .filter_map(|entry| {
            let filename = entry.get("filename")?.as_str()?;
            Some(IndexFile {
                filename: filename.to_owned(),
                url: entry.get("url")?.as_str()?.to_owned(),
                has_metadata: filename.ends_with(".whl"),
                yanked: truthy(entry.get("yanked")),
                size: entry.get("size").and_then(Json::as_u64),
            })
        })
        .collect();
    (!files.is_empty()).then_some(files)
}

/// The files of one release, from the release JSON where the index offers it and from the project
/// listing otherwise. The listing names every file of every release (megabytes for a popular package),
/// so skipping it is most of the saving when auditing a lock file.
fn release_files(
    client: &dyn Client,
    index_url: &str,
    name: &str,
    version: &str,
) -> Result<Vec<IndexFile>, IndexError> {
    let from_release_json = pypi_release_json_url(index_url, name, version)
        .and_then(|url| client.get(&url, None, None).ok())
        .and_then(|response| files_from_release_json(&response.body));
    match from_release_json {
        Some(files) => Ok(files),
        None => Ok(project_files(client, index_url, name)?.0),
    }
}

fn version_matches(file_version: &Version, wanted: &str) -> bool {
    Version::from_str(wanted).is_ok_and(|wanted| *file_version == wanted)
}

/// Download a source distribution and write its `PKG-INFO` as `METADATA`, with its license files,
/// into `dist_info`: the same shape a wheel's `.dist-info` has, so detection reads it the same way.
fn fill_from_sdist(
    client: &dyn Client,
    sdist: &IndexFile,
    dist_info: &Path,
    max_bytes: usize,
) -> Result<(), FetchError> {
    let io_error =
        |error: std::io::Error| FetchError(format!("could not cache sdist metadata: {error}"));
    let body = client.get(&sdist.url, None, Some(max_bytes))?.body;
    let contents = sdist::read_sdist(&body, &sdist.filename)
        .map_err(|error| FetchError(format!("{}: {error}", sdist.filename)))?;
    fs::write(dist_info.join("METADATA"), contents.pkg_info).map_err(io_error)?;
    if let Some(backend) = &contents.in_tree_backend {
        fs::write(dist_info.join(IN_TREE_BACKEND_FILE), backend).map_err(io_error)?;
    }
    for (relative, bytes) in contents.licences {
        let target = dist_info
            .join("licenses")
            .join(sdist::stored_path(&relative));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        fs::write(target, bytes).map_err(io_error)?;
    }
    Ok(())
}

/// Read the license metadata of a pinned release from an index.
///
/// Prefers the small separate metadata file (PEP 658) and stops there when declared
/// metadata already resolves; otherwise downloads the wheel to read its bundled license
/// files, exactly as for an installed package. A release with no wheel is read from its source
/// distribution. Results are cached under `options.cache_dir`, so a repeat run needs no network.
/// Fails closed: whatever can't be read is an error, never a pass.
///
/// # Errors
///
/// When the index cannot be queried, the release is not listed, or it cannot be inspected.
pub fn fetch_distribution(
    client: &dyn Client,
    index_url: &str,
    name: &str,
    version: &str,
    options: &FetchOptions<'_>,
) -> Result<Distribution, FetchError> {
    let entry = cache_entry(options, index_url, name, version);
    if let Some(cached) = load_cached(&entry, name, version) {
        return Ok(cached);
    }

    let files = release_files(client, index_url, name, version)?;
    let matching: Vec<&IndexFile> = files
        .iter()
        .filter(|file| {
            filename_version(&file.filename).is_some_and(|v| version_matches(&v, version))
        })
        .collect();
    if matching.is_empty() {
        return Err(FetchError(format!(
            "{name} {version} is not listed on {}.",
            redact_url(index_url)
        )));
    }
    let wheel = pick_wheel(&matching);
    let sdist = if wheel.is_none() {
        pick_sdist(&matching)
    } else {
        None
    };
    if wheel.is_none() && sdist.is_none() {
        return Err(FetchError(format!(
            "{name} {version} has no wheel or source distribution on {}.",
            redact_url(index_url)
        )));
    }

    let staging = entry.with_file_name(format!(
        "{}.partial-{}",
        safe_component(version),
        std::process::id()
    ));
    let dist_info = staging.join(format!(
        "{}-{}.dist-info",
        safe_component(name),
        safe_component(version)
    ));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&dist_info)
        .map_err(|error| FetchError(format!("could not create cache directory: {error}")))?;

    if let Some(wheel) = wheel {
        let mut declared_only = false;
        if wheel.has_metadata {
            match client.get(&metadata_url(&wheel.url), None, None) {
                Ok(response) => {
                    let text = String::from_utf8_lossy(&response.body).into_owned();
                    declared_only = !declared_keys(&parse_metadata(&text)).is_empty();
                    fs::write(dist_info.join("METADATA"), &response.body).map_err(|error| {
                        FetchError(format!("could not cache metadata: {error}"))
                    })?;
                }
                Err(IndexError::Http { .. }) => {}
                Err(error) => {
                    let _ = fs::remove_dir_all(&staging);
                    return Err(error.into());
                }
            }
        }
        if !declared_only {
            let result = open_wheel(client, &wheel.url, wheel.size, options.max_wheel_bytes)
                .map_err(FetchError::from)
                .and_then(|source| extract_wheel(source, &dist_info));
            if let Err(error) = result {
                let _ = fs::remove_dir_all(&staging);
                return Err(error);
            }
        }
    } else if let Some(sdist) = sdist {
        if let Err(error) = fill_from_sdist(client, sdist, &dist_info, options.max_wheel_bytes) {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    }
    if !dist_info.join("METADATA").is_file() {
        let _ = fs::remove_dir_all(&staging);
        return Err(FetchError(format!(
            "the distribution for {name} {version} has no METADATA file."
        )));
    }
    fs::write(staging.join(".complete"), b"")
        .map_err(|error| FetchError(format!("could not cache metadata: {error}")))?;

    // Another process may have filled the entry first; either copy is equivalent.
    if let Some(parent) = entry.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| FetchError(format!("could not create cache directory: {error}")))?;
    }
    if fs::rename(&staging, &entry).is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    load_cached(&entry, name, version)
        .ok_or_else(|| FetchError(format!("could not cache metadata for {name} {version}.")))
}
