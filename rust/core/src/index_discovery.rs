//! Work out which package index to ask about a package, from what the project already
//! configures. Nothing here touches the network, and the answer is always shown for
//! confirmation before anything is sent: guessing wrong could send an internal package's
//! name to a public host.
//!
//! First hit wins: the project's lock file (which records the index each package actually
//! came from, right even for multi-index projects), then index settings in the project's
//! own files (uv, poetry, pipenv), then the environment and `pip.conf`, then pypi.org,
//! labelled as an assumption. Credentials are deliberately not handled here.

use crate::detection::canonical_name;
use crate::index::CaBundle;
use crate::sources::lock::{parse_pipfile_lock, parse_poetry_lock, parse_uv_lock};
use crate::sources::{LockedPackage, PackageSource};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_INDEX: &str = "https://pypi.org/simple";

/// The index to ask, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexChoice {
    /// The index's "simple" API URL. May contain credentials if the user's own
    /// configuration does; display it through [`redact_url`].
    pub url: String,
    pub origin: String,
}

/// What discovery may read besides the project directory.
#[derive(Clone, Debug, Default)]
pub struct DiscoveryContext {
    pub env: HashMap<String, String>,
    pub home: Option<PathBuf>,
    /// Whether to consult the system-wide `/etc/pip.conf`.
    pub include_system: bool,
}

impl DiscoveryContext {
    #[must_use]
    pub fn from_process() -> Self {
        Self::from_env(std::env::vars().collect())
    }

    #[must_use]
    pub fn from_env(env: HashMap<String, String>) -> Self {
        let home = env
            .get("HOME")
            .or_else(|| env.get("USERPROFILE"))
            .map(PathBuf::from);
        Self {
            env,
            home,
            include_system: true,
        }
    }
}

/// Strip any `user:password@` from a URL so it is safe to print.
#[must_use]
pub fn redact_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://").map(|i| i + 3) else {
        return url.to_owned();
    };
    let rest = &url[scheme_end..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{}{}{}", &url[..scheme_end], host, &rest[authority_end..]),
        None => url.to_owned(),
    }
}

fn is_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn load_toml(path: &Path) -> Option<toml::Table> {
    fs::read_to_string(path).ok()?.parse().ok()
}

fn registry_of(packages: &[LockedPackage], name: &str) -> Option<String> {
    packages
        .iter()
        .find(|package| package.name == name)
        .and_then(|package| match &package.source {
            PackageSource::Registry(Some(url)) if is_url(url) => Some(url.clone()),
            _ => None,
        })
}

fn from_lock(
    project_dir: &Path,
    file: &str,
    parse: fn(&str) -> Result<Vec<LockedPackage>, crate::sources::SourceError>,
    name: &str,
) -> Option<String> {
    let text = fs::read_to_string(project_dir.join(file)).ok()?;
    registry_of(&parse(&text).ok()?, name)
}

fn uv_table_index(table: &toml::Table) -> Option<String> {
    let default_index = table
        .get("index")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
        .find(|index| {
            index.get("default").and_then(toml::Value::as_bool) == Some(true)
                && index
                    .get("url")
                    .and_then(toml::Value::as_str)
                    .is_some_and(is_url)
        })
        .and_then(|index| index.get("url")?.as_str().map(str::to_owned));
    default_index.or_else(|| {
        table
            .get("index-url")
            .and_then(toml::Value::as_str)
            .filter(|url| is_url(url))
            .map(str::to_owned)
    })
}

fn from_uv_config(project_dir: &Path) -> Option<String> {
    let pyproject_table = load_toml(&project_dir.join("pyproject.toml"))
        .and_then(|doc| doc.get("tool")?.as_table()?.get("uv")?.as_table().cloned())
        .unwrap_or_default();
    uv_table_index(&pyproject_table).or_else(|| {
        load_toml(&project_dir.join("uv.toml")).and_then(|table| uv_table_index(&table))
    })
}

fn from_poetry_config(project_dir: &Path) -> Option<String> {
    let document = load_toml(&project_dir.join("pyproject.toml"))?;
    let sources = document
        .get("tool")?
        .as_table()?
        .get("poetry")?
        .as_table()?
        .get("source")?
        .as_array()?;
    for priority in ["default", "primary"] {
        for source in sources.iter().filter_map(toml::Value::as_table) {
            let url = source.get("url").and_then(toml::Value::as_str);
            if source.get("priority").and_then(toml::Value::as_str) == Some(priority) {
                if let Some(url) = url.filter(|url| is_url(url)) {
                    return Some(url.to_owned());
                }
            }
        }
    }
    None
}

fn from_pipfile(project_dir: &Path) -> Option<String> {
    let document = load_toml(&project_dir.join("Pipfile"))?;
    let first = document.get("source")?.as_array()?.first()?.as_table()?;
    first
        .get("url")?
        .as_str()
        .filter(|url| is_url(url))
        .map(str::to_owned)
}

fn from_environment(env: &HashMap<String, String>) -> Option<String> {
    ["UV_DEFAULT_INDEX", "UV_INDEX_URL", "PIP_INDEX_URL"]
        .iter()
        .filter_map(|key| env.get(*key))
        .find(|value| is_url(value))
        .cloned()
}

fn pip_conf_paths(context: &DiscoveryContext) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(file) = context
        .env
        .get("PIP_CONFIG_FILE")
        .filter(|file| !file.is_empty())
    {
        paths.push(PathBuf::from(file));
    }
    if let Some(appdata) = context.env.get("APPDATA").filter(|dir| !dir.is_empty()) {
        paths.push(Path::new(appdata).join("pip").join("pip.ini"));
    }
    if let Some(home) = &context.home {
        paths.push(home.join(".config/pip/pip.conf"));
        paths.push(home.join("Library/Application Support/pip/pip.conf"));
        paths.push(home.join(".pip/pip.conf"));
    }
    if context.include_system {
        paths.push(PathBuf::from("/etc/pip.conf"));
    }
    paths
}

type PipConfSections = HashMap<String, HashMap<String, String>>;

/// `None` for a file that does not parse as INI, which is skipped like any unparseable config.
fn pip_conf_sections(text: &str) -> Option<PipConfSections> {
    let mut sections = PipConfSections::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        if let Some(header) = trimmed.strip_prefix('[') {
            current = Some(header.strip_suffix(']')?.to_owned());
            continue;
        }
        let section = current.as_ref()?;
        let (key, value) = trimmed.split_once(['=', ':'])?;
        sections
            .entry(section.clone())
            .or_default()
            .insert(key.trim().to_lowercase(), value.trim().to_owned());
    }
    Some(sections)
}

/// `key` from a `[global]` or `[install]` section, preferring `[global]`.
fn pip_conf_option(
    sections: &PipConfSections,
    key: &str,
    usable: impl Fn(&str) -> bool,
) -> Option<String> {
    ["global", "install"].iter().find_map(|section| {
        sections
            .get(*section)
            .and_then(|options| options.get(key))
            .filter(|value| usable(value))
            .cloned()
    })
}

fn pip_conf_index(text: &str) -> Option<String> {
    pip_conf_option(&pip_conf_sections(text)?, "index-url", is_url)
}

fn first_in_pip_conf(
    context: &DiscoveryContext,
    pick: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    pip_conf_paths(context).iter().find_map(|path| {
        let bytes = fs::read(path).ok()?;
        pick(std::str::from_utf8(&bytes).ok()?)
    })
}

fn from_pip_conf(context: &DiscoveryContext) -> Option<String> {
    first_in_pip_conf(context, pip_conf_index)
}

/// The CA bundle the environment points at. First set wins: `SSL_CERT_FILE`, `PIP_CERT`,
/// `cert` in `pip.conf`, then `REQUESTS_CA_BUNDLE`.
#[must_use]
pub fn discover_ca_bundle(context: &DiscoveryContext) -> Option<CaBundle> {
    let from_env = |key: &str| {
        context
            .env
            .get(key)
            .filter(|path| !path.is_empty())
            .map(|path| CaBundle {
                path: PathBuf::from(path),
                origin: key.to_owned(),
            })
    };
    from_env("SSL_CERT_FILE")
        .or_else(|| from_env("PIP_CERT"))
        .or_else(|| {
            first_in_pip_conf(context, |text| {
                pip_conf_option(&pip_conf_sections(text)?, "cert", |path| !path.is_empty())
            })
            .map(|path| CaBundle {
                path: PathBuf::from(path),
                origin: "cert in pip.conf".to_owned(),
            })
        })
        .or_else(|| from_env("REQUESTS_CA_BUNDLE"))
}

type Finder<'a> = Box<dyn Fn() -> Option<String> + 'a>;

/// Choose the index to ask about `package`.
#[must_use]
pub fn discover_index(
    project_dir: &Path,
    package: &str,
    context: &DiscoveryContext,
) -> IndexChoice {
    let name = canonical_name(package);
    let steps: [(&str, Finder<'_>); 8] = [
        (
            "uv.lock",
            Box::new(|| from_lock(project_dir, "uv.lock", parse_uv_lock, &name)),
        ),
        (
            "poetry.lock",
            Box::new(|| from_lock(project_dir, "poetry.lock", parse_poetry_lock, &name)),
        ),
        (
            "Pipfile.lock",
            Box::new(|| from_lock(project_dir, "Pipfile.lock", parse_pipfile_lock, &name)),
        ),
        (
            "uv config in pyproject.toml/uv.toml",
            Box::new(|| from_uv_config(project_dir)),
        ),
        (
            "[[tool.poetry.source]] in pyproject.toml",
            Box::new(|| from_poetry_config(project_dir)),
        ),
        ("Pipfile [[source]]", Box::new(|| from_pipfile(project_dir))),
        (
            "index environment variable",
            Box::new(|| from_environment(&context.env)),
        ),
        ("pip.conf", Box::new(|| from_pip_conf(context))),
    ];
    for (origin, find) in steps {
        if let Some(url) = find() {
            return IndexChoice {
                url,
                origin: origin.to_owned(),
            };
        }
    }
    IndexChoice {
        url: DEFAULT_INDEX.to_owned(),
        origin: "default -- no index is configured for this project".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const INTERNAL: &str = "https://nexus.example.com/repository/pypi-internal/simple";
    const OTHER: &str = "https://other.example.com/simple";

    fn find_with(project: &Path, package: &str, env: &[(&str, &str)]) -> (String, String) {
        let context = DiscoveryContext {
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..DiscoveryContext::default()
        };
        let choice = discover_index(project, package, &context);
        (choice.url, choice.origin)
    }

    fn find(project: &Path) -> (String, String) {
        find_with(project, "webencodings", &[])
    }

    fn write(dir: &Path, name: &str, body: &str) {
        fs::write(dir.join(name), body).expect("write");
    }

    #[test]
    fn redact_url_strips_credentials_and_leaves_plain_urls_alone() {
        assert_eq!(
            redact_url("https://user:s3cret@nexus.example.com/simple"),
            "https://nexus.example.com/simple"
        );
        assert_eq!(redact_url(INTERNAL), INTERNAL);
        assert_eq!(
            redact_url("http://u:p@127.0.0.1:8080/a@b?x=1"),
            "http://127.0.0.1:8080/a@b?x=1"
        );
    }

    #[test]
    fn falls_back_to_pypi_and_says_so() {
        let tmp = tempdir().expect("tempdir");
        let (url, origin) = find(tmp.path());
        assert_eq!(url, DEFAULT_INDEX);
        assert!(origin.contains("default"));
    }

    #[test]
    fn uv_lock_records_the_index_per_package() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "uv.lock",
            &format!(
                "[[package]]\nname = \"webencodings\"\nversion = \"0.5.1\"\nsource = {{ registry = \"{INTERNAL}\" }}\n\n\
                 [[package]]\nname = \"other\"\nversion = \"1\"\nsource = {{ registry = \"{OTHER}\" }}\n"
            ),
        );
        assert_eq!(
            find(tmp.path()),
            (INTERNAL.to_owned(), "uv.lock".to_owned())
        );
        assert_eq!(find_with(tmp.path(), "OTHER", &[]).0, OTHER);
    }

    #[test]
    fn uv_lock_ignores_non_http_sources() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "uv.lock",
            "[[package]]\nname = \"webencodings\"\nversion = \"1\"\nsource = { editable = \".\" }\n",
        );
        assert_eq!(find(tmp.path()).0, DEFAULT_INDEX);
    }

    #[test]
    fn poetry_lock_records_a_legacy_source() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "poetry.lock",
            &format!(
                "[[package]]\nname = \"webencodings\"\nversion = \"0.5.1\"\n\n\
                 [package.source]\ntype = \"legacy\"\nurl = \"{INTERNAL}\"\nreference = \"internal\"\n"
            ),
        );
        assert_eq!(
            find(tmp.path()),
            (INTERNAL.to_owned(), "poetry.lock".to_owned())
        );
    }

    #[test]
    fn pipfile_lock_resolves_the_named_index_or_the_first_source() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "Pipfile.lock",
            &format!(
                r#"{{"_meta": {{"sources": [{{"name": "pypi", "url": "{DEFAULT_INDEX}"}}, {{"name": "internal", "url": "{INTERNAL}"}}]}},
                   "default": {{"webencodings": {{"index": "internal", "version": "==0.5.1"}}}}}}"#
            ),
        );
        assert_eq!(
            find(tmp.path()),
            (INTERNAL.to_owned(), "Pipfile.lock".to_owned())
        );

        write(
            tmp.path(),
            "Pipfile.lock",
            &format!(
                r#"{{"_meta": {{"sources": [{{"name": "internal", "url": "{INTERNAL}"}}]}},
                   "default": {{"webencodings": {{"version": "==0.5.1"}}}}}}"#
            ),
        );
        assert_eq!(find(tmp.path()).0, INTERNAL);
    }

    #[test]
    fn uv_config_default_index_from_pyproject() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "pyproject.toml",
            &format!(
                "[[tool.uv.index]]\nname = \"x\"\nurl = \"{OTHER}\"\n\n\
                 [[tool.uv.index]]\nname = \"d\"\nurl = \"{INTERNAL}\"\ndefault = true\n"
            ),
        );
        assert_eq!(
            find(tmp.path()),
            (
                INTERNAL.to_owned(),
                "uv config in pyproject.toml/uv.toml".to_owned()
            )
        );
    }

    #[test]
    fn uv_toml_legacy_index_url() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "uv.toml",
            &format!("index-url = \"{INTERNAL}\"\n"),
        );
        assert_eq!(find(tmp.path()).0, INTERNAL);
    }

    #[test]
    fn poetry_source_prefers_default_then_primary() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "pyproject.toml",
            &format!(
                "[[tool.poetry.source]]\nname = \"e\"\nurl = \"{OTHER}\"\npriority = \"explicit\"\n\n\
                 [[tool.poetry.source]]\nname = \"p\"\nurl = \"{INTERNAL}\"\npriority = \"primary\"\n"
            ),
        );
        assert_eq!(
            find(tmp.path()),
            (
                INTERNAL.to_owned(),
                "[[tool.poetry.source]] in pyproject.toml".to_owned()
            )
        );
    }

    #[test]
    fn pipfile_first_source() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "Pipfile",
            &format!("[[source]]\nurl = \"{INTERNAL}\"\nverify_ssl = true\nname = \"internal\"\n"),
        );
        assert_eq!(
            find(tmp.path()),
            (INTERNAL.to_owned(), "Pipfile [[source]]".to_owned())
        );
    }

    #[test]
    fn environment_variables_in_precedence_order() {
        let tmp = tempdir().expect("tempdir");
        assert_eq!(
            find_with(
                tmp.path(),
                "webencodings",
                &[("PIP_INDEX_URL", OTHER), ("UV_INDEX_URL", INTERNAL)]
            )
            .0,
            INTERNAL
        );
        assert_eq!(
            find_with(tmp.path(), "webencodings", &[("PIP_INDEX_URL", OTHER)]),
            (OTHER.to_owned(), "index environment variable".to_owned())
        );
    }

    #[test]
    fn pip_conf_named_by_the_environment() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "pip.conf",
            &format!("[global]\nindex-url = {INTERNAL}\n"),
        );
        let conf = tmp.path().join("pip.conf");
        assert_eq!(
            find_with(
                tmp.path(),
                "webencodings",
                &[("PIP_CONFIG_FILE", conf.to_str().expect("utf8"))]
            ),
            (INTERNAL.to_owned(), "pip.conf".to_owned())
        );
    }

    #[test]
    fn lockfile_beats_config_and_environment() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "uv.lock",
            &format!(
                "[[package]]\nname = \"webencodings\"\nversion = \"1\"\nsource = {{ registry = \"{INTERNAL}\" }}\n"
            ),
        );
        write(tmp.path(), "uv.toml", &format!("index-url = \"{OTHER}\"\n"));
        assert_eq!(
            find_with(tmp.path(), "webencodings", &[("PIP_INDEX_URL", OTHER)]).0,
            INTERNAL
        );
    }

    #[test]
    fn malformed_files_are_ignored_not_fatal() {
        let tmp = tempdir().expect("tempdir");
        write(tmp.path(), "uv.lock", "not [ valid toml");
        write(tmp.path(), "Pipfile.lock", "{nope");
        assert_eq!(find(tmp.path()).0, DEFAULT_INDEX);

        fs::write(tmp.path().join("pip.conf"), b"[global\xffbroken").expect("write");
        let conf = tmp.path().join("pip.conf");
        assert_eq!(
            find_with(
                tmp.path(),
                "webencodings",
                &[("PIP_CONFIG_FILE", conf.to_str().expect("utf8"))]
            )
            .0,
            DEFAULT_INDEX
        );
    }

    #[test]
    fn a_poetry_default_source_package_does_not_claim_an_index() {
        let tmp = tempdir().expect("tempdir");
        write(
            tmp.path(),
            "poetry.lock",
            "[[package]]\nname = \"webencodings\"\nversion = \"0.5.1\"\n",
        );
        assert_eq!(find(tmp.path()).0, DEFAULT_INDEX);
    }

    #[test]
    fn pip_conf_prefers_global_over_install_and_skips_bad_lines() {
        assert_eq!(
            pip_conf_index(&format!(
                "[install]\nindex-url = {OTHER}\n[global]\nindex-url={INTERNAL}\n"
            )),
            Some(INTERNAL.to_owned())
        );
        assert_eq!(pip_conf_index("index-url = https://x/simple\n"), None);
        assert_eq!(pip_conf_index("[global]\nno delimiter here\n"), None);
    }

    fn ca_bundle_with(env: &[(&str, &str)]) -> Option<(String, String)> {
        let context = DiscoveryContext {
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            ..DiscoveryContext::default()
        };
        discover_ca_bundle(&context)
            .map(|bundle| (bundle.path.display().to_string(), bundle.origin))
    }

    #[test]
    fn ca_bundle_sources_in_order() {
        let tmp = tempdir().expect("tempdir");
        write(tmp.path(), "pip.conf", "[global]\ncert = /conf.pem\n");
        let conf = tmp.path().join("pip.conf");
        let conf = conf.to_str().expect("utf8");
        let all = [
            ("SSL_CERT_FILE", "/ssl.pem"),
            ("PIP_CERT", "/pip.pem"),
            ("PIP_CONFIG_FILE", conf),
            ("REQUESTS_CA_BUNDLE", "/requests.pem"),
        ];
        let expected = [
            ("/ssl.pem", "SSL_CERT_FILE"),
            ("/pip.pem", "PIP_CERT"),
            ("/conf.pem", "cert in pip.conf"),
            ("/requests.pem", "REQUESTS_CA_BUNDLE"),
        ];
        for (skip, (path, origin)) in expected.iter().enumerate() {
            assert_eq!(
                ca_bundle_with(&all[skip..]),
                Some(((*path).to_owned(), (*origin).to_owned()))
            );
        }
        assert_eq!(ca_bundle_with(&[]), None);
    }

    #[test]
    fn an_empty_ca_bundle_setting_is_ignored() {
        assert_eq!(
            ca_bundle_with(&[("SSL_CERT_FILE", ""), ("REQUESTS_CA_BUNDLE", "/r.pem")]),
            Some(("/r.pem".to_owned(), "REQUESTS_CA_BUNDLE".to_owned()))
        );
    }
}
