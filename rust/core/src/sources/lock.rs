//! Read the package set pinned by a lock file.
//!
//! Local code is not audited: a project's own editable or virtual entries are skipped.
//! Anything else that cannot be looked up on a package index (git, URL, local path) is
//! kept with its source so the caller can fail closed rather than silently pass it.

use super::{requirements, source_error, LockedPackage, PackageSource, SourceError};
use crate::detection::canonical_name;
use regex::Regex;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockFormat {
    UvLock,
    PyLock,
    PoetryLock,
    PipfileLock,
    Requirements,
}

impl LockFormat {
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            Self::UvLock => "uv.lock",
            Self::PyLock => "pylock.toml",
            Self::PoetryLock => "poetry.lock",
            Self::PipfileLock => "Pipfile.lock",
            Self::Requirements => "requirements.txt",
        }
    }

    /// Infer the format from a path given explicitly, e.g. `--lock ci/pylock.toml`.
    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_string_lossy().to_lowercase();
        match name.as_str() {
            "uv.lock" => Some(Self::UvLock),
            "poetry.lock" => Some(Self::PoetryLock),
            "pipfile.lock" => Some(Self::PipfileLock),
            "pylock.toml" => Some(Self::PyLock),
            _ if name.starts_with("pylock.") && name.ends_with(".toml") => Some(Self::PyLock),
            _ if name.ends_with(".txt") || name.ends_with(".in") => Some(Self::Requirements),
            _ => None,
        }
    }
}

const DETECTION_ORDER: [LockFormat; 5] = [
    LockFormat::UvLock,
    LockFormat::PyLock,
    LockFormat::PoetryLock,
    LockFormat::PipfileLock,
    LockFormat::Requirements,
];

/// The first lock file found in `project_dir`, in precedence order.
#[must_use]
pub fn detect_lock(project_dir: &Path) -> Option<(LockFormat, PathBuf)> {
    DETECTION_ORDER.iter().find_map(|format| {
        let path = project_dir.join(format.file_name());
        path.is_file().then_some((*format, path))
    })
}

/// Read the packages pinned by the lock file at `path`.
///
/// # Errors
///
/// When the file cannot be read or parsed, or (for requirements files) a requirement is
/// not pinned to an exact version.
pub fn read_lock(format: LockFormat, path: &Path) -> Result<Vec<LockedPackage>, SourceError> {
    if format == LockFormat::Requirements {
        return requirements::read_requirements(path);
    }
    let text = fs::read_to_string(path)
        .map_err(|error| source_error(format!("cannot read {}: {error}", path.display())))?;
    let wrap = |error: SourceError| source_error(format!("{}: {error}", path.display()));
    match format {
        LockFormat::UvLock => parse_uv_lock(&text),
        LockFormat::PyLock => parse_pylock(&text),
        LockFormat::PoetryLock => parse_poetry_lock(&text),
        LockFormat::PipfileLock => parse_pipfile_lock(&text),
        LockFormat::Requirements => unreachable!("handled above"),
    }
    .map(merge_duplicates)
    .map_err(wrap)
}

fn parse_toml(text: &str) -> Result<toml::Table, SourceError> {
    text.parse::<toml::Table>()
        .map_err(|error| source_error(format!("not valid TOML: {}", error.message())))
}

fn string<'a>(table: &'a toml::Table, key: &str) -> Option<&'a str> {
    table.get(key).and_then(toml::Value::as_str)
}

fn entries<'a>(table: &'a toml::Table, key: &str) -> Vec<&'a toml::Table> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|array| array.iter().filter_map(toml::Value::as_table).collect())
        .unwrap_or_default()
}

fn named(package: &toml::Table, source: PackageSource) -> Result<LockedPackage, SourceError> {
    let name =
        string(package, "name").ok_or_else(|| source_error("a package entry has no name"))?;
    Ok(LockedPackage {
        name: canonical_name(name),
        version: string(package, "version").unwrap_or("").to_owned(),
        source,
        groups: BTreeSet::new(),
    })
}

/// `uv.lock`: `[[package]]` with a `source` table. Workspace members and the project
/// itself appear as `editable` or `virtual` and are skipped.
///
/// # Errors
///
/// When the TOML is invalid or a package has no name.
pub fn parse_uv_lock(text: &str) -> Result<Vec<LockedPackage>, SourceError> {
    let document = parse_toml(text)?;
    let mut packages = Vec::new();
    for package in entries(&document, "package") {
        let source = package.get("source").and_then(toml::Value::as_table);
        let get = |key: &str| source.and_then(|source| string(source, key));
        if source
            .is_some_and(|source| source.contains_key("editable") || source.contains_key("virtual"))
        {
            continue;
        }
        let source = if let Some(url) = get("registry") {
            PackageSource::Registry(Some(url.to_owned()))
        } else if let Some(url) = get("git") {
            PackageSource::Git(url.to_owned())
        } else if let Some(url) = get("url") {
            PackageSource::Url(url.to_owned())
        } else if let Some(path) = get("path").or_else(|| get("directory")) {
            PackageSource::Path(path.to_owned())
        } else {
            PackageSource::Registry(None)
        };
        packages.push(named(package, source)?);
    }
    let labels = uv_group_labels(&document);
    for package in &mut packages {
        package.groups = labels.get(&package.name).cloned().unwrap_or_default();
    }
    Ok(packages)
}

/// A dependency edge: the package depended on, and the extras of it that are activated.
type Edge = (String, Vec<String>);

fn uv_edges(entries: Option<&toml::Value>) -> Vec<Edge> {
    entries
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
        .filter_map(|dependency| {
            let name = canonical_name(string(dependency, "name")?);
            let mut extras: Vec<String> = dependency
                .get("extra")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(canonical_name)
                .collect();
            extras.sort();
            Some((name, extras))
        })
        .collect()
}

/// For each package in a `uv.lock`, the labels it is reached by from the project: its runtime
/// `dependencies` (`main`), each dev dependency group, and each optional extra. Empty when the lock
/// has no project to walk from, so nothing is guessed.
fn uv_group_labels(document: &toml::Table) -> HashMap<String, BTreeSet<String>> {
    let packages = entries(document, "package");
    // A resolution fork lists one name at several versions; each one's edges count.
    let mut by_name: HashMap<String, Vec<&toml::Table>> = HashMap::new();
    for package in &packages {
        if let Some(name) = string(package, "name") {
            by_name
                .entry(canonical_name(name))
                .or_default()
                .push(package);
        }
    }
    let is_project = |package: &toml::Table| {
        package
            .get("source")
            .and_then(toml::Value::as_table)
            .is_some_and(|source| source.contains_key("editable") || source.contains_key("virtual"))
    };

    let mut starts: BTreeMap<String, Vec<Edge>> = BTreeMap::new();
    for project in packages.iter().filter(|package| is_project(package)) {
        starts
            .entry("main".to_owned())
            .or_default()
            .extend(uv_edges(project.get("dependencies")));
        for (key, prefix) in [
            ("dev-dependencies", "group"),
            ("optional-dependencies", "extra"),
        ] {
            for (name, dependencies) in project
                .get(key)
                .and_then(toml::Value::as_table)
                .into_iter()
                .flatten()
            {
                starts
                    .entry(format!("{prefix}:{}", canonical_name(name)))
                    .or_default()
                    .extend(uv_edges(Some(dependencies)));
            }
        }
    }

    let mut labels: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (label, start) in starts {
        let mut seen: HashSet<Edge> = HashSet::new();
        let mut queue = start;
        while let Some(edge) = queue.pop() {
            if !seen.insert(edge.clone()) {
                continue;
            }
            let (name, extras) = edge;
            labels
                .entry(name.clone())
                .or_default()
                .insert(label.clone());
            for table in by_name.get(&name).into_iter().flatten() {
                queue.extend(uv_edges(table.get("dependencies")));
                for (extra, dependencies) in table
                    .get("optional-dependencies")
                    .and_then(toml::Value::as_table)
                    .into_iter()
                    .flatten()
                {
                    if extras.contains(&canonical_name(extra)) {
                        queue.extend(uv_edges(Some(dependencies)));
                    }
                }
            }
        }
    }
    labels
}

/// `pylock.toml` (PEP 751): `[[packages]]` whose install source is one of `vcs`,
/// `directory`, `archive`, or an index with `sdist`/`wheels`.
///
/// # Errors
///
/// When the TOML is invalid or a package has no name.
pub fn parse_pylock(text: &str) -> Result<Vec<LockedPackage>, SourceError> {
    let document = parse_toml(text)?;
    let mut packages = Vec::new();
    for package in entries(&document, "packages") {
        let table = |key: &str| package.get(key).and_then(toml::Value::as_table);
        let locate = |table: &toml::Table| {
            string(table, "url")
                .or_else(|| string(table, "path"))
                .unwrap_or("")
                .to_owned()
        };
        let source = if let Some(vcs) = table("vcs") {
            PackageSource::Git(locate(vcs))
        } else if let Some(directory) = table("directory") {
            if directory.get("editable").and_then(toml::Value::as_bool) == Some(true) {
                continue;
            }
            PackageSource::Path(locate(directory))
        } else if let Some(archive) = table("archive") {
            PackageSource::Url(locate(archive))
        } else {
            PackageSource::Registry(string(package, "index").map(str::to_owned))
        };
        let mut locked = named(package, source)?;
        locked.groups = pylock_groups(string(package, "marker"));
        packages.push(locked);
    }
    Ok(packages)
}

/// The groups and extras a `pylock.toml` package's marker ties it to. Only the plain terms PEP 751
/// defines are read (`'dev' in dependency_groups`, `'x' in extras`, `extra == 'x'`); a marker with
/// none of them is a main dependency.
fn pylock_groups(marker: Option<&str>) -> BTreeSet<String> {
    let main = || BTreeSet::from(["main".to_owned()]);
    let Some(marker) = marker else {
        return main();
    };
    // `or` or `not` mean the package may be installed without the group, so it can't be tied to it.
    let words: Vec<&str> = marker
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .collect();
    if words.iter().any(|word| matches!(*word, "or" | "not")) {
        return main();
    }
    let patterns = [
        (r#"['"]([^'"]+)['"]\s+in\s+dependency_groups"#, "group"),
        (r#"['"]([^'"]+)['"]\s+in\s+extras"#, "extra"),
        (r#"extra\s*==\s*['"]([^'"]+)['"]"#, "extra"),
    ];
    let mut labels = BTreeSet::new();
    for (pattern, prefix) in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            for capture in regex.captures_iter(marker) {
                labels.insert(format!("{prefix}:{}", canonical_name(&capture[1])));
            }
        }
    }
    if labels.is_empty() {
        labels.insert("main".to_owned());
    }
    labels
}

/// `poetry.lock`: `[[package]]` with an optional `[package.source]` of type `legacy`
/// (a private index), `git`, `url`, `directory` or `file`. No source means the default index.
///
/// # Errors
///
/// When the TOML is invalid or a package has no name.
pub fn parse_poetry_lock(text: &str) -> Result<Vec<LockedPackage>, SourceError> {
    let document = parse_toml(text)?;
    let mut packages = Vec::new();
    for package in entries(&document, "package") {
        let source = package.get("source").and_then(toml::Value::as_table);
        let kind = source.and_then(|source| string(source, "type"));
        let url = source
            .and_then(|source| string(source, "url"))
            .unwrap_or("")
            .to_owned();
        let source = match kind {
            None => PackageSource::Registry(None),
            Some("legacy") => PackageSource::Registry(Some(url)),
            Some("git") => PackageSource::Git(url),
            Some("url") => PackageSource::Url(url),
            Some(_) => {
                let develop = source
                    .and_then(|source| source.get("develop"))
                    .or_else(|| package.get("develop"))
                    .and_then(toml::Value::as_bool);
                if develop == Some(true) {
                    continue;
                }
                PackageSource::Path(url)
            }
        };
        let mut locked = named(package, source)?;
        locked.groups = poetry_groups(package);
        packages.push(locked);
    }
    Ok(packages)
}

/// The groups a `poetry.lock` package belongs to: the `groups` list of Poetry 2, else the single
/// `category` of older locks. Empty when the lock records neither.
fn poetry_groups(package: &toml::Table) -> BTreeSet<String> {
    let label = |group: &str| {
        if group == "main" {
            "main".to_owned()
        } else {
            format!("group:{}", canonical_name(group))
        }
    };
    if let Some(groups) = package.get("groups").and_then(toml::Value::as_array) {
        return groups
            .iter()
            .filter_map(toml::Value::as_str)
            .map(label)
            .collect();
    }
    string(package, "category").map(label).into_iter().collect()
}

/// `Pipfile.lock` (JSON): `default` and `develop` sections keyed by package name.
///
/// # Errors
///
/// When the JSON is invalid, or an entry has neither a pinned version nor a git/path/file source.
pub fn parse_pipfile_lock(text: &str) -> Result<Vec<LockedPackage>, SourceError> {
    let lock: Json = serde_json::from_str(text)
        .map_err(|error| source_error(format!("not valid JSON: {error}")))?;
    let sources = lock
        .pointer("/_meta/sources")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let index_url = |name: Option<&str>| -> Option<String> {
        let by_name = sources
            .iter()
            .find(|source| name.is_some() && source.get("name").and_then(Json::as_str) == name);
        by_name
            .or_else(|| sources.first())
            .and_then(|source| source.get("url"))
            .and_then(Json::as_str)
            .map(str::to_owned)
    };

    let mut packages = Vec::new();
    for section_name in ["default", "develop"] {
        let Some(section) = lock.get(section_name).and_then(Json::as_object) else {
            continue;
        };
        for (name, entry) in section {
            let text = |key: &str| entry.get(key).and_then(Json::as_str).map(str::to_owned);
            let editable = entry.get("editable").and_then(Json::as_bool) == Some(true);
            let version = text("version")
                .map(|version| version.trim_start_matches('=').to_owned())
                .unwrap_or_default();
            let source = if let Some(git) = text("git") {
                PackageSource::Git(git)
            } else if let Some(path) = text("path") {
                if editable {
                    continue;
                }
                PackageSource::Path(path)
            } else if let Some(file) = text("file") {
                PackageSource::Url(file)
            } else if version.is_empty() {
                return Err(source_error(format!("{name} has no pinned version")));
            } else {
                PackageSource::Registry(index_url(entry.get("index").and_then(Json::as_str)))
            };
            packages.push(LockedPackage {
                name: canonical_name(name),
                version,
                source,
                groups: BTreeSet::from([if section_name == "default" {
                    "main".to_owned()
                } else {
                    format!("group:{section_name}")
                }]),
            });
        }
    }
    Ok(packages)
}

/// A package listed more than once (a Pipfile.lock package in both `default` and `develop`) becomes
/// one entry that is reached every way it was listed. Any listing that says nothing about groups
/// makes the merged entry say nothing, so an unknown is never narrowed by a known.
fn merge_duplicates(packages: Vec<LockedPackage>) -> Vec<LockedPackage> {
    let mut merged: Vec<LockedPackage> = Vec::with_capacity(packages.len());
    for package in packages {
        match merged.iter_mut().find(|existing| {
            existing.name == package.name
                && existing.version == package.version
                && existing.source == package.source
        }) {
            Some(existing) if existing.groups.is_empty() || package.groups.is_empty() => {
                existing.groups.clear();
            }
            Some(existing) => existing.groups.extend(package.groups),
            None => merged.push(package),
        }
    }
    merged
}

/// What a label is called to the user: the group or extra name.
fn label_name(label: &str) -> &str {
    label.split_once(':').map_or(label, |(_, name)| name)
}

/// Drop the packages reached only through the named dependency groups or extras.
///
/// A package is kept if it has any other way in (a dev tool that is also a runtime dependency stays)
/// and if the lock says nothing about how it is reached. Returns the packages kept and how many were
/// dropped.
///
/// # Errors
///
/// When the lock records no groups at all, when a name matches no group or extra in it, or when
/// `main` is named: the project's own dependencies are not a group to leave out.
pub fn exclude_groups(
    packages: Vec<LockedPackage>,
    excluded: &[String],
) -> Result<(Vec<LockedPackage>, usize), SourceError> {
    if excluded.is_empty() {
        return Ok((packages, 0));
    }
    let wanted: BTreeSet<String> = excluded.iter().map(|name| canonical_name(name)).collect();
    if wanted.contains("main") {
        return Err(source_error(
            "`main` is the project's own dependencies and can't be excluded; name a dependency group or extra",
        ));
    }
    if packages.iter().all(|package| package.groups.is_empty()) {
        return Err(source_error(
            "this lock file records no dependency groups (a requirements file never does), so there is \
             nothing for --exclude-group to go on",
        ));
    }
    let known: BTreeSet<&str> = packages
        .iter()
        .flat_map(|package| package.groups.iter())
        .map(|label| label_name(label))
        .filter(|name| *name != "main")
        .collect();
    let unknown: Vec<&String> = wanted
        .iter()
        .filter(|name| !known.contains(name.as_str()))
        .collect();
    if !unknown.is_empty() {
        let list = |names: &mut dyn Iterator<Item = String>| names.collect::<Vec<_>>().join(", ");
        return Err(source_error(format!(
            "no dependency group or extra named {} in this lock file; it has: {}",
            list(&mut unknown.iter().map(|name| format!("'{name}'"))),
            list(&mut known.iter().map(|name| (*name).to_owned()))
        )));
    }
    let before = packages.len();
    let kept: Vec<LockedPackage> = packages
        .into_iter()
        .filter(|package| {
            package.groups.is_empty()
                || package
                    .groups
                    .iter()
                    .any(|label| !wanted.contains(label_name(label)))
        })
        .collect();
    let dropped = before - kept.len();
    Ok((kept, dropped))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn registry(url: &str) -> PackageSource {
        PackageSource::Registry(Some(url.to_owned()))
    }

    #[test]
    fn uv_lock_skips_the_project_and_keeps_registry_and_other_sources() {
        let packages = parse_uv_lock(
            r#"
version = 1
[[package]]
name = "Some_Pkg"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "gitdep"
version = "0.1"
source = { git = "https://github.com/x/y?rev=abc#abc" }
[[package]]
name = "localdep"
source = { directory = "../localdep" }
[[package]]
name = "me"
version = "0.0.1"
source = { editable = "." }
[[package]]
name = "virt"
source = { virtual = "." }
"#,
        )
        .expect("parse");
        assert_eq!(
            packages,
            [
                LockedPackage {
                    name: "some-pkg".to_owned(),
                    version: "1.2.3".to_owned(),
                    source: registry("https://pypi.org/simple"),
                    groups: BTreeSet::new(),
                },
                LockedPackage {
                    name: "gitdep".to_owned(),
                    version: "0.1".to_owned(),
                    source: PackageSource::Git("https://github.com/x/y?rev=abc#abc".to_owned()),
                    groups: BTreeSet::new(),
                },
                LockedPackage {
                    name: "localdep".to_owned(),
                    version: String::new(),
                    source: PackageSource::Path("../localdep".to_owned()),
                    groups: BTreeSet::new(),
                },
            ]
        );
    }

    #[test]
    fn reads_this_repos_own_uv_lock() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../uv.lock");
        let packages = read_lock(LockFormat::UvLock, &path).expect("read");
        // Not an exact count: it changes whenever this repo's dependencies do.
        assert!(packages.len() > 20, "{} packages", packages.len());
        assert!(packages.iter().any(|p| p.name == "pytest"));
        assert!(packages
            .iter()
            .all(|p| matches!(&p.source, PackageSource::Registry(Some(_)))));
        assert!(packages.iter().all(|p| !p.version.is_empty()));
        assert!(!packages.iter().any(|p| p.name == "trustedlicenses"));
    }

    #[test]
    fn pylock_distinguishes_index_vcs_directory_and_archive() {
        let packages = parse_pylock(
            r#"
lock-version = "1.0"
[[packages]]
name = "idx"
version = "1.0"
index = "https://pypi.org/simple"
[[packages]]
name = "plain"
version = "2.0"
[[packages]]
name = "v"
vcs = { type = "git", url = "https://example.com/v.git", commit = "abc" }
[[packages]]
name = "d"
directory = { path = "./d" }
[[packages]]
name = "dev"
directory = { path = ".", editable = true }
[[packages]]
name = "a"
archive = { url = "https://example.com/a.whl" }
"#,
        )
        .expect("parse");
        let summary: Vec<_> = packages
            .iter()
            .map(|p| (p.name.as_str(), p.source.clone()))
            .collect();
        assert_eq!(
            summary,
            [
                ("idx", registry("https://pypi.org/simple")),
                ("plain", PackageSource::Registry(None)),
                (
                    "v",
                    PackageSource::Git("https://example.com/v.git".to_owned())
                ),
                ("d", PackageSource::Path("./d".to_owned())),
                (
                    "a",
                    PackageSource::Url("https://example.com/a.whl".to_owned())
                ),
            ]
        );
    }

    #[test]
    fn poetry_lock_sources() {
        let packages = parse_poetry_lock(
            r#"
[[package]]
name = "default-index"
version = "1.0"
[[package]]
name = "private"
version = "2.0"
[package.source]
type = "legacy"
url = "https://private.example/simple"
[[package]]
name = "gitty"
version = "3.0"
[package.source]
type = "git"
url = "https://example.com/g.git"
[[package]]
name = "dev-local"
version = "0.1"
develop = true
[package.source]
type = "directory"
url = "../dev"
[[package]]
name = "frozen-local"
version = "0.2"
[package.source]
type = "file"
url = "dist/x.whl"
"#,
        )
        .expect("parse");
        let summary: Vec<_> = packages
            .iter()
            .map(|p| (p.name.as_str(), p.source.clone()))
            .collect();
        assert_eq!(
            summary,
            [
                ("default-index", PackageSource::Registry(None)),
                ("private", registry("https://private.example/simple")),
                (
                    "gitty",
                    PackageSource::Git("https://example.com/g.git".to_owned())
                ),
                ("frozen-local", PackageSource::Path("dist/x.whl".to_owned())),
            ]
        );
    }

    #[test]
    fn pipfile_lock_sections_and_indexes() {
        let packages = parse_pipfile_lock(
            r#"{
  "_meta": {"sources": [
     {"name": "pypi", "url": "https://pypi.org/simple"},
     {"name": "priv", "url": "https://priv.example/simple"}]},
  "default": {
     "Requests": {"version": "==2.31.0", "index": "pypi"},
     "internal": {"version": "==1.0", "index": "priv"},
     "gitdep": {"git": "https://example.com/g.git", "ref": "abc"},
     "mine": {"path": ".", "editable": true}
  },
  "develop": {"pytest": {"version": "==8.0.0"}}
}"#,
        )
        .expect("parse");
        let summary: Vec<_> = packages
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str(), p.source.clone()))
            .collect();
        assert_eq!(
            summary,
            [
                ("requests", "2.31.0", registry("https://pypi.org/simple")),
                (
                    "gitdep",
                    "",
                    PackageSource::Git("https://example.com/g.git".to_owned())
                ),
                ("internal", "1.0", registry("https://priv.example/simple")),
                ("pytest", "8.0.0", registry("https://pypi.org/simple")),
            ]
        );
    }

    #[test]
    fn pipfile_lock_entry_without_a_version_is_an_error() {
        let error = parse_pipfile_lock(r#"{"default": {"loose": {}}}"#).expect_err("error");
        assert!(error.0.contains("loose has no pinned version"));
    }

    #[test]
    fn invalid_files_name_the_problem() {
        assert!(parse_uv_lock("[[package")
            .expect_err("e")
            .0
            .contains("not valid TOML"));
        assert!(parse_pipfile_lock("{")
            .expect_err("e")
            .0
            .contains("not valid JSON"));
        assert!(parse_uv_lock("[[package]]\nversion = \"1\"\n")
            .expect_err("e")
            .0
            .contains("no name"));
    }

    #[test]
    fn detect_lock_follows_the_precedence_order() {
        let tmp = tempdir().expect("tempdir");
        assert!(detect_lock(tmp.path()).is_none());
        fs::write(tmp.path().join("requirements.txt"), "").expect("write");
        assert_eq!(
            detect_lock(tmp.path()).map(|f| f.0),
            Some(LockFormat::Requirements)
        );
        fs::write(tmp.path().join("poetry.lock"), "").expect("write");
        assert_eq!(
            detect_lock(tmp.path()).map(|f| f.0),
            Some(LockFormat::PoetryLock)
        );
        fs::write(tmp.path().join("pylock.toml"), "").expect("write");
        assert_eq!(
            detect_lock(tmp.path()).map(|f| f.0),
            Some(LockFormat::PyLock)
        );
        fs::write(tmp.path().join("uv.lock"), "").expect("write");
        assert_eq!(
            detect_lock(tmp.path()).map(|f| f.0),
            Some(LockFormat::UvLock)
        );
    }

    #[test]
    fn format_is_inferred_from_an_explicit_path() {
        for (name, expected) in [
            ("ci/uv.lock", Some(LockFormat::UvLock)),
            ("pylock.dev.toml", Some(LockFormat::PyLock)),
            ("Pipfile.lock", Some(LockFormat::PipfileLock)),
            ("reqs/prod.txt", Some(LockFormat::Requirements)),
            ("notes.md", None),
        ] {
            assert_eq!(LockFormat::from_path(Path::new(name)), expected, "{name}");
        }
    }

    // -----------------------------------------------------------------------------
    // Dependency groups.
    // -----------------------------------------------------------------------------

    const GROUPED_UV_LOCK: &str = r#"
version = 1
[[package]]
name = "me"
version = "0.1"
source = { editable = "." }
dependencies = [{ name = "app" }, { name = "lib", extra = ["speed"] }]
[package.dev-dependencies]
dev = [{ name = "pytest" }, { name = "shared" }]
docs = [{ name = "mkdocs" }]
[package.optional-dependencies]
cli = [{ name = "click" }]

[[package]]
name = "app"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "shared" }]
[[package]]
name = "shared"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "lib"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[package.optional-dependencies]
speed = [{ name = "fastlib" }]
[[package]]
name = "fastlib"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "pytest"
version = "8.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]
[[package]]
name = "pluggy"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "mkdocs"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "click"
version = "8.0"
source = { registry = "https://pypi.org/simple" }
"#;

    fn labels(packages: &[LockedPackage], name: &str) -> Vec<String> {
        packages
            .iter()
            .find(|package| package.name == name)
            .unwrap_or_else(|| panic!("{name} missing"))
            .groups
            .iter()
            .cloned()
            .collect()
    }

    fn names(packages: &[LockedPackage]) -> Vec<&str> {
        packages
            .iter()
            .map(|package| package.name.as_str())
            .collect()
    }

    #[test]
    fn uv_lock_labels_each_package_by_how_it_is_reached() {
        let packages = parse_uv_lock(GROUPED_UV_LOCK).expect("parse");
        assert_eq!(labels(&packages, "app"), ["main"]);
        // Reached by the app (main) and by the dev group: both labels.
        assert_eq!(labels(&packages, "shared"), ["group:dev", "main"]);
        // An extra of a dependency that the project activates is a runtime dependency.
        assert_eq!(labels(&packages, "fastlib"), ["main"]);
        // Transitive dependencies of a group's packages belong to the group.
        assert_eq!(labels(&packages, "pytest"), ["group:dev"]);
        assert_eq!(labels(&packages, "pluggy"), ["group:dev"]);
        assert_eq!(labels(&packages, "mkdocs"), ["group:docs"]);
        assert_eq!(labels(&packages, "click"), ["extra:cli"]);
    }

    #[test]
    fn excluding_a_group_drops_only_what_is_reached_through_nothing_else() {
        let packages = parse_uv_lock(GROUPED_UV_LOCK).expect("parse");
        let (kept, dropped) =
            exclude_groups(packages.clone(), &["dev".to_owned()]).expect("exclude");
        assert_eq!(dropped, 2);
        let kept = names(&kept);
        assert!(!kept.contains(&"pytest") && !kept.contains(&"pluggy"));
        assert!(
            kept.contains(&"shared"),
            "also a runtime dependency, so it stays"
        );
        assert!(kept.contains(&"mkdocs") && kept.contains(&"click"));

        let (kept, dropped) = exclude_groups(
            packages,
            &["DEV".to_owned(), "docs".to_owned(), "cli".to_owned()],
        )
        .expect("exclude");
        assert_eq!(dropped, 4);
        assert_eq!(names(&kept), ["app", "shared", "lib", "fastlib"]);
    }

    #[test]
    fn nothing_is_excluded_without_being_asked() {
        let packages = parse_uv_lock(GROUPED_UV_LOCK).expect("parse");
        let count = packages.len();
        assert_eq!(
            exclude_groups(packages, &[]).expect("exclude").0.len(),
            count
        );
    }

    #[test]
    fn an_unknown_group_is_an_error_that_lists_the_known_ones() {
        let packages = parse_uv_lock(GROUPED_UV_LOCK).expect("parse");
        let error = exclude_groups(packages, &["tests".to_owned()])
            .expect_err("error")
            .0;
        assert!(
            error.contains("no dependency group or extra named 'tests'"),
            "{error}"
        );
        assert!(error.contains("cli, dev, docs"), "{error}");
    }

    #[test]
    fn main_cannot_be_excluded() {
        let packages = parse_uv_lock(GROUPED_UV_LOCK).expect("parse");
        let error = exclude_groups(packages, &["main".to_owned()])
            .expect_err("error")
            .0;
        assert!(error.contains("can't be excluded"), "{error}");
    }

    #[test]
    fn a_lock_that_records_no_groups_cannot_exclude_any() {
        let plain = parse_uv_lock(&uv_lock_without_a_project()).expect("parse");
        assert!(plain.iter().all(|package| package.groups.is_empty()));
        let error = exclude_groups(plain, &["dev".to_owned()])
            .expect_err("error")
            .0;
        assert!(error.contains("records no dependency groups"), "{error}");
    }

    fn uv_lock_without_a_project() -> String {
        "[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { registry = \"https://pypi.org/simple\" }\n".to_owned()
    }

    #[test]
    fn a_package_the_lock_says_nothing_about_is_never_dropped() {
        let mut packages = parse_uv_lock(GROUPED_UV_LOCK).expect("parse");
        for package in &mut packages {
            if package.name == "pytest" {
                package.groups.clear();
            }
        }
        let (kept, _) = exclude_groups(packages, &["dev".to_owned()]).expect("exclude");
        assert!(names(&kept).contains(&"pytest"));
    }

    #[test]
    fn poetry_groups_come_from_groups_or_the_older_category() {
        let packages = parse_poetry_lock(
            r#"
[[package]]
name = "runtime"
version = "1"
groups = ["main"]
[[package]]
name = "tool"
version = "1"
groups = ["dev", "docs"]
[[package]]
name = "both"
version = "1"
groups = ["main", "dev"]
[[package]]
name = "old-main"
version = "1"
category = "main"
[[package]]
name = "old-dev"
version = "1"
category = "dev"
[[package]]
name = "unrecorded"
version = "1"
"#,
        )
        .expect("parse");
        assert_eq!(labels(&packages, "runtime"), ["main"]);
        assert_eq!(labels(&packages, "tool"), ["group:dev", "group:docs"]);
        assert_eq!(labels(&packages, "both"), ["group:dev", "main"]);
        assert_eq!(labels(&packages, "old-main"), ["main"]);
        assert_eq!(labels(&packages, "old-dev"), ["group:dev"]);
        assert!(labels(&packages, "unrecorded").is_empty());
        let (kept, dropped) = exclude_groups(packages, &["dev".to_owned()]).expect("exclude");
        assert_eq!(dropped, 1, "tool is also in docs, so only old-dev goes");
        assert!(names(&kept).contains(&"tool"));
    }

    #[test]
    fn a_pipfile_package_in_both_sections_is_one_entry_with_both_labels() {
        let text = r#"{"default": {"shared": {"version": "==1"}, "app": {"version": "==2"}},
                      "develop": {"shared": {"version": "==1"}, "pytest": {"version": "==8"}}}"#;
        let path = tempdir().expect("tempdir");
        let file = path.path().join("Pipfile.lock");
        fs::write(&file, text).expect("write");
        let packages = read_lock(LockFormat::PipfileLock, &file).expect("read");
        assert_eq!(packages.len(), 3, "{:?}", names(&packages));
        assert_eq!(labels(&packages, "shared"), ["group:develop", "main"]);
        let (kept, dropped) = exclude_groups(packages, &["develop".to_owned()]).expect("exclude");
        assert_eq!(dropped, 1);
        assert!(names(&kept).contains(&"shared"));
    }

    #[test]
    fn pylock_markers_name_groups_and_extras() {
        let packages = parse_pylock(
            r#"
lock-version = "1.0"
[[packages]]
name = "runtime"
version = "1"
[[packages]]
name = "devtool"
version = "1"
marker = "'dev' in dependency_groups"
[[packages]]
name = "optional"
version = "1"
marker = "'speed' in extras"
[[packages]]
name = "legacy-extra"
version = "1"
marker = "extra == 'speed' and python_version >= '3.9'"
[[packages]]
name = "platform"
version = "1"
marker = "sys_platform == 'win32'"
"#,
        )
        .expect("parse");
        assert_eq!(labels(&packages, "runtime"), ["main"]);
        assert_eq!(labels(&packages, "devtool"), ["group:dev"]);
        assert_eq!(labels(&packages, "optional"), ["extra:speed"]);
        assert_eq!(labels(&packages, "legacy-extra"), ["extra:speed"]);
        assert_eq!(
            labels(&packages, "platform"),
            ["main"],
            "an unrelated marker is not a group"
        );
    }

    #[test]
    fn a_duplicate_with_unknown_groups_stays_unknown() {
        let package = |groups: &[&str]| LockedPackage {
            name: "x".to_owned(),
            version: "1".to_owned(),
            source: PackageSource::Registry(None),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
        };
        let merged = merge_duplicates(vec![
            package(&["main"]),
            package(&[]),
            package(&["group:dev"]),
        ]);
        assert_eq!(merged.len(), 1);
        assert!(merged[0].groups.is_empty());
        let merged = merge_duplicates(vec![package(&["main"]), package(&["group:dev"])]);
        assert_eq!(merged[0].groups.len(), 2);
    }

    #[test]
    fn a_forked_package_has_every_version_walked() {
        let packages = parse_uv_lock(
            r#"
[[package]]
name = "me"
version = "0.1"
source = { virtual = "." }
dependencies = [{ name = "x", version = "1.0" }, { name = "x", version = "2.0" }]
[package.dev-dependencies]
dev = [{ name = "y" }]
[[package]]
name = "x"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "z" }]
[[package]]
name = "x"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "w" }]
[[package]]
name = "y"
version = "1"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "z" }]
[[package]]
name = "z"
version = "1"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "w"
version = "1"
source = { registry = "https://pypi.org/simple" }
"#,
        )
        .expect("parse");
        assert_eq!(labels(&packages, "z"), ["group:dev", "main"]);
        let (kept, _) = exclude_groups(packages, &["dev".to_owned()]).expect("exclude");
        assert!(names(&kept).contains(&"z") && !names(&kept).contains(&"y"));
    }

    #[test]
    fn a_marker_with_or_or_not_is_never_tied_to_a_group() {
        for marker in [
            "python_full_version < '3.11' or 'dev' in dependency_groups",
            "'dev' not in dependency_groups",
            "('dev' in dependency_groups) or sys_platform == 'win32'",
        ] {
            assert_eq!(
                pylock_groups(Some(marker)),
                BTreeSet::from(["main".to_owned()]),
                "{marker}"
            );
        }
        assert_eq!(
            pylock_groups(Some(
                "'dev' in dependency_groups and sys_platform == 'linux'"
            )),
            BTreeSet::from(["group:dev".to_owned()])
        );
    }

    #[test]
    fn the_same_version_from_two_sources_stays_two_entries() {
        let package = |source| LockedPackage {
            name: "a".to_owned(),
            version: "1.0".to_owned(),
            source,
            groups: BTreeSet::new(),
        };
        let merged = merge_duplicates(vec![
            package(PackageSource::Git("https://example.com/a".to_owned())),
            package(PackageSource::Registry(None)),
        ]);
        assert_eq!(merged.len(), 2);
    }
}
