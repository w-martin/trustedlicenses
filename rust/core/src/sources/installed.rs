//! Read the distributions installed in a Python environment without running Python.
//!
//! `METADATA` parsing mirrors what `importlib.metadata` hands the Python implementation:
//! header values are kept raw including continuation lines, and a value is dedented only
//! when its continuation indent is exactly eight spaces.

use super::{source_error, SourceError};
use crate::detection::{Distribution, Metadata};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONTINUATION_INDENT: &str = "        ";

/// `textwrap.dedent`: strip the longest whitespace prefix common to all non-blank lines,
/// and normalise whitespace-only lines to empty.
fn dedent(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let leading = |line: &str| -> String {
        line.chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .collect()
    };
    let mut margin: Option<String> = None;
    for line in lines
        .iter()
        .filter(|line| !line.trim_matches([' ', '\t']).is_empty())
    {
        let indent = leading(line);
        margin = Some(match margin {
            None => indent,
            Some(current) => current
                .chars()
                .zip(indent.chars())
                .take_while(|(a, b)| a == b)
                .map(|(a, _)| a)
                .collect(),
        });
    }
    let margin = margin.unwrap_or_default();
    lines
        .iter()
        .map(|line| {
            if line.trim_matches([' ', '\t']).is_empty() {
                ""
            } else {
                line.strip_prefix(margin.as_str()).unwrap_or(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn redent(value: String) -> String {
    if !value.contains(&format!("\n{CONTINUATION_INDENT}")) {
        return value;
    }
    dedent(&format!("{CONTINUATION_INDENT}{value}"))
}

fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| (b'!'..=b'~').contains(&b) && b != b':')
}

/// Parse core metadata (`METADATA` / `PKG-INFO`) headers, ignoring the body.
#[must_use]
pub fn parse_metadata(text: &str) -> Metadata {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            match fields.last_mut() {
                Some((_, value)) => {
                    value.push('\n');
                    value.push_str(line);
                    continue;
                }
                None => break,
            }
        }
        match line.split_once(':') {
            Some((name, value)) if is_header_name(name) => {
                fields.push((
                    name.to_owned(),
                    value.trim_start_matches([' ', '\t']).to_owned(),
                ));
            }
            _ => break,
        }
    }
    Metadata::new(
        fields
            .into_iter()
            // Current CPython strips leading whitespace, newlines included, from the whole
            // joined value (3.9 stripped only the first line), so a value that starts on
            // the line after the field name has no leading newline.
            .map(|(name, value)| {
                (
                    name,
                    redent(value.trim_start_matches([' ', '\t', '\r', '\n']).to_owned()),
                )
            })
            .collect(),
    )
}

fn read_metadata_file(path: &Path) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn load_distribution(path: &Path) -> Option<Distribution> {
    let file_name = path.file_name()?.to_string_lossy().into_owned();
    let (text, dist_info) = if file_name.ends_with(".dist-info") && path.is_dir() {
        let text = read_metadata_file(&path.join("METADATA"))
            .or_else(|| read_metadata_file(&path.join("PKG-INFO")))?;
        (text, Some(path.to_path_buf()))
    } else if file_name.ends_with(".egg-info") {
        let text = if path.is_dir() {
            read_metadata_file(&path.join("PKG-INFO"))?
        } else {
            read_metadata_file(path)?
        };
        (text, None)
    } else {
        return None;
    };
    let metadata = parse_metadata(&text);
    let version = metadata.get("Version").unwrap_or("").to_owned();
    Some(Distribution {
        metadata,
        version,
        dist_info,
    })
}

/// Every distribution found directly inside `directory`, in name order.
#[must_use]
pub fn scan_directory(directory: &Path) -> Vec<Distribution> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    paths
        .iter()
        .filter_map(|path| load_distribution(path))
        .collect()
}

/// Every distribution on the given `sys.path`-style entries, in path order.
#[must_use]
pub fn installed_distributions(paths: &[PathBuf]) -> Vec<Distribution> {
    paths.iter().flat_map(|path| scan_directory(path)).collect()
}

/// Directories a `.pth` file adds to the path. Lines starting with `import` are code the
/// interpreter would execute, which is deliberately not run here.
fn pth_directories(site_packages: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(site_packages) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pth"))
        .collect();
    files.sort();
    let mut found = Vec::new();
    for file in files {
        let Some(text) = read_metadata_file(&file) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with('#')
                || line.starts_with("import ")
                || line.starts_with("import\t")
            {
                continue;
            }
            let candidate = site_packages.join(line);
            if candidate.is_dir() && !found.contains(&candidate) {
                found.push(candidate);
            }
        }
    }
    found
}

/// The `site-packages` directories of a virtual environment, plus anything its `.pth`
/// files add. Does not follow `include-system-site-packages`; use [`query_sys_path`] for an
/// exact answer.
#[must_use]
pub fn venv_search_paths(venv: &Path) -> Vec<PathBuf> {
    // Compared by resolved path: on Linux `lib64` is usually a symlink to `lib`, and the same
    // directory scanned twice would report every package twice.
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut fresh =
        |path: &Path| seen.insert(fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));

    let mut site_dirs: Vec<PathBuf> = Vec::new();
    let windows = venv.join("Lib").join("site-packages");
    if windows.is_dir() && fresh(&windows) {
        site_dirs.push(windows);
    }
    for lib in ["lib", "lib64"] {
        let Ok(entries) = fs::read_dir(venv.join(lib)) else {
            continue;
        };
        let mut pythons: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("python"))
            })
            .collect();
        pythons.sort();
        for python in pythons {
            let site = python.join("site-packages");
            if site.is_dir() && fresh(&site) {
                site_dirs.push(site);
            }
        }
    }
    let mut paths = Vec::new();
    for site in site_dirs {
        let extra = pth_directories(&site);
        paths.push(site);
        paths.extend(extra.into_iter().filter(|dir| fresh(dir)));
    }
    paths
}

/// Ask an interpreter for its `sys.path`, keeping only absolute entries that exist.
///
/// # Errors
///
/// When the interpreter cannot be run or its output is not the expected JSON.
pub fn query_sys_path(python: &Path) -> Result<Vec<PathBuf>, SourceError> {
    let output = Command::new(python)
        .args(["-c", "import json, sys; print(json.dumps(sys.path))"])
        .current_dir(std::env::temp_dir())
        .output()
        .map_err(|error| source_error(format!("could not run {}: {error}", python.display())))?;
    if !output.status.success() {
        return Err(source_error(format!(
            "{} failed: {}",
            python.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let entries: Vec<String> = serde_json::from_slice(&output.stdout).map_err(|error| {
        source_error(format!(
            "unexpected sys.path output from {}: {error}",
            python.display()
        ))
    })?;
    Ok(entries
        .into_iter()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_dir())
        .collect())
}

/// How to locate the environment to audit.
#[derive(Clone, Debug, Default)]
pub struct EnvironmentSpec {
    /// An interpreter whose `sys.path` is queried: exact, but starts Python.
    pub python: Option<PathBuf>,
    /// A virtual environment directory, scanned without running Python.
    pub venv: Option<PathBuf>,
}

fn executable_on_path(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| candidate.is_file())
}

/// Resolve the directories to scan: `--python`, then `--venv`, then `VIRTUAL_ENV`, then
/// `<project>/.venv`, and only then a `python3` on `PATH`.
///
/// # Errors
///
/// When nothing resolves, or an explicitly requested environment is unusable.
pub fn resolve_environment(
    spec: &EnvironmentSpec,
    project_dir: &Path,
) -> Result<Vec<PathBuf>, SourceError> {
    if let Some(python) = &spec.python {
        return query_sys_path(python);
    }
    let venv = spec
        .venv
        .clone()
        .or_else(|| std::env::var_os("VIRTUAL_ENV").map(PathBuf::from))
        .or_else(|| Some(project_dir.join(".venv")).filter(|path| path.is_dir()));
    if let Some(venv) = venv {
        let paths = venv_search_paths(&venv);
        if paths.is_empty() {
            return Err(source_error(format!(
                "no site-packages found in {}; is it a virtual environment?",
                venv.display()
            )));
        }
        return Ok(paths);
    }
    match executable_on_path(&["python3", "python", "python.exe"]) {
        Some(python) => query_sys_path(&python),
        None => Err(source_error(
            "no Python environment found: pass --python or --venv, or run inside an activated environment",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_simple_headers_and_stops_at_the_body() {
        let metadata = parse_metadata(
            "Metadata-Version: 2.4\nName: Foo\nVersion: 3.0\nLicense-Expression: MIT\n\nName: not-a-header\n",
        );
        assert_eq!(metadata.get("name"), Some("Foo"));
        assert_eq!(metadata.get("Version"), Some("3.0"));
        assert_eq!(metadata.get_all("Name").count(), 1);
    }

    #[test]
    fn keeps_repeated_headers_in_order() {
        let metadata = parse_metadata("Name: x\nClassifier: A\nClassifier: B\n\n");
        assert_eq!(
            metadata.get_all("classifier").collect::<Vec<_>>(),
            ["A", "B"]
        );
    }

    #[test]
    fn eight_space_continuations_are_dedented() {
        let metadata = parse_metadata("Name: x\nLicense: blah\n        de-blah\n\n");
        assert_eq!(metadata.get("License"), Some("blah\nde-blah"));
    }

    #[test]
    fn other_continuation_indents_are_kept_raw() {
        let metadata = parse_metadata("Name: x\nLicense: blah\n    de-blah\n\n");
        assert_eq!(metadata.get("License"), Some("blah\n    de-blah"));
    }

    #[test]
    fn crlf_is_normalised() {
        let metadata = parse_metadata("Name: x\r\nLicense: MIT\r\n\r\n");
        assert_eq!(metadata.get("License"), Some("MIT"));
    }

    #[test]
    fn a_line_without_a_colon_starts_the_body() {
        let metadata = parse_metadata("Name: x\njust prose\nVersion: 9\n");
        assert_eq!(metadata.get("Name"), Some("x"));
        assert_eq!(metadata.get("Version"), None);
    }

    #[test]
    fn scans_dist_info_and_egg_info_but_not_other_entries() {
        let tmp = tempdir().expect("tempdir");
        let dist_info = tmp.path().join("a-1.0.dist-info");
        fs::create_dir_all(&dist_info).expect("mkdir");
        fs::write(dist_info.join("METADATA"), "Name: a\nVersion: 1.0\n").expect("write");
        let egg_dir = tmp.path().join("b-2.0.egg-info");
        fs::create_dir_all(&egg_dir).expect("mkdir");
        fs::write(egg_dir.join("PKG-INFO"), "Name: b\nVersion: 2.0\n").expect("write");
        fs::write(tmp.path().join("c-3.0.egg-info"), "Name: c\nVersion: 3.0\n").expect("write");
        fs::create_dir_all(tmp.path().join("plainpkg")).expect("mkdir");
        let dists = scan_directory(tmp.path());
        let names: Vec<_> = dists
            .iter()
            .map(|d| d.metadata.get("Name").unwrap_or(""))
            .collect();
        assert_eq!(names, ["a", "b", "c"]);
        assert_eq!(dists[0].dist_info.as_deref(), Some(dist_info.as_path()));
        assert!(dists[1].dist_info.is_none());
        assert_eq!(dists[2].version, "3.0");
    }

    #[test]
    fn a_dist_info_without_metadata_is_skipped() {
        let tmp = tempdir().expect("tempdir");
        fs::create_dir_all(tmp.path().join("a-1.0.dist-info")).expect("mkdir");
        assert!(scan_directory(tmp.path()).is_empty());
    }

    #[test]
    fn venv_search_paths_include_pth_directories_and_skip_import_lines() {
        let tmp = tempdir().expect("tempdir");
        let site = tmp.path().join("lib/python3.13/site-packages");
        fs::create_dir_all(&site).expect("mkdir");
        fs::create_dir_all(tmp.path().join("src")).expect("mkdir");
        fs::write(
            site.join("dev.pth"),
            "# note\nimport os\n../../../src\nmissing\n",
        )
        .expect("write");
        let paths = venv_search_paths(tmp.path());
        assert_eq!(paths[0], site);
        assert_eq!(paths.len(), 2);
        assert!(paths[1].ends_with("src"));
    }

    #[test]
    fn an_empty_directory_is_not_a_venv() {
        let tmp = tempdir().expect("tempdir");
        let spec = EnvironmentSpec {
            venv: Some(tmp.path().to_path_buf()),
            ..EnvironmentSpec::default()
        };
        let error = resolve_environment(&spec, tmp.path()).expect_err("error");
        assert!(error.0.contains("no site-packages"));
    }

    #[test]
    fn dedent_matches_textwrap_on_mixed_blank_lines() {
        assert_eq!(dedent("    a\n   \n    b"), "a\n\nb");
        assert_eq!(dedent("\ta\n    b"), "\ta\n    b");
    }

    /// Expected headers generated by running `importlib.metadata`'s own `Message` over each
    /// sample, so any divergence in continuation or dedent handling shows here.
    #[test]
    fn matches_importlib_on_tricky_metadata() {
        let golden: &[(&str, &[(&str, &str)])] = &[
        ("Name: a\nVersion: 1\nLicense: blah\n        de-blah\n\nbody\n", &[("Name", "a"), ("Version", "1"), ("License", "blah\nde-blah")]),
        ("Name: a\nLicense: blah\n    four\n    spaces\n", &[("Name", "a"), ("License", "blah\n    four\n    spaces")]),
        ("Name: a\nLicense: first\n\tTabbed\n", &[("Name", "a"), ("License", "first\n\tTabbed")]),
        ("Name: a\nLicense: top\n        mid\n          deeper\n        end\n", &[("Name", "a"), ("License", "top\nmid\n  deeper\nend")]),
        ("Name: a\nLicense: x\n        \n        y\n", &[("Name", "a"), ("License", "x\n\ny")]),
        ("Name: a\nLicense:    padded   \nClassifier: License :: OSI Approved :: MIT License\nClassifier: Other\n", &[("Name", "a"), ("License", "padded   "), ("Classifier", "License :: OSI Approved :: MIT License"), ("Classifier", "Other")]),
        ("Name: a\nlicense-expression: MIT OR Apache-2.0\n", &[("Name", "a"), ("license-expression", "MIT OR Apache-2.0")]),
        ("Name: a\nLicense:\n        MIT License\n        Copyright\n", &[("Name", "a"), ("License", "MIT License\nCopyright")]),
        ("Name: a\r\nLicense: crlf\r\n        line2\r\n\r\nbody", &[("Name", "a"), ("License", "crlf\nline2")]),
        ("Name: a\nNo colon here\nVersion: hidden\n", &[("Name", "a")]),
        ("Name: a\nVersion: 1\n\nVersion: 2\n", &[("Name", "a"), ("Version", "1")]),
        ("Name: a\nLicense: trailing space \nVersion: 1 \n", &[("Name", "a"), ("License", "trailing space "), ("Version", "1 ")]),
        ("Name: a\nLicense: a: b: c\n", &[("Name", "a"), ("License", "a: b: c")]),
        ("Name: a\n Leading\nVersion: 1\n", &[("Name", "a\n Leading"), ("Version", "1")]),
        ];
        for (text, expected) in golden {
            let metadata = parse_metadata(text);
            let actual: Vec<(&str, &str)> = metadata.iter().collect();
            assert_eq!(&actual, expected, "for {text:?}");
        }
    }

    /// A Linux virtual environment has `lib64` as a symlink to `lib`.
    #[cfg(unix)]
    #[test]
    fn a_lib64_symlink_to_lib_does_not_list_site_packages_twice() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let site = tmp.path().join("lib/python3.12/site-packages");
        std::fs::create_dir_all(&site).expect("mkdir");
        std::os::unix::fs::symlink("lib", tmp.path().join("lib64")).expect("symlink");
        let paths = venv_search_paths(tmp.path());
        assert_eq!(paths, [site]);
    }

    #[cfg(unix)]
    #[test]
    fn a_pth_directory_already_listed_is_not_listed_again() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let site = tmp.path().join("lib/python3.12/site-packages");
        std::fs::create_dir_all(site.join("extra")).expect("mkdir");
        std::fs::write(site.join("one.pth"), "extra\n").expect("write");
        std::fs::write(site.join("two.pth"), "extra\n").expect("write");
        let paths = venv_search_paths(tmp.path());
        assert_eq!(paths, [site.clone(), site.join("extra")]);
    }
}
