//! Pinned `requirements.txt` files (the output of `pip freeze` or `uv pip compile`).
//!
//! Only exact pins (`==` / `===`) can be audited without a resolver, so any other
//! specifier is an error that lists every offender rather than a silent skip.

use super::{source_error, LockedPackage, PackageSource, SourceError};
use crate::detection::canonical_name;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

struct Patterns {
    requirement: Regex,
    pin: Regex,
    option_split: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        requirement: Regex::new(
            r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$",
        )
        .expect("static pattern"),
        pin: Regex::new(r"^===?\s*([^\s,;*<>=!~]+)$").expect("static pattern"),
        option_split: Regex::new(r"\s+--?[A-Za-z]").expect("static pattern"),
    })
}

#[derive(Default)]
struct Collected {
    packages: Vec<LockedPackage>,
    problems: Vec<String>,
    index_url: Option<String>,
    visited: HashSet<PathBuf>,
}

/// Join `\` continuations and drop comments (a `#` at line start or after whitespace).
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let (content, continued) = match raw.strip_suffix('\\') {
            Some(stripped) => (stripped, true),
            None => (raw, false),
        };
        pending.push_str(content);
        if continued {
            continue;
        }
        let line = std::mem::take(&mut pending);
        let cleaned = match line
            .char_indices()
            .find(|(i, c)| *c == '#' && (*i == 0 || line[..*i].ends_with(char::is_whitespace)))
        {
            Some((i, _)) => &line[..i],
            None => line.as_str(),
        };
        lines.push(cleaned.trim().to_owned());
    }
    if !pending.trim().is_empty() {
        lines.push(pending.trim().to_owned());
    }
    lines
}

fn option_value<'a>(line: &'a str, short: &str, long: &str) -> Option<&'a str> {
    if let Some(rest) = line.strip_prefix(long) {
        return Some(rest.trim_start_matches(['=', ' ', '\t']).trim());
    }
    line.strip_prefix(short)
        .filter(|rest| rest.starts_with([' ', '\t']) || !rest.is_empty())
        .map(|rest| rest.trim_start_matches([' ', '\t']).trim())
}

fn looks_like_location(text: &str) -> bool {
    text.contains("://") || text.starts_with(['.', '/', '~']) || text.starts_with("file:")
}

fn add_requirement(line: &str, collected: &mut Collected) {
    let patterns = patterns();
    let line = patterns
        .option_split
        .split(line)
        .next()
        .unwrap_or(line)
        .split(';')
        .next()
        .unwrap_or(line)
        .trim();

    if let Some((name, location)) = line.split_once(" @ ").or_else(|| line.split_once("@ ")) {
        let name = name.split('[').next().unwrap_or(name).trim();
        let location = location.trim().to_owned();
        let source = if location.starts_with("git+") {
            PackageSource::Git(location)
        } else if location.starts_with("file:") {
            PackageSource::Path(location)
        } else {
            PackageSource::Url(location)
        };
        collected.packages.push(LockedPackage {
            name: canonical_name(name),
            version: String::new(),
            source,
            groups: std::collections::BTreeSet::new(),
        });
        return;
    }
    if looks_like_location(line) {
        collected
            .problems
            .push(format!("{line} (a location with no package name)"));
        return;
    }
    let Some(captures) = patterns.requirement.captures(line) else {
        collected
            .problems
            .push(format!("{line} (not a requirement)"));
        return;
    };
    let name = &captures[1];
    let spec = captures[2].trim();
    match patterns.pin.captures(spec) {
        Some(pin) if !spec.contains(',') => collected.packages.push(LockedPackage {
            name: canonical_name(name),
            version: pin[1].to_owned(),
            source: PackageSource::Registry(None),
            groups: std::collections::BTreeSet::new(),
        }),
        _ if spec.is_empty() => collected.problems.push(format!("{name} (no version)")),
        _ => collected
            .problems
            .push(format!("{name}{spec} (not pinned with ==)")),
    }
}

fn read_into(path: &Path, collected: &mut Collected) -> Result<(), SourceError> {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !collected.visited.insert(canonical) {
        return Ok(());
    }
    let text = fs::read_to_string(path)
        .map_err(|error| source_error(format!("cannot read {}: {error}", path.display())))?;
    let base = path.parent().unwrap_or_else(|| Path::new(""));

    for line in logical_lines(&text) {
        if line.is_empty() {
            continue;
        }
        if let Some(include) = option_value(&line, "-r", "--requirement") {
            if line.starts_with("-r") || line.starts_with("--requirement") {
                read_into(&base.join(include), collected)?;
                continue;
            }
        }
        if line.starts_with("-c") || line.starts_with("--constraint") {
            continue;
        }
        if let Some(target) = option_value(&line, "-e", "--editable") {
            if line.starts_with("-e") || line.starts_with("--editable") {
                if target.contains("://") {
                    collected
                        .problems
                        .push(format!("-e {target} (editable remote requirement)"));
                }
                continue;
            }
        }
        if line.starts_with("--index-url") || line.starts_with("-i ") {
            if let Some(url) = option_value(&line, "-i", "--index-url") {
                collected.index_url = Some(url.to_owned());
            }
            continue;
        }
        if line.starts_with('-') {
            continue;
        }
        add_requirement(&line, collected);
    }
    Ok(())
}

/// Read the exact pins from a requirements file, following `-r` includes.
///
/// # Errors
///
/// When a file cannot be read, or any requirement is not pinned to an exact version.
pub fn read_requirements(path: &Path) -> Result<Vec<LockedPackage>, SourceError> {
    let mut collected = Collected::default();
    read_into(path, &mut collected)?;
    if !collected.problems.is_empty() {
        return Err(source_error(format!(
            "{}: cannot audit requirements that are not pinned to an exact version \
             (pin them, or audit a lock file instead): {}",
            path.display(),
            collected.problems.join("; ")
        )));
    }
    let index = collected.index_url;
    Ok(collected
        .packages
        .into_iter()
        .map(|mut package| {
            if let (PackageSource::Registry(slot), Some(url)) = (&mut package.source, &index) {
                *slot = Some(url.clone());
            }
            package
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn read(body: &str) -> Result<Vec<LockedPackage>, SourceError> {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("requirements.txt");
        fs::write(&path, body).expect("write");
        read_requirements(&path)
    }

    fn pins(body: &str) -> Vec<(String, String)> {
        read(body)
            .expect("read")
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect()
    }

    #[test]
    fn reads_exact_pins_with_extras_markers_hashes_and_comments() {
        let got = pins(
            "# frozen\nrequests[security]==2.31.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\n\
             Some_Pkg === 1.0 ; python_version < '3.12'  # trailing\nplain==3.0.post1\n",
        );
        assert_eq!(
            got,
            [
                ("requests".to_owned(), "2.31.0".to_owned()),
                ("some-pkg".to_owned(), "1.0".to_owned()),
                ("plain".to_owned(), "3.0.post1".to_owned()),
            ]
        );
    }

    #[test]
    fn lists_every_unpinned_requirement_at_once() {
        let error = read("good==1.0\nloose>=2\nnone\nrange==1.*\ntwo==1,!=2\n").expect_err("error");
        for needle in [
            "loose>=2",
            "none (no version)",
            "range==1.* (not pinned",
            "two==1,!=2",
        ] {
            assert!(
                error.0.contains(needle),
                "{needle} missing from {}",
                error.0
            );
        }
        assert!(!error.0.contains("good"));
    }

    #[test]
    fn direct_references_become_non_registry_sources() {
        let got = read(
            "a @ https://example.com/a-1.0.whl\nb @ git+https://example.com/b.git@abc\nc @ file:///src/c\n",
        )
        .expect("read");
        assert_eq!(
            got[0].source,
            PackageSource::Url("https://example.com/a-1.0.whl".to_owned())
        );
        assert_eq!(
            got[1].source,
            PackageSource::Git("git+https://example.com/b.git@abc".to_owned())
        );
        assert_eq!(
            got[2].source,
            PackageSource::Path("file:///src/c".to_owned())
        );
    }

    #[test]
    fn index_url_applies_to_registry_packages() {
        let got = read("--index-url https://priv.example/simple\nx==1\n--extra-index-url https://other/simple\n")
            .expect("read");
        assert_eq!(
            got[0].source,
            PackageSource::Registry(Some("https://priv.example/simple".to_owned()))
        );
    }

    #[test]
    fn follows_includes_and_ignores_constraints_and_flags() {
        let tmp = tempdir().expect("tempdir");
        fs::write(
            tmp.path().join("base.txt"),
            "inner==1\n-r requirements.txt\n",
        )
        .expect("write");
        let path = tmp.path().join("requirements.txt");
        fs::write(
            &path,
            "-r base.txt\n-c constraints.txt\n--pre\n--no-binary :all:\nouter==2\n",
        )
        .expect("write");
        let names: Vec<_> = read_requirements(&path)
            .expect("read")
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, ["inner", "outer"]);
    }

    #[test]
    fn local_editables_are_skipped_but_remote_ones_are_reported() {
        assert_eq!(
            pins("-e .\n-e ../lib\nx==1\n"),
            [("x".to_owned(), "1".to_owned())]
        );
        let error = read("-e git+https://example.com/r.git#egg=r\n").expect_err("error");
        assert!(error.0.contains("editable remote requirement"));
    }

    #[test]
    fn a_bare_location_without_a_name_is_reported() {
        let error = read("https://example.com/x.whl\n").expect_err("error");
        assert!(error.0.contains("a location with no package name"));
    }

    #[test]
    fn a_missing_file_is_an_error() {
        let tmp = tempdir().expect("tempdir");
        assert!(read_requirements(&tmp.path().join("nope.txt")).is_err());
    }
}
