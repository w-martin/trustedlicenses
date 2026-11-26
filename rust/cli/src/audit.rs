//! `trustedlicenses audit`: one Markdown report across several codebases, including ones
//! that don't use trustedlicenses yet.

use crate::args::Cli;
use crate::check::with_overrides;
use crate::context::Context;
use crate::gather::{gather, project_dir, PackageSet};
use crate::wizard::today_utc;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use trustedlicenses_core::config::{
    ignored_reasons, load_policy, load_policy_file, policy_source, project_name, ConfigError,
    STANDALONE_FILENAME,
};
use trustedlicenses_core::detection::DistributionLicence;
use trustedlicenses_core::policy::Policy;
use trustedlicenses_core::report::{render_audit, AuditProject, ReportInput};
use trustedlicenses_core::sources::lock::{detect_lock, LockFormat};

fn fail(ctx: &mut Context, message: &str) -> i32 {
    let _ = writeln!(ctx.term.err, "trustedlicenses: {message}");
    1
}

/// What one codebase turned out to be, owned so the report can borrow it.
struct Audited {
    path: String,
    name: String,
    read_from: String,
    policy_from: String,
    policy: Option<Policy>,
    detected: Vec<DistributionLicence>,
    reasons: BTreeMap<String, String>,
    error: Option<String>,
}

/// The project a lock file belongs to: the nearest directory at or above it holding a
/// `pyproject.toml` or `trustedlicenses.toml`, not looking past a repository root. Its own
/// directory when there's none.
fn project_root(lock_dir: &Path) -> PathBuf {
    let mut dir = lock_dir.to_path_buf();
    loop {
        if dir.join("pyproject.toml").is_file() || dir.join(STANDALONE_FILENAME).is_file() {
            return dir;
        }
        if dir.join(".git").exists() {
            break;
        }
        match dir.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => dir = parent.to_path_buf(),
            Some(_) if dir != Path::new(".") => dir = PathBuf::from("."),
            _ => break,
        }
    }
    lock_dir.to_path_buf()
}

/// The lock file to read for `path`: the path itself, or the one a project directory holds.
fn locate(path: &Path) -> Result<(PathBuf, LockFormat, PathBuf), String> {
    if path.is_dir() {
        return detect_lock(path)
            .map(|(format, lock)| (path.to_path_buf(), format, lock))
            .ok_or_else(|| {
                "no uv.lock, pylock.toml, poetry.lock, Pipfile.lock or requirements.txt here; \
                 give the lock file's path instead"
                    .to_owned()
            });
    }
    if path.is_file() {
        let format = LockFormat::from_path(path).ok_or_else(|| {
            "not a lock file trustedlicenses reads (uv.lock, pylock.toml, poetry.lock, \
             Pipfile.lock or a requirements .txt)"
                .to_owned()
        })?;
        return Ok((project_root(&project_dir(path)), format, path.to_path_buf()));
    }
    Err("doesn't exist".to_owned())
}

fn display_name(path: &Path, directory: &Path, pyproject: &Path) -> String {
    project_name(pyproject)
        .or_else(|| {
            fs::canonicalize(directory)
                .ok()
                .and_then(|dir| dir.file_name().map(|n| n.to_string_lossy().into_owned()))
        })
        .unwrap_or_else(|| path.display().to_string())
}

fn audit_one(
    ctx: &mut Context,
    cli: &Cli,
    path: &Path,
    fallback: Option<(&Policy, &str)>,
) -> Audited {
    let mut audited = Audited {
        path: path.display().to_string(),
        name: path.file_name().map_or_else(
            || path.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        ),
        read_from: String::new(),
        policy_from: String::new(),
        policy: None,
        detected: Vec::new(),
        reasons: BTreeMap::new(),
        error: None,
    };
    let (directory, format, lock) = match locate(path) {
        Ok(found) => found,
        Err(error) => {
            audited.error = Some(error);
            return audited;
        }
    };
    let pyproject = directory.join("pyproject.toml");
    audited.name = display_name(path, &directory, &pyproject);
    audited.read_from = format!(
        "`{}`",
        lock.file_name().map_or_else(
            || lock.display().to_string(),
            |n| n.to_string_lossy().into_owned()
        )
    );
    match load_policy(&pyproject) {
        Ok(policy) => {
            let source = policy_source(&pyproject);
            let shown = if directory == project_dir(&lock) {
                source
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
            } else {
                source.display().to_string()
            };
            audited.policy_from = format!("its own (`{shown}`)");
            audited.reasons = ignored_reasons(&pyproject);
            audited.policy = Some(with_overrides(policy, cli));
        }
        Err(ConfigError::NoPolicyConfigured(_)) => {
            if let Some((policy, from)) = fallback {
                audited.policy_from = from.to_owned();
                audited.policy = Some(policy.clone());
            }
        }
        Err(error) => {
            audited.error = Some(format!("its policy can't be read: {}", error.message()));
            return audited;
        }
    }
    let mut scoped = cli.clone();
    scoped.pyproject = pyproject;
    scoped.lock = Some(lock.clone());
    match gather(
        ctx,
        &scoped,
        &PackageSet::Lock(format, lock),
        &BTreeSet::new(),
    ) {
        Ok(gathered) => audited.detected = gathered.detections,
        Err(error) => audited.error = Some(error),
    }
    audited
}

/// Two codebases with the same `[project].name` would merge in the cross-codebase table.
fn disambiguate(audited: &mut [Audited]) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for one in audited.iter() {
        *seen.entry(one.name.clone()).or_default() += 1;
    }
    for one in audited.iter_mut() {
        if seen.get(&one.name).is_some_and(|count| *count > 1) {
            one.name = format!("{} ({})", one.name, one.path);
        }
    }
}

/// Exits 0 whatever the codebases' licenses, as long as the report is written.
pub fn audit(
    ctx: &mut Context,
    cli: &Cli,
    paths: &[PathBuf],
    fallback: Option<&Path>,
    output: Option<&Path>,
) -> i32 {
    if cli.lock.is_some() || cli.installed || cli.venv.is_some() || cli.python.is_some() {
        return fail(
            ctx,
            "audit reads each codebase from the paths it's given, so it doesn't take --lock, \
             --installed, --venv or --python.",
        );
    }
    let fallback = match fallback {
        None => None,
        Some(path) => match load_policy_file(path) {
            Ok(policy) => Some((
                with_overrides(policy, cli),
                format!("`{}` (`--policy`)", path.display()),
            )),
            Err(error) => return fail(ctx, error.message()),
        },
    };

    // Progress goes to stderr, so a report written to stdout is only Markdown.
    std::mem::swap(&mut ctx.term.out, &mut ctx.term.err);
    let mut audited = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in paths {
        if !seen.insert(path) {
            ctx.term.echo(&format!(
                "Skipping {}: it's already in this audit.",
                path.display()
            ));
            continue;
        }
        ctx.term.echo(&format!("Auditing {}...", path.display()));
        let one = audit_one(
            ctx,
            cli,
            path,
            fallback
                .as_ref()
                .map(|(policy, from)| (policy, from.as_str())),
        );
        if let Some(error) = &one.error {
            ctx.term.echo(&format!(
                "  couldn't be read: {}",
                error.lines().next().unwrap_or("")
            ));
        }
        audited.push(one);
    }
    std::mem::swap(&mut ctx.term.out, &mut ctx.term.err);
    disambiguate(&mut audited);

    let projects: Vec<AuditProject<'_>> = audited
        .iter()
        .map(|one| AuditProject {
            path: &one.path,
            name: &one.name,
            outcome: match &one.error {
                Some(error) => Err(error.clone()),
                None => Ok(ReportInput {
                    project: Some(&one.name),
                    generated: "",
                    read_from: &one.read_from,
                    from_lock: true,
                    policy_from: &one.policy_from,
                    policy: one.policy.as_ref(),
                    detected: &one.detected,
                    ignored_reasons: &one.reasons,
                }),
            },
        })
        .collect();
    let generated = format!(
        "{} by trustedlicenses {}",
        today_utc(),
        env!("CARGO_PKG_VERSION")
    );
    let text = render_audit(
        &generated,
        fallback.as_ref().map(|(_, from)| from.as_str()),
        &projects,
    );
    match output {
        None => {
            let _ = write!(ctx.term.out, "{text}");
            0
        }
        Some(path) => match fs::write(path, &text) {
            Ok(()) => {
                let _ = writeln!(ctx.term.err, "Wrote the audit to {}.", path.display());
                0
            }
            Err(error) => fail(ctx, &format!("cannot write {}: {error}", path.display())),
        },
    }
}
