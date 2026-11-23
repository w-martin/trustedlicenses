//! `trustedlicenses report`: a Markdown summary of the policy for whoever reviews it.

use crate::args::Cli;
use crate::check::with_overrides;
use crate::context::Context;
use crate::gather::{gather, select_package_set, PackageSet};
use crate::wizard::today_utc;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use trustedlicenses_core::config::{
    ignored_reasons, load_policy, policy_source, project_name, ConfigError,
};
use trustedlicenses_core::report::{render_report, ReportInput};

/// Errors go to stderr, so they never end up in a report or a pin listing redirected to a file.
fn fail(ctx: &mut Context, message: &str) -> i32 {
    let _ = writeln!(ctx.term.err, "trustedlicenses: {message}");
    1
}

/// Exits 0 whatever the packages' licenses: the report describes the policy, it doesn't
/// gate on it.
pub fn report(ctx: &mut Context, cli: &Cli, output: Option<&Path>) -> i32 {
    let pyproject = cli.pyproject.as_path();
    let policy = match load_policy(pyproject) {
        Ok(policy) => Some(with_overrides(policy, cli)),
        Err(ConfigError::NoPolicyConfigured(_)) => None,
        Err(error) => return fail(ctx, error.message()),
    };
    let set = match select_package_set(cli) {
        Ok(set) => set,
        Err(message) => return fail(ctx, &message),
    };
    let (read_from, from_lock) = match &set {
        PackageSet::Installed => ("the installed environment".to_owned(), false),
        PackageSet::Lock(_, path) => (format!("`{}`", path.display()), true),
    };
    // Progress goes to stderr, so a report written to stdout is only Markdown. Ignored
    // packages are read too, so the report can tell an installed one from a stale entry.
    std::mem::swap(&mut ctx.term.out, &mut ctx.term.err);
    let gathered = gather(ctx, cli, &set, &BTreeSet::new());
    std::mem::swap(&mut ctx.term.out, &mut ctx.term.err);
    let detected = match gathered {
        Ok(gathered) => gathered.detections,
        Err(message) => return fail(ctx, &message),
    };

    let project = project_name(pyproject);
    let generated = format!(
        "{} by trustedlicenses {}",
        today_utc(),
        env!("CARGO_PKG_VERSION")
    );
    let reasons = ignored_reasons(pyproject);
    let text = render_report(&ReportInput {
        project: project.as_deref(),
        generated: &generated,
        read_from: &read_from,
        from_lock,
        policy_file: &policy_source(pyproject).display().to_string(),
        policy: policy.as_ref(),
        detected: &detected,
        ignored_reasons: &reasons,
    });
    match output {
        None => {
            let _ = write!(ctx.term.out, "{text}");
            0
        }
        Some(path) => match fs::write(path, &text) {
            Ok(()) => {
                let _ = writeln!(ctx.term.err, "Wrote the report to {}.", path.display());
                0
            }
            Err(error) => fail(ctx, &format!("cannot write {}: {error}", path.display())),
        },
    }
}
