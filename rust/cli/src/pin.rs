//! `trustedlicenses pin`: replace `allowed-categories` with the specific licenses they allow
//! in the project today, so a license new to the project fails until someone accepts it.

use crate::args::Cli;
use crate::context::{Color, Context, Style};
use crate::gather::{gather, select_package_set};
use std::io::Write;
use trustedlicenses_core::config::{load_policy, pin_policy, policy_source, ConfigError};
use trustedlicenses_core::policy::pin_licenses;
use trustedlicenses_core::report::needs_individual_check;

/// Errors go to stderr, so they never end up in a report or a pin listing redirected to a file.
fn fail(ctx: &mut Context, message: &str) -> i32 {
    let _ = writeln!(ctx.term.err, "trustedlicenses: {message}");
    1
}

pub fn pin(ctx: &mut Context, cli: &Cli, dry_run: bool) -> i32 {
    let pyproject = cli.pyproject.as_path();
    let source = policy_source(pyproject);
    let policy = match load_policy(pyproject) {
        Ok(policy) => policy,
        Err(ConfigError::NoPolicyConfigured(_)) => {
            return fail(
                ctx,
                "there's no policy to pin yet -- run `trustedlicenses` in a terminal to set one up.",
            );
        }
        Err(error) => return fail(ctx, error.message()),
    };
    if policy.allowed_categories.is_empty() {
        ctx.term.echo(&format!(
            "{} is already pinned: it allows only the licenses in allowed-licenses.",
            source.display()
        ));
        return 0;
    }
    let detected = match select_package_set(cli)
        .and_then(|set| gather(ctx, cli, &set, &policy.ignored_packages))
    {
        Ok(gathered) => gathered.detections,
        Err(message) => return fail(ctx, &message),
    };
    let licenses = pin_licenses(&detected, &policy);
    if licenses.is_empty() {
        return fail(
            ctx,
            "nothing passes through allowed-categories today, so there's nothing to pin.",
        );
    }

    let categories = policy
        .allowed_categories
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    ctx.term.echo(&format!(
        "allowed-categories ({categories}) becomes allowed-licenses with {} license(s):",
        licenses.len()
    ));
    for license in &licenses {
        let mut notes = Vec::new();
        if policy.allowed_licenses.contains(license) {
            notes.push("already listed".to_owned());
        }
        if let Some(why) = needs_individual_check(license) {
            notes.push(format!("check individually: {why}"));
        }
        let notes = if notes.is_empty() {
            String::new()
        } else {
            format!(" ({})", notes.join("; "))
        };
        ctx.term.echo(&format!("  {license}{notes}"));
    }
    if dry_run {
        ctx.term.echo("\nDry run -- nothing written.");
        return 0;
    }
    match pin_policy(&source, &licenses) {
        Ok(()) => {
            ctx.term.secho(
                &format!(
                    "\nPinned {}. A license new to the project now fails until you accept it.",
                    source.display()
                ),
                Style::bold(Color::Green),
            );
            0
        }
        Err(error) => fail(ctx, error.message()),
    }
}
