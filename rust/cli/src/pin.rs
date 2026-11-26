//! `trustedlicenses pin`: replace allowed categories with the specific licenses they allow in
//! the project today, so a license new to the project fails until someone accepts it.

use crate::args::Cli;
use crate::context::{Color, Context, Style};
use crate::gather::{gather, select_package_set};
use std::collections::BTreeSet;
use std::io::Write;
use trustedlicenses_core::config::{load_policy, pin_policy, policy_source, ConfigError};
use trustedlicenses_core::detection::known_categories;
use trustedlicenses_core::policy::{pin_licenses, pinnable_licenses, Policy};
use trustedlicenses_core::report::needs_individual_check;

/// Errors go to stderr, so they never end up in a report or a pin listing redirected to a file.
fn fail(ctx: &mut Context, message: &str) -> i32 {
    let _ = writeln!(ctx.term.err, "trustedlicenses: {message}");
    1
}

fn quoted<'a>(names: impl IntoIterator<Item = &'a String>) -> String {
    names
        .into_iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The categories to pin: those asked for, or every allowed one.
fn chosen_categories(policy: &Policy, asked: &[String]) -> Result<BTreeSet<String>, String> {
    if asked.is_empty() {
        return Ok(policy.allowed_categories.clone());
    }
    let mut chosen = BTreeSet::new();
    for name in asked {
        if policy.allowed_categories.contains(name) {
            chosen.insert(name.clone());
        } else if !policy.pinned_categories.contains(name) {
            return Err(format!(
                "\"{name}\" isn't in allowed-categories, so there's nothing to pin. Allowed: {}.",
                quoted(&policy.allowed_categories)
            ));
        }
    }
    Ok(chosen)
}

pub fn pin(ctx: &mut Context, cli: &Cli, dry_run: bool, asked: &[String]) -> i32 {
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
    let known = known_categories();
    if let Some(unknown) = asked.iter().find(|name| !known.contains(*name)) {
        return fail(
            ctx,
            &format!(
                "\"{unknown}\" isn't a license category. Known categories: {}.",
                quoted(&known)
            ),
        );
    }
    if policy.allowed_categories.is_empty() {
        ctx.term.echo(&format!(
            "{} is already pinned: it allows only the licenses in allowed-licenses.",
            source.display()
        ));
        return 0;
    }
    let categories = match chosen_categories(&policy, asked) {
        Ok(categories) => categories,
        Err(message) => return fail(ctx, &message),
    };
    if categories.is_empty() {
        ctx.term.echo(&format!(
            "{} is already pinned in {}.",
            quoted(asked),
            source.display()
        ));
        return 0;
    }
    let partial = categories.len() < policy.allowed_categories.len();
    let detected = match select_package_set(cli)
        .and_then(|set| gather(ctx, cli, &set, &policy.ignored_packages))
    {
        Ok(gathered) => gathered.detections,
        Err(message) => return fail(ctx, &message),
    };
    let licenses = if partial {
        pinnable_licenses(&detected, &policy, &categories)
    } else {
        pin_licenses(&detected, &policy)
    };
    if licenses.is_empty() && !partial {
        return fail(
            ctx,
            "nothing passes through allowed-categories today, so there's nothing to pin.",
        );
    }

    let names = quoted(&categories);
    if partial {
        let kept: Vec<&String> = policy.allowed_categories.difference(&categories).collect();
        let kept = format!(
            "{} {}",
            quoted(kept.iter().copied()),
            if kept.len() == 1 { "stays" } else { "stay" }
        );
        if licenses.is_empty() {
            ctx.term.echo(&format!(
                "No package passes through {names} today, so pinning it adds no licenses: a \
                 {names} license will fail until you accept it. {kept} allowed whole."
            ));
        } else {
            ctx.term.echo(&format!(
                "{names} becomes {} license(s) in allowed-licenses; {kept} allowed whole:",
                licenses.len()
            ));
        }
    } else {
        ctx.term.echo(&format!(
            "allowed-categories ({}) becomes allowed-licenses with {} license(s):",
            policy
                .allowed_categories
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", "),
            licenses.len()
        ));
    }
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
    match pin_policy(&source, &categories, &licenses) {
        Ok(()) => {
            let what = if partial {
                format!("Pinned {names} in {}. A {names} license", source.display())
            } else {
                format!("Pinned {}. A license", source.display())
            };
            ctx.term.secho(
                &format!("\n{what} new to the project now fails until you accept it."),
                Style::bold(Color::Green),
            );
            0
        }
        Err(error) => fail(ctx, error.message()),
    }
}
