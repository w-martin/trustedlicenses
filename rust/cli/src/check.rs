use crate::args::Cli;
use crate::context::{Color, Context, Style};
use crate::gather::{gather, project_dir, select_package_set};
use crate::wizard::Services;
use std::collections::BTreeSet;
use std::io::Write;
use trustedlicenses_core::config::{load_policy, policy_source, ConfigError, DOCS_URL};
use trustedlicenses_core::detection::{canonical_name, DistributionLicence};
use trustedlicenses_core::policy::{
    evaluate, format_failure, format_remediation, reevaluate, Policy, PolicyResult,
};
use trustedlicenses_core::sources::installed::scan_directory;

pub fn should_offer_wizard(ctx: &Context, quiet: bool) -> bool {
    !quiet && ctx.term.stdin_is_tty
}

pub fn print_result(ctx: &mut Context, result: &PolicyResult) {
    let term = &mut ctx.term;
    if !result.compatibility_notes.is_empty() {
        term.secho(
            &format!(
                "i {} compatibility note(s) -- not a pass/fail result, see below:",
                result.compatibility_notes.len()
            ),
            Style::bold(Color::Yellow),
        );
        for note in &result.compatibility_notes {
            term.echo(note);
        }
    }
    if !result.exceptions.is_empty() {
        term.secho(
            &format!(
                "i {} package(s) pass only by an exception in your policy:",
                result.exceptions.len()
            ),
            Style::bold(Color::Yellow),
        );
        for exception in &result.exceptions {
            term.echo(&exception.describe());
        }
    }
    if result.failures.is_empty() {
        term.secho(
            &format!("✓ All {} packages passed.", result.checked),
            Style::bold(Color::Green),
        );
    } else {
        term.secho(
            &format!(
                "✗ Disallowed or undetectable licenses in {} of {} packages:",
                result.failures.len(),
                result.checked
            ),
            Style::bold(Color::Red),
        );
        for failure in &result.failures {
            term.echo(&format_failure(failure));
            term.echo(&format_remediation(failure));
        }
    }
}

fn error_line(ctx: &mut Context, message: &str) -> i32 {
    ctx.term.secho(
        &format!("trustedlicenses: {message}"),
        Style::bold(Color::Red),
    );
    1
}

/// Why a flow stopped before producing a result.
enum Halt {
    Failed(String),
    /// Input ended mid-prompt: abort the run, like click's `Abort`.
    Aborted,
}

impl Halt {
    fn exit_code(self, ctx: &mut Context) -> i32 {
        match self {
            Self::Failed(message) => error_line(ctx, &message),
            Self::Aborted => {
                let _ = writeln!(ctx.term.err, "Aborted!");
                1
            }
        }
    }
}

/// Load the policy, offering the interactive wizard if none is configured yet.
///
/// `Ok(None)` means nothing is configured and either interactive setup is not appropriate
/// or the user declined; the caller falls back to report-only behaviour.
fn load_or_configure(ctx: &mut Context, cli: &Cli) -> Result<Option<Policy>, Halt> {
    let pyproject = cli.pyproject.as_path();
    match load_policy(pyproject) {
        Err(ConfigError::NoPolicyConfigured(_)) => {
            if !should_offer_wizard(ctx, cli.quiet) {
                return Ok(None);
            }
            let set = select_package_set(cli).map_err(Halt::Failed)?;
            let detected = gather(ctx, cli, &set, &BTreeSet::new())
                .map_err(Halt::Failed)?
                .detections;
            let written = ctx
                .wizard
                .run(&mut ctx.term, pyproject, &detected)
                .map_err(|_| Halt::Aborted)?;
            if written.is_none() {
                return Ok(None);
            }
            ctx.term.echo("");
            load_policy(pyproject)
                .map(Some)
                .map_err(|error| Halt::Failed(error.message().to_owned()))
        }
        other => other
            .map(Some)
            .map_err(|error| Halt::Failed(error.message().to_owned())),
    }
}

fn describe(detected: &DistributionLicence) -> String {
    let categories = if detected.categories.is_empty() {
        "none".to_owned()
    } else {
        detected
            .categories
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    };
    let keys = if detected.keys.is_empty() {
        "no license detected".to_owned()
    } else {
        detected.keys.iter().cloned().collect::<Vec<_>>().join(", ")
    };
    format!("  {}: {keys} ({categories})", detected.name)
}

/// Apply command-line switches over the policy read from the config.
fn with_overrides(mut policy: Policy, cli: &Cli) -> Policy {
    policy.allow_unlicensed |= cli.allow_unlicensed;
    policy
}

/// `ignored-packages` trusts a package rather than a license, so say so when it is used.
fn note_ignored_packages(ctx: &mut Context, policy: &Policy) {
    if policy.ignored_packages.is_empty() {
        return;
    }
    ctx.term.secho(
        &format!(
            "i ignored-packages trusts {} package(s) whatever their license ({}). Prefer \
             accepted-licenses (one license for one package) or allow-unlicensed.",
            policy.ignored_packages.len(),
            policy
                .ignored_packages
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Style::dim(),
    );
}

/// Check every package in the environment or lock file against the policy.
pub fn check_environment(ctx: &mut Context, cli: &Cli) -> i32 {
    let pyproject = cli.pyproject.as_path();
    let policy = match load_or_configure(ctx, cli) {
        Ok(policy) => policy,
        Err(halt) => return halt.exit_code(ctx),
    };
    let set = match select_package_set(cli) {
        Ok(set) => set,
        Err(message) => {
            error_line(ctx, &message);
            return 1;
        }
    };

    let Some(mut policy) = policy.map(|policy| with_overrides(policy, cli)) else {
        ctx.term.secho(
            &format!(
                "i {} has no policy configured yet -- showing detected licenses only.",
                pyproject.display()
            ),
            Style::dim(),
        );
        match gather(ctx, cli, &set, &BTreeSet::new()) {
            Ok(gathered) => {
                for detected in &gathered.detections {
                    ctx.term.echo(&describe(detected));
                }
            }
            Err(message) => {
                error_line(ctx, &message);
                return 1;
            }
        }
        ctx.term.echo(&format!(
            "\nAdd a policy to start enforcing this (re-run without --quiet in a terminal for guided setup). \
             See {DOCS_URL} for the full guide."
        ));
        return 0;
    };

    ctx.term.echo("Checking dependency licenses...");
    note_ignored_packages(ctx, &policy);
    // Detection is kept apart from evaluation so a wizard-driven policy change can be
    // re-judged with `reevaluate` alone, instead of re-scanning (and re-fetching) every
    // package just to apply a policy-level change.
    let detected = match gather(ctx, cli, &set, &policy.ignored_packages) {
        Ok(gathered) => gathered.detections,
        Err(message) => {
            error_line(ctx, &message);
            return 1;
        }
    };
    let mut result = reevaluate(&detected, &policy);
    print_result(ctx, &result);

    if !result.failures.is_empty() && should_offer_wizard(ctx, cli.quiet) {
        ctx.term.echo("");
        let services = Services {
            client: &*ctx.client,
            env: &ctx.env,
        };
        let outcome = ctx.wizard.review_failures(
            &mut ctx.term,
            &services,
            &policy_source(pyproject),
            &result,
            &policy,
        );
        let Ok(changed) = outcome else {
            return Halt::Aborted.exit_code(ctx);
        };
        if changed {
            ctx.term.echo("\nRe-checking against the updated policy...");
            policy = match load_policy(pyproject) {
                Ok(policy) => with_overrides(policy, cli),
                Err(error) => {
                    error_line(ctx, error.message());
                    return 1;
                }
            };
            result = reevaluate(&detected, &policy);
            print_result(ctx, &result);
        }
    }
    i32::from(!result.failures.is_empty())
}

/// Check whether adding package(s), and their transitive dependencies, would pass policy.
///
/// Resolves into an isolated temporary directory, independent of whatever installer the
/// project itself uses, then evaluates every resolved distribution. Nothing is installed
/// into the real environment.
pub fn check_new_packages(ctx: &mut Context, cli: &Cli, packages: &[String]) -> i32 {
    let policy = match load_or_configure(ctx, cli) {
        Ok(policy) => policy,
        Err(halt) => return halt.exit_code(ctx),
    };
    let Some(policy) = policy.map(|policy| with_overrides(policy, cli)) else {
        ctx.term.secho(
            &format!(
                "trustedlicenses: no policy configured yet -- add one first (see {DOCS_URL}, or re-run without \
                 --quiet in a terminal for guided setup) so there's something to check {} against.",
                packages.join(", ")
            ),
            Style::bold(Color::Red),
        );
        return 1;
    };

    note_ignored_packages(ctx, &policy);
    ctx.term.echo(&format!(
        "Resolving {} and its transitive dependencies...",
        packages.join(", ")
    ));
    let target = match tempfile::Builder::new()
        .prefix("trustedlicenses-check-")
        .tempdir()
    {
        Ok(target) => target,
        Err(error) => {
            error_line(
                ctx,
                &format!("could not create a temporary directory: {error}"),
            );
            return 1;
        }
    };
    if let Err(message) = ctx
        .resolver
        .resolve(packages, target.path(), cli.python.as_deref())
    {
        error_line(ctx, &message);
        return 1;
    }
    // Metadata and license files are read from `target`, so evaluation has to finish
    // before the temporary directory is removed.
    let resolved = scan_directory(target.path());
    ctx.term.echo(&format!(
        "Checking {} package(s) (requested plus transitive dependencies)...",
        resolved.len()
    ));
    let result = evaluate(&policy, &resolved);
    print_result(ctx, &result);
    i32::from(!result.failures.is_empty())
}

/// Ask the package index whether a newer release of `package` ships a license.
///
/// Explicit and opt-in: a plain check never does this. Only the package name is sent, to
/// the index the project's lock file or config points at (printed first), with credentials
/// taken from the environment.
pub fn index_check(ctx: &mut Context, cli: &Cli, package: &str) -> i32 {
    use trustedlicenses_core::config::py_repr;
    use trustedlicenses_core::index::{audit_package, format_audit, AuditOptions};
    use trustedlicenses_core::index_discovery::{discover_index, redact_url, DiscoveryContext};
    use trustedlicenses_core::sources::installed::{
        installed_distributions, resolve_environment, EnvironmentSpec,
    };

    let project = project_dir(&cli.pyproject);
    let discovery = DiscoveryContext {
        env: ctx.env.clone(),
        home: ctx.env.get("HOME").map(std::path::PathBuf::from),
        include_system: true,
    };
    let choice = discover_index(&project, package, &discovery);
    ctx.term.echo(&format!(
        "Asking {} (from {}) about {}...",
        redact_url(&choice.url),
        choice.origin,
        py_repr(package)
    ));

    let spec = EnvironmentSpec {
        python: cli.python.clone(),
        venv: cli.venv.clone(),
    };
    let wanted = canonical_name(package);
    let current = resolve_environment(&spec, &project)
        .map(|paths| installed_distributions(&paths))
        .unwrap_or_default()
        .into_iter()
        .find(|dist| canonical_name(dist.metadata.get("Name").unwrap_or("")) == wanted)
        .map_or_else(String::new, |dist| dist.version);

    match audit_package(
        &*ctx.client,
        &choice.url,
        package,
        &current,
        AuditOptions::default(),
    ) {
        Ok(audit) => {
            ctx.term.echo(&format_audit(&audit));
            0
        }
        Err(error) => {
            error_line(ctx, &error.to_string());
            1
        }
    }
}
