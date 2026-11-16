//! The `trustedlicenses` command line, as a library so the binary and the in-process mode
//! share one implementation.

// The matcher allocates heavily (normalised text, n-gram tables). jemalloc on Linux, where the
// platform allocator can be slow under many threads (musl's especially), and mimalloc on Windows.
// macOS keeps its own: jemalloc was measured there to be no faster. Keep the `cfg`s in step with
// `Cargo.toml`; the `system-allocator` feature opts out for comparison.
#[cfg(all(
    not(feature = "system-allocator"),
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "powerpc64",
        target_arch = "riscv64"
    )
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(not(feature = "system-allocator"), target_os = "windows"))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod args;
mod check;
mod context;
mod gather;
mod prompt;
mod resolve;
mod wizard;

#[cfg(test)]
mod tests;

pub use context::{Capture, Color, Context, Style, Terminal};
pub use prompt::{LineSource, PromptError, Prompter, PROMPT_TIMEOUT};
pub use resolve::{PipResolver, Resolver};
pub use wizard::{InteractiveWizard, NoWizard, Services, Wizard};

use args::{Cli, Command};
use clap::Parser;
use std::ffi::OsString;
use std::io::Write;

/// Run the CLI with `args` (including the program name) and return the exit code.
pub fn run(args: &[OsString], ctx: &mut Context) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let rendered = error.render().to_string();
            let sink = if code == 0 {
                &mut ctx.term.out
            } else {
                &mut ctx.term.err
            };
            let _ = write!(sink, "{rendered}");
            return code;
        }
    };
    // Scan results are cached beside the fetched license metadata, and `--no-cache` disables both.
    trustedlicenses_core::match_cache::configure(
        ctx.cache_dir
            .as_ref()
            .filter(|_| !cli.no_cache)
            .map(|dir| dir.join("matches")),
    );
    match &cli.command {
        None => check::check_environment(ctx, &cli),
        Some(Command::Check { packages }) => check::check_new_packages(ctx, &cli, packages),
        Some(Command::IndexCheck { package }) => check::index_check(ctx, &cli, package),
    }
}

/// Run the command line against the real process: its terminal, environment and network.
/// `args` includes the program name. Returns the exit status.
#[must_use]
pub fn main_with(args: &[String]) -> i32 {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    run(&args, &mut Context::from_process())
}

/// Like [`main_with`], but returns the exit status, standard output and standard error
/// instead of writing them. Never prompts.
#[must_use]
pub fn run_captured(args: &[String]) -> (i32, String, String) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (mut context, out, err) = Context::captured();
    let status = run(&args, &mut context);
    (status, out.text(), err.text())
}
