use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Check dependency licenses against policy.
#[derive(Clone, Debug, Parser)]
#[command(name = "trustedlicenses", version)]
pub struct Cli {
    /// Path to the pyproject.toml holding [tool.trustedlicenses].
    #[arg(long, global = true, default_value = "pyproject.toml")]
    pub pyproject: PathBuf,

    /// Never prompt interactively; fall back to report-only mode when no policy is
    /// configured. Recommended for CI/CD and pre-commit hooks.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Audit the packages pinned by this lock file (uv.lock, pylock.toml, poetry.lock,
    /// Pipfile.lock) or pinned requirements file, reading license metadata from the package
    /// index. Without this, a lock file next to pyproject.toml is used if there is one.
    #[arg(long, global = true, value_name = "FILE")]
    pub lock: Option<PathBuf>,

    /// Audit the installed environment even when a lock file is present.
    #[arg(long, global = true, conflicts_with = "lock")]
    pub installed: bool,

    /// Interpreter whose environment to audit (queried for its exact sys.path).
    #[arg(long, global = true, value_name = "EXE")]
    pub python: Option<PathBuf>,

    /// Virtual environment directory to audit, scanned without running Python.
    #[arg(long, global = true, value_name = "DIR")]
    pub venv: Option<PathBuf>,

    /// Never use the network: read only license metadata already in the local cache.
    #[arg(long, global = true)]
    pub offline: bool,

    /// How many package lookups to run at once when auditing a lock file. Raise it for a fast index
    /// you control; lower it for a shared or rate-limited one.
    #[arg(long, global = true, value_name = "N", default_value_t = 16, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub jobs: u16,

    /// Let packages with no license at all pass (same as `allow-unlicensed = true` in the config).
    /// A detected license, or a free-text statement awaiting review, is still judged as usual.
    #[arg(long, global = true)]
    pub allow_unlicensed: bool,

    /// With a lock file, read a package's license from the installed environment when its name
    /// and version match the lock entry, and from the package index otherwise. For local and
    /// offline use: an installed copy isn't verified against the lock's hashes.
    #[arg(long, global = true)]
    pub prefer_installed: bool,

    /// Leave out packages reached only through this dependency group or extra (dev, docs, ...). Repeat
    /// to leave out several. Needs a lock file that records groups: uv.lock, poetry.lock,
    /// Pipfile.lock or pylock.toml.
    #[arg(long, global = true, value_name = "NAME")]
    pub exclude_group: Vec<String>,

    /// Do not keep fetched license metadata after this run.
    #[arg(long, global = true)]
    pub no_cache: bool,

    /// PEM file of extra CA certificates to trust for the package index (e.g. a private CA),
    /// alongside the bundled Mozilla roots. Without this, SSL_CERT_FILE, PIP_CERT, `cert` in
    /// pip.conf, then REQUESTS_CA_BUNDLE are used, whichever is set first.
    #[arg(long, global = true, value_name = "FILE")]
    pub ca_cert: Option<PathBuf>,

    /// Trust the operating system's certificate store instead of the bundled Mozilla roots, e.g.
    /// for a corporate CA installed in the macOS keychain or Windows store.
    #[arg(long, global = true, conflicts_with = "ca_cert")]
    pub system_certs: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Check whether package(s) could be added without a license problem, before adding them.
    Check {
        /// Package requirement(s) to check, e.g. requests 'django>=5,<6'.
        #[arg(required = true)]
        packages: Vec<String>,
    },
    /// Run the guided setup, even when a policy already exists: each answer then defaults to
    /// what the policy says now, and the package-by-package decisions from reviews can be kept.
    ///
    /// Needs a terminal; it never runs under --quiet.
    Setup,
    /// Ask the package index whether a newer release of a package ships a license.
    ///
    /// Opt-in: sends only the package name to the index your project's lockfile/config
    /// points at. Also reports what that index supports -- safe to run anywhere.
    IndexCheck {
        /// Package to look up, e.g. webencodings.
        package: String,
    },
    /// Replace allowed-categories with the specific licenses they allow in this project today.
    ///
    /// Stricter, for publishing: afterwards a license new to the project fails until you
    /// accept it, instead of passing because it shares a category.
    Pin {
        /// Show what would be written, without writing it.
        #[arg(long)]
        dry_run: bool,

        /// Pin only this category, e.g. "Copyleft Limited", and keep allowing the others whole.
        /// Repeat to pin several. Without it, every allowed category is pinned.
        #[arg(long, value_name = "NAME")]
        category: Vec<String>,
    },
    /// Write a Markdown report of the policy for whoever reviews it: what's accepted and
    /// why, and what could be accepted but isn't.
    ///
    /// Always exits 0 when the report is written: it describes the policy, it doesn't gate.
    Report {
        /// Write the report to this file instead of standard output.
        #[arg(long, short, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Write one Markdown report covering several codebases, whether or not they use
    /// trustedlicenses yet: the licenses each one uses, and how each fares against a policy.
    ///
    /// Each codebase is judged by its own policy, else by --policy, else just listed. Always
    /// exits 0 when the report is written: it describes, it doesn't gate.
    Audit {
        /// Codebases to audit: a project directory holding uv.lock, pylock.toml, poetry.lock,
        /// Pipfile.lock or a pinned requirements.txt, or one of those files.
        #[arg(required = true, value_name = "PATH")]
        paths: Vec<PathBuf>,

        /// Policy for codebases that have none of their own: a trustedlicenses.toml, or a
        /// pyproject.toml with a [tool.trustedlicenses] table.
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,

        /// Write the report to this file instead of standard output.
        #[arg(long, short, value_name = "FILE")]
        output: Option<PathBuf>,
    },
}
