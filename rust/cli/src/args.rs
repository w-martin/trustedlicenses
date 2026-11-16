use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Check dependency licenses against policy.
#[derive(Debug, Parser)]
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

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check whether package(s) could be added without a license problem, before adding them.
    Check {
        /// Package requirement(s) to check, e.g. requests 'django>=5,<6'.
        #[arg(required = true)]
        packages: Vec<String>,
    },
    /// Ask the package index whether a newer release of a package ships a license.
    ///
    /// Opt-in: sends only the package name to the index your project's lockfile/config
    /// points at. Also reports what that index supports -- safe to run anywhere.
    IndexCheck {
        /// Package to look up, e.g. webencodings.
        package: String,
    },
}
