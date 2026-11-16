//! Resolve packages, and their transitive dependencies, into an isolated directory for
//! `trustedlicenses check <pkg>`: answering "would adding this introduce a license
//! problem" without touching the real environment or assuming which installer the project
//! itself uses.

use std::path::Path;
use std::process::Command;

pub trait Resolver: Sync {
    /// Install `packages` and their transitive dependencies into the empty directory
    /// `target`, using `python` if given.
    ///
    /// # Errors
    ///
    /// A message when neither `uv` nor `pip` is usable, or resolution failed (a typo'd
    /// name, a version conflict, no network, ...).
    fn resolve(
        &self,
        packages: &[String],
        target: &Path,
        python: Option<&Path>,
    ) -> Result<(), String>;
}

const NO_INSTALLER: &str =
    "could not resolve packages: neither `uv` nor a working `pip` is available. \
                            Install either to use `trustedlicenses check`.";

fn on_path(names: &[&str]) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| candidate.is_file())
}

/// Tries `uv pip install` first, since it is an order of magnitude faster, and falls back
/// to `python -m pip install`. Both install into `target` only, via `--target`.
pub struct PipResolver;

impl Resolver for PipResolver {
    fn resolve(
        &self,
        packages: &[String],
        target: &Path,
        python: Option<&Path>,
    ) -> Result<(), String> {
        let mut command;
        if let Some(uv) = on_path(&["uv", "uv.exe"]) {
            command = Command::new(uv);
            command.args(["pip", "install", "--target"]).arg(target);
            if let Some(python) = python {
                command.arg("--python").arg(python);
            }
        } else {
            let interpreter = python
                .map(Path::to_path_buf)
                .or_else(|| on_path(&["python3", "python", "python.exe"]))
                .ok_or_else(|| NO_INSTALLER.to_owned())?;
            command = Command::new(interpreter);
            command
                .args(["-m", "pip", "install", "--target"])
                .arg(target);
        }
        command.args(packages);
        let output = command.output().map_err(|_| NO_INSTALLER.to_owned())?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "could not resolve {}:\n{}",
                packages.join(", "),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}
