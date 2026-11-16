//! Where the set of packages to audit comes from: an installed environment, or a lock
//! file / pinned requirements file.

pub mod installed;
pub mod lock;
pub mod requirements;

use std::fmt;

/// A package source could not be read or understood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceError(pub String);

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SourceError {}

pub(crate) fn source_error(message: impl Into<String>) -> SourceError {
    SourceError(message.into())
}

/// Where a locked package comes from, which decides whether its license can be looked up
/// on a package index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageSource {
    /// A package index. `None` means the lock does not say, i.e. the default index.
    Registry(Option<String>),
    Git(String),
    Url(String),
    Path(String),
}

/// One package pinned by a lock file or requirements file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedPackage {
    /// Canonical (PEP 503) name.
    pub name: String,
    /// Empty when the lock does not record one (e.g. a local directory).
    pub version: String,
    pub source: PackageSource,
    /// The ways the package is reached from the project: `main` for its runtime dependencies,
    /// `group:NAME` for a dependency group (dev, docs, ...), `extra:NAME` for an optional extra.
    /// Empty when the lock records nothing about it, which is treated as "always include".
    pub groups: std::collections::BTreeSet<String>,
}
