//! Turn "the packages to audit" into license detections, from an installed environment or
//! from a lock file plus the package index.

use crate::args::Cli;
use crate::context::Context;
use rayon::prelude::*;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use trustedlicenses_core::detection::{
    canonical_name, inspect_distribution, prescan_licence_files, Distribution, DistributionLicence,
};
use trustedlicenses_core::index::{
    fetch_distribution, in_tree_backend, Client, FetchOptions, IndexError, Response,
    MAX_WHEEL_BYTES,
};
use trustedlicenses_core::index_discovery::{discover_index, redact_url, DiscoveryContext};
use trustedlicenses_core::policy::{detect_all, index_key};
use trustedlicenses_core::sources::installed::{
    installed_distributions, resolve_environment, EnvironmentSpec,
};
use trustedlicenses_core::sources::lock::{exclude_groups, read_lock, LockFormat};
use trustedlicenses_core::sources::{LockedPackage, PackageSource};

/// Lock files that fully pin an environment. A `requirements.txt` is deliberately not
/// auto-detected: most are loose ranges, which cannot be audited, so it must be asked for.
const AUTO_DETECTED: [LockFormat; 4] = [
    LockFormat::UvLock,
    LockFormat::PyLock,
    LockFormat::PoetryLock,
    LockFormat::PipfileLock,
];

#[derive(Clone, Debug)]
pub enum PackageSet {
    Installed,
    Lock(LockFormat, PathBuf),
}

pub fn project_dir(pyproject: &Path) -> PathBuf {
    pyproject
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Pick what to audit: an explicit `--lock`, else `--installed`, else a lock file beside
/// `pyproject.toml`, else the installed environment.
pub fn select_package_set(cli: &Cli) -> Result<PackageSet, String> {
    if let Some(lock) = &cli.lock {
        let format = LockFormat::from_path(lock).ok_or_else(|| {
            format!(
                "cannot tell what kind of lock file {} is; expected uv.lock, pylock.toml, poetry.lock, \
                 Pipfile.lock or a requirements .txt file",
                lock.display()
            )
        })?;
        return Ok(PackageSet::Lock(format, lock.clone()));
    }
    if cli.installed {
        return Ok(PackageSet::Installed);
    }
    let directory = project_dir(&cli.pyproject);
    for format in AUTO_DETECTED {
        let path = directory.join(format.file_name());
        if path.is_file() {
            return Ok(PackageSet::Lock(format, path));
        }
    }
    Ok(PackageSet::Installed)
}

/// Stands in for the network under `--offline`: only the local cache can answer.
struct Offline;

impl Client for Offline {
    fn get(
        &self,
        url: &str,
        _accept: Option<&str>,
        _max: Option<usize>,
    ) -> Result<Response, IndexError> {
        Err(IndexError::Query(format!(
            "--offline: {} is not in the local cache (run once without --offline to fill it).",
            redact_url(url)
        )))
    }

    fn credentials_for(&self, _url: &str) -> String {
        "none".to_owned()
    }
}

fn unresolved(package: &LockedPackage, reason: String) -> DistributionLicence {
    DistributionLicence {
        name: package.name.clone(),
        version: package.version.clone(),
        source: reason,
        unreadable: true,
        ..DistributionLicence::default()
    }
}

/// A pinned package whose metadata has been obtained, ready for detection.
struct Fetched {
    name: String,
    version: String,
    index: String,
    distribution: Distribution,
    from_installed: bool,
}

/// Installed copies that may stand in for an index lookup, by canonical name and version.
type InstalledCopies = HashMap<(String, String), Distribution>;

/// The installed distributions of the chosen environment that came from an index. One installed
/// from a URL, VCS or path carries `direct_url.json` and may differ from what the lock pins.
fn installed_copies(cli: &Cli, project: &Path) -> Result<InstalledCopies, String> {
    let spec = EnvironmentSpec {
        python: cli.python.clone(),
        venv: cli.venv.clone(),
    };
    let paths = resolve_environment(&spec, project).map_err(|error| error.to_string())?;
    let mut copies = InstalledCopies::new();
    for dist in installed_distributions(&paths) {
        // Only a `.dist-info` can be checked for `direct_url.json`, and only one carries bundled
        // license files; a legacy `.egg-info` is neither, so it never stands in for the index.
        let Some(dist_info) = dist.dist_info.as_ref() else {
            continue;
        };
        if dist_info.join("direct_url.json").exists() {
            continue;
        }
        let name = canonical_name(dist.metadata.get("Name").unwrap_or(""));
        // Where one name and version is installed twice, the copy found first on the search path
        // is the one Python would import, so it is the one used.
        copies.entry((name, dist.version.clone())).or_insert(dist);
    }
    Ok(copies)
}

/// The index a registry package is read from: the lock's, else the project's configured one.
fn index_of(package: &LockedPackage, project: &Path, discovery: &DiscoveryContext) -> String {
    match &package.source {
        PackageSource::Registry(Some(url)) => url.clone(),
        _ => discover_index(project, &package.name, discovery).url,
    }
}

/// The I/O half of looking up a pinned package: find its index and fetch its license
/// metadata. `Err` is the finished (failed-closed) detection for a package that cannot be
/// read, so it never reaches the CPU-bound half.
fn fetch_locked(
    client: &dyn Client,
    project: &Path,
    discovery: &DiscoveryContext,
    cache: &Path,
    installed: &InstalledCopies,
    package: &LockedPackage,
) -> Result<Fetched, Box<DistributionLicence>> {
    if matches!(package.source, PackageSource::Registry(_)) {
        if let Some(distribution) = installed.get(&(package.name.clone(), package.version.clone()))
        {
            return Ok(Fetched {
                name: package.name.clone(),
                version: package.version.clone(),
                index: index_of(package, project, discovery),
                distribution: distribution.clone(),
                from_installed: true,
            });
        }
    }
    let index = match &package.source {
        PackageSource::Registry(_) => index_of(package, project, discovery),
        PackageSource::Git(location)
        | PackageSource::Url(location)
        | PackageSource::Path(location) => {
            let kind = match package.source {
                PackageSource::Git(_) => "git",
                PackageSource::Url(_) => "URL",
                _ => "local path",
            };
            return Err(Box::new(unresolved(
                package,
                format!(
                    "lock file: {kind} source {} -- its license can't be read from a package index",
                    redact_url(location)
                ),
            )));
        }
    };
    let options = FetchOptions {
        cache_dir: cache,
        max_wheel_bytes: MAX_WHEEL_BYTES,
    };
    fetch_distribution(client, &index, &package.name, &package.version, &options)
        .map(|distribution| Fetched {
            name: package.name.clone(),
            version: package.version.clone(),
            index: index.clone(),
            distribution,
            from_installed: false,
        })
        .map_err(|error| {
            let mut failed = unresolved(package, format!("package index: {error}"));
            failed.index = Some(index_key(&index));
            Box::new(failed)
        })
}

/// The CPU half: detect the license from fetched metadata and bundled license files.
fn inspect_fetched(fetched: &Fetched) -> DistributionLicence {
    let mut detected = inspect_distribution(&fetched.distribution, Some(&fetched.name));
    if detected.version.is_empty() {
        detected.version.clone_from(&fetched.version);
    }
    if fetched.from_installed {
        detected.source.push_str(" [installed environment]");
    }
    detected.index = Some(index_key(&fetched.index));
    if let Some(backend) = in_tree_backend(&fetched.distribution) {
        detected.source.push_str(&format!(
            " [source archive built by its own backend, {backend}: what installs may differ]"
        ));
        detected.in_tree_backend = Some(backend);
    }
    detected
}

pub struct Gathered {
    pub detections: Vec<DistributionLicence>,
}

/// Detect the license of every package in `set`, skipping `exclude`.
pub fn gather(
    ctx: &mut Context,
    cli: &Cli,
    set: &PackageSet,
    exclude: &BTreeSet<String>,
) -> Result<Gathered, String> {
    let project = project_dir(&cli.pyproject);
    match set {
        PackageSet::Installed => {
            if !cli.exclude_group.is_empty() {
                return Err(
                    "--exclude-group needs a lock file: an installed environment doesn't record why each package is there"
                        .to_owned(),
                );
            }
            let spec = EnvironmentSpec {
                python: cli.python.clone(),
                venv: cli.venv.clone(),
            };
            let paths = resolve_environment(&spec, &project).map_err(|error| error.to_string())?;
            let distributions = installed_distributions(&paths);
            Ok(Gathered {
                detections: detect_all(&distributions, exclude),
            })
        }
        PackageSet::Lock(format, path) => {
            let mut packages = read_lock(*format, path).map_err(|error| error.to_string())?;
            let (kept, dropped) = exclude_groups(packages, &cli.exclude_group)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            packages = kept;
            if dropped > 0 {
                ctx.term.echo(&format!(
                    "Left out {dropped} package(s) reached only through {}.",
                    cli.exclude_group.join(", ")
                ));
            }
            packages.retain(|package| !exclude.contains(&package.name));
            let mut seen = BTreeSet::new();
            packages.retain(|package| {
                seen.insert((
                    package.name.clone(),
                    package.version.clone(),
                    format!("{:?}", package.source),
                ))
            });

            let scratch;
            let cache: PathBuf = match (&ctx.cache_dir, cli.no_cache) {
                (Some(dir), false) => dir.clone(),
                _ => {
                    scratch = tempfile::tempdir()
                        .map_err(|error| format!("could not create a cache directory: {error}"))?;
                    scratch.path().to_path_buf()
                }
            };
            let file_name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            ctx.term.echo(&format!(
                "Reading {} package(s) pinned in {file_name}; license metadata comes from the package index{}.",
                packages.len(),
                if cli.offline { " (--offline: local cache only)" } else { "" }
            ));

            let discovery = DiscoveryContext {
                env: ctx.env.clone(),
                home: ctx.env.get("HOME").map(PathBuf::from),
                include_system: true,
            };
            let installed = if cli.prefer_installed {
                installed_copies(cli, &project).unwrap_or_else(|error| {
                    ctx.term.echo(&format!(
                        "--prefer-installed: no installed environment to read ({error}); using the index for everything."
                    ));
                    HashMap::new()
                })
            } else {
                HashMap::new()
            };
            let offline = Offline;
            let client: &dyn Client = if cli.offline { &offline } else { &*ctx.client };
            // Two phases with different parallelism: lookups are bounded because an index is a
            // shared service, while detection is CPU-bound and should use every core.
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(usize::from(cli.jobs))
                .build()
                .map_err(|error| error.to_string())?;
            let outcomes: Vec<Result<Fetched, Box<DistributionLicence>>> = pool.install(|| {
                packages
                    .par_iter()
                    .map(|package| {
                        fetch_locked(client, &project, &discovery, &cache, &installed, package)
                    })
                    .collect()
            });
            let from_installed = outcomes
                .iter()
                .filter(|outcome| outcome.as_ref().is_ok_and(|fetched| fetched.from_installed))
                .count();
            if from_installed > 0 {
                ctx.term.echo(&format!(
                    "Read {from_installed} of {} package(s) from the installed environment (--prefer-installed), \
                     matching on name and version only; the rest from the package index.",
                    packages.len()
                ));
            }
            if let Some(traffic) = client.traffic().filter(|traffic| traffic.requests > 0) {
                ctx.term.echo(&format!(
                    "Fetched {:.1} MB from the package index in {} request(s).",
                    traffic.bytes as f64 / 1e6,
                    traffic.requests
                ));
            }
            let built_in_tree: Vec<String> = outcomes
                .iter()
                .filter_map(|outcome| outcome.as_ref().ok())
                .filter_map(|fetched| {
                    in_tree_backend(&fetched.distribution)
                        .map(|backend| format!("{} {} ({backend})", fetched.name, fetched.version))
                })
                .collect();
            if !built_in_tree.is_empty() {
                ctx.term.echo(&format!(
                    "i Read from a source archive that builds with its own backend at install time, \
                     which may download or generate what actually installs, so its license may not \
                     be the one read here: {}. Check what it installs.",
                    built_in_tree.join(", ")
                ));
            }
            prescan_licence_files(
                outcomes
                    .iter()
                    .filter_map(|outcome| outcome.as_ref().ok())
                    .map(|fetched| &fetched.distribution),
            );
            let mut detections: Vec<DistributionLicence> = outcomes
                .into_par_iter()
                .map(|outcome| {
                    outcome.map_or_else(|failed| *failed, |fetched| inspect_fetched(&fetched))
                })
                .collect();
            detections.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
            Ok(Gathered { detections })
        }
    }
}
