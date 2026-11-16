//! Reading the license metadata of a source distribution.
//!
//! Some releases publish only an sdist (a `.tar.gz`, or older `.zip`), whose license can't be read
//! from a wheel or a separate metadata file. An sdist carries `PKG-INFO`, which is a package's core
//! metadata, and its license files. The files to take are the ones `PKG-INFO` names in
//! `License-File`, plus license-like files at the top of the project, and everything in a top-level
//! `licenses` directory. Not every license-like file in the tree: a project vendoring other code carries that
//! code's licenses deep inside it, and they are not this package's.

use crate::sources::installed::parse_metadata;
use flate2::read::GzDecoder;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

/// Cap on one extracted file; real license texts are a few tens of kilobytes.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Caps on the license files taken from one sdist, so a crafted archive can't make a lookup large.
const MAX_LICENCE_FILES: usize = 64;
const MAX_LICENCE_BYTES: usize = 8 * 1024 * 1024;
/// Cap on how much a gzip stream may expand to, so a small download cannot become a huge read.
const MAX_UNPACKED_BYTES: u64 = 1024 * 1024 * 1024;
/// Directory names (below the project root) that conventionally hold license files.
const LICENCE_DIRECTORIES: [&str; 4] = ["licenses", "license", "licences", "licence"];

/// What was read from an sdist.
#[derive(Debug)]
pub struct Sdist {
    /// `PKG-INFO`, which is the package's core metadata.
    pub pkg_info: String,
    /// The license files, as paths relative to the project root, with their contents.
    pub licences: Vec<(PathBuf, Vec<u8>)>,
}

/// Whether the file at `relative` (under the project root) is one to read.
fn wanted(relative: &Path, declared: &[String]) -> bool {
    let parts: Vec<String> = relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    let joined = parts.join("/");
    if declared
        .iter()
        .any(|path| path.trim_start_matches("./") == joined)
    {
        return true;
    }
    let Some(base) = parts.last() else {
        return false;
    };
    match parts.len() {
        1 => super::is_licence_file_name(base),
        // Whatever a top-level licenses directory holds is a license: the REUSE convention names the
        // files after the license (`LICENSES/MIT.txt`), not after the word.
        2 => LICENCE_DIRECTORIES.contains(&parts[0].to_lowercase().as_str()),
        _ => false,
    }
}

/// The path below the archive's top directory, if it is a plain relative path that stays inside it.
fn below_top(path: &Path) -> Option<(String, PathBuf)> {
    let mut components = path.components();
    let Component::Normal(top) = components.next()? else {
        return None;
    };
    let mut relative = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!relative.as_os_str().is_empty()).then(|| (top.to_string_lossy().into_owned(), relative))
}

fn read_capped(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("unreadable file in the archive: {error}"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "a file in the archive is larger than {} MB",
            MAX_FILE_BYTES / (1024 * 1024)
        ));
    }
    Ok(bytes)
}

/// Adds a license file, refusing an archive with more of them than any real project has.
fn add_licence(
    found: &mut Vec<(PathBuf, Vec<u8>)>,
    relative: PathBuf,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let total: usize = found.iter().map(|(_, existing)| existing.len()).sum();
    if found.len() >= MAX_LICENCE_FILES || total + bytes.len() > MAX_LICENCE_BYTES {
        return Err(format!(
            "the sdist has more license files than expected (over {MAX_LICENCE_FILES} files or {} MB)",
            MAX_LICENCE_BYTES / (1024 * 1024)
        ));
    }
    found.push((relative, bytes));
    Ok(())
}

fn tar_entries(body: &[u8]) -> tar::Archive<impl Read + '_> {
    tar::Archive::new(GzDecoder::new(Cursor::new(body)).take(MAX_UNPACKED_BYTES))
}

fn read_tar_gz(body: &[u8]) -> Result<Sdist, String> {
    let invalid = |error: std::io::Error| format!("not a valid sdist archive: {error}");

    // First pass: the project root and PKG-INFO, which says which license files to take.
    let mut found: Option<(String, String)> = None;
    for entry in tar_entries(body).entries().map_err(invalid)? {
        let mut entry = entry.map_err(invalid)?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().map_err(invalid)?.into_owned();
        if let Some((top, relative)) = below_top(&path) {
            if relative == Path::new("PKG-INFO") {
                let text = String::from_utf8_lossy(&read_capped(&mut entry)?).into_owned();
                found = Some((top, text));
                break;
            }
        }
    }
    let (top, pkg_info) = found.ok_or("the sdist has no PKG-INFO")?;
    let declared: Vec<String> = parse_metadata(&pkg_info)
        .get_all("License-File")
        .map(str::to_owned)
        .collect();

    // Second pass: the license files.
    let mut licences = Vec::new();
    for entry in tar_entries(body).entries().map_err(invalid)? {
        let mut entry = entry.map_err(invalid)?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().map_err(invalid)?.into_owned();
        let Some((entry_top, relative)) = below_top(&path) else {
            continue;
        };
        if entry_top == top && wanted(&relative, &declared) {
            add_licence(&mut licences, relative, read_capped(&mut entry)?)?;
        }
    }
    Ok(Sdist { pkg_info, licences })
}

fn read_zip(body: &[u8]) -> Result<Sdist, String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(body))
        .map_err(|error| format!("not a valid sdist archive: {error}"))?;
    let names: Vec<(usize, String, PathBuf)> = (0..archive.len())
        .filter_map(|index| {
            let name = archive.name_for_index(index)?.ok()?.into_owned();
            if name.ends_with('/') {
                return None;
            }
            let (top, relative) = below_top(Path::new(&name))?;
            Some((index, top, relative))
        })
        .collect();
    let (pkg_index, top) = names
        .iter()
        .find(|(_, _, relative)| relative == Path::new("PKG-INFO"))
        .map(|(index, top, _)| (*index, top.clone()))
        .ok_or("the sdist has no PKG-INFO")?;
    let pkg_info = {
        let mut entry = archive
            .by_index(pkg_index)
            .map_err(|error| format!("unreadable PKG-INFO: {error}"))?;
        String::from_utf8_lossy(&read_capped(&mut entry)?).into_owned()
    };
    let declared: Vec<String> = parse_metadata(&pkg_info)
        .get_all("License-File")
        .map(str::to_owned)
        .collect();
    let mut licences = Vec::new();
    for (index, entry_top, relative) in names {
        if entry_top == top && wanted(&relative, &declared) {
            let mut entry = archive
                .by_index(index)
                .map_err(|error| format!("unreadable file in the archive: {error}"))?;
            add_licence(&mut licences, relative, read_capped(&mut entry)?)?;
        }
    }
    Ok(Sdist { pkg_info, licences })
}

/// Where a license file is stored: its own path, except that a name detection wouldn't recognise
/// (`LICENSES/MIT.txt` in the REUSE layout is named after the license) gets a `LICENSE-` prefix.
#[must_use]
pub fn stored_path(relative: &Path) -> PathBuf {
    match relative
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    {
        Some(name) if !super::is_licence_file_name(&name) => {
            relative.with_file_name(format!("LICENSE-{name}"))
        }
        _ => relative.to_path_buf(),
    }
}

/// Read an sdist's `PKG-INFO` and license files from its bytes; `filename` says which format.
///
/// # Errors
///
/// When the archive is not valid, or has no `PKG-INFO`.
pub fn read_sdist(body: &[u8], filename: &str) -> Result<Sdist, String> {
    if filename.ends_with(".zip") {
        read_zip(body)
    } else {
        read_tar_gz(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tar_gz(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, body.as_bytes())
                .expect("append");
        }
        let tar = builder.into_inner().expect("tar");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar).expect("gzip");
        encoder.finish().expect("finish")
    }

    fn zip_of(entries: &[(&str, &str)]) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let mut buffer = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut buffer);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (path, body) in entries {
                archive.start_file(*path, options).expect("start");
                archive.write_all(body.as_bytes()).expect("write");
            }
            archive.finish().expect("finish");
        }
        buffer.into_inner()
    }

    fn names(sdist: &Sdist) -> Vec<String> {
        let mut names: Vec<String> = sdist
            .licences
            .iter()
            .map(|(path, _)| path.to_string_lossy().replace('\\', "/"))
            .collect();
        names.sort();
        names
    }

    const INFO: &str = "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\n";

    fn project() -> Vec<(&'static str, &'static str)> {
        vec![
            ("pkg-1.0/PKG-INFO", INFO),
            ("pkg-1.0/LICENSE", "root licence"),
            ("pkg-1.0/COPYING.txt", "copying"),
            ("pkg-1.0/licenses/EXTRA-LICENSE", "in licenses dir"),
            ("pkg-1.0/LICENSES/MIT.txt", "reuse style"),
            ("pkg-1.0/src/pkg/__init__.py", "code"),
            (
                "pkg-1.0/vendor/dep/LICENSE",
                "a vendored dependency's licence",
            ),
            ("pkg-1.0/docs/licenses/LICENSE", "too deep"),
            ("other-9.9/LICENSE", "another project in the same archive"),
        ]
    }

    #[test]
    fn takes_the_projects_own_license_files_and_not_vendored_ones() {
        for archive in [
            (tar_gz(&project()), "pkg-1.0.tar.gz"),
            (zip_of(&project()), "pkg-1.0.zip"),
        ] {
            let sdist = read_sdist(&archive.0, archive.1).expect("read");
            assert_eq!(sdist.pkg_info, INFO, "{}", archive.1);
            assert_eq!(
                names(&sdist),
                [
                    "COPYING.txt",
                    "LICENSE",
                    "LICENSES/MIT.txt",
                    "licenses/EXTRA-LICENSE"
                ],
                "{}",
                archive.1
            );
        }
    }

    #[test]
    fn license_files_named_in_pkg_info_are_taken_wherever_they_are() {
        let info = format!(
            "{INFO}License-File: vendor/dep/LICENSE\nLicense-File: ./docs/licenses/LICENSE\n"
        );
        let mut entries = project();
        entries[0] = ("pkg-1.0/PKG-INFO", info.as_str());
        let sdist = read_sdist(&tar_gz(&entries), "pkg-1.0.tar.gz").expect("read");
        assert!(names(&sdist).contains(&"vendor/dep/LICENSE".to_owned()));
        assert!(names(&sdist).contains(&"docs/licenses/LICENSE".to_owned()));
    }

    #[test]
    fn pkg_info_may_come_last_as_setuptools_writes_it() {
        let mut entries = project();
        let info = entries.remove(0);
        entries.push(info);
        let sdist = read_sdist(&tar_gz(&entries), "pkg-1.0.tar.gz").expect("read");
        assert_eq!(sdist.pkg_info, INFO);
        assert!(names(&sdist).contains(&"LICENSE".to_owned()));
    }

    #[test]
    fn an_archive_without_pkg_info_or_that_is_not_an_archive_is_an_error() {
        let without = tar_gz(&[("pkg-1.0/LICENSE", "x")]);
        assert!(read_sdist(&without, "pkg-1.0.tar.gz")
            .expect_err("error")
            .contains("no PKG-INFO"));
        assert!(read_sdist(b"not gzip", "pkg-1.0.tar.gz")
            .expect_err("error")
            .contains("not a valid sdist"));
        assert!(read_sdist(b"not a zip", "pkg-1.0.zip")
            .expect_err("error")
            .contains("not a valid sdist"));
        assert!(
            read_sdist(&zip_of(&[("pkg-1.0/LICENSE", "x")]), "pkg-1.0.zip")
                .expect_err("error")
                .contains("no PKG-INFO")
        );
    }

    #[test]
    fn paths_that_climb_out_of_the_project_are_ignored() {
        // `tar::Builder` refuses to write such a path, so build the header bytes directly.
        let mut raw = Vec::new();
        for (path, body) in [
            ("pkg-1.0/PKG-INFO", INFO),
            ("pkg-1.0/../../escape/LICENSE", "bad"),
            ("/abs/LICENSE", "bad"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            let bytes = path.as_bytes();
            header.as_old_mut().name[..bytes.len()].copy_from_slice(bytes);
            header.set_cksum();
            raw.extend_from_slice(header.as_bytes());
            raw.extend_from_slice(body.as_bytes());
            raw.extend(std::iter::repeat_n(0u8, (512 - body.len() % 512) % 512));
        }
        raw.extend(std::iter::repeat_n(0u8, 1024));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&raw).expect("gzip");
        let sdist = read_sdist(&encoder.finish().expect("finish"), "pkg-1.0.tar.gz").expect("read");
        assert!(sdist.licences.is_empty(), "{:?}", names(&sdist));
    }

    #[test]
    fn an_oversized_license_file_is_an_error_not_a_truncated_read() {
        let big = "x".repeat(3 * 1024 * 1024);
        let archive = tar_gz(&[
            ("pkg-1.0/PKG-INFO", INFO),
            ("pkg-1.0/LICENSE", big.as_str()),
        ]);
        let error = read_sdist(&archive, "pkg-1.0.tar.gz").expect_err("error");
        assert!(error.contains("larger than 2 MB"), "{error}");
    }

    #[test]
    fn an_archive_with_too_many_license_files_is_refused() {
        let names: Vec<String> = (0..=MAX_LICENCE_FILES)
            .map(|n| format!("pkg-1.0/LICENSE-{n}"))
            .collect();
        let mut entries: Vec<(&str, &str)> = vec![("pkg-1.0/PKG-INFO", INFO)];
        entries.extend(names.iter().map(|name| (name.as_str(), "text")));
        for archive in [
            (tar_gz(&entries), "pkg-1.0.tar.gz"),
            (zip_of(&entries), "pkg-1.0.zip"),
        ] {
            let error = read_sdist(&archive.0, archive.1).expect_err("error");
            assert!(
                error.contains("more license files than expected"),
                "{}: {error}",
                archive.1
            );
        }
    }

    #[test]
    fn a_realistic_number_of_license_files_is_fine() {
        let names: Vec<String> = (0..10).map(|n| format!("pkg-1.0/LICENSE-{n}")).collect();
        let mut entries: Vec<(&str, &str)> = vec![("pkg-1.0/PKG-INFO", INFO)];
        entries.extend(names.iter().map(|name| (name.as_str(), "text")));
        assert_eq!(
            read_sdist(&tar_gz(&entries), "pkg-1.0.tar.gz")
                .expect("read")
                .licences
                .len(),
            10
        );
    }
}
