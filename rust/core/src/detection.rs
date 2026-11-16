//! License detection for one distribution.
//!
//! Priority order: declared metadata (`License-Expression`, `License`, `License ::`
//! classifiers) resolved against the SPDX identifier table, then, only when nothing
//! resolved, text matching of bundled license files. Free-text corrections are attached as
//! `suggested` but never folded into `keys` here: trusting one is a policy decision.
//!
//! License categories are an editorial taxonomy extracted from ScanCode Toolkit's
//! CC-BY-4.0 license database (see `NOTICE`), not something SPDX publishes.

use crate::matcher::{prescan, scan_license_text, DEFAULT_CONFIDENCE_THRESHOLD};
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// ScanCode's marker for "there is clearly a license reference here but it cannot be
/// identified". Never proof of a license.
pub const UNSTATED_CATEGORY: &str = "Unstated License";

const LICENCE_FILE_PREFIXES: [&str; 4] = ["LICENSE", "LICENCE", "COPYING", "NOTICE"];
const SPDX_OPERATORS: [&str; 3] = ["and", "or", "with"];

const CATEGORY_TABLE_JSON: &str = include_str!("../data/spdx_license_categories.json");

/// A package's core metadata as ordered `(field, value)` pairs, looked up
/// case-insensitively like email headers.
#[derive(Clone, Debug, Default)]
pub struct Metadata {
    fields: Vec<(String, String)>,
}

impl Metadata {
    #[must_use]
    pub fn new(fields: Vec<(String, String)>) -> Self {
        Self { fields }
    }

    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.fields
            .iter()
            .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Every `(field, value)` pair in header order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields
            .iter()
            .map(|(field, value)| (field.as_str(), value.as_str()))
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One distribution to inspect: its metadata and, when it has one, the `.dist-info`
/// directory that may bundle license files.
#[derive(Clone, Debug, Default)]
pub struct Distribution {
    pub metadata: Metadata,
    pub version: String,
    pub dist_info: Option<PathBuf>,
}

/// The licenses detected for one distribution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DistributionLicence {
    /// Canonical (PEP 503 normalised) name.
    pub name: String,
    pub keys: BTreeSet<String>,
    pub categories: BTreeSet<String>,
    /// Where the detection came from, for a failure report.
    pub source: String,
    /// `(declared statement, corrected SPDX id)` pairs, populated whenever `keys` is empty.
    pub suggested: BTreeSet<(String, String)>,
    pub version: String,
    /// The license could not be read at all (a failed lookup, a dependency with no index), which
    /// is not the same as a package that has none.
    pub unreadable: bool,
    /// A license statement is declared or license files are shipped, whether or not they could be
    /// identified. Such a package has a license; it is just not one this tool recognises.
    pub declares_license: bool,
}

impl DistributionLicence {
    /// A package that was read and has no license at all: nothing identified, nothing declared,
    /// no license file shipped. Not the same as a license that could not be identified.
    #[must_use]
    pub fn is_unlicensed(&self) -> bool {
        self.keys.is_empty()
            && self.suggested.is_empty()
            && !self.unreadable
            && !self.declares_license
    }
}

fn category_table() -> &'static HashMap<String, String> {
    static TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let raw: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(CATEGORY_TABLE_JSON)
                .expect("bundled category table is valid JSON");
        raw.into_iter()
            .filter_map(|(key, value)| value.as_str().map(|v| (key, v.to_owned())))
            .collect()
    })
}

/// Every category a policy may name, excluding the unidentifiable-reference marker.
#[must_use]
pub fn known_categories() -> BTreeSet<String> {
    category_table()
        .values()
        .filter(|category| category.as_str() != UNSTATED_CATEGORY)
        .cloned()
        .collect()
}

/// Lowercased key -> canonical SPDX case, so casing alone never stops a token resolving.
fn category_table_ci() -> &'static HashMap<String, String> {
    static TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        category_table()
            .keys()
            .map(|key| (key.to_lowercase(), key.clone()))
            .collect()
    })
}

/// Normalise a distribution name per PEP 503.
#[must_use]
pub fn canonical_name(raw: &str) -> String {
    let mut name = String::with_capacity(raw.len());
    let mut in_separator = false;
    for c in raw.trim().to_lowercase().chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_separator {
                name.push('-');
            }
            in_separator = true;
        } else {
            name.push(c);
            in_separator = false;
        }
    }
    name
}

fn is_licence_file_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    LICENCE_FILE_PREFIXES
        .iter()
        .any(|prefix| upper.starts_with(prefix))
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => walk(&path, found),
            _ => found.push(path),
        }
    }
}

/// Every bundled file under `dist_info` whose name looks like a license file, sorted by path.
fn licence_files(dist_info: Option<&Path>) -> Vec<PathBuf> {
    let Some(dir) = dist_info.filter(|dir| dir.is_dir()) else {
        return Vec::new();
    };
    let mut all = Vec::new();
    walk(dir, &mut all);
    all.sort();
    all.into_iter()
        .filter(|path| {
            fs::metadata(path).is_ok_and(|meta| meta.is_file())
                && path
                    .file_name()
                    .is_some_and(|name| is_licence_file_name(&name.to_string_lossy()))
        })
        .collect()
}

/// Split an expression or trove classifier into candidate identifier tokens.
fn expression_tokens(expression: &str) -> BTreeSet<&str> {
    expression
        .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter(|token| {
            !token.is_empty() && !SPDX_OPERATORS.contains(&token.to_lowercase().as_str())
        })
        .collect()
}

fn read_text(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_default();
    // Python's `read_text` applies universal newlines; matching must see the same text.
    String::from_utf8_lossy(&bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n")
}

fn keys_from_licence_files(files: &[PathBuf]) -> BTreeSet<String> {
    files
        .iter()
        .flat_map(|path| scan_license_text(&read_text(path), DEFAULT_CONFIDENCE_THRESHOLD))
        .map(|(spdx_id, _score)| spdx_id)
        .collect()
}

fn declared_statements(metadata: &Metadata) -> Vec<String> {
    let declared = ["License-Expression", "License"]
        .into_iter()
        .flat_map(|field| metadata.get_all(field));
    let classifiers = metadata
        .get_all("Classifier")
        .filter(|classifier| classifier.starts_with("License ::"));
    declared
        .chain(classifiers)
        .filter(|statement| !statement.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Resolve a raw license statement to the SPDX identifiers it names.
///
/// A token is trusted once it matches a real SPDX identifier; free prose such as
/// "Apache Software License" resolves to nothing.
#[must_use]
pub fn resolve_license_expression(expression: &str) -> BTreeSet<String> {
    let index = category_table_ci();
    expression_tokens(expression)
        .into_iter()
        .filter_map(|token| index.get(&token.to_lowercase()).cloned())
        .collect()
}

fn keys_from_declared(statements: &[String]) -> BTreeSet<String> {
    statements
        .iter()
        .flat_map(|statement| resolve_license_expression(statement))
        .collect()
}

struct CorrectionRegexes {
    whitespace: Regex,
    leading_digit: Regex,
    version_word: Regex,
}

fn correction_regexes() -> &'static CorrectionRegexes {
    static REGEXES: OnceLock<CorrectionRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| CorrectionRegexes {
        whitespace: Regex::new(r"\s+").expect("static pattern"),
        leading_digit: Regex::new(r",?\s*(\d)").expect("static pattern"),
        version_word: Regex::new(r",?\s*(?:V\.|v\.|V|v|Version|version)\s*(\d)")
            .expect("static pattern"),
    })
}

// Structural transforms, each applied to the original candidate rather than chained.
// None pads a bare single-digit version with a fabricated ".0": several families (MPL,
// OSL, ...) have more than one real minor release, so "MPL 1" cannot be corrected without
// guessing. Ported from the validated tier of `spdx-correct.js` (jslicense, Apache-2.0;
// see NOTICE).
type Transform = Box<dyn Fn(&str) -> String>;

fn correction_transforms() -> [Transform; 6] {
    let re = correction_regexes();
    [
        Box::new(|text| text.replace('.', "")),
        Box::new(|text| re.whitespace.replace_all(text, "").into_owned()),
        Box::new(|text| re.whitespace.replace_all(text, "-").into_owned()),
        Box::new(|text| re.leading_digit.replacen(text, 1, "-$1").into_owned()),
        Box::new(|text| re.version_word.replacen(text, 1, "-$1").into_owned()),
        Box::new(|text| text.replace('/', "-")),
    ]
}

// Single substring replacements, tried independently before re-attempting the transforms.
// The first four spell a family out as its acronym; the last drops the word "License",
// which no SPDX identifier in this family contains. That one is not from `spdx-correct.js`.
const CORRECTION_TRANSPOSITIONS: [(&str, &str); 5] = [
    ("GNU Lesser General Public License", "LGPL"),
    ("GNU Affero General Public License", "AGPL"),
    ("GNU General Public License", "GPL"),
    ("Mozilla Public License", "MPL"),
    (" License", ""),
];

/// Deterministically correct a free-text statement into a real SPDX id.
///
/// Only a result that changed from the input and resolves through the same
/// case-insensitive table as direct resolution is accepted. The last-resort substring
/// guessing tier of `spdx-correct.js` (any "GPL" -> GPL-3.0-or-later) is deliberately
/// excluded: it would manufacture a version or variant the text never stated, which PEP 639
/// says tools MUST NOT do for ambiguous classifiers.
fn correct_license_statement(statement: &str) -> Option<String> {
    let index = category_table_ci();
    let transforms = correction_transforms();
    let candidate = statement.trim();

    for transform in &transforms {
        let corrected = transform(candidate);
        let corrected = corrected.trim();
        if corrected != candidate {
            if let Some(canonical) = index.get(&corrected.to_lowercase()) {
                return Some(canonical.clone());
            }
        }
    }

    for (pattern, replacement) in CORRECTION_TRANSPOSITIONS {
        if !candidate.contains(pattern) {
            continue;
        }
        let transposed = candidate.replace(pattern, replacement);
        if let Some(canonical) = index.get(&transposed.to_lowercase()) {
            return Some(canonical.clone());
        }
        for transform in &transforms {
            let corrected = transform(&transposed);
            let corrected = corrected.trim();
            if corrected != transposed {
                if let Some(canonical) = index.get(&corrected.to_lowercase()) {
                    return Some(canonical.clone());
                }
            }
        }
    }
    None
}

fn suggested_corrections(statements: &[String]) -> BTreeSet<(String, String)> {
    statements
        .iter()
        .filter_map(|statement| {
            correct_license_statement(statement).map(|corrected| (statement.clone(), corrected))
        })
        .collect()
}

/// SPDX identifiers that a distribution's declared metadata resolves to, with no
/// license-file fallback. Non-empty means declared metadata alone decides its license.
#[must_use]
pub fn declared_keys(metadata: &Metadata) -> BTreeSet<String> {
    keys_from_declared(&declared_statements(metadata))
}

/// Map SPDX identifiers to their categories, excluding the unidentifiable-reference marker.
pub fn categories_for<'a>(keys: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let table = category_table();
    keys.into_iter()
        .filter_map(|key| table.get(key))
        .filter(|category| category.as_str() != UNSTATED_CATEGORY)
        .cloned()
        .collect()
}

fn categories_of(keys: &BTreeSet<String>) -> BTreeSet<String> {
    categories_for(keys.iter().map(String::as_str))
}

/// Scan, ahead of time and once each, the license texts that detecting `distributions` will need.
///
/// Detection scans bundled license files only when declared metadata resolves nothing. Many packages
/// ship byte-identical text, so doing the scanning here, over the distinct texts, before detection
/// fans out over packages, means each is scanned once rather than by every worker holding a copy.
pub fn prescan_licence_files<'a>(distributions: impl IntoIterator<Item = &'a Distribution>) {
    let texts: Vec<String> = distributions
        .into_iter()
        .filter(|dist| keys_from_declared(&declared_statements(&dist.metadata)).is_empty())
        .flat_map(|dist| licence_files(dist.dist_info.as_deref()))
        .map(|path| read_text(&path))
        .collect();
    prescan(&texts, DEFAULT_CONFIDENCE_THRESHOLD);
}

/// Detect the licenses of one distribution.
///
/// `name` is its canonical name; derived from the metadata `Name` when absent or empty.
#[must_use]
pub fn inspect_distribution(dist: &Distribution, name: Option<&str>) -> DistributionLicence {
    let resolved_name = match name {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => canonical_name(dist.metadata.get("Name").unwrap_or("")),
    };

    let statements = declared_statements(&dist.metadata);
    let declared_keys = keys_from_declared(&statements);
    if !declared_keys.is_empty() {
        return DistributionLicence {
            name: resolved_name,
            categories: categories_of(&declared_keys),
            keys: declared_keys,
            source: "declared metadata".to_owned(),
            suggested: BTreeSet::new(),
            version: dist.version.clone(),
            unreadable: false,
            declares_license: true,
        };
    }

    let suggested = suggested_corrections(&statements);

    let files = licence_files(dist.dist_info.as_deref());
    let (keys, source) = if files.is_empty() {
        (BTreeSet::new(), "no license information found".to_owned())
    } else {
        let names: BTreeSet<String> = files
            .iter()
            .filter_map(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        let joined = names.into_iter().collect::<Vec<_>>().join(", ");
        (
            keys_from_licence_files(&files),
            format!("license files: {joined}"),
        )
    };
    DistributionLicence {
        name: resolved_name,
        categories: categories_of(&keys),
        keys,
        source,
        suggested,
        version: dist.version.clone(),
        unreadable: false,
        declares_license: !statements.is_empty() || !files.is_empty(),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::{Distribution, Metadata};
    use std::fs;
    use std::path::Path;

    pub const MIT: &str = include_str!("../../tests/fixtures/mit.txt");
    pub const GPL_2_0: &str = include_str!("../../tests/fixtures/gpl-2.0.txt");

    /// A synthetic installed distribution under `root`, optionally bundling a LICENSE file.
    pub fn make_distribution(
        root: &Path,
        name: &str,
        license_text: Option<&str>,
        declared: &[(&str, &str)],
    ) -> Distribution {
        let dist_info = root.join(format!("{name}-1.0.dist-info"));
        fs::create_dir_all(&dist_info).expect("create dist-info");
        if let Some(text) = license_text {
            fs::write(dist_info.join("LICENSE"), text).expect("write LICENSE");
        }
        let mut fields = vec![
            ("Name".to_owned(), name.to_owned()),
            ("Version".to_owned(), "1.0".to_owned()),
        ];
        fields.extend(
            declared
                .iter()
                .map(|(field, value)| ((*field).to_owned(), (*value).to_owned())),
        );
        Distribution {
            metadata: Metadata::new(fields),
            version: "1.0".to_owned(),
            dist_info: Some(dist_info),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{make_distribution, GPL_2_0, MIT};
    use super::*;
    use tempfile::tempdir;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn pairs(items: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        items
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn canonical_name_normalises_case_separators_and_whitespace() {
        assert_eq!(canonical_name("Some_Package"), "some-package");
        assert_eq!(canonical_name("Some.Package"), "some-package");
        assert_eq!(canonical_name("  Spacey  "), "spacey");
        assert_eq!(canonical_name("already-canonical"), "already-canonical");
    }

    #[test]
    fn detects_permissive_license_from_bundled_file() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "somepkg", Some(MIT), &[]);
        let result = inspect_distribution(&dist, Some("somepkg"));
        assert_eq!(result.name, "somepkg");
        assert!(result.keys.contains("MIT"));
        assert!(result.categories.contains("Permissive"));
        assert_eq!(result.source, "license files: LICENSE");
    }

    #[test]
    fn detects_copyleft_license_from_bundled_file() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "gplpkg", Some(GPL_2_0), &[]);
        assert!(inspect_distribution(&dist, Some("gplpkg"))
            .categories
            .contains("Copyleft"));
    }

    #[test]
    fn detects_multiple_licenses_in_one_vendored_file() {
        let tmp = tempdir().expect("tempdir");
        let concatenated = format!("{MIT}\n\n{GPL_2_0}");
        let dist = make_distribution(tmp.path(), "vendoring-pkg", Some(&concatenated), &[]);
        let result = inspect_distribution(&dist, Some("vendoring-pkg"));
        assert!(result.categories.contains("Permissive"));
        assert!(result.categories.contains("Copyleft"));
    }

    #[test]
    fn prefers_declared_metadata_over_bundled_file() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "metaonly",
            Some(GPL_2_0),
            &[("License-Expression", "MIT")],
        );
        let result = inspect_distribution(&dist, Some("metaonly"));
        assert_eq!(result.keys, set(&["MIT"]));
        assert_eq!(result.categories, set(&["Permissive"]));
        assert_eq!(result.source, "declared metadata");
    }

    #[test]
    fn detects_nothing_without_any_license_information() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "bare", None, &[]);
        let result = inspect_distribution(&dist, Some("bare"));
        assert!(result.keys.is_empty());
        assert!(result.categories.is_empty());
        assert_eq!(result.source, "no license information found");
    }

    #[test]
    fn free_text_license_field_without_a_file_is_unresolved() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "prosepkg",
            None,
            &[("License", "Apache Software License")],
        );
        let result = inspect_distribution(&dist, Some("prosepkg"));
        assert!(result.keys.is_empty());
        assert!(result.categories.is_empty());
    }

    #[test]
    fn suggests_catboosts_real_world_free_text_license_field() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "catboost",
            None,
            &[("License", "Apache License, Version 2.0")],
        );
        let result = inspect_distribution(&dist, Some("catboost"));
        assert!(result.keys.is_empty());
        assert!(result.categories.is_empty());
        assert_eq!(result.source, "no license information found");
        assert_eq!(
            result.suggested,
            pairs(&[("Apache License, Version 2.0", "Apache-2.0")])
        );
    }

    #[test]
    fn suggests_via_a_direct_transform_with_no_transposition() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "directcase",
            None,
            &[("License", "Apache Version 2.0")],
        );
        let result = inspect_distribution(&dist, Some("directcase"));
        assert!(result.keys.is_empty());
        assert_eq!(
            result.suggested,
            pairs(&[("Apache Version 2.0", "Apache-2.0")])
        );
    }

    #[test]
    fn suggests_a_family_name_reformatted_via_its_acronym() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "mozillapkg",
            None,
            &[("License", "Mozilla Public License, Version 2.0")],
        );
        let result = inspect_distribution(&dist, Some("mozillapkg"));
        assert!(result.keys.is_empty());
        assert_eq!(
            result.suggested,
            pairs(&[("Mozilla Public License, Version 2.0", "MPL-2.0")])
        );
    }

    #[test]
    fn suggestion_does_not_override_a_bundled_file() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "filewins",
            Some(GPL_2_0),
            &[("License", "Apache License, Version 2.0")],
        );
        let result = inspect_distribution(&dist, Some("filewins"));
        assert_eq!(result.keys, set(&["GPL-2.0-or-later"]));
        assert_eq!(result.source, "license files: LICENSE");
        assert_eq!(
            result.suggested,
            pairs(&[("Apache License, Version 2.0", "Apache-2.0")])
        );
    }

    #[test]
    fn falls_back_to_file_when_correction_also_fails() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(
            tmp.path(),
            "fallsback",
            Some(MIT),
            &[("License", "Zope Public License")],
        );
        let result = inspect_distribution(&dist, Some("fallsback"));
        assert_eq!(result.keys, set(&["MIT"]));
        assert_eq!(result.source, "license files: LICENSE");
        assert!(result.suggested.is_empty());
    }

    #[test]
    fn does_not_guess_ambiguous_or_underspecified_statements() {
        for (name, statement) in [
            ("gplfree", "GNU General Public License, Version 3"),
            ("bsdfree", "BSD License"),
            ("mplfree", "MPL 1"),
        ] {
            let tmp = tempdir().expect("tempdir");
            let dist = make_distribution(tmp.path(), name, None, &[("License", statement)]);
            let result = inspect_distribution(&dist, Some(name));
            assert!(result.keys.is_empty(), "{statement}");
            assert!(result.suggested.is_empty(), "{statement}");
        }
    }

    #[test]
    fn records_the_version_whichever_path_resolved() {
        let tmp = tempdir().expect("tempdir");
        let declared = make_distribution(
            tmp.path(),
            "declaredpkg",
            None,
            &[("License-Expression", "MIT")],
        );
        let bare = make_distribution(tmp.path(), "barepkg", None, &[]);
        assert_eq!(
            inspect_distribution(&declared, Some("declaredpkg")).version,
            "1.0"
        );
        assert_eq!(inspect_distribution(&bare, Some("barepkg")).version, "1.0");
    }

    #[test]
    fn derives_the_name_from_metadata_when_omitted() {
        let tmp = tempdir().expect("tempdir");
        let dist = make_distribution(tmp.path(), "Some_Pkg", Some(MIT), &[]);
        assert_eq!(inspect_distribution(&dist, None).name, "some-pkg");
    }

    #[test]
    fn a_distribution_without_a_dist_info_directory_detects_nothing() {
        let dist = Distribution::default();
        let result = inspect_distribution(&dist, Some("x"));
        assert!(result.keys.is_empty());
        assert_eq!(result.source, "no license information found");
    }

    #[test]
    fn expression_operators_and_brackets_are_stripped() {
        assert_eq!(
            resolve_license_expression("(MIT OR apache-2.0) AND BSD-3-Clause"),
            set(&["MIT", "Apache-2.0", "BSD-3-Clause"])
        );
    }

    #[test]
    fn trove_classifiers_resolve_only_when_a_token_is_an_spdx_id() {
        assert_eq!(
            resolve_license_expression("License :: OSI Approved :: MIT License"),
            set(&["MIT"])
        );
        assert!(resolve_license_expression("License :: OSI Approved :: BSD License").is_empty());
    }

    /// Expected values generated from the Python implementation (`_correct_license_statement`
    /// and `resolve_license_expression`), so any divergence in the regex transforms shows here.
    #[test]
    fn matches_the_python_implementation_on_golden_statements() {
        let golden: &[(&str, Option<&str>, &[&str])] = &[
            ("Apache License, Version 2.0", Some("Apache-2.0"), &[]),
            ("Apache Version 2.0", Some("Apache-2.0"), &[]),
            ("Apache 2.0", Some("Apache-2.0"), &[]),
            ("Apache-2.0", None, &["Apache-2.0"]),
            ("apache-2.0", None, &["Apache-2.0"]),
            ("MIT License", Some("MIT"), &["MIT"]),
            ("MIT", None, &["MIT"]),
            ("BSD License", None, &[]),
            ("BSD 3-Clause", Some("BSD-3-Clause"), &[]),
            (
                "BSD-3-Clause License",
                Some("BSD-3-Clause"),
                &["BSD-3-Clause"],
            ),
            ("GNU General Public License, Version 3", None, &[]),
            ("GNU General Public License v2.0 or later", None, &[]),
            ("GNU Lesser General Public License v3", None, &[]),
            ("GNU Lesser General Public License, Version 2.1", None, &[]),
            ("GNU Affero General Public License v3.0", None, &[]),
            ("Mozilla Public License, Version 2.0", Some("MPL-2.0"), &[]),
            ("Mozilla Public License 2.0", Some("MPL-2.0"), &[]),
            ("MPL 1", None, &[]),
            ("MPL 2.0", Some("MPL-2.0"), &[]),
            ("MPL/2.0", Some("MPL-2.0"), &[]),
            ("Apache/2.0", Some("Apache-2.0"), &[]),
            ("Apache v2.0", Some("Apache-2.0"), &[]),
            ("Apache V.2.0", Some("Apache-2.0"), &[]),
            ("Apache version 2.0", Some("Apache-2.0"), &[]),
            ("  Apache 2.0  ", Some("Apache-2.0"), &[]),
            ("ISC License", Some("ISC"), &["ISC"]),
            ("Python Software Foundation License", None, &[]),
            ("PSF-2.0", None, &["PSF-2.0"]),
            ("Zope Public License", None, &[]),
            ("Unlicense", None, &["Unlicense"]),
            ("The Unlicense", None, &["Unlicense"]),
            ("CC0 1.0", Some("CC0-1.0"), &[]),
            ("CC0-1.0", None, &["CC0-1.0"]),
            ("GPL v3", None, &[]),
            ("GPLv3", None, &[]),
            ("LGPL, v2.1", None, &[]),
            ("EPL 2.0", Some("EPL-2.0"), &[]),
            ("Eclipse Public License 2.0", None, &[]),
            ("Eclipse Public License, Version 2.0", None, &[]),
            ("BSD, 3-Clause", Some("BSD-3-Clause"), &[]),
            ("Apache,2.0", Some("Apache-2.0"), &[]),
            ("", None, &[]),
            ("x", None, &[]),
            ("Artistic License 2.0", Some("Artistic-2.0"), &[]),
            ("OFL 1.1", Some("OFL-1.1"), &[]),
            ("Boost Software License 1.0", None, &[]),
            ("Zlib License", Some("Zlib"), &["Zlib"]),
            ("WTFPL", None, &["WTFPL"]),
            ("Public Domain", None, &[]),
            ("MIT OR Apache-2.0", None, &["Apache-2.0", "MIT"]),
            ("(MIT AND BSD-2-Clause)", None, &["BSD-2-Clause", "MIT"]),
            ("MIT with exception", None, &["MIT"]),
            ("License :: OSI Approved :: MIT License", None, &["MIT"]),
            ("ß License 2.0", None, &[]),
            ("Apache\t2.0", Some("Apache-2.0"), &[]),
            ("Apache\n2.0", Some("Apache-2.0"), &[]),
        ];
        for (statement, corrected, resolved) in golden {
            assert_eq!(
                correct_license_statement(statement).as_deref(),
                *corrected,
                "correction of {statement:?}"
            );
            assert_eq!(
                resolve_license_expression(statement),
                resolved
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect::<BTreeSet<_>>(),
                "resolution of {statement:?}"
            );
        }
    }

    #[test]
    fn canonical_name_collapses_runs_of_separators_like_pep_503() {
        assert_eq!(canonical_name("Zope.Interface"), "zope-interface");
        assert_eq!(canonical_name("a__b"), "a-b");
        assert_eq!(canonical_name("A.B_c--d"), "a-b-c-d");
        assert_eq!(canonical_name("  Foo_-.Bar "), "foo-bar");
        assert_eq!(canonical_name("plain"), "plain");
    }
}
