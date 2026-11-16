//! Load a [`Policy`] from a project's config, and edit it in place.
//!
//! A project opts in with a `[tool.trustedlicenses]` table in `pyproject.toml`, or a
//! standalone `trustedlicenses.toml` beside it with the same keys at the root; the
//! standalone file wins when both exist. `allowed-categories` is required and has no
//! default, so a project states its policy rather than inheriting an assumption.
//!
//! The project's own `[project.license]` (PEP 639) is read from `pyproject.toml` whatever
//! the policy source, solely to feed the informational compatibility notes.

use crate::detection::{canonical_name, known_categories, resolve_license_expression};
use crate::policy::Policy;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, Value};

pub const CONFIG_SECTION: [&str; 2] = ["tool", "trustedlicenses"];
pub const STANDALONE_FILENAME: &str = "trustedlicenses.toml";
pub const DOCS_URL: &str = "https://trustedlicenses.readthedocs.io/en/latest/usage/";

/// A config file misconfigures `trustedlicenses`.
///
/// `NoPolicyConfigured` is distinct from `Invalid`: an unconfigured project has not
/// opted in, whereas a broken one tried and failed, so only the former may fall back to
/// the setup wizard or a report-only mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    NoPolicyConfigured(String),
    Invalid(String),
}

impl ConfigError {
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::NoPolicyConfigured(message) | Self::Invalid(message) => message,
        }
    }

    #[must_use]
    pub fn is_no_policy_configured(&self) -> bool {
        matches!(self, Self::NoPolicyConfigured(_))
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ConfigError {}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}

fn standalone_path(pyproject: &Path) -> PathBuf {
    pyproject
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(STANDALONE_FILENAME)
}

/// The file that holds (or would hold) the policy: the sibling `trustedlicenses.toml` if
/// it exists, else `pyproject` itself. Reads neither.
#[must_use]
pub fn policy_source(pyproject: &Path) -> PathBuf {
    let standalone = standalone_path(pyproject);
    if standalone.is_file() {
        standalone
    } else {
        pyproject.to_path_buf()
    }
}

/// 1-based `(line, column)` of a byte offset, for error text.
fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..offset.min(text.len())];
    let line = before.matches('\n').count() + 1;
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |tail| tail.chars().count())
        + 1;
    (line, column)
}

fn read_toml(path: &Path) -> Result<toml::Table, ConfigError> {
    let text = fs::read_to_string(path)
        .map_err(|error| invalid(format!("cannot read {}: {error}", path.display())))?;
    text.parse::<toml::Table>().map_err(|error| {
        let location = error.span().map_or_else(String::new, |span| {
            let (line, column) = line_col(&text, span.start);
            format!(" (at line {line}, column {column})")
        });
        invalid(format!(
            "{} is not valid TOML: {}{location}",
            path.display(),
            error.message()
        ))
    })
}

/// Resolve the project's own declared license to SPDX ids: the PEP 639 string form, the
/// legacy `{ text = ... }` table form, and `License ::` classifiers. Empty when nothing
/// resolves, which includes `{ file = ... }`, deliberately not parsed further.
fn project_license_keys(document: &toml::Table) -> BTreeSet<String> {
    let Some(project) = document.get("project").and_then(toml::Value::as_table) else {
        return BTreeSet::new();
    };
    let mut statements: Vec<String> = Vec::new();
    match project.get("license") {
        Some(toml::Value::String(text)) => statements.push(text.clone()),
        Some(toml::Value::Table(table)) => {
            if let Some(text) = table.get("text").and_then(toml::Value::as_str) {
                statements.push(text.to_owned());
            }
        }
        _ => {}
    }
    if let Some(classifiers) = project.get("classifiers").and_then(toml::Value::as_array) {
        statements.extend(
            classifiers
                .iter()
                .filter_map(toml::Value::as_str)
                .filter(|classifier| classifier.starts_with("License ::"))
                .map(str::to_owned),
        );
    }
    statements
        .iter()
        .flat_map(|statement| resolve_license_expression(statement))
        .collect()
}

fn verified_packages(
    section: &toml::Table,
    source: &Path,
) -> Result<HashMap<String, (String, String)>, ConfigError> {
    let source = source.display();
    let Some(raw) = section.get("verified-packages") else {
        return Ok(HashMap::new());
    };
    let Some(table) = raw.as_table() else {
        return Err(invalid(format!(
            "{source}: verified-packages must be a table of package name -> {{ statement, spdx-id }}."
        )));
    };
    let mut result = HashMap::new();
    for (name, entry) in table {
        let pair = entry.as_table().and_then(|entry| {
            Some((
                entry.get("statement")?.as_str()?.to_owned(),
                entry.get("spdx-id")?.as_str()?.to_owned(),
            ))
        });
        let Some(pair) = pair else {
            return Err(invalid(format!(
                "{source}: verified-packages.{name} needs both \"statement\" and \"spdx-id\"."
            )));
        };
        result.insert(canonical_name(name), pair);
    }
    Ok(result)
}

fn verified_statements(
    section: &toml::Table,
    source: &Path,
) -> Result<HashMap<String, String>, ConfigError> {
    let message = || {
        invalid(format!(
            "{}: verified-statements must be a table of statement text -> spdx id.",
            source.display()
        ))
    };
    let Some(raw) = section.get("verified-statements") else {
        return Ok(HashMap::new());
    };
    let table = raw.as_table().ok_or_else(message)?;
    table
        .iter()
        .map(|(statement, id)| {
            id.as_str()
                .map(|id| (statement.clone(), id.to_owned()))
                .ok_or_else(message)
        })
        .collect()
}

/// Python's `repr` of a string, which the error text uses: single quotes unless the text
/// itself contains one.
pub fn py_repr(text: &str) -> String {
    if text.contains('\'') && !text.contains('"') {
        format!("\"{text}\"")
    } else {
        format!("'{}'", text.replace('\'', "\\'"))
    }
}

fn display_value(value: &toml::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

/// Load a policy from a project's config.
///
/// # Errors
///
/// `NoPolicyConfigured` when neither config exists yet; `Invalid` when one exists but is
/// malformed, has no non-empty `allowed-categories`, or names an unknown category.
pub fn load_policy(pyproject: &Path) -> Result<Policy, ConfigError> {
    let standalone = standalone_path(pyproject);
    let source = policy_source(pyproject);

    let document = if pyproject.is_file() {
        read_toml(pyproject)?
    } else {
        toml::Table::new()
    };

    let (section, section_source): (toml::Table, PathBuf) = if source == standalone {
        (read_toml(&source)?, standalone)
    } else {
        let mut current = Some(&document);
        let mut found: Option<&toml::Table> = None;
        for key in CONFIG_SECTION {
            found = current
                .and_then(|table| table.get(key))
                .and_then(toml::Value::as_table);
            if found.is_none() {
                return Err(ConfigError::NoPolicyConfigured(format!(
                    "Neither {} nor a [tool.trustedlicenses] table in {} exists yet. \
                     Add one to enable enforcement, e.g.:\n\n  [tool.trustedlicenses]\n  \
                     allowed-categories = [\"Permissive\", \"Public Domain\", \"Copyleft Limited\"]\n\n\
                     See {DOCS_URL} for the full guide, or run `trustedlicenses` interactively to set \
                     this up with guided prompts.",
                    standalone.display(),
                    pyproject.display()
                )));
            }
            current = found;
        }
        (found.cloned().unwrap_or_default(), pyproject.to_path_buf())
    };

    let allowed: Vec<&toml::Value> = section
        .get("allowed-categories")
        .and_then(toml::Value::as_array)
        .map(|array| array.iter().collect())
        .unwrap_or_default();
    if allowed.is_empty() {
        return Err(invalid(format!(
            "{} needs a non-empty allowed-categories list, e.g.:\n\n  \
             allowed-categories = [\"Permissive\", \"Public Domain\", \"Copyleft Limited\"]\n\n\
             See {DOCS_URL} for the full category vocabulary.",
            section_source.display()
        )));
    }

    let known = known_categories();
    let mut unknown: Vec<String> = allowed
        .iter()
        .filter(|category| !category.as_str().is_some_and(|name| known.contains(name)))
        .map(|category| display_value(category))
        .collect();
    if !unknown.is_empty() {
        unknown.sort();
        let named = unknown
            .iter()
            .map(|name| py_repr(name))
            .collect::<Vec<_>>()
            .join(", ");
        let vocabulary = known
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(invalid(format!(
            "{}: unknown allowed-categories {named}. Known categories: {vocabulary}.\n\
             See {DOCS_URL} for the full category vocabulary.",
            section_source.display()
        )));
    }

    let ignored_packages = section
        .get("ignored-packages")
        .map(|raw| {
            raw.as_array()
                .map(|names| {
                    names
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(canonical_name)
                        .collect()
                })
                .ok_or_else(|| {
                    invalid(format!(
                        "{}: ignored-packages must be a list of package names.",
                        section_source.display()
                    ))
                })
        })
        .transpose()?
        .unwrap_or_default();

    Ok(Policy {
        accepted_licenses: accepted_licenses(&section, &section_source)?,
        allow_unlicensed: allow_unlicensed(&section, &section_source)?,
        allowed_categories: allowed
            .iter()
            .filter_map(|c| c.as_str())
            .map(str::to_owned)
            .collect(),
        ignored_packages,
        project_license_keys: project_license_keys(&document),
        trust_corrected_licenses: section
            .get("trust-corrected-licenses")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
        verified_packages: verified_packages(&section, &section_source)?,
        verified_statements: verified_statements(&section, &section_source)?,
    })
}

fn allow_unlicensed(section: &toml::Table, source: &Path) -> Result<bool, ConfigError> {
    match section.get("allow-unlicensed") {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or_else(|| {
            invalid(format!(
                "{}: allow-unlicensed must be true or false.",
                source.display()
            ))
        }),
    }
}

/// `accepted-licenses`: a table of package name -> list of SPDX ids accepted for that package.
fn accepted_licenses(
    section: &toml::Table,
    source: &Path,
) -> Result<std::collections::BTreeMap<String, BTreeSet<String>>, ConfigError> {
    let Some(raw) = section.get("accepted-licenses") else {
        return Ok(std::collections::BTreeMap::new());
    };
    let shape = || {
        invalid(format!(
            "{}: accepted-licenses must be a table of package name -> list of SPDX ids, e.g.\n\n  \
             [tool.trustedlicenses.accepted-licenses]\n  certifi = [\"MPL-2.0\"]",
            source.display()
        ))
    };
    let table = raw.as_table().ok_or_else(shape)?;
    let mut accepted = std::collections::BTreeMap::new();
    for (name, ids) in table {
        let ids: BTreeSet<String> = ids
            .as_array()
            .ok_or_else(shape)?
            .iter()
            .map(|id| id.as_str().map(str::to_owned).ok_or_else(shape))
            .collect::<Result<_, _>>()?;
        if ids.is_empty() {
            return Err(invalid(format!(
                "{}: accepted-licenses.{name} lists no licenses.",
                source.display()
            )));
        }
        accepted
            .entry(canonical_name(name))
            .or_insert_with(BTreeSet::new)
            .extend(ids);
    }
    Ok(accepted)
}

fn io_error(path: &Path, error: &std::io::Error) -> ConfigError {
    invalid(format!("cannot write {}: {error}", path.display()))
}

fn parse_document(path: &Path) -> Result<(DocumentMut, String), ConfigError> {
    let text = fs::read_to_string(path)
        .map_err(|error| invalid(format!("cannot read {}: {error}", path.display())))?;
    let document = text
        .parse::<DocumentMut>()
        .map_err(|error| invalid(format!("{} is not valid TOML: {error}", path.display())))?;
    Ok((document, text))
}

fn string_array(items: &[String]) -> Array {
    let mut array = Array::new();
    for item in items {
        array.push(item.as_str());
    }
    array
}

/// Write a policy to disk for the interactive setup wizard.
///
/// With `standalone`, writes a sibling `trustedlicenses.toml`; otherwise adds a
/// `[tool.trustedlicenses]` table to `pyproject`, leaving the rest of the file untouched.
///
/// # Errors
///
/// `Invalid` when editing a `pyproject` that does not exist, or on an I/O or parse failure.
pub fn write_policy(
    pyproject: &Path,
    allowed_categories: &[String],
    ignored_packages: &[String],
    standalone: bool,
) -> Result<PathBuf, ConfigError> {
    if standalone {
        let target = standalone_path(pyproject);
        let mut document = DocumentMut::new();
        document["allowed-categories"] = Item::Value(string_array(allowed_categories).into());
        if !ignored_packages.is_empty() {
            document["ignored-packages"] = Item::Value(string_array(ignored_packages).into());
        }
        fs::write(&target, document.to_string()).map_err(|error| io_error(&target, &error))?;
        return Ok(target);
    }

    if !pyproject.is_file() {
        return Err(invalid(format!(
            "{} doesn't exist -- can't add a [tool.trustedlicenses] table to a file that isn't there.",
            pyproject.display()
        )));
    }

    let (mut document, original) = parse_document(pyproject)?;
    let mut section = Table::new();
    section["allowed-categories"] = Item::Value(string_array(allowed_categories).into());
    if !ignored_packages.is_empty() {
        section["ignored-packages"] = Item::Value(string_array(ignored_packages).into());
    }
    // A blank line before the new header, matching how the rest of the file reads.
    let separator = if original.is_empty() || original.ends_with("\n\n") {
        ""
    } else if original.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    section.decor_mut().set_prefix(separator);

    let tool = document.entry("tool").or_insert_with(|| {
        let mut table = Table::new();
        table.set_implicit(true);
        Item::Table(table)
    });
    let Some(tool) = tool.as_table_like_mut() else {
        return Err(invalid(format!(
            "{}: `tool` must be a table.",
            pyproject.display()
        )));
    };
    tool.insert(CONFIG_SECTION[1], Item::Table(section));

    fs::write(pyproject, document.to_string()).map_err(|error| io_error(pyproject, &error))?;
    Ok(pyproject.to_path_buf())
}

fn policy_table<'a>(
    document: &'a mut DocumentMut,
    path: &Path,
) -> Result<&'a mut dyn TableLike, ConfigError> {
    if path
        .file_name()
        .is_some_and(|name| name == STANDALONE_FILENAME)
    {
        return Ok(document.as_table_mut());
    }
    let missing = || {
        invalid(format!(
            "{} has no [tool.trustedlicenses] table to extend.",
            path.display()
        ))
    };
    let tool = document
        .get_mut(CONFIG_SECTION[0])
        .and_then(Item::as_table_like_mut)
        .ok_or_else(missing)?;
    tool.get_mut(CONFIG_SECTION[1])
        .and_then(Item::as_table_like_mut)
        .ok_or_else(missing)
}

fn not_an_array(key: &str) -> ConfigError {
    invalid(format!("{key} must be an array"))
}

fn extend_unique(
    section: &mut dyn TableLike,
    key: &str,
    values: &[String],
) -> Result<(), ConfigError> {
    let Some(item) = section.get_mut(key) else {
        section.insert(key, Item::Value(string_array(values).into()));
        return Ok(());
    };
    let array = item.as_array_mut().ok_or_else(|| not_an_array(key))?;
    for value in values {
        if !array
            .iter()
            .any(|existing| existing.as_str() == Some(value))
        {
            array.push(value.as_str());
        }
    }
    Ok(())
}

fn is_blank(text: Option<&str>) -> bool {
    text.is_none_or(|text| text.trim().is_empty())
}

/// Rewrite an array one element per line with a trailing comma, attaching each reason as
/// a trailing comment on its element. Existing elements keep any comments they carry.
fn rewrite_multiline(array: &mut Array, new_entries: &[(String, Option<String>)]) {
    // A comment after the last element lives in the array's trailing text; once more
    // elements follow it, it has to move into the first new element's prefix.
    let carried = array
        .trailing()
        .as_str()
        .filter(|trailing| trailing.contains('#'))
        .map(str::to_owned);

    for value in array.iter_mut() {
        let decor = value.decor_mut();
        if is_blank(decor.prefix().and_then(|prefix| prefix.as_str())) {
            decor.set_prefix("\n    ");
        }
        if is_blank(decor.suffix().and_then(|suffix| suffix.as_str())) {
            decor.set_suffix("");
        }
    }

    let existing = array.len();
    let mut comments: Vec<Option<String>> = vec![None; existing];
    for (name, reason) in new_entries {
        array.push(name.as_str());
        comments.push(reason.clone());
    }

    let total = array.len();
    for (index, value) in array.iter_mut().enumerate().skip(existing) {
        let previous_comment = if index == existing {
            carried.clone()
        } else {
            comments[index - 1]
                .as_ref()
                .map(|reason| format!(" # {reason}\n"))
        };
        let prefix = match previous_comment {
            Some(comment) if comment.ends_with('\n') => format!("{comment}    "),
            Some(comment) => format!("{comment}\n    "),
            None => "\n    ".to_owned(),
        };
        let decor = value.decor_mut();
        decor.set_prefix(prefix);
        decor.set_suffix("");
    }
    let trailing = match comments.get(total.wrapping_sub(1)).and_then(Option::as_ref) {
        Some(reason) if total > existing => format!(" # {reason}\n"),
        _ => carried
            .filter(|_| total == existing)
            .unwrap_or_else(|| "\n".to_owned()),
    };
    array.set_trailing(trailing);
    array.set_trailing_comma(true);
}

fn extend_ignored_packages(
    section: &mut dyn TableLike,
    names: &[String],
    reasons: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    const KEY: &str = "ignored-packages";
    let current: BTreeSet<String> = match section.get(KEY) {
        Some(item) => item
            .as_array()
            .ok_or_else(|| not_an_array(KEY))?
            .iter()
            .filter_map(Value::as_str)
            .map(canonical_name)
            .collect(),
        None => BTreeSet::new(),
    };
    let new_names: Vec<&String> = names
        .iter()
        .filter(|name| !current.contains(&canonical_name(name)))
        .collect();
    if new_names.is_empty() {
        return Ok(());
    }
    if section.get(KEY).is_none() {
        section.insert(KEY, Item::Value(Array::new().into()));
    }
    let array = section
        .get_mut(KEY)
        .and_then(Item::as_array_mut)
        .ok_or_else(|| not_an_array(KEY))?;

    let wants_comment = new_names
        .iter()
        .any(|name| reasons.get(*name).is_some_and(|reason| !reason.is_empty()));
    if wants_comment {
        let entries: Vec<(String, Option<String>)> = new_names
            .iter()
            .map(|name| {
                (
                    (*name).clone(),
                    reasons
                        .get(*name)
                        .filter(|reason| !reason.is_empty())
                        .cloned(),
                )
            })
            .collect();
        rewrite_multiline(array, &entries);
    } else {
        // A plain push leaves an existing single-line array exactly as it was.
        for name in new_names {
            array.push(name.as_str());
        }
    }
    Ok(())
}

fn table_to_extend<'a>(
    section: &'a mut dyn TableLike,
    key: &str,
) -> Result<&'a mut dyn TableLike, ConfigError> {
    if section.get(key).is_none() {
        let mut table = Table::new();
        table.decor_mut().set_prefix("\n");
        section.insert(key, Item::Table(table));
    }
    section
        .get_mut(key)
        .and_then(Item::as_table_like_mut)
        .ok_or_else(|| invalid(format!("{key} must be a table")))
}

fn extend_verified_packages(
    section: &mut dyn TableLike,
    entries: &[(String, (String, String))],
) -> Result<(), ConfigError> {
    let table = table_to_extend(section, "verified-packages")?;
    for (name, (statement, spdx_id)) in entries {
        let mut entry = InlineTable::new();
        entry.insert("statement", statement.as_str().into());
        entry.insert("spdx-id", spdx_id.as_str().into());
        entry.fmt();
        entry.decor_mut().set_prefix(" ");
        table.insert(
            &canonical_name(name),
            Item::Value(Value::InlineTable(entry)),
        );
    }
    Ok(())
}

fn extend_verified_statements(
    section: &mut dyn TableLike,
    entries: &[(String, String)],
) -> Result<(), ConfigError> {
    let table = table_to_extend(section, "verified-statements")?;
    for (statement, spdx_id) in entries {
        table.insert(statement, Item::Value(spdx_id.as_str().into()));
    }
    Ok(())
}

/// Set a key's value, keeping the comment and spacing around the value it replaces.
fn set_value(section: &mut dyn TableLike, key: &str, mut value: Value) {
    if let Some(existing) = section.get(key).and_then(Item::as_value) {
        *value.decor_mut() = existing.decor().clone();
    }
    section.insert(key, Item::Value(value));
}

fn extend_accepted_licenses(
    section: &mut dyn TableLike,
    entries: &[(String, String)],
) -> Result<(), ConfigError> {
    let table = table_to_extend(section, "accepted-licenses")?;
    for (name, id) in entries {
        let key = canonical_name(name);
        if table.get(&key).is_none() {
            table.insert(&key, Item::Value(Array::new().into()));
        }
        let array = table
            .get_mut(&key)
            .and_then(Item::as_array_mut)
            .ok_or_else(|| not_an_array(&format!("accepted-licenses.{key}")))?;
        if !array
            .iter()
            .filter_map(Value::as_str)
            .any(|have| have == id)
        {
            array.push(id.as_str());
        }
    }
    Ok(())
}

/// Free-text correction trust decisions to write with [`add_to_policy`].
#[derive(Clone, Debug, Default)]
pub struct CorrectionTrust {
    /// When set, written to `trust-corrected-licenses`.
    pub enabled: Option<bool>,
    /// Canonical package name -> `(declared statement, corrected SPDX id)`. An entry for an
    /// already-pinned package replaces the old pin: re-verifying is how a pin is updated.
    pub verified_packages: Vec<(String, (String, String))>,
    pub verified_statements: Vec<(String, String)>,
}

/// Everything [`add_to_policy`] may add to an already-configured policy file.
#[derive(Clone, Debug, Default)]
pub struct PolicyAdditions {
    pub ignored_packages: Vec<String>,
    pub allowed_categories: Vec<String>,
    /// `(package, SPDX id)` pairs for `accepted-licenses`.
    pub accepted_licenses: Vec<(String, String)>,
    /// Sets `allow-unlicensed = true`.
    pub allow_unlicensed: bool,
    /// Package name -> one-line reason, recorded as a comment on its new entry.
    pub reasons: HashMap<String, String>,
    pub trust: Option<CorrectionTrust>,
}

/// Append to an already-configured policy file in place, keeping comments, other keys and
/// existing entries. Unlike [`write_policy`] this never rebuilds the table.
///
/// # Errors
///
/// `Invalid` when the file is unreadable, malformed, or has no policy table to extend.
pub fn add_to_policy(path: &Path, additions: &PolicyAdditions) -> Result<(), ConfigError> {
    let (mut document, _) = parse_document(path)?;
    {
        let section = policy_table(&mut document, path)?;
        if !additions.allowed_categories.is_empty() {
            extend_unique(section, "allowed-categories", &additions.allowed_categories)?;
        }
        if !additions.ignored_packages.is_empty() {
            extend_ignored_packages(section, &additions.ignored_packages, &additions.reasons)?;
        }
        if !additions.accepted_licenses.is_empty() {
            extend_accepted_licenses(section, &additions.accepted_licenses)?;
        }
        if additions.allow_unlicensed {
            set_value(section, "allow-unlicensed", true.into());
        }
        if let Some(trust) = &additions.trust {
            if let Some(enabled) = trust.enabled {
                set_value(section, "trust-corrected-licenses", enabled.into());
            }
            if !trust.verified_packages.is_empty() {
                extend_verified_packages(section, &trust.verified_packages)?;
            }
            if !trust.verified_statements.is_empty() {
                extend_verified_statements(section, &trust.verified_statements)?;
            }
        }
    }
    fs::write(path, document.to_string()).map_err(|error| io_error(path, &error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn pyproject(tmp: &TempDir, body: &str) -> PathBuf {
        let path = tmp.path().join("pyproject.toml");
        fs::write(&path, body).expect("write pyproject");
        path
    }

    fn standalone(tmp: &TempDir, body: &str) -> PathBuf {
        let path = tmp.path().join(STANDALONE_FILENAME);
        fs::write(&path, body).expect("write standalone");
        path
    }

    const PERMISSIVE: &str = "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n";

    fn load(body: &str) -> Result<Policy, ConfigError> {
        let tmp = tempdir().expect("tempdir");
        load_policy(&pyproject(&tmp, body))
    }

    fn load_err(body: &str) -> ConfigError {
        load(body).expect_err("expected an error")
    }

    fn text(path: &Path) -> String {
        fs::read_to_string(path).expect("read")
    }

    #[test]
    fn reads_a_valid_config() {
        let policy = load(
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\", \"Public Domain\"]\n\
             ignored-packages = [\"mypy-extensions\", \"Some_Package\"]\n",
        )
        .expect("load");
        assert_eq!(
            policy.allowed_categories,
            set(&["Permissive", "Public Domain"])
        );
        assert_eq!(
            policy.ignored_packages,
            set(&["mypy-extensions", "some-package"])
        );
    }

    #[test]
    fn ignored_packages_default_to_empty() {
        assert!(load(PERMISSIVE).expect("load").ignored_packages.is_empty());
    }

    #[test]
    fn a_missing_file_is_unconfigured_not_misconfigured() {
        let tmp = tempdir().expect("tempdir");
        let error = load_policy(&tmp.path().join("nope.toml")).expect_err("error");
        assert!(error.is_no_policy_configured());
        assert!(error.message().contains("[tool.trustedlicenses]"));
    }

    #[test]
    fn a_missing_table_is_unconfigured_not_broken() {
        let error = load_err("[tool.other]\nfoo = 1\n");
        assert!(error.is_no_policy_configured());
        assert!(error.message().contains("[tool.trustedlicenses]"));
    }

    #[test]
    fn missing_or_empty_allowed_categories_is_a_plain_config_error() {
        for body in [
            "[tool.trustedlicenses]\nignored-packages = [\"x\"]\n",
            "[tool.trustedlicenses]\nallowed-categories = []\n",
        ] {
            let error = load_err(body);
            assert!(!error.is_no_policy_configured(), "{body}");
            assert!(error.message().contains("allowed-categories"), "{body}");
        }
    }

    #[test]
    fn names_the_unknown_category_with_the_known_vocabulary() {
        let error = load_err(
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\", \"Permissiv\"]\n",
        );
        assert!(error
            .message()
            .contains("unknown allowed-categories 'Permissiv'"));
        assert!(error.message().contains("Copyleft Limited"));
        assert!(!error.message().contains("Unstated License"));
    }

    #[test]
    fn malformed_pyproject_is_a_config_error_naming_the_file() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"\n",
        );
        let error = load_policy(&path).expect_err("error");
        assert!(error.message().contains("not valid TOML"));
        assert!(error.message().contains(&path.display().to_string()));
        assert!(!error.is_no_policy_configured());
    }

    #[test]
    fn malformed_standalone_file_is_a_config_error_naming_that_file() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, "[project]\nname = 'x'\n");
        standalone(&tmp, "allowed-categories = [\n");
        let error = load_policy(&path).expect_err("error");
        assert!(error
            .message()
            .contains("trustedlicenses.toml is not valid TOML"));
    }

    #[test]
    fn resolves_project_license_from_pep_639_string() {
        let policy = load(
            "[project]\nname = \"consuming-project\"\nlicense = \"GPL-3.0-only\"\n\n\
             [tool.trustedlicenses]\nallowed-categories = [\"Copyleft\"]\n",
        )
        .expect("load");
        assert_eq!(policy.project_license_keys, set(&["GPL-3.0-only"]));
    }

    #[test]
    fn resolves_project_license_from_legacy_table_form() {
        let policy = load(
            "[project]\nname = \"c\"\nlicense = { text = \"MIT\" }\n\n\
             [tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n",
        )
        .expect("load");
        assert_eq!(policy.project_license_keys, set(&["MIT"]));
    }

    #[test]
    fn resolves_project_license_from_classifiers() {
        let policy = load(
            "[project]\nname = \"c\"\nclassifiers = [\"License :: OSI Approved :: MIT License\"]\n\n\
             [tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n",
        )
        .expect("load");
        assert_eq!(policy.project_license_keys, set(&["MIT"]));
    }

    #[test]
    fn project_license_keys_are_empty_without_a_project_table() {
        assert!(load(PERMISSIVE)
            .expect("load")
            .project_license_keys
            .is_empty());
    }

    #[test]
    fn project_license_keys_are_empty_for_the_file_form() {
        let policy = load(
            "[project]\nname = \"c\"\nlicense = { file = \"LICENSE\" }\n\n\
             [tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n",
        )
        .expect("load");
        assert!(policy.project_license_keys.is_empty());
    }

    #[test]
    fn correction_trust_fields_default_to_off_and_empty() {
        let policy = load(PERMISSIVE).expect("load");
        assert!(!policy.trust_corrected_licenses);
        assert!(policy.verified_packages.is_empty());
        assert!(policy.verified_statements.is_empty());
    }

    #[test]
    fn reads_trust_corrected_licenses() {
        let policy = load(&format!("{PERMISSIVE}trust-corrected-licenses = true\n")).expect("load");
        assert!(policy.trust_corrected_licenses);
    }

    #[test]
    fn reads_verified_packages_keyed_by_canonical_name() {
        let policy = load(&format!(
            "{PERMISSIVE}[tool.trustedlicenses.verified-packages]\n\
             CatBoost = {{ statement = \"Apache License, Version 2.0\", spdx-id = \"Apache-2.0\" }}\n"
        ))
        .expect("load");
        assert_eq!(
            policy.verified_packages,
            HashMap::from([(
                "catboost".to_owned(),
                (
                    "Apache License, Version 2.0".to_owned(),
                    "Apache-2.0".to_owned()
                )
            )])
        );
    }

    #[test]
    fn a_malformed_verified_package_entry_is_a_config_error() {
        let error = load_err(&format!(
            "{PERMISSIVE}[tool.trustedlicenses.verified-packages]\n\
             catboost = {{ statement = \"Apache License, Version 2.0\" }}\n"
        ));
        assert!(error.message().contains("verified-packages"));
    }

    #[test]
    fn reads_verified_statements() {
        let policy = load(&format!(
            "{PERMISSIVE}[tool.trustedlicenses.verified-statements]\n\
             \"Apache License, Version 2.0\" = \"Apache-2.0\"\n"
        ))
        .expect("load");
        assert_eq!(
            policy.verified_statements,
            HashMap::from([(
                "Apache License, Version 2.0".to_owned(),
                "Apache-2.0".to_owned()
            )])
        );
    }

    #[test]
    fn verified_tables_must_be_tables() {
        for key in ["verified-packages", "verified-statements"] {
            let error = load_err(&format!("{PERMISSIVE}{key} = [\"not-a-table\"]\n"));
            assert!(error.message().contains(key), "{key}");
        }
    }

    #[test]
    fn reads_a_standalone_file_without_the_tool_wrapper() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, "[project]\nname = 'x'\n");
        standalone(
            &tmp,
            "allowed-categories = [\"Permissive\"]\nignored-packages = [\"mypy-extensions\"]\n",
        );
        let policy = load_policy(&path).expect("load");
        assert_eq!(policy.allowed_categories, set(&["Permissive"]));
        assert_eq!(policy.ignored_packages, set(&["mypy-extensions"]));
    }

    #[test]
    fn the_standalone_file_wins_over_pyprojects_table() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[tool.trustedlicenses]\nallowed-categories = [\"Copyleft\"]\n",
        );
        standalone(&tmp, "allowed-categories = [\"Permissive\"]\n");
        assert_eq!(
            load_policy(&path).expect("load").allowed_categories,
            set(&["Permissive"])
        );
    }

    #[test]
    fn project_license_still_comes_from_pyproject_with_a_standalone_file() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, "[project]\nname = \"x\"\nlicense = \"MIT\"\n");
        standalone(&tmp, "allowed-categories = [\"Permissive\"]\n");
        assert_eq!(
            load_policy(&path).expect("load").project_license_keys,
            set(&["MIT"])
        );
    }

    #[test]
    fn a_broken_standalone_file_is_a_plain_config_error() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, "[project]\nname = 'x'\n");
        standalone(&tmp, "ignored-packages = []\n");
        let error = load_policy(&path).expect_err("error");
        assert!(error.message().contains("allowed-categories"));
        assert!(!error.is_no_policy_configured());
    }

    #[test]
    fn write_policy_adds_a_table_preserving_the_rest() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[project]\nname = \"x\"\n# a comment worth preserving\n\n[tool.other]\nfoo = 1\n",
        );
        let written = write_policy(
            &path,
            &strings(&["Permissive", "Public Domain"]),
            &strings(&["mypy-extensions"]),
            false,
        )
        .expect("write");
        assert_eq!(written, path);
        assert_eq!(
            text(&path),
            "[project]\nname = \"x\"\n# a comment worth preserving\n\n[tool.other]\nfoo = 1\n\n\
             [tool.trustedlicenses]\nallowed-categories = [\"Permissive\", \"Public Domain\"]\n\
             ignored-packages = [\"mypy-extensions\"]\n"
        );
        let policy = load_policy(&path).expect("load");
        assert_eq!(
            policy.allowed_categories,
            set(&["Permissive", "Public Domain"])
        );
        assert_eq!(policy.ignored_packages, set(&["mypy-extensions"]));
    }

    #[test]
    fn write_policy_omits_an_empty_ignored_packages() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, "[project]\nname = \"x\"\n");
        write_policy(&path, &strings(&["Permissive"]), &[], false).expect("write");
        assert!(!text(&path).contains("ignored-packages"));
    }

    #[test]
    fn write_policy_writes_a_standalone_file() {
        let tmp = tempdir().expect("tempdir");
        let path = tmp.path().join("pyproject.toml");
        let written =
            write_policy(&path, &strings(&["Permissive"]), &strings(&["a"]), true).expect("write");
        assert_eq!(written, tmp.path().join(STANDALONE_FILENAME));
        assert_eq!(
            text(&written),
            "allowed-categories = [\"Permissive\"]\nignored-packages = [\"a\"]\n"
        );
    }

    #[test]
    fn write_policy_refuses_to_edit_a_missing_pyproject() {
        let tmp = tempdir().expect("tempdir");
        let error = write_policy(
            &tmp.path().join("pyproject.toml"),
            &strings(&["Permissive"]),
            &[],
            false,
        )
        .expect_err("error");
        assert!(error.message().contains("doesn't exist"));
    }

    #[test]
    fn policy_source_is_pyproject_unless_a_standalone_file_exists() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, PERMISSIVE);
        assert_eq!(policy_source(&path), path);
        let alone = standalone(&tmp, "allowed-categories = [\"Permissive\"]\n");
        assert_eq!(policy_source(&path), alone);
    }

    fn additions() -> PolicyAdditions {
        PolicyAdditions::default()
    }

    const CATBOOST: &str = "Apache License, Version 2.0";

    #[test]
    fn add_to_policy_appends_to_a_pyproject_table_with_a_comment() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[project]\nname = \"x\"\n# keep me\n\n[tool.trustedlicenses]\n\
             allowed-categories = [\"Permissive\"]\nignored-packages = [\"mypy-extensions\"]\n",
        );
        add_to_policy(
            &path,
            &PolicyAdditions {
                ignored_packages: strings(&["catboost"]),
                allowed_categories: strings(&["Copyleft Limited"]),
                reasons: HashMap::from([(
                    "catboost".to_owned(),
                    "no license detected -- accepted 2026-09-15".to_owned(),
                )]),
                ..additions()
            },
        )
        .expect("add");
        let written = text(&path);
        assert!(written.contains("# keep me"));
        assert!(written.contains("no license detected -- accepted 2026-09-15"));
        let policy = load_policy(&path).expect("load");
        assert_eq!(
            policy.allowed_categories,
            set(&["Permissive", "Copyleft Limited"])
        );
        assert_eq!(
            policy.ignored_packages,
            set(&["mypy-extensions", "catboost"])
        );
    }

    #[test]
    fn add_to_policy_matches_tomlkits_multiline_layout() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n\
             ignored-packages = [\"mypy-extensions\"]\n",
        );
        add_to_policy(
            &path,
            &PolicyAdditions {
                ignored_packages: strings(&["catboost", "plain"]),
                allowed_categories: strings(&["Copyleft Limited"]),
                reasons: HashMap::from([(
                    "catboost".to_owned(),
                    "no license -- accepted".to_owned(),
                )]),
                ..additions()
            },
        )
        .expect("add");
        assert_eq!(
            text(&path),
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\", \"Copyleft Limited\"]\n\
             ignored-packages = [\n    \"mypy-extensions\",\n    \"catboost\", # no license -- accepted\n    \"plain\",\n]\n"
        );
    }

    #[test]
    fn add_to_policy_comments_every_entry_into_an_absent_array() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, PERMISSIVE);
        add_to_policy(
            &path,
            &PolicyAdditions {
                ignored_packages: strings(&["catboost", "plain"]),
                reasons: HashMap::from([
                    ("catboost".to_owned(), "why".to_owned()),
                    ("plain".to_owned(), "also".to_owned()),
                ]),
                ..additions()
            },
        )
        .expect("add");
        assert_eq!(
            text(&path),
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n\
             ignored-packages = [\n    \"catboost\", # why\n    \"plain\", # also\n]\n"
        );
    }

    #[test]
    fn add_to_policy_appends_to_a_standalone_file() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, "[project]\nname = \"x\"\n");
        let alone = standalone(&tmp, "allowed-categories = [\"Permissive\"]\n");
        add_to_policy(
            &alone,
            &PolicyAdditions {
                ignored_packages: strings(&["ds-mlops-components"]),
                ..additions()
            },
        )
        .expect("add");
        assert_eq!(
            load_policy(&path).expect("load").ignored_packages,
            set(&["ds-mlops-components"])
        );
    }

    #[test]
    fn add_to_policy_keeps_a_single_line_array_without_a_reason() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\nignored-packages = [\"a\", \"b\"]\n",
        );
        add_to_policy(
            &path,
            &PolicyAdditions {
                ignored_packages: strings(&["c"]),
                ..additions()
            },
        )
        .expect("add");
        assert!(text(&path).contains("ignored-packages = [\"a\", \"b\", \"c\"]"));
        assert_eq!(
            load_policy(&path).expect("load").ignored_packages,
            set(&["a", "b", "c"])
        );
    }

    #[test]
    fn add_to_policy_does_not_duplicate_an_ignored_package() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\nignored-packages = [\"Some_Package\"]\n",
        );
        add_to_policy(
            &path,
            &PolicyAdditions {
                ignored_packages: strings(&["some-package"]),
                ..additions()
            },
        )
        .expect("add");
        let written = text(&path);
        assert_eq!(
            written.matches("some-package").count() + written.matches("Some_Package").count(),
            1
        );
        assert_eq!(
            load_policy(&path).expect("load").ignored_packages,
            set(&["some-package"])
        );
    }

    #[test]
    fn add_to_policy_does_not_duplicate_an_allowed_category() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, PERMISSIVE);
        add_to_policy(
            &path,
            &PolicyAdditions {
                allowed_categories: strings(&["Permissive"]),
                ..additions()
            },
        )
        .expect("add");
        assert_eq!(text(&path).matches("Permissive").count(), 1);
    }

    fn with_trust(trust: CorrectionTrust) -> PolicyAdditions {
        PolicyAdditions {
            trust: Some(trust),
            ..additions()
        }
    }

    #[test]
    fn add_to_policy_sets_trust_corrected_licenses() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, PERMISSIVE);
        add_to_policy(
            &path,
            &with_trust(CorrectionTrust {
                enabled: Some(true),
                ..CorrectionTrust::default()
            }),
        )
        .expect("add");
        assert!(load_policy(&path).expect("load").trust_corrected_licenses);
    }

    #[test]
    fn add_to_policy_writes_pins_that_round_trip() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, PERMISSIVE);
        add_to_policy(
            &path,
            &with_trust(CorrectionTrust {
                verified_packages: vec![(
                    "catboost".to_owned(),
                    (CATBOOST.to_owned(), "Apache-2.0".to_owned()),
                )],
                verified_statements: vec![(CATBOOST.to_owned(), "Apache-2.0".to_owned())],
                ..CorrectionTrust::default()
            }),
        )
        .expect("add");
        let policy = load_policy(&path).expect("load");
        assert_eq!(
            policy.verified_packages.get("catboost"),
            Some(&(CATBOOST.to_owned(), "Apache-2.0".to_owned()))
        );
        assert_eq!(
            policy.verified_statements.get(CATBOOST).map(String::as_str),
            Some("Apache-2.0")
        );
    }

    #[test]
    fn add_to_policy_writes_the_trust_tables_after_the_policy_keys() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\nignored-packages = [\"a\", \"b\"]\n",
        );
        add_to_policy(
            &path,
            &PolicyAdditions {
                ignored_packages: strings(&["c"]),
                trust: Some(CorrectionTrust {
                    enabled: Some(true),
                    verified_packages: vec![(
                        "CatBoost".to_owned(),
                        (CATBOOST.to_owned(), "Apache-2.0".to_owned()),
                    )],
                    verified_statements: vec![(CATBOOST.to_owned(), "Apache-2.0".to_owned())],
                }),
                ..additions()
            },
        )
        .expect("add");
        assert_eq!(
            text(&path),
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n\
             ignored-packages = [\"a\", \"b\", \"c\"]\ntrust-corrected-licenses = true\n\n\
             [tool.trustedlicenses.verified-packages]\n\
             catboost = { statement = \"Apache License, Version 2.0\", spdx-id = \"Apache-2.0\" }\n\n\
             [tool.trustedlicenses.verified-statements]\n\"Apache License, Version 2.0\" = \"Apache-2.0\"\n"
        );
    }

    #[test]
    fn re_verifying_a_package_replaces_its_old_pin() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            &format!(
                "{PERMISSIVE}[tool.trustedlicenses.verified-packages]\n\
                 catboost = {{ statement = \"Old Text\", spdx-id = \"MIT\" }}\n"
            ),
        );
        add_to_policy(
            &path,
            &with_trust(CorrectionTrust {
                verified_packages: vec![(
                    "catboost".to_owned(),
                    (CATBOOST.to_owned(), "Apache-2.0".to_owned()),
                )],
                ..CorrectionTrust::default()
            }),
        )
        .expect("add");
        assert_eq!(
            load_policy(&path)
                .expect("load")
                .verified_packages
                .get("catboost"),
            Some(&(CATBOOST.to_owned(), "Apache-2.0".to_owned()))
        );
    }

    #[test]
    fn a_second_statement_pin_extends_the_existing_table() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            &format!("{PERMISSIVE}[tool.trustedlicenses.verified-statements]\n\"MIT License\" = \"MIT\"\n"),
        );
        add_to_policy(
            &path,
            &with_trust(CorrectionTrust {
                verified_statements: vec![(CATBOOST.to_owned(), "Apache-2.0".to_owned())],
                ..CorrectionTrust::default()
            }),
        )
        .expect("add");
        assert_eq!(
            load_policy(&path).expect("load").verified_statements,
            HashMap::from([
                ("MIT License".to_owned(), "MIT".to_owned()),
                (CATBOOST.to_owned(), "Apache-2.0".to_owned()),
            ])
        );
    }

    #[test]
    fn a_mixed_batch_only_comments_entries_with_a_reason() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, PERMISSIVE);
        add_to_policy(
            &path,
            &PolicyAdditions {
                ignored_packages: strings(&["catboost", "no-reason-pkg"]),
                reasons: HashMap::from([("catboost".to_owned(), "accepted".to_owned())]),
                ..additions()
            },
        )
        .expect("add");
        assert_eq!(
            text(&path),
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n\
             ignored-packages = [\n    \"catboost\", # accepted\n    \"no-reason-pkg\",\n]\n"
        );
    }

    #[test]
    fn without_trust_none_of_the_correction_keys_appear() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, PERMISSIVE);
        add_to_policy(
            &path,
            &PolicyAdditions {
                ignored_packages: strings(&["somepkg"]),
                ..additions()
            },
        )
        .expect("add");
        let written = text(&path);
        for key in [
            "trust-corrected-licenses",
            "verified-packages",
            "verified-statements",
        ] {
            assert!(!written.contains(key), "{key}");
        }
    }

    #[test]
    fn add_to_policy_without_a_policy_table_is_an_error() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(&tmp, "[project]\nname = \"x\"\n");
        let error = add_to_policy(&path, &additions()).expect_err("error");
        assert!(error.message().contains("no [tool.trustedlicenses] table"));
    }

    /// Expected messages generated from the Python implementation, with `<DIR>` standing
    /// for the project directory.
    #[test]
    fn error_messages_match_the_python_implementation() {
        let golden: &[(&str, &str)] = &[
            ("[tool.other]\nfoo = 1\n", "Neither <DIR>/trustedlicenses.toml nor a [tool.trustedlicenses] table in <DIR>/pyproject.toml exists yet. Add one to enable enforcement, e.g.:\n\n  [tool.trustedlicenses]\n  allowed-categories = [\"Permissive\", \"Public Domain\", \"Copyleft Limited\"]\n\nSee https://trustedlicenses.readthedocs.io/en/latest/usage/ for the full guide, or run `trustedlicenses` interactively to set this up with guided prompts."),
            ("[tool.trustedlicenses]\nignored-packages = []\n", "<DIR>/pyproject.toml needs a non-empty allowed-categories list, e.g.:\n\n  allowed-categories = [\"Permissive\", \"Public Domain\", \"Copyleft Limited\"]\n\nSee https://trustedlicenses.readthedocs.io/en/latest/usage/ for the full category vocabulary."),
            ("[tool.trustedlicenses]\nallowed-categories = [\"Permissiv\", \"Another\", \"it's\"]\n", "<DIR>/pyproject.toml: unknown allowed-categories 'Another', 'Permissiv', \"it's\". Known categories: CLA, Commercial, Copyleft, Copyleft Limited, Free Restricted, Patent License, Permissive, Proprietary Free, Public Domain, Source-available.\nSee https://trustedlicenses.readthedocs.io/en/latest/usage/ for the full category vocabulary."),
            ("[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\n[tool.trustedlicenses.verified-packages]\ncatboost = {statement = \"x\"}\n", "<DIR>/pyproject.toml: verified-packages.catboost needs both \"statement\" and \"spdx-id\"."),
            ("[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\nverified-packages = [\"x\"]\n", "<DIR>/pyproject.toml: verified-packages must be a table of package name -> { statement, spdx-id }."),
            ("[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\nverified-statements = [\"x\"]\n", "<DIR>/pyproject.toml: verified-statements must be a table of statement text -> spdx id."),
        ];
        for (body, expected) in golden {
            let tmp = tempdir().expect("tempdir");
            let path = pyproject(&tmp, body);
            let error = load_policy(&path).expect_err("error");
            let dir = format!("{}/", tmp.path().display());
            assert_eq!(
                error.message().replace(&dir, "<DIR>/"),
                *expected,
                "for {body:?}"
            );
        }
    }

    #[test]
    fn accepted_licenses_and_allow_unlicensed_are_read() {
        let policy = load(&format!(
            "{PERMISSIVE}allow-unlicensed = true\n\n\
             [tool.trustedlicenses.accepted-licenses]\nCertifi = [\"MPL-2.0\"]\n\
             some_pkg = [\"LGPL-3.0-only\", \"MPL-2.0\"]\n"
        ))
        .expect("load");
        assert!(policy.allow_unlicensed);
        assert_eq!(policy.accepted_licenses["certifi"], set(&["MPL-2.0"]));
        assert_eq!(
            policy.accepted_licenses["some-pkg"],
            set(&["LGPL-3.0-only", "MPL-2.0"])
        );
    }

    #[test]
    fn both_default_to_nothing_accepted() {
        let policy = load(PERMISSIVE).expect("load");
        assert!(!policy.allow_unlicensed && policy.accepted_licenses.is_empty());
    }

    #[test]
    fn malformed_accepted_licenses_and_allow_unlicensed_are_plain_errors() {
        for (body, needle) in [
            (
                "allow-unlicensed = \"yes\"\n",
                "allow-unlicensed must be true or false",
            ),
            (
                "accepted-licenses = [\"certifi\"]\n",
                "accepted-licenses must be a table",
            ),
            (
                "[tool.trustedlicenses.accepted-licenses]\ncertifi = \"MPL-2.0\"\n",
                "accepted-licenses must be a table",
            ),
            (
                "[tool.trustedlicenses.accepted-licenses]\ncertifi = [1]\n",
                "accepted-licenses must be a table",
            ),
            (
                "[tool.trustedlicenses.accepted-licenses]\ncertifi = []\n",
                "accepted-licenses.certifi lists no licenses",
            ),
        ] {
            let text = if body.starts_with('[') {
                format!("{PERMISSIVE}\n{body}")
            } else {
                format!("{PERMISSIVE}{body}")
            };
            let error = load_err(&text);
            assert!(
                error.message().contains(needle),
                "{body}: {}",
                error.message()
            );
        }
    }

    #[test]
    fn add_to_policy_records_an_accepted_license_keeping_comments_and_merging() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[tool.trustedlicenses]\n# reviewed by legal\nallowed-categories = [\"Permissive\"]\n\n\
             [tool.trustedlicenses.accepted-licenses]\ncertifi = [\"MPL-2.0\"]\n",
        );
        add_to_policy(
            &path,
            &PolicyAdditions {
                accepted_licenses: vec![
                    ("certifi".to_owned(), "MPL-2.0".to_owned()),
                    ("Certifi".to_owned(), "GPL-2.0-only".to_owned()),
                    ("other_pkg".to_owned(), "LGPL-3.0-only".to_owned()),
                ],
                allow_unlicensed: true,
                ..additions()
            },
        )
        .expect("write");
        let written = text(&path);
        assert!(written.contains("# reviewed by legal"), "{written}");
        let policy = load_policy(&path).expect("load");
        assert!(policy.allow_unlicensed);
        assert_eq!(
            policy.accepted_licenses["certifi"],
            set(&["MPL-2.0", "GPL-2.0-only"])
        );
        assert_eq!(
            policy.accepted_licenses["other-pkg"],
            set(&["LGPL-3.0-only"])
        );
    }

    #[test]
    fn add_to_policy_accepts_a_license_in_a_standalone_file() {
        let tmp = tempdir().expect("tempdir");
        let path = standalone(&tmp, "allowed-categories = [\"Permissive\"]\n");
        add_to_policy(
            &path,
            &PolicyAdditions {
                accepted_licenses: vec![("certifi".to_owned(), "MPL-2.0".to_owned())],
                ..additions()
            },
        )
        .expect("write");
        assert_eq!(
            text(&path),
            "allowed-categories = [\"Permissive\"]\n\n[accepted-licenses]\ncertifi = [\"MPL-2.0\"]\n"
        );
    }

    #[test]
    fn replacing_a_value_keeps_its_trailing_comment() {
        let tmp = tempdir().expect("tempdir");
        let path = pyproject(
            &tmp,
            "[tool.trustedlicenses]\nallowed-categories = [\"Permissive\"]\nallow-unlicensed = false # review in Q3\n",
        );
        add_to_policy(
            &path,
            &PolicyAdditions {
                allow_unlicensed: true,
                ..additions()
            },
        )
        .expect("write");
        let written = text(&path);
        assert!(
            written.contains("allow-unlicensed = true # review in Q3"),
            "{written}"
        );
    }
}
