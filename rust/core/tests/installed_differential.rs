//! Compare this crate's view of an installed environment with `importlib.metadata`'s.
//!
//! Needs the project's `.venv`; skipped (with a note) when it is not there.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use trustedlicenses_core::sources::installed::{
    installed_distributions, query_sys_path, venv_search_paths,
};

const DUMP: &str = r#"
import json, sys
from importlib.metadata import distributions
rows = []
for d in distributions():
    m = d.metadata
    rows.append({
        "name": m["Name"] or "",
        "version": d.version or "",
        "license_expression": m.get_all("License-Expression") or [],
        "license": m.get_all("License") or [],
        "classifiers": [c for c in (m.get_all("Classifier") or []) if c.startswith("License ::")],
    })
print(json.dumps(rows))
"#;

type Row = (Vec<String>, Vec<String>, Vec<String>, String);

fn venv() -> Option<PathBuf> {
    let venv = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.venv");
    venv.join("bin/python").exists().then_some(venv)
}

fn python_rows(python: &Path) -> BTreeMap<(String, String), Vec<Row>> {
    let output = Command::new(python)
        .args(["-c", DUMP])
        .current_dir(std::env::temp_dir())
        .output()
        .expect("run python");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).expect("json");
    let strings = |row: &serde_json::Value, key: &str| -> Vec<String> {
        row[key]
            .as_array()
            .expect("array")
            .iter()
            .map(|v| v.as_str().expect("str").to_owned())
            .collect()
    };
    let mut by_key: BTreeMap<(String, String), Vec<Row>> = BTreeMap::new();
    for row in &rows {
        by_key
            .entry((
                row["name"].as_str().expect("name").to_owned(),
                row["version"].as_str().expect("version").to_owned(),
            ))
            .or_default()
            .push((
                strings(row, "license_expression"),
                strings(row, "license"),
                strings(row, "classifiers"),
                String::new(),
            ));
    }
    by_key
}

fn rust_rows(paths: &[PathBuf]) -> BTreeMap<(String, String), Vec<Row>> {
    let mut by_key: BTreeMap<(String, String), Vec<Row>> = BTreeMap::new();
    for dist in installed_distributions(paths) {
        let collect = |field: &str| {
            dist.metadata
                .get_all(field)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        let classifiers = collect("Classifier")
            .into_iter()
            .filter(|c| c.starts_with("License ::"))
            .collect();
        by_key
            .entry((
                dist.metadata.get("Name").unwrap_or("").to_owned(),
                dist.version.clone(),
            ))
            .or_default()
            .push((
                collect("License-Expression"),
                collect("License"),
                classifiers,
                String::new(),
            ));
    }
    by_key
}

#[test]
fn metadata_matches_importlib_for_every_installed_distribution() {
    let Some(venv) = venv() else {
        eprintln!("skipped: no .venv");
        return;
    };
    let python = venv.join("bin/python");
    let expected = python_rows(&python);
    assert!(
        expected.len() >= 10,
        "suspiciously few distributions: {}",
        expected.len()
    );

    for (label, paths) in [
        (
            "queried sys.path",
            query_sys_path(&python).expect("sys.path"),
        ),
        ("scanned venv", venv_search_paths(&venv)),
    ] {
        let mut actual = rust_rows(&paths);
        let mut expected = expected.clone();
        for rows in actual.values_mut().chain(expected.values_mut()) {
            rows.sort();
        }
        let missing: Vec<_> = expected
            .keys()
            .filter(|k| !actual.contains_key(*k))
            .collect();
        let extra: Vec<_> = actual
            .keys()
            .filter(|k| !expected.contains_key(*k))
            .collect();
        assert!(missing.is_empty(), "{label}: missing {missing:?}");
        assert!(extra.is_empty(), "{label}: extra {extra:?}");
        for (key, rows) in &expected {
            assert_eq!(&actual[key], rows, "{label}: metadata differs for {key:?}");
        }
    }
}
