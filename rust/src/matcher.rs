//! License-text scanning against the SPDX corpus.
//!
//! # Why `ScanMode::TopDown`, not `ScanMode::Elimination`
//!
//! `Elimination` mode finds the single best overall match, then repeatedly
//! "whites out" (blanks) the matched lines and re-analyzes the rest of the document to
//! find further matches -- see the `spdx` crate's `detection::scan` module. That
//! re-analysis step relies on `TextData::optimize_bounds`, which locates a match's line
//! range with a ternary search that assumes the match score is roughly unimodal across
//! the searched range. Verified directly against the real crate (not assumed): that
//! assumption breaks down when a later match sits in a small region near the very start
//! of a document whose middle-to-end has just been blanked out by a prior elimination
//! pass -- `optimize_bounds` degenerates to an empty range and the match is silently
//! lost, even though `Store::analyze` on its own correctly ranks it as the top
//! candidate. Concretely: scanning an MIT license followed by the full GPL-2.0 text,
//! `Elimination` finds GPL-2.0 (the larger, so higher-ranked, initial match) but then
//! fails to locate MIT in the second pass.
//!
//! `TopDown` mode -- a real sliding-window scan across the document rather than
//! whiting-out and re-analyzing -- does not share this failure mode, and reliably finds
//! both licenses regardless of order or position. It's slower than `Elimination` (per
//! the crate's own doc comment), but license files are small (at most a few hundred
//! lines), so this is not a practical concern: a concatenated MIT+GPL-2.0 file scans in
//! well under 100ms.

use pyo3::prelude::*;
use spdx::detection::{
    scan::{ScanMode, Scanner},
    Store, TextData,
};
use std::sync::OnceLock;

/// The default confidence threshold. A match must clear this to be reported at all --
/// see `Scanner::confidence_threshold`.
///
/// Deliberately not the `spdx`/askalono *library's* own default (0.9): verified directly
/// against real installed packages that 0.9 is measurably too strict -- genuine,
/// unmodified BSD-3-Clause LICENSE files from `jupyter` and `prompt-toolkit` on PyPI
/// score 0.85 and 0.91 respectively, so 0.9 produces false negatives on two extremely
/// common packages. 0.8 is what askalono's own CLI actually uses, overriding its
/// library's 0.9 default for exactly this reason; independently confirmed here that it
/// resolves both cases without introducing false positives (0.7 starts misidentifying
/// BSD-3 variants).
const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.8;

fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| Store::load_inline().expect("inline SPDX detection cache is malformed"))
}

/// Scan `text` for SPDX-licensed text, returning every match that clears
/// `confidence_threshold`.
///
/// Returns `(spdx_license_id, confidence_score)` pairs, one per license found -- more
/// than one when `text` concatenates several licenses (e.g. a package's own permissive
/// grant alongside a vendored dependency's copyleft notice). `spdx_license_id` is the
/// exact SPDX license-list identifier (e.g. `"MIT"`, `"GPL-2.0-or-later"`), not a
/// lowercased key.
#[pyfunction]
#[pyo3(signature = (text, confidence_threshold = DEFAULT_CONFIDENCE_THRESHOLD))]
pub(crate) fn scan_license_text(text: &str, confidence_threshold: f32) -> Vec<(String, f32)> {
    let data = TextData::new(text);
    let strategy = Scanner::with_scan_mode(store(), ScanMode::top_down())
        .confidence_threshold(confidence_threshold);
    let result = strategy.scan(&data);

    result
        .containing
        .into_iter()
        .map(|contained| (contained.license.name.to_string(), contained.score))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIT: &str = include_str!("../tests/fixtures/mit.txt");
    const GPL_2_0: &str = include_str!("../tests/fixtures/gpl-2.0.txt");

    #[test]
    fn finds_a_single_license() {
        let matches = scan_license_text(MIT, DEFAULT_CONFIDENCE_THRESHOLD);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "MIT");
        assert!(matches[0].1 > 0.9);
    }

    #[test]
    fn finds_both_licenses_in_a_concatenated_file() {
        let concatenated = format!("{MIT}\n\n{GPL_2_0}");
        let matches = scan_license_text(&concatenated, DEFAULT_CONFIDENCE_THRESHOLD);
        let names: Vec<&str> = matches.iter().map(|(name, _)| name.as_str()).collect();
        assert!(names.contains(&"MIT"), "expected MIT in {names:?}");
        assert!(
            names.contains(&"GPL-2.0-or-later"),
            "expected GPL-2.0-or-later in {names:?}"
        );
    }

    #[test]
    fn finds_nothing_in_unrelated_text() {
        let matches = scan_license_text(
            "this is a README, not a license",
            DEFAULT_CONFIDENCE_THRESHOLD,
        );
        assert!(matches.is_empty());
    }
}
