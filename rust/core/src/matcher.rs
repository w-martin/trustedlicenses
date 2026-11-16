//! License-text scanning against the SPDX corpus.
//!
//! `ScanMode::TopDown`, not `Elimination`: `Elimination` blanks each matched region and
//! re-analyses the rest, and its `optimize_bounds` ternary search assumes a roughly
//! unimodal score. Verified against the real crate, that breaks when a later match sits
//! near the start of a document whose middle-to-end was just blanked: scanning MIT
//! followed by the full GPL-2.0 text finds GPL-2.0 and then loses MIT. `TopDown` is a
//! real sliding-window scan and finds both regardless of order. It is slower, but
//! license files are small.
//!
//! # Cost, and what was tried
//!
//! `TopDown` scores windows of lines against the whole store (about 15 ms per window), one file at
//! a time and sequentially: linear in the file for a license that starts at line 0, quadratic when
//! it starts late. Measured on 436 real packages:
//!
//! - **Identical texts are common** (Apache-2.0 alone appears 9 times), and were 26% of the scan
//!   time. [`prescan`] scans each distinct text once: 61% of the CPU work, with the same results.
//! - **Scoring a row of windows in parallel** gave identical results (checked over 463 real license
//!   files) and sped up a few huge files, but used 1.5-2x the CPU on a normal run because the
//!   extra threads spin and over-compute, and it meant keeping a copy of the library's algorithm.
//!   Dropped.

use rayon::prelude::*;
use spdx::detection::{
    scan::{ScanMode, Scanner},
    LicenseType, Store, TextData,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Not the `spdx` library's own default (0.9): genuine, unmodified BSD-3-Clause files from
/// `jupyter` and `prompt-toolkit` score 0.85 and 0.91, so 0.9 gives false negatives on two
/// very common packages. 0.8 is what askalono's CLI uses; 0.7 starts misidentifying BSD-3
/// variants.
pub const DEFAULT_CONFIDENCE_THRESHOLD: f32 = 0.8;

const LGPL_3_0_IDS: [&str; 2] = ["LGPL-3.0-only", "LGPL-3.0-or-later"];

/// The FSF's short-form LGPL-3.0 (gnu.org/licenses/lgpl-3.0.txt), which references GPLv3 by
/// pointer. SPDX's corpus only ships the long form, so the short form most LGPLv3 packages
/// bundle would otherwise score ~0.
pub(crate) const LGPL_3_0_SHORT_FORM: &str =
    include_str!("../../tests/fixtures/lgpl-3.0-short-form.txt");

fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| {
        let mut store = Store::load_inline().expect("inline SPDX detection cache is malformed");
        register_lgpl_3_0_short_form(&mut store);
        store
    })
}

/// Attach the short form under whichever LGPL-3.0 id the opaque corpus actually uses.
///
/// `debug_assert!`, not `assert!`: a panic inside the `OnceLock` initialiser aborts the
/// whole process under `panic = "abort"`, which is worse than silently losing one optional
/// template. `cargo test` still catches a regression.
fn register_lgpl_3_0_short_form(store: &mut Store) {
    let data = TextData::new(LGPL_3_0_SHORT_FORM);
    let registered = LGPL_3_0_IDS
        .iter()
        .filter(|id| {
            store
                .add_variant(id, LicenseType::Alternate, data.clone())
                .is_ok()
        })
        .count();
    debug_assert!(
        registered > 0,
        "inline SPDX corpus no longer contains any LGPL-3.0 entry to attach the short form to"
    );
}

type Matches = Vec<(String, f32)>;

/// Results by exact text and threshold, so identical license texts (Apache-2.0 is shipped by dozens
/// of packages) are scanned once per run.
///
/// Keyed by the text itself, never a hash of it: a package could craft a license file that collides
/// with a permissive one under any non-cryptographic hash and so inherit its result. Equal text
/// scans equal, so a hit is exact.
///
/// Lookups never wait on a scan in progress. A blocking wait here deadlocks under rayon: a worker
/// waiting inside a nested parallel scan can steal another task for the same text and then wait on
/// itself. Concurrent duplicates are avoided up front by [`prescan`] instead.
type Memo = Mutex<HashMap<(u32, String), Matches>>;

fn memo() -> &'static Memo {
    static MEMO: OnceLock<Memo> = OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(HashMap::new()))
}

fn memo_lock() -> std::sync::MutexGuard<'static, HashMap<(u32, String), Matches>> {
    memo()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Scan every distinct text in `texts` once, in parallel, so later [`scan_license_text`] calls for
/// them are lookups. Call this before fanning out over packages: duplicates then cost nothing,
/// instead of every worker scanning its own copy at the same moment.
pub fn prescan(texts: &[String], confidence_threshold: f32) {
    let bits = confidence_threshold.to_bits();
    let mut distinct: Vec<&String> = {
        let memo = memo_lock();
        let mut seen = std::collections::HashSet::new();
        texts
            .iter()
            .filter(|text| !memo.contains_key(&(bits, (*text).clone())) && seen.insert(*text))
            .collect()
    };
    // Biggest first, so the longest scans start earliest and the tail is short.
    distinct.sort_by_key(|text| std::cmp::Reverse(text.len()));
    let scanned: Vec<(String, Matches)> = distinct
        .par_iter()
        .map(|text| ((*text).clone(), scan_cached(text, confidence_threshold)))
        .collect();
    let mut memo = memo_lock();
    for (text, matches) in scanned {
        memo.insert((bits, text), matches);
    }
}

/// Scan `text`, returning `(spdx_license_id, score)` for every match clearing
/// `confidence_threshold`. More than one when the text concatenates several licenses.
#[must_use]
pub fn scan_license_text(text: &str, confidence_threshold: f32) -> Vec<(String, f32)> {
    let key = (confidence_threshold.to_bits(), text.to_owned());
    if let Some(found) = memo_lock().get(&key) {
        return found.clone();
    }
    let matches = scan_cached(text, confidence_threshold);
    memo_lock().entry(key).or_insert_with(|| matches.clone());
    matches
}

/// The scan, via the on-disk cache when one is configured.
fn scan_cached(text: &str, confidence_threshold: f32) -> Matches {
    let bits = confidence_threshold.to_bits();
    if let Some(found) = crate::match_cache::load(text, bits) {
        return found;
    }
    let matches = scan_uncached(text, confidence_threshold);
    crate::match_cache::store(text, bits, &matches);
    matches
}

/// Every license in the text, by the library's `TopDown` window search.
fn scan_top_down(data: &TextData, confidence_threshold: f32) -> Matches {
    Scanner::with_scan_mode(store(), ScanMode::top_down())
        .confidence_threshold(confidence_threshold)
        .scan(data)
        .containing
        .into_iter()
        .map(|contained| (contained.license.name.to_string(), contained.score))
        .collect()
}

fn scan_uncached(text: &str, confidence_threshold: f32) -> Matches {
    let started = std::time::Instant::now();
    let matches = scan_top_down(&TextData::new(text), confidence_threshold);
    if std::env::var_os("TRUSTEDLICENSES_TRACE").is_some_and(|value| !value.is_empty()) {
        eprintln!(
            "trace {:>7.1}ms scan  {:>7} bytes",
            started.elapsed().as_secs_f64() * 1000.0,
            text.len()
        );
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIT: &str = include_str!("../../tests/fixtures/mit.txt");
    const GPL_2_0: &str = include_str!("../../tests/fixtures/gpl-2.0.txt");
    const GPL_3_0: &str = include_str!("../../tests/fixtures/gpl-3.0.txt");
    const LGPL_3_0_SHORT: &str = include_str!("../../tests/fixtures/lgpl-3.0-short-form.txt");

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
    fn finds_the_short_form_lgpl_3_0_supplement() {
        let matches = scan_license_text(LGPL_3_0_SHORT, DEFAULT_CONFIDENCE_THRESHOLD);
        assert_eq!(matches.len(), 1, "got {matches:?}");
        assert!(matches[0].0.starts_with("LGPL-3.0"), "got {matches:?}");
        assert!(matches[0].1 > 0.9);
    }

    #[test]
    fn does_not_misidentify_gpl_3_0_as_lgpl() {
        let matches = scan_license_text(GPL_3_0, DEFAULT_CONFIDENCE_THRESHOLD);
        assert_eq!(matches.len(), 1, "got {matches:?}");
        assert!(matches[0].0.starts_with("GPL-3.0"), "got {matches:?}");
    }

    #[test]
    fn finds_nothing_in_unrelated_text() {
        let matches = scan_license_text(
            "this is a README, not a license",
            DEFAULT_CONFIDENCE_THRESHOLD,
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn a_repeated_text_gives_the_same_answer_every_time() {
        let first = scan_license_text(MIT, DEFAULT_CONFIDENCE_THRESHOLD);
        assert_eq!(scan_license_text(MIT, DEFAULT_CONFIDENCE_THRESHOLD), first);
        assert_eq!(first[0].0, "MIT");
    }

    #[test]
    fn the_threshold_is_part_of_the_key() {
        // A text that clears 0.8 but not 1.0 must not be answered from the other's cache entry.
        let strict = scan_license_text(MIT, 1.1);
        let normal = scan_license_text(MIT, DEFAULT_CONFIDENCE_THRESHOLD);
        assert!(strict.is_empty());
        assert_eq!(normal.len(), 1);
    }

    #[test]
    fn prescan_fills_the_cache_so_lookups_agree_and_duplicates_are_harmless() {
        let texts = vec![
            MIT.to_owned(),
            GPL_2_0.to_owned(),
            MIT.to_owned(),
            format!("{MIT}\n\n{GPL_2_0}"),
            MIT.to_owned(),
        ];
        prescan(&texts, DEFAULT_CONFIDENCE_THRESHOLD);
        for text in &texts {
            assert_eq!(
                scan_license_text(text, DEFAULT_CONFIDENCE_THRESHOLD),
                scan_uncached(text, DEFAULT_CONFIDENCE_THRESHOLD)
            );
        }
        prescan(&texts, DEFAULT_CONFIDENCE_THRESHOLD);
    }

    /// Regression test for a deadlock found while tuning: a cache that made later callers *wait* for
    /// an in-progress scan can wait on itself under rayon's work stealing. Many threads asking for
    /// the same few texts at once, some of them through `prescan`, must always finish.
    #[test]
    fn many_threads_asking_for_the_same_texts_never_deadlock() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let texts: Vec<String> = (0..6)
                .map(|n| format!("{MIT}\n\nvariant number {n}"))
                .collect();
            for _ in 0..4 {
                (0..96usize).into_par_iter().for_each(|i| {
                    if i % 8 == 0 {
                        prescan(&texts, DEFAULT_CONFIDENCE_THRESHOLD);
                    }
                    let found =
                        scan_license_text(&texts[i % texts.len()], DEFAULT_CONFIDENCE_THRESHOLD);
                    assert_eq!(found[0].0, "MIT");
                });
            }
            let _ = sender.send(());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(120))
            .expect("the scans deadlocked");
    }
}
