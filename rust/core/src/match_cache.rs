//! A persistent cache of license-text scan results, so the same text is never scanned twice across
//! runs (CI and pre-commit check the same package versions again and again).
//!
//! Entries are advisory: anything missing, unreadable or malformed is a miss, and a failed write is
//! ignored. The key is a SHA-256 over everything the answer depends on (see [`identity`]) and the
//! full text, so a crafted license file cannot collide with another's entry, and a changed corpus
//! or algorithm can never be served an old answer. An entry only ever says what scanning that exact
//! text would have said.

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

type Matches = Vec<(String, f32)>;

/// Bump when the entry format, or what a scan means, changes.
const FORMAT: u32 = 1;
const HEADER: &str = "trustedlicenses-match-cache 1";
/// The last line of every entry. An entry cut short, by a crash or a racing writer, lacks it and so
/// is a miss rather than a shorter answer.
const END: &str = "end";

fn directory() -> &'static Mutex<Option<PathBuf>> {
    static DIRECTORY: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
    DIRECTORY.get_or_init(|| Mutex::new(None))
}

/// Where entries live, or `None` to neither read nor write the cache. Process-wide: set once at
/// startup.
pub fn configure(dir: Option<PathBuf>) {
    *directory()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = dir;
}

fn current_directory() -> Option<PathBuf> {
    directory()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Everything besides the text that a scan's answer depends on: the corpus (the `spdx` crate's
/// version), the extra LGPL template this crate registers, and the scan itself (`TopDown`, whose
/// parameters are fixed in the matcher).
fn identity() -> &'static str {
    static IDENTITY: OnceLock<String> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let template = hex(&Sha256::digest(
            crate::matcher::LGPL_3_0_SHORT_FORM.as_bytes(),
        ));
        format!(
            "format={FORMAT};spdx={};lgpl-short-form={template}",
            env!("TL_SPDX_VERSION")
        )
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn key(text: &str, threshold_bits: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(identity().as_bytes());
    hasher.update([0]);
    hasher.update(threshold_bits.to_le_bytes());
    hasher.update([0]);
    hasher.update(text.as_bytes());
    hex(&hasher.finalize())
}

fn encode(matches: &Matches) -> String {
    let mut out = format!("{HEADER}\n");
    for (name, score) in matches {
        out.push_str(&format!("{:08x}\t{name}\n", score.to_bits()));
    }
    out.push_str(END);
    out.push('\n');
    out
}

fn decode(text: &str) -> Option<Matches> {
    let mut lines = text.lines();
    if lines.next()? != HEADER {
        return None;
    }
    let mut matches = Vec::new();
    loop {
        let line = lines.next()?;
        if line == END {
            return lines.next().is_none().then_some(matches);
        }
        let (bits, name) = line.split_once('\t')?;
        (!name.is_empty()).then_some(())?;
        matches.push((
            name.to_owned(),
            f32::from_bits(u32::from_str_radix(bits, 16).ok()?),
        ));
    }
}

fn entry(dir: &Path, key: &str) -> PathBuf {
    dir.join(&key[..2]).join(key)
}

/// The cached answer for `text`, if one is stored.
#[must_use]
pub fn load(text: &str, threshold_bits: u32) -> Option<Matches> {
    let dir = current_directory()?;
    decode(&fs::read_to_string(entry(&dir, &key(text, threshold_bits))).ok()?)
}

/// Remember the answer for `text`. Best effort: a cache that cannot be written is just a cache.
pub fn store(text: &str, threshold_bits: u32, matches: &Matches) {
    let Some(dir) = current_directory() else {
        return;
    };
    let key = key(text, threshold_bits);
    let path = entry(&dir, &key);
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    // Written beside the target and renamed into place, so a reader never sees half an entry. Unique
    // per write: two threads storing the same key must not share a file.
    static WRITES: AtomicU64 = AtomicU64::new(0);
    let temporary = parent.join(format!(
        ".{key}.{}.{}.tmp",
        std::process::id(),
        WRITES.fetch_add(1, Ordering::Relaxed)
    ));
    if fs::write(&temporary, encode(matches)).is_err() || fs::rename(&temporary, &path).is_err() {
        let _ = fs::remove_file(&temporary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// `configure` is process-wide, so the tests that use it must not overlap.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn sample() -> Matches {
        vec![
            ("MIT".to_owned(), 0.987_654),
            ("GPL-2.0-or-later".to_owned(), 0.8),
        ]
    }

    #[test]
    fn entries_round_trip_exactly_including_the_float_bits() {
        let encoded = encode(&sample());
        let decoded = decode(&encoded).expect("decodes");
        assert_eq!(decoded.len(), 2);
        for ((name, score), (want_name, want_score)) in decoded.iter().zip(sample()) {
            assert_eq!(name, &want_name);
            assert_eq!(score.to_bits(), want_score.to_bits());
        }
        assert_eq!(
            decode(&encode(&Vec::new())),
            Some(Vec::new()),
            "no matches is an answer too"
        );
    }

    #[test]
    fn malformed_entries_are_misses() {
        for bad in [
            "",
            "wrong header\n3f800000\tMIT\nend\n",
            &format!("{HEADER}\nnothex\tMIT\nend\n"),
            &format!("{HEADER}\n3f800000\t\nend\n"),
            &format!("{HEADER}\n3f800000 MIT\nend\n"),
            &format!("{HEADER}\n3f800000\tMIT\n"),
            &format!("{HEADER}\n3f800000\tMIT\nend\ntrailing\n"),
            &format!("{HEADER}\n"),
        ] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn keys_depend_on_the_text_the_threshold_and_the_identity() {
        let base = key("text", 1);
        assert_eq!(base, key("text", 1));
        assert_ne!(base, key("text ", 1));
        assert_ne!(base, key("text", 2));
        assert_eq!(base.len(), 64);
        assert!(identity().contains("spdx=0."), "{}", identity());
    }

    #[test]
    fn stores_and_loads_through_the_directory_and_misses_without_one() {
        let _guard = serial();
        let tmp = tempdir().expect("tempdir");
        let text = "a text only this test uses";
        configure(Some(tmp.path().to_path_buf()));
        assert_eq!(load(text, 7), None);
        store(text, 7, &sample());
        let loaded = load(text, 7).expect("hit");
        assert_eq!(loaded[0].0, "MIT");
        assert_eq!(load(text, 8), None, "another threshold is another entry");

        let path = entry(tmp.path(), &key(text, 7));
        fs::write(&path, "corrupted").expect("corrupt");
        assert_eq!(load(text, 7), None, "a corrupt entry is a miss");

        configure(None);
        assert_eq!(load(text, 7), None);
        store(text, 99, &sample());
        assert!(
            !entry(tmp.path(), &key(text, 99)).exists(),
            "nothing is written without a directory"
        );
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let _guard = serial();
        let tmp = tempdir().expect("tempdir");
        configure(Some(tmp.path().to_path_buf()));
        store("another text for this test", 3, &sample());
        configure(None);
        let leftovers: Vec<_> =
            fs::read_dir(tmp.path().join(&key("another text for this test", 3)[..2]))
                .expect("shard")
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
                .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn a_truncated_entry_never_reads_as_a_shorter_answer() {
        let full = encode(&sample());
        // The last byte is only the newline after `end`: without it the entry is still complete.
        for cut in 0..full.len() - 1 {
            if full.is_char_boundary(cut) {
                assert_eq!(decode(&full[..cut]), None, "cut at {cut}");
            }
        }
        assert!(decode(&full).is_some());
    }

    #[test]
    fn threads_storing_the_same_key_never_publish_a_partial_entry() {
        let _guard = serial();
        let tmp = tempdir().expect("tempdir");
        configure(Some(tmp.path().to_path_buf()));
        let big: Matches = (0..400)
            .map(|n| (format!("License-Number-{n}"), 0.9))
            .collect();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..50 {
                        store("one shared text", 5, &big);
                        if let Some(read) = load("one shared text", 5) {
                            assert_eq!(read.len(), 400, "a reader saw a partial entry");
                        }
                    }
                });
            }
        });
        configure(None);
    }
}
