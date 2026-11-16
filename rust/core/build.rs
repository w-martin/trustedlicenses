//! Records the resolved version of the `spdx` crate, so a cached scan result is never reused after
//! the corpus or the scanning algorithm changes underneath it. The build fails rather than record
//! an unknown version, because that would let a stale cache entry outlive a spdx upgrade.

use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=../Cargo.lock");
    let lock = fs::read_to_string("../Cargo.lock").unwrap_or_else(|error| {
        panic!("cannot read rust/Cargo.lock to find the spdx version for the scan cache: {error}")
    });
    let mut versions = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line == "name = \"spdx\"" {
            let version = lines
                .next()
                .and_then(|next| next.strip_prefix("version = \""))
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or_else(|| panic!("rust/Cargo.lock has a spdx entry without a version"));
            versions.push(version.to_owned());
        }
    }
    assert!(
        !versions.is_empty(),
        "rust/Cargo.lock has no spdx package, so the scan cache has no version to key on"
    );
    println!("cargo:rustc-env=TL_SPDX_VERSION={}", versions.join("+"));
}
