//! Rust license-text matcher for `trustedlicenses`, exposed to Python via PyO3.
//!
//! Wraps the `spdx` crate's `detection` feature -- a maintained continuation of
//! askalono's word-bigram Sorensen-Dice matching algorithm against the official SPDX
//! license-list-data corpus (baked into this binary via `detection-inline-cache`, so
//! there's no runtime data file to locate). See [`matcher::scan_license_text`] for the
//! scanning strategy and why `TopDown` mode is used rather than `Elimination`.

mod matcher;

use pyo3::prelude::*;

#[pymodule]
fn rust_matcher(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(matcher::scan_license_text, m)?)?;
    Ok(())
}
