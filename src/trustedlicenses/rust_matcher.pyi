# Type stub for the compiled Rust extension (`rust_matcher.abi3.so`).
#
# Mirrors the single `#[pyfunction]` registered in `rust/src/lib.rs`'s `#[pymodule]`
# block; the signature comes from its `#[pyo3(signature = ...)]` declaration in
# `rust/src/matcher.rs`.
#
# Batched: scans every text in `texts` in one call, returning one match list per input
# text (same order) -- see `matcher::scan_license_texts` for why (parallelizes the scan
# across CPU cores and releases the GIL exactly once for the whole batch).

def scan_license_texts(texts: list[str], confidence_threshold: float = 0.8) -> list[list[tuple[str, float]]]: ...
