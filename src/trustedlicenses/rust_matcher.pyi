# Type stub for the compiled Rust extension (`rust_matcher.abi3.so`).
#
# Mirrors the single `#[pyfunction]` registered in `rust/src/lib.rs`'s `#[pymodule]`
# block; the signature comes from its `#[pyo3(signature = ...)]` declaration in
# `rust/src/matcher.rs`.

def scan_license_text(text: str, confidence_threshold: float = 0.8) -> list[tuple[str, float]]: ...
