//! `trustedlicenses._rust`: the command line, run inside the Python interpreter.

use pyo3::prelude::*;

/// Exit statuses are 0-255 on every platform this runs on.
fn status(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

/// Run the `trustedlicenses` command line with `argv` (the program name first); returns the
/// exit status.
#[pyfunction]
fn main(py: Python<'_>, argv: Vec<String>) -> u8 {
    // The CLI uses its own threads and no Python objects, so the interpreter can run meanwhile.
    py.detach(|| status(trustedlicenses_cli::main_with(&argv)))
}

/// Like `main`, but returns the exit status, standard output and standard error instead of
/// writing them.
#[pyfunction]
fn run_captured(py: Python<'_>, argv: Vec<String>) -> (u8, String, String) {
    let (code, out, err) = py.detach(|| trustedlicenses_cli::run_captured(&argv));
    (status(code), out, err)
}

#[pymodule]
fn _rust(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(main, module)?)?;
    module.add_function(wrap_pyfunction!(run_captured, module)?)
}
