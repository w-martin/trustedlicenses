"""trustedlicenses: policy-driven license auditing for Python dependencies.

The command line is a Rust program installed alongside this package; `python -m trustedlicenses` starts it,
and `trustedlicenses-py` runs it inside the Python process. There is no Python API: see the usage guide.
"""

__version__: str
__all__ = ["__version__"]


def __getattr__(name: str) -> str:
    # Read on first use: `importlib.metadata` at import time cost `python -m trustedlicenses` about a third
    # of its startup, and the command line never needs it.
    if name != "__version__":
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    from importlib.metadata import PackageNotFoundError, version  # noqa: PLC0415

    try:
        found = version("trustedlicenses")
    except PackageNotFoundError:  # pragma: no cover -- only when run from a source tree that is not installed
        found = "0+unknown"
    globals()["__version__"] = found
    return found
