"""trustedlicenses: policy-driven license auditing for Python dependencies.

The command line is a Rust program installed alongside this package; `python -m trustedlicenses` starts it,
and `trustedlicenses-py` runs it inside the Python process. There is no Python API: see the usage guide.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("trustedlicenses")
except PackageNotFoundError:  # pragma: no cover -- only when run from a source tree that is not installed
    __version__ = "0+unknown"

__all__ = ["__version__"]
