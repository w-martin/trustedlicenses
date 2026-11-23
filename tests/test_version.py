"""Tests for the trustedlicenses package itself."""

import subprocess
import sys
from importlib.metadata import version

import pytest

import trustedlicenses


def test_version_is_the_installed_distributions() -> None:
    """The package reports the version of the distribution that provides it."""
    assert version("trustedlicenses") == trustedlicenses.__version__


def test_other_missing_attributes_still_raise() -> None:
    """Only `__version__` is looked up on demand."""
    with pytest.raises(AttributeError, match="no_such_attribute"):
        _ = trustedlicenses.no_such_attribute


def _loaded_after(statement: str, modules: list[str]) -> list[str]:
    probe = f"import sys; {statement}; print(*(m for m in {modules!r} if m in sys.modules))"
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)  # noqa: S603
    return result.stdout.split()


def test_importing_the_package_reads_no_metadata() -> None:
    """`python -m trustedlicenses` imports the package, and must not pay for `importlib.metadata` to start."""
    assert _loaded_after("import trustedlicenses._binary", ["importlib.metadata"]) == []


@pytest.mark.skipif(sys.version_info < (3, 15), reason="lazy imports (PEP 810) are new in 3.15")
def test_the_launcher_defers_the_modules_it_rarely_needs() -> None:
    """Replacing the process with the executable needs neither `subprocess` nor `shutil`."""
    assert _loaded_after("import trustedlicenses._binary", ["shutil", "subprocess"]) == []
