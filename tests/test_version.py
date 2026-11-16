"""Tests for the trustedlicenses package itself."""

from importlib.metadata import version

import trustedlicenses


def test_version_is_the_installed_distributions() -> None:
    """The package reports the version of the distribution that provides it."""
    assert version("trustedlicenses") == trustedlicenses.__version__
