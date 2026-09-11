"""Policy-driven license auditing for installed Python dependencies."""

from trustedlicenses.config import ConfigError, NoPolicyConfiguredError, load_policy, write_policy
from trustedlicenses.detection import (
    DistributionLicence,
    canonical_name,
    categories_for,
    inspect_distribution,
    inspect_installed,
    resolve_license_expression,
)
from trustedlicenses.policy import Policy, PolicyResult, detect_all, evaluate, format_failure, format_remediation
from trustedlicenses.resolve import ResolutionError, resolve_packages

__all__ = [
    "ConfigError",
    "DistributionLicence",
    "NoPolicyConfiguredError",
    "Policy",
    "PolicyResult",
    "ResolutionError",
    "canonical_name",
    "categories_for",
    "detect_all",
    "evaluate",
    "format_failure",
    "format_remediation",
    "inspect_distribution",
    "inspect_installed",
    "load_policy",
    "resolve_license_expression",
    "resolve_packages",
    "write_policy",
]
