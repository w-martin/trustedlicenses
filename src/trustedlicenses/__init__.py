"""Policy-driven license auditing for installed Python dependencies."""

from trustedlicenses.config import (
    ConfigError,
    CorrectionTrust,
    NoPolicyConfiguredError,
    add_to_policy,
    load_policy,
    policy_source,
    write_policy,
)
from trustedlicenses.detection import (
    DistributionLicence,
    canonical_name,
    categories_for,
    inspect_distribution,
    inspect_installed,
    resolve_license_expression,
)
from trustedlicenses.policy import (
    Policy,
    PolicyResult,
    detect_all,
    evaluate,
    format_failure,
    format_remediation,
    format_suggestion,
)
from trustedlicenses.resolve import ResolutionError, resolve_packages

__all__ = [
    "ConfigError",
    "CorrectionTrust",
    "DistributionLicence",
    "NoPolicyConfiguredError",
    "Policy",
    "PolicyResult",
    "ResolutionError",
    "add_to_policy",
    "canonical_name",
    "categories_for",
    "detect_all",
    "evaluate",
    "format_failure",
    "format_remediation",
    "format_suggestion",
    "inspect_distribution",
    "inspect_installed",
    "load_policy",
    "policy_source",
    "resolve_license_expression",
    "resolve_packages",
    "write_policy",
]
