# API Reference

`trustedlicenses` detects and categorizes the licenses of installed Python packages,
then evaluates them against a policy declared in `pyproject.toml`.

| Module | Contents |
|--------|----------|
| [Detection](detection.md) | `DistributionLicence`, `inspect_distribution`, `inspect_installed`, `canonical_name` — license detection |
| [Policy](policy.md) | `Policy`, `PolicyResult`, `detect_all`, `evaluate`, `format_failure`, `format_remediation` — policy evaluation |
| [Config](config.md) | `load_policy`, `write_policy`, `ConfigError`, `NoPolicyConfiguredError` — loading and writing policy config |
| [Resolve](resolve.md) | `resolve_packages`, `ResolutionError` — resolving a candidate package for `check` |
| [CLI](cli.md) | `trustedlicenses` command (environment check, `check <package>`, and the interactive setup wizard) |
