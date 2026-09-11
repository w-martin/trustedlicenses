# CLI

The `trustedlicenses` command (built with [Typer](https://typer.tiangolo.com/))
checks installed packages against the policy declared in `pyproject.toml` or
`trustedlicenses.toml`. It has two modes: check the current environment (the
default), or check a candidate package before adding it (`check`).

## Basic usage

```shell
trustedlicenses
```

With no policy configured yet, behavior depends on whether a real terminal is
attached: interactively, it runs a guided setup wizard that explains each license
category and writes the config for you; non-interactively (or with `--quiet`), it
reports every detected license without judgment instead of prompting or erroring.
See [Usage Guide § No policy configured yet](../usage.md#no-policy-configured-yet).

## Checking a candidate package

```shell
trustedlicenses check <package> [<package> ...]
```

Resolves each `<package>` (a pip-style requirement, e.g. `requests` or
`"django>=5,<6"`) and its full transitive dependency tree into an isolated temporary
location, then evaluates the whole set against your project's policy — without
installing anything into your real environment. Same wizard-vs-report-mode rule as
the environment check applies when no policy is configured yet. See [Usage Guide
§ Checking a package before you add it](../usage.md#checking-a-package-before-you-add-it).

## Flags

- **`--pyproject PATH`** (default `./pyproject.toml`) — path to the `pyproject.toml`
  holding `[tool.trustedlicenses]` (a sibling `trustedlicenses.toml`, if present,
  takes priority — see [Usage Guide § Step 1](../usage.md#step-1-declare-a-policy)).
  Applies to both modes; goes before the `check` subcommand if used:

  ```shell
  trustedlicenses --pyproject path/to/pyproject.toml
  trustedlicenses --pyproject path/to/pyproject.toml check requests
  ```

- **`--quiet` / `-q`** — never prompt interactively; fall back to report-only mode
  (environment check) or a hard error (`check`) when no policy is configured, even
  if a real terminal happens to be attached. **Use this in CI/CD and pre-commit
  hooks** — see [Usage Guide § No policy configured
  yet](../usage.md#no-policy-configured-yet) for a sample pre-commit hook entry. As a
  second safety net if this gets left off, every wizard prompt also individually
  times out (`wizard.PROMPT_TIMEOUT_SECONDS`, 30s) and aborts the same way declining
  it does — see [Usage Guide § No policy configured
  yet](../usage.md#no-policy-configured-yet) for why that matters even with
  `--quiet` in place.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every checked package had an allowed license, or no policy is configured yet and report-only mode ran (environment check only) |
| `1` | At least one package failed the policy; a config file exists but is misconfigured; `check` was run with no policy configured (and non-interactively, or the wizard was declined); the candidate package(s) couldn't be resolved (`check` only); or the wizard was declined during an interactive environment check |

See [Usage Guide](../usage.md) for the full config format and output examples.

---

::: trustedlicenses.cli.main_command

::: trustedlicenses.cli.check

::: trustedlicenses.wizard.run
