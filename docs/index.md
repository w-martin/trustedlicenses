# trustedlicenses

`trustedlicenses` checks that every package in your Python project, installed or pinned in a
lock file, has a license you've agreed to allow, so you can gate a CI build on it.

```shell
uv add --dev trustedlicenses
```

Run `trustedlicenses` in a terminal and, with no policy configured, it
[sets one up with you](usage.md#no-policy-configured-yet). Or write one yourself:

```toml
# pyproject.toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
ignored-packages = ["mypy-extensions"]
```

Each run then checks every package and exits non-zero on a failure, with the line to add if
you accept it.

Where to go next:

- [Choosing a policy](choosing-a-policy.md): what to allow for internal tooling, open-source
  packages and products.
- [Usage Guide](usage.md): every key, command and flag.
- [How it works](how-it-works.md): detection, text matching and package indexes.
- [Comparison to Alternatives](comparison.md) and [Performance](performance.md).

`trustedlicenses` is not a lawyer and does not give legal advice; read the
[legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer) before
relying on it for a compliance decision.
