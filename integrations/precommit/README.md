# SmartDelegate pre-commit hooks

The repository ships [`.pre-commit-hooks.yaml`](../../.pre-commit-hooks.yaml)
with two hooks. Add to your `.pre-commit-config.yaml`:

```yaml
- repo: <url of the SmartDelegate repository>
  rev: <tag>
  hooks:
    - id: smartdelegate-policy-check
    - id: smartdelegate-policy-test
```

| Hook | Runs | Fails when |
|---|---|---|
| `smartdelegate-policy-check` | `sf-smartdelegate policy check --bundle bundle` | a bundle file does not parse, or `policies.json` is stale relative to the `.cedar` sources (`bundle_stale`) |
| `smartdelegate-policy-test` | `sf-smartdelegate policy test --bundle bundle` | one of the bundle's `tests/*.json` cases fails |

Both run once per commit (not once per file) and only when a `.cedar` or
`.json` file under `bundle/` changed. They use `language: python`, so
pre-commit installs the package and its `smartdelegate` console script into its own
environment.

For a bundle in another directory, override `files` and `args` together:

```yaml
    - id: smartdelegate-policy-check
      files: ^policy/bundle/.*\.(cedar|json)$
      args: [--bundle, policy/bundle]
```

Tested: the hooks file is parsed and each hook's `entry` plus `args` is run
against a bundle, including a stale one. `pre-commit` itself was not run, so
the installation step it performs is unverified here.
