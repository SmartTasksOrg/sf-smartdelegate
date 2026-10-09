# SmartDelegate policy check (GitHub Action)

A composite action for a repository that keeps a SmartDelegate policy bundle.

```yaml
jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
      - uses: SmartTasksOrg/sf-smartdelegate/integrations/github-action@<commit of a release tag>  # pin a full commit SHA
        with:
          bundle: bundle
          public-key: ${{ vars.SMARTDELEGATE_BUNDLE_PUBLIC_KEY }}   # optional
```

Replace `<commit of a release tag>` with the full commit SHA of the release you use (`git ls-remote https://github.com/SmartTasksOrg/sf-smartdelegate refs/tags/vX.Y.Z`).

| Input | Default | Meaning |
|---|---|---|
| `bundle` | required | the bundle directory (the one with `policies.json`) |
| `public-key` | empty | base64 Ed25519 public key; when set, the bundle must carry a valid `bundle.sig.json` signed by it |
| `package` | `sf-smartdelegate` | the requirement pip installs, or a path such as `.` |
| `python-version` | `3.12` | passed to `actions/setup-python` |

What it runs, in order:

1. `actions/setup-python@v5` (the only action it uses) and `pip install`.
2. `sf-smartdelegate policy check --bundle DIR`. Fails when a bundle file does not parse,
   and with `bundle_stale` when `policies.json` does not match the `.cedar`
   sources, so the policy a reviewer reads is the policy that runs.
3. `sf-smartdelegate policy test --bundle DIR`. Runs the bundle's `tests/*.json`.
4. Only with `public-key`: `sf-smartdelegate policy check --config FILE --bundle DIR`, where the
   file holds `{"bundle_public_key": "..."}`. Fails with `bundle_unsigned`
   or `bundle_signature`.

The action does not compile `.cedar` files; that is `smartdelegate bundle compile` in
the Rust port. A public key is not a secret, so a repository variable is enough.

Tested: `tests/test_integrations.py` executes the shell of steps 2 to 4 with
bash against the conformance bundle and against stale, unsigned, wrongly
signed and modified copies. The action has not been run on GitHub, and step 1
(setup-python, pip install) was not executed.
