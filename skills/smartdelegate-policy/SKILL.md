---
name: smartdelegate-policy
description: Author, test, compile and sign a SmartDelegate policy bundle - field catalog, role ceilings, Cedar policies in the portable subset, policy unit tests. Use when a resource, field, role or rule must be added or changed, when a bundle fails to load (bundle_stale, policy_parse, roles_parse, catalog_parse), or before a bundle is deployed.
---

# Author and test a bundle

A bundle is a directory:

| File | Holds | Reference |
|---|---|---|
| `catalog.json` | resources, their entity type, every field and its labels (`pii`, `secret`, ...) | `docs/SCOPE.md` section 8.2 |
| `entities.json` | users, groups, agents; written by the directory sync where one runs | `docs/BRIDGES.md` |
| `roles.json` | who holds each role and its ceiling (`cap`, `max_ttl`, `tasks`, `agents`) | `spec/ROLES.md` |
| `policies/*.cedar` | the rules, in the portable Cedar subset | `spec/POLICY_SUBSET.md` |
| `policies.json` | the compiled rules every engine evaluates | generated |
| `tests/*.json` | policy unit tests | `spec/conformance/bundle/tests/basics.json` |
| `bundle.sig.json` | file hashes and an Ed25519 signature | generated |

Commands are written `smartdelegate ...`; from a clone without installing,
`PYTHONPATH=src python3 -m sf_smartdelegate ...`. `--bundle DIR` names the bundle.

## Never without a human

- Never deploy, reload or hand over a bundle that is untested or unsigned.
- Never edit `policies.json` by hand. It is produced by the compiler; an
  engine cannot tell whether a hand-edited file still means what its source says.
- Never widen a role's `cap`, lengthen `max_ttl`, loosen `tasks` or `agents`,
  remove a `forbid`, remove a label from a field or add a permit without a
  human reviewing that exact change. Prepare the change and the tests; a
  human approves and signs.
- Never create, read aloud or commit the signing key (`*.key`). Signing is a
  human's step, or a release job's.
- Never weaken or delete a failing test to make the suite pass.

## Commands

Work on a copy, never on the bundle a running engine loads.

1. Edit `catalog.json`, `roles.json`, `policies/*.cedar`. Fields are default
   deny: a field that is in no permit is removed. An unknown key in
   `roles.json` fails the load; that is deliberate.

2. Compile. Only the Rust port turns Cedar text into `policies.json`:

```bash
ports/rust/target/release/smartdelegate bundle compile --bundle bundle
```

   (The binary comes from `cargo build --release` in `ports/rust`; that build
   was not run while this skill was written, the binary already existed. The
   Python command of the same name only tells you to use the Rust port.)

3. Load it and run its tests:

```bash
sf-smartdelegate policy check --bundle bundle
sf-smartdelegate policy test --bundle bundle
```

   Write a test for every rule you add: an allow case, the nearest deny case,
   and the field mask you expect. Tests state the acting chain directly, so
   they exercise policies and the catalog, not tokens or role ceilings.

4. See what the new bundle would do without enforcing it. In shadow mode
   (`--shadow`, or `"mode": "shadow"` in the configuration) a would-be denial
   is let through, answered with `would_deny` (and `would_mask` for data) and
   logged with `enforced: false`:

```bash
sf-smartdelegate authorize --token "$TOKEN" --action read --resource hr.salary/e-1 --bundle bundle --shadow
```

   Shadow mode enforces nothing. It is for a rollout window, never the end state.

5. A human signs, with a key that never enters the repository:

```bash
sf-smartdelegate bundle keygen release
sf-smartdelegate bundle sign --key release.key --bundle bundle
```

   The engine requires the signature only when `bundle_public_key` is set in
   its configuration. `bundle.sig.json` covers `policies.json`,
   `entities.json`, `catalog.json` and `roles.json`: after any change to one
   of them, including a directory sync, the bundle must be signed again.

6. A running engine keeps the bundle it loaded until `reload` (admin key;
   `POST /v1/admin/reload`, or the MCP server's `reload` tool). A bundle that
   fails to load leaves the old one in force. Reloading is a privileged step:
   prepare it, a human runs it.

## The subset in one paragraph

`permit` and `forbid`; scopes with `==`, `in`, `is`; `when` and `unless`;
booleans, longs, strings, sets, records; `has`, `like`, `contains`. No `ip`,
`decimal`, `datetime`, no templates: a bundle that uses them does not load.
Policies are not schema-checked: a misspelt attribute in a permit makes it
never apply; in a forbid it makes requests fail with `DELEGATE-POLICY-ERROR`.
Guard attributes with `has`. Annotations with meaning: `@id`, `@row_filter`,
`@rate_limit`, `@require_approval`.

## Load errors

| Error | Cause |
|---|---|
| `bundle_stale` | a `.cedar` file changed after `policies.json` was compiled: compile again |
| `policy_parse` | `policies.json` is malformed or uses something outside the subset |
| `roles_parse` | `roles.json`: unknown key, wrong type, empty members, bad pattern |
| `catalog_parse`, `entities_parse` | the named file is malformed |
| `bundle_unsigned`, `bundle_signature` | a signature is required and is missing, wrong, or older than the files |

## Review checklist for the human

Every changed role: is the ceiling the least the task needs, is `max_ttl`
set, are `tasks` and `agents` listed? Every new permit: which test shows the
nearest request that must stay denied? Every `@row_filter` on a list read?
Every label on a new field? Was the diff of `policies.json` produced by the
compiler from the reviewed `.cedar` files?
