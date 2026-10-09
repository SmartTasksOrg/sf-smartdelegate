# Writing a port

A port is an independent implementation of the engine in another language.
The Python package (`src/sf_smartdelegate`) is the reference: when this document
and the reference disagree, the conformance vectors decide, and the loser
gets fixed.

## What a port must pass

| Suite | Where | Meaning |
|---|---|---|
| Policy evaluation | `conformance/eval/cases.json` (95 cases) | Your evaluator gives the real Cedar engine's answer |
| Engine conformance | `conformance/vectors/*.json` (78 cases, 327 steps) with `conformance/bundle` | Tokens, delegation, fields, spend, approval, guards, audit |
| Interoperability | see below | Your port and the reference accept each other's tokens, signed bundles and audit logs |

A port that passes the first two but was never checked against the reference
is not done: the vectors cannot tell whether your token bytes are readable by
anyone else.

Current ports:

| Port | Engine | CLI, daemon, proxies | How it is tested |
|---|---|---|---|
| `src/sf_smartdelegate` (Python, reference) | native | yes | `tests/` |
| `ports/java/` | native | no (library + REST client) | `ports/java/src/test`: eval, conformance in-process, interop with the reference |
| `ports/node/` | native | CLI and REST daemon (no proxies) | `ports/node/test` |
| `ports/go/` | native | CLI and REST daemon (no proxies) | `go test` |
| `ports/php/` | native | CLI, REST daemon and a front controller (no proxies) | `ports/php/test` |
| `ports/rust/` | native, real Cedar | yes, plus C ABI | `cargo test`; `tests/test_interop.py` |
| `ports/js/` | REST client only (browser, Deno, Node) | no | conformance over REST against the reference daemon |

`ports/conformance/run.sh` runs every port whose toolchain is installed.

## Order of work

1. **JSON.** Integers must stay integers (64-bit), and you need canonical output (below).
2. **Policy evaluator.** Port `src/sf_smartdelegate/cedar.py` (about 400 lines). Run the eval cases. Read `POLICY_SUBSET.md`.
3. **Field masking.** Port `fields.py` (about 130 lines).
4. **Tokens.** Port `tokens.py`: capability narrowing, EdDSA JWT sign and verify.
5. **Bundle, state, audit.** Port `bundle.py`, `state.py`, `audit.py`.
6. **Engine.** Port `engine.py`. Run the conformance vectors with a fresh engine and state directory per case, configured as `{"bundle_dir": …, "state_dir": …, "allow_test_clock": true, "max_depth": 3}` merged with the vector file's top-level `config`, when it has one. Roles: `ROLES.md`.
7. **Interoperability.** Issue a token in your port and authorize it in the reference, and the reverse. Sign a bundle in each and load it in the other. Write an audit log and run the reference's `audit verify` on it.

The vector runner is small (under 100 lines): `src/sf_smartdelegate/conformance.py`.

## Formats that must match byte for byte

### Canonical JSON

Used for the audit hash chain, approval ids, the bundle version and the bundle signature.

- object keys sorted by Unicode code point
- no whitespace
- strings: `"` and `\` escaped; `\b \f \n \r \t`; other characters below U+0020 as `\u00xx` in lowercase hex; everything else, including non-ASCII, written as itself
- integers only; a float has no canonical form and must not reach it

### Keys

- private key: base64 of the Ed25519 PKCS#8 **version 1** DER (48 bytes: the 16-byte prefix `302e020100300506032b657004220420`, then the seed)
- public key: base64 of the 32 raw bytes
- key id: first 16 hex characters of `sha256(raw public key)`

### Capability token

A JWT, `alg` `EdDSA`, header `kid` = key id. Claims: `docs/SCOPE.md` section 8.1.
Verification must check, in this order: three base64url parts without padding;
`alg` is exactly `EdDSA`; `kid` is a known key; the signature; the claim types;
`aud` is `smartdelegate`; `iss` is the configured issuer. Then the engine checks
expiry and revocation.

### Bundle

- version = `sha256(canonical({relative path: sha256(file with CRLF replaced by LF)}))` over `policies.json`, `entities.json`, `catalog.json`, `roles.json` (each only when present)
- signature = Ed25519 over `canonical({"files": …, "version": …})`, base64, stored in `bundle.sig.json`
- on load: if `policies/*.cedar` files are present, their hashes must equal `policies.json`'s `sources`, else `bundle_stale`

### Audit record

One JSON object per line, canonical form.
`hash = sha256(prev + canonical(record without "hash"))`, the first `prev` is 64 zeros, `seq` starts at 1.

### State directory

`state.json` (`revoked`, `approvals`, `pending`, `ledger`, `limits`, `revoked_users`; a missing key is an empty object), `audit.jsonl`,
`signing_key.pk8.b64`, `signing_key.pub.b64`, `lock`. An engine takes an
exclusive lock on `lock` for each operation and re-reads `state.json` first.

The Python, Rust, Go and PHP engines all use `flock` on `lock`, so they can
share a state directory (tested together by `ports/conformance/matrix.py`).
The Java engine uses the JVM's file lock and the Node engine its own lock
file; neither excludes the others: **do not share a state directory between
Java or Node and any other port.**

## Rules that are easy to get wrong

Each has a vector.

- A capability is a ceiling, not a grant: `actions: ["*"]` permits nothing by itself.
- Narrowing covers actions, resources, **both** deny lists (they can only grow) and every budget currency.
- Revoking a token revokes every token that lists it in `anc`.
- Revoking a user (`revoke {"user"}`) stores the time of the call in `state.revoked_users[user]`; a token of that user with `iat` at or before it is `token_revoked`. Checked after the token-id revocations, before anything else. Entries are never pruned, and a new cut-off is `max(stored, now)`: it never moves back. Audit event `user_revoked` with `user`, `issued_up_to`, `by`.
- Spend is charged to the token and to every ancestor; an ancestor's limit applies to the sum of its descendants. The limit of ancestor `a` is `state.limits[a]` when this engine has it, otherwise the token's `lim[a]` claim, so a verify-only engine with its own state enforces it as well (over the spends it sees).
- An erroring forbid denies. An erroring permit is ignored.
- Unknown fields in a `cap` are an error, not ignored.
- `context.iam` from the caller is an error.
- `dry_run` spends nothing, counts nothing towards rate limits, consumes no approval and writes no audit record.
- The approval id is the first 24 hex characters of `sha256(canonical({"user", "chain", "tenant", "action", "resource": "path/id", "attrs": <resource.attrs as sent, {} when absent>, "context": <caller context>, "label"}))`. A request that differs in any of these, including a resource attribute, needs its own approval.
- An approval is bound to the exact request, is single use, expires, cannot be given by the user the agent acts for, and needs a policy permit for action `approve`.
- Strict mode denies; it never drops a field from an input.
- Data that is not a record (a string, a number) cannot be authorised: it comes back as `null`.
- A role is a ceiling too: the human must hold it, the token cannot exceed it, and sub-agents cannot change it.
- Live membership replaces the stored membership of that user; it is not added to it.
- A failure to write the audit log, read the state file or verify the bundle refuses the request.

## Strictness (0.3)

Found by running the ports against each other. Each port has its own test for
these; the eval cases cover the Cedar ones.

- **Audit lines end at `\n` and nowhere else.** Canonical JSON writes U+2028, U+2029 and U+0085 as themselves; they are data, not line breaks. (`str.splitlines()` and similar helpers get this wrong.)
- **base64url is strict.** Only `A-Z a-z 0-9 - _`, no padding, no skipped characters. Anything else in any of the three token parts is `token_invalid`. One token has one spelling.
- **Entity type names match in full:** `[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*`. A trailing newline is not a match.
- **`containsAll` / `containsAny` check both operands are sets** before looking at their contents, so an empty argument does not hide a non-set receiver (eval cases 92 to 95).
- **Policy JSON shapes are checked at load:** `conditions`, a `Set` literal, a `like` pattern and scope `entities` are arrays; a `Record` literal and `annotations` are objects. Otherwise `policy_parse`. (`annotations` that is absent, `null` or otherwise empty means no annotations.)
- **Token claims:** `anc` is an array of strings; a string is not.
- **Files that are not UTF-8:** `state.json` → `state_io`; the audit log → `audit_broken`; a bundle file → `bundle_io`. `entities.json` that is not a list of objects → `entities_parse`. None of these may escape as an exception.
- **Creating the signing key** must be safe when two processes start on an empty state directory at once: one creates it, the other reads it. Write the key to a temporary file and hard-link it into place, so the key file is complete when it appears. A key file found empty is still being written by someone else: wait for it, then fail with `state_io`; never treat it as "no key".

## OIDC ID tokens (0.3, after the first run against a real identity provider)

Checked in this order after the signature, issuer and audience:

- **Authorised party.** If the token has `azp`, it must equal the configured audience. If `aud` is a list with more than one entry and there is no `azp`, the token is refused. Both are `id_token_invalid`. (Keycloak puts every client a user has roles on into an access token's `aud`; without this check another client's access token passes as an ID token.)
- **Revoked users.** If `state.revoked_users` has a cut-off for the token's user, the ID token's `iat` must be an integer greater than the cut-off; otherwise `id_token_invalid`. Checked after the user is known and before roles.
- **Nested group claim.** `idp.groups_claim` is first looked up as a top-level claim with that exact name; if absent and the name contains `.`, it is followed as a path through nested objects. Not found means the empty list.
- **`reload`** re-reads `idp.jwks_file` (when the keys came from a file) as well as the bundle. If either fails to load, neither is replaced and the error is returned (`invalid_config` for the JWKS).
