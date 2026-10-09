# Comparing this build with the Sprint Council's output

Two things to compare: the council's scope against [SCOPE.md](../docs/SCOPE.md), and the
code generated from the council's spec against this code.

The six questions below are the ones the council's seed left open. Roles, live
group membership, offboarding and the bridges were added to this scope later
(SCOPE 5.1, 5.8, [ROLES.md](ROLES.md), [docs/BRIDGES.md](../docs/BRIDGES.md)); a council scope written
from the seed will not have them.

## A. Scope

| Question | This scope | Where |
|---|---|---|
| Policy language | Cedar | SCOPE 6.1 |
| Token format | EdDSA JWT with RFC 8693 `act` chain, exchanged at the service | SCOPE 6.2, 8.1 |
| Field masks on nested and streamed data | Path syntax, buffered, unparseable withheld | SCOPE 6.3 |
| Revocation latency | Short TTL + list covering descendants | SCOPE 6.4 |
| Multi-tenancy | Tenant claim vs resource attribute, hard guard | SCOPE 6.5 |
| Approval flow | Request-bound, single-use, policy-authorised approver | SCOPE 6.6 |

Things worth checking in the council's scope, because they are easy to leave vague:

1. Does it say which enforcement points an agent **cannot** bypass, and what the deployment must do to make that true?
2. Is every level default deny (resource, action, field, route, tool), or only the top one?
3. What happens on each failure: policy error, state store down, audit log full, daemon unreachable?
4. Can a hop ever widen? How is "narrower" defined for patterns, deny lists, budgets, lifetime?
5. Is spend cumulative across sub-agents, or only checked per call?
6. Are tool **inputs** checked, or only outputs?
7. What does the audit log contain, and does it avoid storing the protected values?
8. Is there a conformance suite that every language implementation must pass, and are the vectors in the spec?
9. Are the acceptance tests per milestone concrete enough to fail?
10. Does it state non-goals and limits as plainly as goals?
11. Where does a human's authority come from, and what happens to tokens already issued when the human loses it?

## B. Code

### Run the same vectors against the council's build

`spec/conformance/vectors/*.json` is language-neutral: 12 files, 78 cases, 298
steps. A file is `{"suite", "config"?, "cases": [...]}` and each case is:

```json
{"name": "...", "steps": [
  {"op": "issue_token", "input": {...}, "expect": {"ok": true}, "save": {"t": "token"}},
  {"op": "authorize",   "input": {"token": "$t", ...}, "expect": {"effect": "deny", "reason": "capability_action"}}
]}
```

To use them on another implementation:

1. Load an equivalent of `spec/conformance/bundle` (three resources, five users, three groups, four agents, 21 policies, four roles).
2. Write a runner: `substitute`, `subset`, `run_case` and `run_vectors` in `src/sf_smartdelegate/conformance.py`, about 60 lines together.
3. Map operation names and field names if they differ. Reason codes will differ; compare **effect** first, then reasons.
4. `now` in inputs sets the clock. An implementation without a test clock can run the cases that do not depend on time.
5. A file's top-level `config` is merged into the engine configuration for its cases (`07_require_role`, `08_oidc`, `09_oidc_groups`). The two OIDC files need the ID-token fixtures in `spec/conformance/oidc`.
6. Files `06` to `10` are about roles, live group membership and revoke-by-user; `11` covers `explain`, `apply_obligations`, `approvals`, `reload` and refund input fields. An implementation without roles can run `01` to `05` and `11`, which are 47 of the 78 cases.

The cases that most often separate a careful implementation from a plausible one:

| Case | What it catches |
|---|---|
| "a hop can never widen actions, resources, budget or deny lists" | Narrowing checked on actions only |
| "revoking a parent revokes the whole subtree" | Revocation by token id only |
| "sub-agents together cannot exceed the parent's budget" | Per-token budgets with no shared ledger |
| "filter masks nested objects, arrays and unlisted fields" | Top-level-only masking; unlisted fields passed through |
| "strict mode rejects tool input…" | Outputs filtered, inputs not |
| "an erroring forbid policy denies" | Policy errors ignored (fail open) |
| "the caller cannot inject identity or malformed context" | Identity read from request context |
| "a large refund waits for a human, and the approval is single use" | Approvals that can be replayed or self-granted |
| "data that is not a record cannot be authorised" | Free text returned unmasked |
| "a wildcard capability does not create permission" | Capability treated as permission instead of a ceiling |
| "a role token cannot carry more than the role allows" | A role used as a label, not as a ceiling |
| "live group membership replaces the stored one for that token" | Provider groups added to stored groups, so a removal at the provider has no effect |
| "revoking a user ends every token already issued for them, sub-agents included" | Offboarding that stops new tokens only |

### Mutation check

Change a policy and confirm a test fails. For this build, from the repository
root (the Rust port must be built: `cargo build --release` in `ports/rust`):

```
cp -r spec/conformance/bundle /tmp/mut
# edit /tmp/mut/policies/crm.cedar, e.g. remove a forbid, then recompile and run
ports/rust/target/release/smartdelegate bundle compile --bundle /tmp/mut
PYTHONPATH=src python3 -m sf_smartdelegate conformance spec/conformance/vectors /tmp/mut
```

For 0.3 each of the 21 policies was removed in turn and the vectors run on the
recompiled bundle. Every removal fails at least one case. (The first pass found
one that did not, `refund-fields`; suite `11_operations` was added for it.) Ask
the same of the council's test plan.

### Other checks

- Remove the token check in a tool path: does a test fail?
- Edit one line of the audit log: is it detected?
- Kill the decision service: do tools stop, or proceed?
- Does the generated code actually run in each language it claims, and against what?
