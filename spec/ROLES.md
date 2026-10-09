# Roles: an agent never holds more than the human's role for the task

A human holds roles. For one task, the human lends an agent **one** of them.
The token that comes back is bounded three ways at once:

1. **Held** – the human must hold the role right now (stored membership, or
   live membership from the identity provider).
2. **Ceiling** – the token's capability can never exceed the role's `cap`.
3. **Policy** – every call is still judged by policy, which can read the role
   as `context.iam.role`.

Sub-agents inherit the role and the membership; they can narrow, never change.

## `roles.json` (in the bundle, optional, part of the bundle version)

```json
{"roles": {
  "support-agent": {
    "description": "free text",
    "members": [{"type": "Group", "id": "support"}],
    "cap": {"actions": ["read"], "resources": ["crm.customer/*"], "deny_labels": ["secret"], "budget": {"EUR": 10000}},
    "max_ttl": 600,
    "tasks": ["ticket-*"],
    "agents": ["support-bot"],
    "bindings": {"aws": {"role_arn": "arn:aws:iam::123456789012:role/support"}}
  }
}}
```

| Key | Required | Rule |
|---|---|---|
| `members` | yes, non-empty | `{type, id}` each. The user holds the role when the `User` entity **is** a member or has a member among its ancestors |
| `cap` | yes | a capability (same shape and validation as a token's `cap`); the ceiling |
| `max_ttl` | no | positive integer; the token lives `min(ttl, max_ttl)` seconds |
| `tasks` | no | non-empty list of names with at most one trailing `*`; the request must carry a `task` matching one |
| `agents` | no | same pattern rule; the root agent must match one |
| `bindings` | no | object, opaque to the engine; bridges read it |
| `description` | no | ignored |

Any other key, a wrong type, or a top level that is not `{"roles": {...}}`
fails the bundle load with `roles_parse`. A misspelt key must never loosen a role.

## `issue_token` with a role

New inputs: `role` (string), `groups` (list of group names, a single name, or
`{type, id}` objects; ignored when `id_token` is present).

Order (first failure wins):

1. Identify the user (`user`, or the verified `id_token`).
2. Membership for this token:
   - `id_token` and `idp.groups_claim` configured → the claim's value. A missing
     claim is the empty list. The value is a string, or a list whose items
     are strings or `{type, id}` objects; anything else → `id_token_invalid`. Each name is passed through `idp.group_map`
     when that is configured (names not in the map are dropped) and becomes
     `{type: idp.group_type or "Group", id}`.
   - no `id_token`, and `groups` given → that list (a bare string is a
     one-element list; a name becomes `{type: "Group", id}`); anything else in
     it → `invalid_input`.
   - otherwise → none: `entities.json` is used as it is.
   - Normalise: keep only entities that `entities.json` defines, remove
     duplicates, sort by `(type, id)`.
3. `role` absent: `role_required` if the engine has `require_role: true`;
   else `cap` is required (`invalid_cap`) and issuance continues as before.
4. `role` present:
   1. `unknown_role` if `roles.json` has no such role.
   2. `role_not_held` unless the user holds it. With live membership the
      user's parents are **exactly** the membership list (stored parents of
      that user are ignored; stored attributes are kept; groups keep their own
      stored parents).
   3. `role_exceeded` if `agents` is set and the agent matches none.
   4. `role_exceeded` if `tasks` is set and there is no `task` or it matches none.
   5. Capability: with no `cap` in the request, the token gets a copy of the
      role's `cap`. With a `cap`: first `deny_labels` and `deny_fields` each
      become `sorted(union(request, role))`, then the result must be narrower
      than the role's `cap` by the ordinary narrowing rule, else `role_exceeded`.
      (`invalid_cap` for a malformed `cap` comes before all role checks.)
   6. `ttl = min(ttl, max_ttl)`.
5. The delegation policy check (`delegate` on the agent) as before, with the
   live membership in force and `context.iam.role` set.
6. Claims: `role` (when a role was used) and `grp` (the normalised membership,
   when there was live membership – including the empty list).

The result of `issue_token` and `exchange_token` gains `"role"` and `"task"` (string or null).

## `exchange_token`

The child copies `role` and `grp` from the parent. An input `role` that
differs from the parent's (including a `role` when the parent has none) →
`widening`. Role ceilings need no re-check: a child is narrower than its parent.

## Everywhere a token is evaluated

- `context.iam.role` is the role, or `""`.
- When the token has `grp`, the store used for **every** policy evaluation of
  that request (resource, fields, delegation) has the `User` entity's parents
  replaced by `grp`.
- `principal` in a decision gains `"role"` (string or null); audit records of
  decisions and of token events gain `"role"`.
- Token verification rejects (`token_invalid`, malformed claims) a `role` that
  is not a non-empty string or a `grp` that is not a list of `{type, id}`.
- With `trust_caller_chain`, `chain` may carry `role` and `groups`; no ceiling
  is applied (there is no token).
- `info` gains `"roles"`: the sorted role names.

## Rule ids

Every decision carries `"rule"`, and every error carries `error.rule`:
`"DELEGATE-" + UPPERCASE(reason or code with "_" replaced by "-")`, for example
`DELEGATE-POLICY-FORBID`, `DELEGATE-ROLE-NOT-HELD`.

## Conformance suites and `config`

A vector file may carry a top-level `"config"` object. The runner merges it
over the standard conformance configuration for every case in that file
(`07_require_role`, `08_oidc`, `09_oidc_groups`). `idp.jwks` may be given
inline as a JWKS object, or as `idp.jwks_file`.

## When the human loses the role

Three things together keep an agent from outliving its human's rights:

- **New tokens:** membership is checked at issuance (live from the identity
  provider, or from the last directory sync).
- **Live tokens:** `revoke {"user": U}` ends every token already issued for
  that human, sub-agents included (`API.md`, suite `10_offboarding`). A
  directory sync can call it for every user it removes or whose groups shrink.
- **The gap in between:** a role's `max_ttl` bounds how long a token can live
  if nobody calls revoke.

## What this does not do

- It does not ask AWS, Azure or Google what the human can do at decision time.
  Bridges (`smartdelegate.bridges`) sync membership and role ceilings in, and
  down-scope cloud credentials out. See `docs/BRIDGES.md`.
- A human can start several agents under the same role; each token has its
  own budget. A per-human budget across tokens is not implemented.
