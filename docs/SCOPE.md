# SmartDelegate — project scope

Open-source identity and access management for LLM agents.
Scope version 1.2, written against build 0.3.0. Licence: Apache-2.0. Up to build 0.2 the working name was AgentIAM.

This document is the scope: what the project is meant to be when it reaches 1.0.
It is not a status report. What the build in this repository actually
implements, per engine, and what it leaves out, is in [COVERAGE.md](COVERAGE.md).

Scope 1.2 adds to 1.1: role-scoped task tokens, live group membership and
offboarding (5.1), the bridges to existing identity and cloud IAM (5.8), and
six engines instead of two with a port (5.6).

Section 6 records how this scope answers the six questions the Sprint Council seed
left open, so the council's answers can be compared one by one.

---

## 1. Problem

LLM agents reach databases, SaaS APIs, internal services and other agents with
long-lived API keys or with a human's full OAuth token. Existing IAM (OIDC, RBAC,
cloud IAM) authorises a user or a service once, at the door. It cannot express:

> agent A, acting for user U on task T, may read `customer.email` but not
> `customer.ssn`, may refund up to 200 EUR, and may pass only a narrower
> permission to a sub-agent.

Consequences today:

- An agent can read every column and call every endpoint its key allows.
- Prompt injection turns an over-broad key into a confused-deputy attack.
- Sensitive fields enter the model context and cannot be recalled.
- Auditors cannot answer "which agent read which field, for whom, under which policy version".
- Each team rebuilds partial checks inside its own agent code, in one language,
  with no shared tests, and those checks only bind an agent that cooperates.
- The agent's key does not follow the human. When a person changes role or
  leaves, the agent that acts for them keeps what it had.

## 2. Users

| Who | What they need |
|---|---|
| Platform and security engineers running agents in production (regulated industry) | One policy engine and enforcement points they control, fail-closed behaviour, a threat model |
| Agent developers (MCP, LangChain-style frameworks) | Integration in under 20 lines, clear denial reasons, no new policy language to learn |
| Data owners and compliance officers | Field-level rules by classification label; proof of which agent read which field under which policy version |
| SREs | One binary, predictable latency, shadow mode for rollout, logs they can ship |

## 3. Goals and non-goals

Goals

1. A single decision: `authorize(principal_chain, action, resource, context)` returning allow, deny, or allow with obligations.
2. Delegation that can only narrow: user → agent → sub-agent, recorded in the token, each hop reducing scope, lifetime and budget.
3. Field-level control applied to tool inputs and to tool outputs before content reaches the model.
4. Enforcement points on every path an agent uses, including ones the agent cannot bypass.
5. A verifiable audit trail.
6. The same behaviour in every language, proven by one shared conformance suite.
7. An agent never holds more than one role its human holds, for one task. When the human loses the role, new tokens stop and the tokens already issued can be ended with one call.
8. It extends the identity and cloud IAM a company already runs; it does not replace them.

Non-goals

- Not an identity provider. Humans sign in through the existing OIDC provider.
- Not a replacement for cloud IAM, and not a live view of it: no cloud is asked what the human may do at decision time.
- Not a prompt firewall or content filter. It decides on structured identity, action, resource and fields, not on free text.
- Not a hosted service.
- No claim to contain an agent that bypasses the enforcement points. In-process SDK checks bind cooperating agents only; the proxies are the boundary. [LIMITATIONS.md](LIMITATIONS.md) must say so.

## 4. Architecture

```
 identity provider ── groups in the ID token, or a scheduled directory sync ──┐
                                                                              ▼
            ┌────────────────────────── policy bundle (signed) ──────────────────────────┐
            │ policies/*.cedar     entities.json      catalog.json (resources, fields,   │
            │ policies.json        roles.json          classification labels)            │
            └────────────────────────────────────┬───────────────────────────────────────┘
                                                 │
 human ──OIDC──► token service ──capability token──► agent ──narrower token──► sub-agent
               (role held? ceiling)                    │                          │
                      │                                │                          │
                      ▼                                ▼                          ▼
              ┌──────────────── policy decision point (the engine) ───────────────────┐
              │ verify token chain → capability → Cedar → obligations → field mask    │
              └──────┬─────────────────────┬──────────────────────┬───────────────────┘
                     │                     │                      │
              MCP proxy             HTTP egress proxy        SDK middleware / connectors
            (tools/call)         (REST tools, sidecar)       (in-process, cooperating)
                     │                     │                      │
                     └──────────── append-only, hash-chained audit log ───────────────┘

 agent ── direct cloud call ──► AWS / GCP / Azure, with a credential down-scoped from the token (5.8)
```

Policy decision and policy enforcement are separate. The decision point is the
engine, specified once and implemented per language (5.6). Enforcement points are thin: they collect the
token, map the call to an action and a resource, ask for a decision, and apply
the obligations they get back.

## 5. Components

### 5.1 Identity and delegation

- Every agent, sub-agent and tool has a registered workload identity.
- A human signs in through the existing OIDC provider. The token service verifies the ID token and issues a **capability token** naming the user, the first agent and what the task may do.
- An agent obtains a token for a sub-agent by **token exchange** (RFC 8693 semantics: subject token in, actor named, new token out). The new token records the full chain and can only be narrower:
  - actions and resources: every pattern must be covered by a parent pattern;
  - deny lists (labels, fields): can only grow;
  - budget: per currency, never above the parent's, and a currency the parent lacks cannot be added;
  - lifetime: never past the parent's expiry;
  - depth: bounded.
- Who may delegate to which agent is itself policy (action `delegate` on the receiving agent).
- Tokens are short-lived. Revoking a token revokes every token derived from it.

Roles ([spec/ROLES.md](../spec/ROLES.md)):

- A human holds roles. For one task the human lends an agent **one** of them. `roles.json` in the bundle defines each role: who holds it (`members`), the most a token under it may carry (`cap`, the ceiling), and optionally a maximum lifetime, the tasks it covers and the agents that may be started in it.
- A root token issued with a `role` is bounded three ways: the human must hold the role at issuance; the token's capability can never exceed the role's ceiling; policy still judges every call and can read the role as `context.iam.role`.
- Sub-agent tokens inherit the role. They can narrow the capability; they cannot change the role.
- An engine can be configured to refuse any root token that names no role (`require_role`).

Live group membership:

- Membership at issuance comes from one of three places: the identity provider's group claim in a verified ID token (`idp.groups_claim`, with `idp.group_map` and `idp.group_type`); `groups` supplied by a trusted caller that has them from the provider; or `entities.json` as last written.
- Live membership **replaces** the stored membership of that user for that token; it is not added to it. It is recorded in the token (`grp`), inherited by sub-agent tokens, and used for every policy evaluation of that token.

Offboarding:

- `revoke {"user": U}` ends every token already issued for that human, sub-agent tokens included. It is a cut-off in time, not a ban: whether the human can get a new token is decided by role membership.

### 5.2 Policy decision point

- One request shape and one response shape (section 7), identical in every binding and over the wire.
- Policies are code in an existing open language. No new language.
- Default deny. Forbid overrides permit.
- Fail closed: a policy that cannot be evaluated never produces an allow; an unreadable state store, an unverifiable bundle or an unwritable audit log refuses the request.
- Policies are versioned (the version is in every decision and audit record) and unit-testable from the command line.
- Every decision carries a rule id and every error an `error.rule`: `DELEGATE-` plus the reason or error code in upper case with dashes (`DELEGATE-POLICY-FORBID`, `DELEGATE-ROLE-NOT-HELD`).

### 5.3 Field-level control

- Resources are addressed as `service.resource` with fields `service.resource.field`; nested fields and array elements have paths (`addresses[].zip`).
- Fields carry classification labels (`pii`, `financial`, `secret`, ...). Policies are written against labels, so a new sensitive field is protected when it is labelled, not when every policy is edited.
- Fields are default deny, like everything else.
- Obligations an allow can carry:
  - **field mask**: fields to drop or redact;
  - **row filter**: conditions each record must meet;
  - **spend limit**: a budget carried in the token, consumed across the delegation tree;
  - **rate limit**;
  - **human approval**: the call is held until a permitted person approves that exact request.
- Enforcement points apply obligations to tool **inputs** (strictly: an input carrying a forbidden field is rejected, never silently altered) and to tool **outputs** before any content reaches the model context.

### 5.4 Enforcement points

| Point | Bypassable by the agent? | Purpose |
|---|---|---|
| MCP proxy | No, when it is the agent's only route to the server | Model Context Protocol `tools/call`, `tools/list` |
| HTTP/OpenAPI egress proxy (sidecar) | No, when network policy forces egress through it and it alone holds upstream credentials | REST tools |
| SDK middleware | Yes | Cooperating agents; fastest path; developer ergonomics |
| Framework wrappers (`integrations/`: LangChain, LlamaIndex, function calling, an MCP server, Flowise) | Yes | The same in-process check inside the tools an agent already runs in |
| Connectors: Postgres (column and row filters), REST/OpenAPI, S3-compatible stores | Depends on deployment | Data sources |

The proxies hold the upstream credentials. The agent holds only its capability token.

### 5.5 Audit

- Append-only, hash-chained decision log: principal chain, policy version, request hash, effect, reason, deciding policies, obligations, masked field names.
- The log records field **names**, never field values, and never tokens.
- OpenTelemetry export.
- `explain`: every check and every per-field decision for one request, without side effects.
- Shadow mode: log would-be denials without enforcing, for rollout.

### 5.6 Languages

One specification, several independent implementations.

- `spec/` is the contract: the API ([API.md](../spec/API.md)), roles ([ROLES.md](../spec/ROLES.md)), the formats that must match byte for byte and the porting rules ([PORTING.md](../spec/PORTING.md)), the portable policy subset ([POLICY_SUBSET.md](../spec/POLICY_SUBSET.md)), and the conformance vectors.
- **Python is the reference implementation** (`src/sf_smartdelegate`) and the first place a feature lands: engine, CLI, daemon, proxies, SQL connector, bridges.
- **Native engines in `ports/<language>/`: Java, Node.js, Go, PHP and Rust.** Each implements every operation of the API, roles and live membership included, and reads and writes the same bundle, token, signature, audit and state formats.
- The Rust port embeds the real Cedar engine, which gives it two extra jobs: compiling policy sources, and recording Cedar's answers for the evaluation vectors every other engine is held to.
- `ports/js` is a REST client for browsers, Deno and Node, not an engine.
- A REST (OpenAPI) and gRPC decision daemon, so a language without a port uses a thin client.
- An engine port need not carry the enforcement points. The proxies exist in the reference and in the Rust port; a port without them says so in its README.
- A state directory may be shared by processes of different ports only if they take the same lock on it. A port that cannot take that lock must say so and must not be given a shared directory ([ports/README.md](../ports/README.md) has the table).
- **A port is released only when it passes the conformance vectors, the policy-evaluation vectors, and the cross-port matrix** (`ports/conformance/matrix.py`: every port's tokens, sub-agent tokens, signed bundles and audit logs are checked by every other port).

Version 1.0 of this scope had one Rust core with bindings. That gives one implementation to audit, but makes every language depend on a native library and makes Rust the only place a contributor can change behaviour. The cost of the present design is N implementations of security-critical logic; the vectors and the matrix are what keeps them the same, so they are part of the specification, not test code.

### 5.7 Operations

- A CLI.
- A minimal admin console.
- Signed policy bundles with a local cache.
- One binary for a laptop; a container image for Kubernetes.

### 5.8 Bridges to existing IAM

`sf_smartdelegate.bridges` ([BRIDGES.md](BRIDGES.md)) connects the role model to the identity and access systems a company already runs. The engine does not depend on it.

Inbound, so that the agent's bound follows the human's:

- **Claims to groups.** Turn the claims of a verified ID token into the group list passed at issuance. Presets for Entra ID, Okta, Keycloak, Cognito, Auth0, Google and a generic claim path. A group-claim overage must be an error, never "no groups".
- **Directory sync.** Read users, groups and memberships from SCIM 2.0, Okta, Entra ID, Keycloak, Google Workspace or AWS IAM Identity Center and write `entities.json`: atomically, with a guard against a response that would remove a large share of users, and with the option to revoke the tokens of every human who was removed or lost a group.
- **Role ceilings from cloud permissions.** Lower a role's `cap` to what the human may do in AWS, Google Cloud or Azure. It can never widen what `roles.json` had.

Outbound, for an agent that must call a cloud API directly:

- A cloud credential no wider than the token: an AWS STS session policy, a Google Credential Access Boundary, the scopes of an Azure On-Behalf-Of request, each generated from the token's capability through a mapping file. What does not map is not granted.
- A cloud credential carries only actions on resources. Field rules and budgets stay with the enforcement points, and the generators must report them as not enforced.

Acceptance for every adapter is a run against the real service. Tests against fakes do not count as that.

## 6. Decisions on the six open questions

| # | Question | Decision in this scope | Why | Cost accepted |
|---|---|---|---|---|
| 1 | Policy language: Cedar or OPA/Rego? | **Cedar**, compiled to Cedar's JSON policy form; ports evaluate a declared subset of it (`spec/POLICY_SUBSET.md`) | Deny-by-default and forbid-overrides are built into the language rather than conventions; it is a Rust library, so the core embeds it without a second runtime; entity hierarchies fit users/groups/agents; policies are analysable | Smaller ecosystem than Rego; no general-purpose data transformation, so obligations are expressed as policy annotations (5.3) rather than computed by the policy. Extension types (ip, decimal, datetime) and schema validation are outside the portable subset; compiling policy text needs the Cedar toolchain |
| 2 | Token format: JWT with a delegation claim, or an attenuable Biscuit-style token? | **JWT (EdDSA) with the RFC 8693 `act` claim**, exchanged at the token service | Every language can already parse a JWT; exchange gives the service one place to check narrowing, apply delegation policy and record the hop | No offline attenuation: an agent must reach the token service to delegate. Biscuit remains a candidate for a later version |
| 3 | Field masks on nested JSON and streamed responses | Path syntax `a.b` and `a[].b`; longest catalogued path decides; unlisted paths are dropped; **responses are buffered**, and a response that cannot be parsed into records is withheld | A mask can only be correct on a complete, parsed document | No token-by-token streaming through a masked route in 1.0. Record-delimited streams (NDJSON) are the planned next step |
| 4 | Revocation latency | Short lifetimes (default 15 min, max 60 min) plus a revocation list that covers a token and all its descendants. Target: effective on the next decision for components sharing a state store; bounded by token lifetime for a verifier that does not | Short lifetimes bound the damage even where the list has not propagated | A shared state store, or a push channel, is required for immediate revocation everywhere |
| 5 | Multi-tenancy | Tenant is a claim in the token and an attribute of the resource; a mismatch is denied before policy runs. One bundle per deployment in 1.0 | A hard guard that no policy mistake can open | Per-tenant bundles and per-tenant keys are post-1.0 |
| 6 | Approval flow | An approval-required permit holds the call and returns an approval id derived from the exact request (user, chain, action, resource, context). Approving is itself authorised by policy; the user the agent acts for cannot approve; an approval is single-use and expires | The approver approves one concrete request, not a class of requests | No built-in notification channel; integrators deliver the approval id to approvers |

Two decisions were taken after the six, with scope 1.2:

| Question | Decision | Why | Cost accepted |
|---|---|---|---|
| Where does a human's authority to delegate come from? | A role in `roles.json` that the human holds through group membership; the role's `cap` is a ceiling on the token (5.1) | The agent's bound follows the human's place in the organisation, and one file states the most each role can hand to an agent | Roles are a second thing to maintain next to policy; membership is as fresh as its source (the ID token in use, or the last sync) |
| What happens to live tokens when the human loses a role or leaves? | Revoke by user: a cut-off time per user, checked on every token of that user (5.1). Decision 4 on latency applies unchanged | One call, no list of token ids needed; sub-agent tokens fall with it | It ends all of the user's tokens, also those under roles still held; a verifier that shares no state store does not see it |

## 7. Decision API

### Request

```json
{
  "token": "<capability token>",
  "action": "read",
  "resource": {"path": "crm.customer", "id": "c-1", "attrs": {"tenant": "acme"}},
  "context": {"spend": {"currency": "EUR", "amount": 5000}},
  "fields": ["email", "ssn"],
  "data": { },
  "strict": false,
  "dry_run": false
}
```

- `token` carries the principal chain. Identity never comes from `context`; the key `iam` in `context` is rejected.
- `resource.attrs` are supplied by the enforcement point, not by the agent.
- Amounts are integers in minor units (5000 = 50.00 EUR).
- `data` (optional) is one record or a list of records to mask. `strict` rejects data that carries a denied field (use for inputs).

### Response

```json
{
  "ok": true,
  "effect": "allow",
  "reason": "policy_permit",
  "rule": "DELEGATE-POLICY-PERMIT",
  "policies": ["support-read-customer"],
  "policy_version": "885eee2e…",
  "decision_id": "d-41c0…",
  "principal": {"user": "alice", "agent": "refund-helper", "chain": ["support-bot", "refund-helper"],
                "tenant": "acme", "task": "T-17", "role": "support-agent", "token_id": "9f…"},
  "obligations": {
    "fields": {"allow": ["email", "id"], "deny": ["ssn"], "redact": []},
    "row_filter": [{"column": "region", "op": "eq", "value": "EU"}],
    "rate_limit": {"limit": 3, "window_seconds": 60, "used": 1}
  },
  "data": { },
  "masked": ["ssn"],
  "rows_dropped": 0
}
```

A deny is a normal response (`"effect": "deny"`) with a machine-readable `reason`:
`token_invalid`, `token_expired`, `token_revoked`, `unknown_resource`, `unknown_field`,
`tenant_mismatch`, `capability_action`, `capability_resource`, `no_matching_permit`,
`policy_forbid`, `policy_error`, `obligation_unresolved`, `rate_limited`,
`budget_exceeded`, `approval_required` (with `approval: {id, label}`), `field_denied`.
`rule` is the reason as a rule id (`DELEGATE-CAPABILITY-ACTION`). `principal.role`
is `null` for a token that names no role.

A malformed request is an error (`"ok": false, "error": {"code", "message", "rule"}`), never an allow.

### Decision order

First failure wins.

1. Token: signature, issuer, audience, expiry, revocation of the token and every ancestor, then the user's offboarding cut-off.
2. Catalog: the resource path must be known.
3. Tenant: token tenant equals resource tenant, when both exist.
4. Capability: the token covers the action and the resource.
5. Policy: default deny; forbid overrides permit; an erroring forbid denies.
6. Obligations of the deciding permits: row filter, rate limit.
7. Budget: against every token in the delegation chain.
8. Human approval.
9. Fields: token deny lists, then policy per field.
10. Strict mode on supplied data.

### Other operations

`issue_token`, `exchange_token`, `inspect_token`, `revoke`, `filter`,
`apply_obligations`, `explain`, `approve`, `approvals`, `audit_verify`,
`audit_tail`, `info`, `reload`. Exact shapes: [spec/API.md](../spec/API.md).

`issue_token` takes `role` and `groups` and runs the role checks before the
delegation policy; it fails with `unknown_role`, `role_not_held`,
`role_exceeded` or `role_required`. `issue_token` and `exchange_token` return
`role` and `task` with the token. The order of the checks is in
[spec/ROLES.md](../spec/ROLES.md).

## 8. Schemas

### 8.1 Capability token (JWT, EdDSA)

```json
{
  "iss": "smartdelegate://prod", "aud": "smartdelegate",
  "sub": "user:alice",
  "act": {"sub": "agent:refund-helper", "act": {"sub": "agent:support-bot"}},
  "iat": 1700000000, "exp": 1700000300, "jti": "9f2c…",
  "anc": ["51ab…"],
  "tnt": "acme", "task": "T-17",
  "role": "support-agent",
  "grp": [{"type": "Group", "id": "support"}],
  "cap": {
    "actions": ["read", "create"],
    "resources": ["crm.customer/c-1", "billing.refund/*"],
    "deny_labels": ["secret"],
    "deny_fields": ["crm.customer.notes"],
    "budget": {"EUR": 20000}
  }
}
```

`act` follows RFC 8693: the current actor is outermost. `anc` lists ancestor token
ids, root first. Patterns allow one trailing `*`.

`role` is present when the token was issued under a role. `grp` is present when
there was live group membership at issuance, also when that membership is the
empty list; it is sorted, without duplicates, and holds only groups that
`entities.json` defines. A token without `grp` is judged against the stored
membership. `tnt`, `task`, `role` and `grp` are each left out when not used.
A sub-agent token copies `role` and `grp` from its parent.

### 8.2 Policy bundle

```
bundle/
  policies/*.cedar     @id("name") names a policy
  policies.json        the compiled policies every engine loads, with the hashes of their sources
  entities.json        users, groups, agents (Cedar entity format)
  catalog.json         resources, entity types, fields, labels, mask mode
  roles.json           optional: roles, who holds them, their ceilings
  tests/*.json         policy unit tests
  bundle.sig.json      file hashes + Ed25519 signature
```

The bundle version and the signature cover `policies.json`, `entities.json`,
`catalog.json` and `roles.json`. `roles.json`:

```json
{"roles": {"support-agent": {
  "members": [{"type": "Group", "id": "support"}],
  "cap": {"actions": ["read"], "resources": ["crm.customer/*"], "deny_labels": ["secret"], "budget": {"EUR": 10000}},
  "max_ttl": 600, "tasks": ["ticket-*"], "agents": ["support-bot"],
  "bindings": {"aws": {"role_arn": "arn:aws:iam::123456789012:role/support"}}
}}}
```

An unknown key or a wrong type in `roles.json` fails the bundle load: a
misspelt key must never loosen a role. `bindings` is opaque to the engine; the
bridges read it.

`catalog.json`:

```json
{"resources": {"crm.customer": {"entity_type": "Customer", "fields": {
  "email": {"labels": ["pii"]},
  "ssn": {"labels": ["pii", "secret"]},
  "addresses[].geo": {"labels": ["internal"]},
  "card.number": {"labels": ["financial", "secret"], "mask": "redact"}
}}}}
```

What a policy sees:

- principal: `Agent::"<the acting agent>"`
- action: `Action::"<action>"`
- resource: the catalogued entity (`Customer::"c-1"`), or for a field decision `Field::"crm.customer.ssn"` with attributes `name`, `resource`, `labels`, `of`
- `context.iam`: `user` (entity), `user_id`, `user_attrs`, `chain`, `depth`, `root_agent`, `tenant`, `task`, `role` (`""` when the token names none)
- group membership of the user: from the token's `grp` when it has one, else from `entities.json`
- the rest of `context` as supplied by the enforcement point

Obligation annotations on a permit: `@row_filter("col == context.key")`,
`@rate_limit("count/seconds")`, `@require_approval("label")`.

### 8.3 Audit record

```json
{"seq": 42, "ts": 1700000000, "prev": "<hash of record 41>", "hash": "<sha256(prev + canonical record)>",
 "event": "decision", "decision_id": "d-…", "effect": "allow", "reason": "policy_permit", "enforced": true,
 "policies": ["support-read-customer"], "policy_version": "…",
 "user": "alice", "chain": ["support-bot"], "role": "support-agent", "tenant": "acme", "task": "T-17", "token_id": "…",
 "action": "read", "resource": "crm.customer/c-1",
 "obligations": {}, "masked": ["ssn"], "rows_dropped": 0, "request_hash": "…"}
```

Other events: `token_issued`, `token_exchanged`, `token_revoked`, `user_revoked`,
`approval_granted`, `obligations_applied`, `bundle_reloaded`.

## 9. Security requirements

1. Default deny at every level: resource, action, field, route, MCP tool, MCP method.
2. Fail closed on: unparsable input, policy evaluation errors in a forbid, unknown resources and fields, unverifiable tokens, unsigned or altered bundles (when signing is required), unreadable state, unwritable audit log, unreachable decision daemon.
3. Identity only from a verified token. Callers cannot inject it.
4. Upstream credentials live in the proxies. Capability tokens are never forwarded upstream.
5. Data that cannot be parsed into records cannot be authorised and is withheld.
6. The audit log holds no field values and no tokens.
7. No offline path widens a token.
8. A threat model ships with 1.0 (prompt-injected agent, malicious sub-agent, compromised tool server, stolen token, tampered bundle, tampered log, bypass of enforcement points, stale or compromised membership source, differences between ports).
9. A role is a ceiling, never a grant. No request, sub-agent or bridge output widens it.
10. Membership that cannot be read is membership in nothing: a missing group claim, an unmapped or unknown group and a failed sync never add access.
11. A bridge never produces a cloud credential wider than the token it was made from. What does not map is not granted. For AWS that means an explicit deny-all session policy, never an absent one, which would leave the cloud role's full permissions.

## 10. Performance targets

Targets, to be measured and published with the benchmark method:

- In-process decision: p99 under 5 ms.
- Daemon decision: p99 under 20 ms.
- Integration: under 20 lines of code for one tool.

## 11. Repository tree

```
smartdelegate/
  README.md  CHANGELOG.md  LICENSE  pyproject.toml  test_all.sh  test_all.ps1
  docs/
    SCOPE.md  COVERAGE.md  LIMITATIONS.md  THREAT_MODEL.md  BRIDGES.md
  spec/
    API.md  ROLES.md  openapi.yaml  PORTING.md  POLICY_SUBSET.md  COMPARE.md
    conformance/
      bundle/         the fixed bundle every implementation loads (with roles.json)
      vectors/*.json  engine cases: steps of {op, input, expect, save}
      eval/           policy-evaluation cases with the real Cedar engine's answers
      oidc/           ID-token fixtures
  src/sf_smartdelegate/  reference: engine, cedar, tokens, fields, audit, state, bundle, cli, daemon,
                      httpproxy, mcpproxy, guard, sql, client, core, models, conformance,
                      example_bundle/, bridges/
  tests/              the reference's tests, and the tests of bridges and integrations
  ports/
    java/             native engine + REST client
    node/             native engine, CLI, daemon, REST client
    go/               native engine, CLI, daemon, REST client
    php/              native engine, CLI, daemon, front controller, REST client
    rust/             engine with real Cedar, CLI, daemon, proxies, C ABI; compiles policies
    js/               REST client, middleware, TypeScript types
    conformance/      run.sh (the shared suites against every port), matrix.py (ports against each other)
  integrations/       adapter and wrappers: LangChain, LlamaIndex, function calling, MCP server,
                      GitHub Action, pre-commit, VS Code, Flowise
  examples/           quickstart, stand-in upstreams, route and tool mappings, bridges walkthrough
  demo/  site/        the scripted demo's notes; a browser playground for the delegation rules
```

## 12. Dependencies

| Implementation | Dependency | Purpose |
|---|---|---|
| Python (reference) | `cryptography` | Ed25519, and RSA/ECDSA for OIDC ID tokens. Everything else is the standard library |
| Bridges (`sf_smartdelegate.bridges`) | none beyond the reference's | Standard library only; functions meant for a cloud SDK return plain dicts the caller passes to that SDK |
| Java | none (JDK 17+) | |
| Node.js | none (Node 18+) | `node:` built-ins only |
| Go | none (Go 1.21+) | Standard library only |
| PHP | none from Composer (PHP 8.1+); extensions `sodium`, `openssl`, `json`, `mbstring` | Ed25519; RSA and ECDSA for OIDC ID tokens |
| Rust port | `cedar-policy` 4.x, `jsonwebtoken` 9.x, `ring` 0.17, `serde`, `serde_json`, `sha2`, `hex`, `base64`, `tiny_http`, `ureq` | real Cedar, tokens, JSON, HTTP |
| JavaScript client | none (Node 18+) | |
| Integrations | `langchain-core`, `llama-index-core` only for the wrappers of those frameworks | |
| Planned | gRPC, OpenTelemetry, a Postgres wire connector | |

## 13. Conformance suite

Language-neutral JSON, in three parts.

1. **Engine vectors.** A case is a list of steps; each step names an operation, its input and a partial expected result. `save` stores a value from a result (for example a token) and `$name` substitutes it in later steps. Time is supplied by the case, so cases are deterministic. Each case runs against a fresh engine loaded with `spec/conformance/bundle`; a vector file may carry a `config` that is merged into the engine configuration. Areas: tokens; delegation and narrowing; field decisions and masking; spend, rate limits and approval; guards and failure modes; audit; roles and their ceilings; `require_role`; OIDC issuance; group claims as live membership; offboarding.
2. **Policy-evaluation vectors.** Policies with requests and the answer the real Cedar engine gives. A port's evaluator must give the same answer. The Rust port regenerates and re-checks them, so they cannot drift from Cedar.
3. **Interoperability.** Every port against every other port, not only against the reference: tokens (with role and live groups), sub-agent tokens, tampered tokens, signed bundles and audit logs; and one state directory used in turn by the ports that share a lock.

Behaviour that the ports were found to disagree on becomes a written rule with a test in every port (`spec/PORTING.md`, "Strictness").

## 14. Milestones and acceptance tests

| | Milestone | Accepted when |
|---|---|---|
| a | Spec, decision API, token format, conformance vectors | Vectors exist for every deny reason in section 7 and every narrowing rule in 5.1; mutating any example policy makes at least one vector fail |
| b | Reference engine (Python), CLI, audit log | Engine passes all vectors and gives Cedar's answer on every evaluation vector; editing, deleting or reordering any audit line is detected |
| c | Second implementation (Java), TypeScript client, MCP proxy | The Java engine passes all vectors and interoperates with the reference; through the MCP proxy an unmapped tool is hidden and uncallable, a mapped tool's result is masked, and non-JSON output is withheld |
| d | HTTP proxy, Postgres and REST connectors, field masking | Through the proxy: the agent never holds the upstream key; a write with a forbidden field never reaches the upstream; path and query tricks do not change which resource is authorised; the Postgres connector never names a denied column |
| e | Further ports (Rust, others), console, shadow mode | Each port passes all three parts of the suite; shadow mode changes no data and logs every would-be denial; console lists held approvals and verifies the audit chain |
| f | Threat model, benchmarks, 1.0 | Each threat maps to a test or a documented limitation; published p99 figures meet section 10 with the method stated |
| g | Roles, live membership, offboarding | Every engine passes the role, group-claim and offboarding vectors; a token issued by any engine with a role and live groups gives the same decision and the same masked data in every other engine |
| h | Bridges | Each adapter has been run against the real service it is written for and its list of unverified assumptions is empty; no generated cloud policy grants anything outside the token's capability |

## 15. Risks

| Risk | Mitigation |
|---|---|
| Teams deploy only the SDK middleware and believe they are protected | LIMITATIONS.md leads with this; the README's first deployment example uses a proxy |
| The catalog drifts from real schemas, so new fields are silently dropped | Dropping unlisted fields is the safe failure; shadow mode reports `would_mask` so drift is visible before enforcement |
| Annotation-based obligations grow into a second policy language | Keep to three annotations; anything richer is a policy condition or an enforcement-point feature |
| Bearer tokens are stolen from an agent's memory | Short lifetimes, narrow capabilities, revocation; proof-of-possession (DPoP or mTLS binding) is the 1.x item |
| Decision latency on hot paths | In-process engine for cooperating agents; entity store kept in memory |
| Ports drift apart | The three-part conformance suite gates every release; a behaviour change lands in the vectors first; a difference found between ports becomes a rule in `spec/PORTING.md` with a test in each port |
| Membership goes stale: the sync stops, or an old ID token is replayed, and a removed human keeps a role | Short role lifetimes (`max_ttl`); the sync records when it last ran so staleness can be monitored; revoke by user for tokens already issued |
| A mapping file (groups, claims, cloud permissions) widens access by one wrong line | Mapping files are reviewed like policy and kept with the bundle; unmapped means not granted |
| A bridge is wrong about a provider's API because it was written from documentation | Acceptance is a run against the real service (5.8, milestone h); until then every adapter says so |
| A cloud credential outlives the token it was made from | Shortest lifetime the cloud allows; the proxies stay the enforcement point where the cloud cannot be told to stop |

## 16. Candidates raised in review

Not yet in scope, worth adopting.

From scope 1.1. None of these five has been built:

- Push revocation to every enforcement point (a pub/sub channel), so a verifier that shares no state store learns of a revocation in seconds. Revoke by user makes this more pressing: a verify-only engine does not see it either.
- Anchoring the audit chain head in storage the writer cannot change, on a schedule.
- Per-tenant bundles and signing keys.
- Named OpenTelemetry attributes for decisions.
- Delivering approval requests through the identity provider's console.

Raised while the bridges were written, and since adopted (now in 5.1 and 7):

- Revoke by user.
- `task` in the result of `issue_token` and `exchange_token`.

Open, from [BRIDGES.md](BRIDGES.md) ("Not implemented", "Engine changes that would help"):

- A budget per human across all of their tokens. Today each token has its own.
- A distinct error for a group-claim overage on the engine's own `idp.groups_claim` path, which now answers `role_not_held`.
- An engine option to reload when `entities.json` changes, so a sync needs no separate reload call.
- Receiving SCIM push and deprovisioning events, instead of waiting for the scheduled sync.
- Incremental (delta) sync, SCIM cursor pagination and filters; retries with back-off on HTTP 429 and 5xx.
- Directory sync for Auth0; adapters for Ping, OneLogin and JumpCloud other than through SCIM; LDAP and Active Directory directly; SAML assertions.
- Google: service-account authentication for the Directory API; service-account impersonation for APIs other than Cloud Storage.
- Okta: OAuth 2.0 service-app authentication.
- AWS: credentials from profiles, the SSO cache or instance metadata; `AssumeRoleWithWebIdentity`.
- Azure: managed identity; certificate-based client assertion.
- A `delegate_as` helper that does claims, delegation and down-scoping in one call.

Open, from the port READMEs:

- HTTP and MCP proxies in the Node.js, Go and PHP ports; a command line and a daemon for the Java port.
- A state-directory lock that Node.js and Java can share with the other ports.
- Typed helpers for `role`, `groups` and revoke-by-user in the JavaScript REST client (`ports/js`), which today passes them only through `call`.
- TLS in the daemons.
- Runs on Windows and macOS, and on the older runtime versions each port declares but was not run on.

## 17. Out of scope for 1.0

Offline-attenuable tokens; per-tenant bundles; proof-of-possession tokens;
token-by-token streaming through masked routes; a policy authoring UI; an
approval notification service; content inspection of free text; asking a
cloud what the human may do at decision time; any cloud enforcement of field
rules or budgets.
