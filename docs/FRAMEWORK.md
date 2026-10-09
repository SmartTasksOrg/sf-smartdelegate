# SmartDelegate in a governance and safety framework

SmartDelegate is one control. This document says what kind, which principles
it implements and where each stops, how it relates to the IAIso framework of
the Smart* family, how it relates to other frameworks an adopter may follow,
and which signals connect it to a governance layer you already run.

Nothing here is a claim of certification, conformance assessment or
compliance with any framework. Build 0.3.0 has had no independent security
review ([LIMITATIONS.md](LIMITATIONS.md)).

## 1. What it is, in framework terms

**An authority-bounding control with evidence.** It answers, at the moment a
human hands work to an agent and at every tool call after that: *who may act
for whom, within what role, for which task*, and it records each answer.

| It is | It is not |
|---|---|
| A bound on what an agent's credential can do: one role of one human, for one task, narrowing at every hop | Containment of a hostile process. Code in the agent's process can skip an in-process check; only a proxy that holds the credential and is the only network path is a boundary, and that depends on the deployment (LIMITATIONS, section 1) |
| A decision point: default-deny policy on every call, with field masking, budgets and human approval | A content filter. It works on structure: resources, fields, labels. A sensitive value typed into a permitted free-text field is not detected (LIMITATIONS, section 10) |
| Evidence: a hash-chained record of every decision, issuance, approval and revocation | Behavioural or pressure monitoring. It does not watch what a model does, measures no load and makes no call to any model |
| A way to make revocation follow the human | An identity provider, a directory or a cloud IAM. It extends the ones you run ([BRIDGES.md](BRIDGES.md)) |

A framework that has layers for "what may this agent do" and "what did it do"
gets those two from SmartDelegate. Layers for "is this agent behaving
normally", "can this process be stopped", "is this output acceptable" need
other controls.

## 2. The principles it implements

Stated generically, so they can be matched to whatever framework you use.
Each has where it lives in the product and where it stops.

| Principle | Where it lives | Its limit |
|---|---|---|
| **Least authority per task** | A root token names one role and one task; its capability cannot exceed the role's ceiling in `roles.json`; `max_ttl`, `tasks`, `agents` per role ([spec/ROLES.md](../spec/ROLES.md)) | Roles are opt-in per request unless `require_role` is set. A budget is per token: a human who starts several agents gets one budget per token (THREAT_MODEL, threats 22 and 23) |
| **Authority only narrows across delegation** | `exchange_token`: the sub-agent's capability must be the parent's or less, deny lists only grow, the role cannot change, the chain has a depth limit; spend is charged to every token in the chain | Within what its token and policy allow, an injected agent can still act (threat 1). Budgets across engines that do not share state are not summed (LIMITATIONS, section 5) |
| **Default deny** | No matching permit is a denial; fields are removed unless a permit covers them; an unmapped tool, route or resource is refused | Policies are not schema-checked: a misspelt attribute in a permit makes it silently never apply (LIMITATIONS, section 9) |
| **Fail closed** | A malformed request, an unreadable state file, an audit record that cannot be written, a bundle that does not verify, an erroring forbid and an unreachable daemon all refuse (threat 16) | Shadow mode lets would-be denials through by design. Two test switches remove checks and nothing warns when they are on (threat 21a) |
| **Separation of duties** | Enforcement points hold the pep key and cannot issue; a verify-only engine cannot issue; the approver cannot be the user the agent acts for; a bundle is signed by a key the engine does not need | The admin key is one static secret for issuing for any user, revoking, approving and reloading (threat 19). Who approved or revoked (`by`) is asserted by the caller, not authenticated (threats 17, 35) |
| **Human approval for marked actions** | `@require_approval` on a permit holds the call; the approval is bound to the exact request, is used once, expires, and needs a policy permit for the approver | The approver's identity is asserted by the admin-key holder (threat 17). There is no "reject": a held request waits |
| **Revocation follows the human** | Revoke-by-user ends every token already issued for a human, sub-agents included; a directory sync can call it for everyone removed; an ID token issued at or before the cut-off is refused | Not immediate at an engine with its own state; does not reach cloud credentials already issued; a cut-off in time, not a ban (LIMITATIONS, section 5; threat 36) |
| **Tamper-evident evidence** | `audit.jsonl`: each record hashes the one before; field names, never values or tokens | Removal of the newest records, and a fully re-forged chain, need an anchor kept elsewhere (LIMITATIONS, section 12). Refused token requests are not logged. The record of an issued token does not hold who supplied the groups (threat 25) |
| **Enforcement outside the agent process** | `sf-smartdelegate http-proxy` and `sf-smartdelegate mcp-proxy` hold the upstream credential and decide every call | A boundary only when egress is restricted to the proxy and the credential exists only there (threat 9). The servers are small, do not terminate TLS and are not hardened (LIMITATIONS, section 11) |

## 3. IAIso

### 3.1 What this section rests on

IAIso is the framework the Smart* family aligns to. This document describes
it **only as the family's own documents describe it**. The source is
SmartFabric, the family's implementation of the "IAIso Fabric Protocol",
whose documents say they bind to "IAIso v5.0". The IAIso standard's own
repository was not consulted for this document; where SmartFabric's
description and the standard differ, the standard is right and this section
is wrong.

Each statement below names the file it comes from; `smartfabric/` is the root
of the SmartFabric repository, `smartroute/` of the SmartRoute repository.
Neither is part of this repository.

| Statement | Source in the SmartFabric repository |
|---|---|
| The IAIso engine answers "is this agent over pressure?"; the fabric protocol answers "what is the pressure of the whole system, is any node about to breach, and can a global halt be honoured everywhere at once?" (emphasis in the original removed) | `smartfabric/README.md` |
| Pressure is a per-node quantity `p` with a rate `dp/dt = I(t) - D(p,t) - R(p,t)`: input accumulation ("compute intensity, token velocity, tool-call density"), dissipation, and release, "atomic reset when p ≥ P_max" | `smartfabric/docs/07_IAISO_CORE_BINDING.md`, "The pressure model, distributed" |
| Zones: `nominal` (p < 0.70), `warning` (0.70 to 0.85), `escalation` (0.85 to 0.95, "multi-party auth required before further expansion"), `release` (p ≥ 0.95, atomic reset). The same document says these defaults "are not empirically calibrated" | `smartfabric/docs/07_IAISO_CORE_BINDING.md`, "Zones (wire enum)" |
| Default coefficients include a pressure increment per tool call (`tool_coefficient`) and per depth level (`depth_coefficient`) | `smartfabric/docs/07_IAISO_CORE_BINDING.md`, the fingerprint field table |
| Seven containment layers, 0 to 6: 0 Physical Boundaries, 1 Optimization Bounds, 2 Memory & Planning, 3 Ecosystem Coupling (with 3.5 Regime Shift), 4 Escalation Bridge ("halt + multi-party authorization (default 2)"), 5 Self-Governance ("ConsentScope tokens, org accountability"), 6 Existential Guards ("singleton prevention, replication caps, global halt") | `smartfabric/docs/07_IAISO_CORE_BINDING.md`, "The 7 containment layers (0-6) as fabric responsibilities" |
| Five invariants: 1 Bounded Pressure, 2 No Learning Across Resets, 3 Clocked Evaluation Only, 4 Consent-Bounded Expansion ("every tool call / expanding verb carries a signed ConsentScope; the fabric rejects expansion without one (default deny)"), 5 No Proxy Optimization (pressure is computed "outside the model"). "Any invariant violation → automatic Layer-4 escalation" | `smartfabric/docs/07_IAISO_CORE_BINDING.md`, "The 5 invariants as wire conformance" |
| Halt: `halt.global` is a protocol verb that "every node MUST honour"; in the reference node, after `halt.global`, "every expanding verb is refused until the node is brought back" | `smartfabric/docs/07_IAISO_CORE_BINDING.md`, "CIR verbs, containment-annotated"; `smartfabric/docs/09_TRANSPORT_AND_OPERATIONS.md`, "What the node actually enforces" |
| Every node publishes a fingerprint: identity, ports, standards, verbs, placement, contract, and an `iaiso` block (enforced layers, pressure settings, consent issuer) | `smartfabric/docs/00_OVERVIEW.md`; `smartfabric/schema/example.fingerprint.json` |
| Design invariant 4, "Everything is observable and attributable": "no silent actions; provenance is mandatory". The reference node handles a `provenance.emit` verb | `smartfabric/docs/00_OVERVIEW.md`, "Design invariants"; `smartfabric/docs/09_TRANSPORT_AND_OPERATIONS.md` |
| The trust boundary: the framework "bounds a cooperating node" and "does not contain a node that executes arbitrary code in its own process"; adversarial containment needs "an out-of-process anchor (seccomp, separate UID, container, VM, hypervisor FLOP cap)" | `smartfabric/docs/07_IAISO_CORE_BINDING.md`, "The trust boundary" |
| Of the fabric's services, the escalation broker as a distinct service, the negotiator and a highly available control-plane store are "still ahead" | `smartfabric/docs/04_MAPPING.md`, "Implementation status (v0.5.0)" |

SmartFabric's trust boundary and SmartDelegate's are the same sentence in two
places: both bound a cooperating participant in process and both need
something outside the process for an adversarial one. SmartFabric's
"mechanical" primitives (pressure, release, halt) act on a node's activity;
SmartDelegate acts on a node's authority. They are complementary and neither
substitutes for the other.

### 3.2 The section label

This repository's files say "IAIso §10 · Delegation" (`README.md`,
`MANIFESTO.md`, `.smart.json`, `spec/iaiso-map.json`). **That number is a
working label chosen by the authors of this repository. It was not assigned
by the standard.** The family index available to us lists nine tools under
§1 to §9, and SmartFabric labels itself "§0 · Fabric"; neither lists a §10.
Treat the label as a name, not as a reference into the standard's text.

### 3.3 There is no code integration today

**No code in this repository calls SmartFabric, the IAIso engine or any other
Smart\* tool, and none of them calls this repository.** SmartDelegate emits
no fabric event, publishes no fingerprint, reads no pressure and honours no
halt signal. `spec/iaiso-map.json` lists `stacks_with` as a statement of
fit, not of wiring. The table below is strict about this.

Status values, used here and in `spec/iaiso-map.json`:

- **implemented in this repo**: the SmartDelegate side exists and is tested here;
- **interface exists**: this repository has an extension point with a
  contract and a reference implementation that the hook would use; the
  IAIso-side adapter is not written;
- **proposed, not built**: a design, below; no code.

| IAIso concept (as SmartFabric describes it) | What SmartDelegate has | Direction | Status |
|---|---|---|---|
| Consent-bounded expansion, default deny (invariant 4) | Every tool call needs a signed capability token and a policy permit; default deny | SmartDelegate enforces its own equivalent | implemented in this repo (as SmartDelegate's own control; it does not issue or check a ConsentScope) |
| ConsentScope tokens (Layer 5) | The capability token: signed, expiring, scoped to actions, resources, a role, a task and a delegation chain | SmartDelegate could supply the scope a ConsentScope is minted from, or check one | proposed, not built. The ConsentScope format was not available to us; no compatibility is claimed |
| Escalation with multi-party authorization (Layer 4) | `@require_approval`: a second human, never the requester, bound to the exact request, used once | SmartDelegate supplies a held request and takes a verdict | interface exists (`ApprovalChannel`, `pump` in `interfaces/`); an adapter to a fabric escalation broker is not written, and SmartFabric lists that broker as still ahead |
| Global halt (Layer 6, `halt.global`) | Revocation by token and by user; no deny-all mode | SmartDelegate would take the signal | proposed, not built (hook H1) |
| Pressure and zones | Nothing. SmartDelegate measures no load | SmartDelegate could supply inputs (tool calls and delegation depth per chain) and take the zone as a signal | proposed, not built (hooks H2, H3) |
| Provenance on the observability plane | The hash-chained audit log | SmartDelegate supplies records | interface exists (`AuditSink`, `ship`); an exporter to fabric events is not written (hook H3) |
| Node fingerprint | `info`: version, policy version, key id, public key, mode, roles | SmartDelegate would publish one | proposed, not built (hook H4) |
| Planning-depth and tool-expansion limits (Layer 2) | A limit on the length of the delegation chain (`max_depth`), `@rate_limit` per policy, unmapped tools hidden | Related, not the same quantity: SmartFabric's limit is on planning depth, SmartDelegate's on how many agents stand between the human and the call | implemented in this repo (as SmartDelegate's own control) |
| Pressure computed outside the model (invariant 5) | Decisions made outside the agent's process when a proxy is the boundary | Same principle, different mechanism | implemented in this repo (the proxies); the limit is LIMITATIONS, section 1 |
| Trust gating of a request (SmartRoute, a sibling tool, not an IAIso layer) | `inspect_token`: user, agent chain, role, capability | SmartDelegate could supply identity and scope | proposed, not built (hook H5) |

Not addressed by this control at all, in any status: physical bounds,
optimization bounds, fleet pressure, regime shift and reset (Layers 0, 1, 3
and 3.5; invariants 1 to 3).

### 3.4 Proposed hooks

Each is small, uses an extension point that exists, and is **not built**.

**H1. Halt.** A fleet-wide halt should stop every decision and every issuance
at once.

- *What can be done today with existing operations.* Publish a bundle that
  adds one policy, `forbid(principal, action, resource);`, and reload. Checked
  by hand for this document on the conformance bundle: every `authorize`
  then answers `DELEGATE-POLICY-FORBID`, and `issue_token` and
  `exchange_token` answer `DELEGATE-DELEGATION-DENIED`. It needs a compile, a
  signature and a reload at every engine, so it is slow, and it is not in the
  test suite.
- *What revoke-by-user gives.* A halt of named humans' agents, immediate at
  every engine sharing the state directory. It is a cut-off in time: new
  tokens can be issued afterwards.
- *Proposed.* A `halted` flag in `state.json`, set and cleared by a new
  admin operation with `by`, checked first in every decision and issuance
  (reason `halted`, rule `DELEGATE-HALTED`), audited, and shared through the
  state directory like revocations. Extension points: the state file and its
  lock, the revocation check at the top of token verification, the
  `RevocationFeed` interface to carry the flag to engines with their own
  state. It needs a vector and the same change in every port.

**H2. Pressure thresholds reduce what is issued.** In the `warning` zone a
token service asks for a shorter lifetime and a smaller budget; in
`escalation` it issues nothing new without an approval.

- *Extension point, existing.* `issue_token` already takes `ttl` and a `cap`
  with a `budget`, and the engine caps both at the role's ceiling. The token
  service (the `IdentitySource` path of [INTEGRATE.md](INTEGRATE.md)) is where
  the zone would be read.
- *Proposed.* A small function in the token service: zone in, `(ttl, budget
  factor)` out, with the mapping as data. No engine change. The zone source
  (a SmartFabric node's `pressure.sample`, per its documents) is the adapter
  to write. Thresholds would have to be calibrated; SmartFabric's own are
  stated as uncalibrated.

**H3. Audit records as fabric events, and as pressure inputs.** Each
`decision` record names the agent chain, the action and the token; a count of
them per chain is a tool-call density, and the chain's length is a depth.

- *Extension point, existing.* `AuditSink` and `ship`
  (`interfaces/reference/audit.py`): ordered, gap-checked, replay-safe delivery
  of every record.
- *Proposed.* An `AuditSink` that turns each record into a provenance event
  for a fabric node. The record format is in [spec/PORTING.md](../spec/PORTING.md)
  ("Audit record") and [SCOPE.md](SCOPE.md), section 8.3. The event format is
  SmartFabric's; the mapping is not written.

**H4. A fingerprint entry for a SmartDelegate daemon.** So that a fabric
registry knows the daemon exists, what it speaks and which policy it runs.

- *Extension point, existing.* `info` (`GET /v1/info`): version,
  implementation, policy version, issuer, key id, public key, mode, roles.
- *Proposed.* A command that prints a fingerprint document from `info` and
  the daemon's listen address, to be validated with SmartFabric's schema.
  Which fingerprint fields a policy decision point should fill is a question
  for the fabric's maintainers.

**H5. Identity for trust gating.** SmartRoute's documents list signals for a
request that "carries no agent identity" and for one where "no
scope/permission was declared" (`smartroute/README.md`).
`inspect_token` returns exactly that for a SmartDelegate token: user, agent
chain, role, capability. *Proposed:* a SmartRoute input built from
`inspect_token`. No code in either repository does this today; this
repository's README says so.

## 4. Other frameworks

For an adopter who follows something else. Each row says which item this
control **supports**; none says the item is satisfied. Items the control
does not help with are listed too.

### NIST AI Risk Management Framework (AI RMF 1.0, NIST AI 100-1)

The framework's core has four functions: Govern, Map, Measure, Manage.

| Function | What SmartDelegate contributes |
|---|---|
| Govern | Role ceilings and policies as reviewed, versioned, signed data; a named human behind every agent action; separation of the keys that issue, enforce and sign |
| Map | Nothing. Establishing context and identifying risks is outside this control |
| Measure | Evidence to measure with: a record per decision with rule id, user, agent chain, role and task; counts of denials, approvals and revocations |
| Manage | A treatment for the risk of over-privileged agents: per-task authority, budgets, approval, revocation; shadow mode to see the effect of a policy before enforcing it |

### ISO/IEC 42001:2023 (AI management system)

A management-system standard: it asks an organisation to run a process, and
its Annex A lists controls by area. SmartDelegate is a technical measure an
organisation can point to under some of those areas; it is not a management
system. The area titles below are as given in public summaries of the
standard; the standard's text was not consulted for this document, so check
them against your copy.

| Annex A area | What SmartDelegate contributes |
|---|---|
| A.3 Internal organization | A technical expression of roles and responsibilities for AI agents: who may delegate what, who may approve |
| A.6 AI system life cycle | Operation and monitoring: the decision log as an event record of an agent system in operation |
| A.9 Use of AI systems | Use within stated bounds: an agent acts only inside the role and task a human gave it |

### NIST SP 800-207 (Zero Trust Architecture)

The publication lists seven tenets and a logical architecture with a policy
engine, a policy administrator and a policy enforcement point.

| Tenet (quoted) | What SmartDelegate contributes |
|---|---|
| "All data sources and computing services are considered resources." | The catalog names each resource and field an agent can reach; anything not in it is refused |
| "All communication is secured regardless of network location." | **Nothing.** No daemon or proxy terminates TLS; that is the deployment's job (LIMITATIONS, section 11) |
| "Access to individual enterprise resources is granted on a per-session basis." | Authority is per task: a short-lived token for one role and one task |
| "Access to resources is determined by dynamic policy..." | Every call is decided by policy on the principal (human, agent chain, role, task), the resource's attributes and the request context |
| "The enterprise monitors and measures the integrity and security posture of all owned and associated assets." | Nothing about asset posture. Agent identity is a name; nothing attests the process (LIMITATIONS, section 5) |
| "All resource authentication and authorization are dynamic and strictly enforced before access is allowed." | The call is authorized before the tool runs, on every call; revocation is checked on every decision |
| "The enterprise collects as much information as possible about the current state of assets, network infrastructure and communications..." | The audit log of decisions |

In that architecture's terms the engine is the policy engine and, for tokens,
the policy administrator; the proxies and guards are policy enforcement points.

### OWASP guidance for LLM and agentic applications

| Item | What SmartDelegate contributes |
|---|---|
| OWASP Top 10 for LLM Applications 2025, LLM06:2025 Excessive Agency | Its main subject: authority limited to one role and one task, narrowing for sub-agents, approval for marked actions |
| LLM02:2025 Sensitive Information Disclosure | Fields the principal may not see are removed before data reaches the model. Structure only: values inside permitted free text are not inspected |
| LLM01:2025 Prompt Injection | It does not prevent injection. It bounds what an injected agent can do to what the task's token and policy allow |
| LLM10:2025 Unbounded Consumption | Budgets and rate limits on tool calls that spend. It does not meter model usage |
| OWASP Top 10 for Agentic Applications for 2026, ASI03 Identity & Privilege Abuse | Per-task delegated identity, no standing agent credentials, revocation that follows the human |
| ASI02 Tool Misuse & Exploitation | A decision on every tool call, strict checking of written data, default deny for unmapped tools |
| ASI10 Rogue Agents | Revocation ends an agent's authority. It does not stop a process |

The LLM entries were checked against OWASP's project page. For the agentic
list, the title and publication date were checked against OWASP's page and
the three entry titles against a public summary of the document; check them
against the document itself.

## 5. Plug it into your own framework

A governance layer needs a few signals out of this control and a few levers
into it. All exist today; the schemas are in the specification.

### Signals out

| Signal | Where | Schema |
|---|---|---|
| **Decision events with rule ids** | every `authorize` / `filter` answer, and every `decision` record in the audit log: `effect`, `reason`, `rule` (`DELEGATE-*`), `policies`, `principal` (user, agent chain, role, task, token id), `decision_id` | [spec/API.md](../spec/API.md), "Decisions"; [SCOPE.md](SCOPE.md), section 7 |
| **Audit stream** | `audit.jsonl` in the state directory; events `decision`, `token_issued`, `token_exchanged`, `token_revoked`, `user_revoked`, `approval_granted`, `obligations_applied`, `bundle_reloaded` | [spec/PORTING.md](../spec/PORTING.md), "Audit record"; [SCOPE.md](SCOPE.md), section 8.3; delivery: [interfaces/docs/AuditSink.md](../interfaces/docs/AuditSink.md) |
| **Audit head** | `audit_verify`: `{"records", "head"}` | [spec/API.md](../spec/API.md), "Audit and administration" |
| **Held requests** | `approvals`: pending and granted | [spec/API.md](../spec/API.md), "Approvals" |
| **Health and configuration** | `GET /healthz`; `info`: version, policy version, mode, key id, roles | [spec/API.md](../spec/API.md); the MCP server's `status` adds warnings and the age of the last directory sync ([integrations/mcp/README.md](../integrations/mcp/README.md)) |
| **Summaries** | the MCP server's `anomalies` tool: counts by rule id, user and agent, with thresholds | [integrations/mcp/README.md](../integrations/mcp/README.md) |

Not available as a signal: refused token requests (`role_not_held`,
`role_exceeded`, `widening`) are answered to the caller and are not in the
audit log. Record them where tokens are requested.

### Levers in

| Lever | Operation | Notes |
|---|---|---|
| **Revoke** | `revoke {"token_id"}` or `{"user", "by"}` (`POST /v1/admin/revoke`) | by token: that token and everything derived from it; by user: every token issued up to now. To other engines: [interfaces/docs/RevocationFeed.md](../interfaces/docs/RevocationFeed.md) |
| **Halt** | no operation today | section 3.4, H1: a forbid-all bundle with the existing operations, or the proposed flag |
| **Role ceilings as policy-as-data** | `roles.json` in the bundle; `reload` | [spec/ROLES.md](../spec/ROLES.md); publishing: [interfaces/docs/RoleCatalog.md](../interfaces/docs/RoleCatalog.md) |
| **Policy** | the signed bundle; `reload`; `policy_version` in every decision ties an answer to the rules that gave it | [spec/POLICY_SUBSET.md](../spec/POLICY_SUBSET.md) |
| **Less at issuance** | `ttl` and `cap.budget` on `issue_token` | the hook for a governance layer that wants to tighten under load (H2) |
| **Approval verdicts** | `approve {"approval_id", "by"}` | [interfaces/docs/ApprovalChannel.md](../interfaces/docs/ApprovalChannel.md) |
| **Identity and membership** | `issue_token` with `id_token`, or `user` and `groups`; `entities.json` | [interfaces/docs/IdentitySource.md](../interfaces/docs/IdentitySource.md), [interfaces/docs/DirectorySource.md](../interfaces/docs/DirectorySource.md) |
| **Observe before enforcing** | `"mode": "shadow"` | decisions carry `would_deny`; records carry `enforced: false` |

### What your framework has to supply

- The network and secret placement that make a proxy a boundary.
- Authentication of administrators and approvers: `by` is a statement.
- An anchor for the audit head outside the engine's host.
- Monitoring of the directory sync's age and of the engine's configuration:
  nothing in the engine alerts.
- Everything in section 1's right-hand column.
