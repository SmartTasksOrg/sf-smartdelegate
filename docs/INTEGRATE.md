# Integrating SmartDelegate

This guide is for a team that already runs an identity provider and an agent
system and wants agents to act with **one role of one human, for one task**.
It has two tracks. Do both; either order works.

- [Track A: connect your IAM](#track-a-connect-your-iam): where the human's
  identity and group membership come from, how groups become role ceilings,
  what happens at offboarding.
- [Track B: connect your agent system](#track-b-connect-your-agent-system):
  where calls are decided, how a framework holds the task token, how
  sub-agents get less.

Then: the [minimum viable integration](#minimum-viable-integration) and the
checklist [before you call it enforced](#before-you-call-it-enforced).

What every integration has:

| Piece | Holds | Does |
|---|---|---|
| **Token service** (yours) | the admin key, or nothing when the engine verifies ID tokens itself | after a human signed in and started a task, asks for a role-scoped token |
| **Engine** (`sf-smartdelegate serve`, or in-process) | the bundle, the state directory, the signing key | issues, decides, masks, records |
| **Enforcement point** (a wrapper or a proxy) | the pep key; a proxy also holds the upstream credential | asks the engine about every tool call, runs it only on allow, filters the result |
| **Agent** | its task token and nothing else | calls tools through the enforcement point |

Read [LIMITATIONS.md](LIMITATIONS.md) first. Build 0.3.0 has had no
independent security review and was built and tested on Linux only.

The commands below were run on Linux with Python 3.11, from a clone
(`PYTHONPATH=src python3 -m sf_smartdelegate` in place of `smartdelegate`), unless
marked "not run here". The Python blocks are run by `tests/test_agent_surface.py`
from the repository root with `PYTHONPATH=src:.`.

```bash
sf-smartdelegate --demo                 # nine scripted steps on the bundled example
sf-smartdelegate init work && cd work   # smartdelegate.json (with a fresh admin key and pep key), bundle/, cap.json
sf-smartdelegate policy test
```

---

## Track A: connect your IAM

### A1. Decide where membership comes from

A token is issued only if the human **holds the role now**. "Now" comes from
one of two places ([BRIDGES.md](BRIDGES.md), "Freshness"):

| | OIDC claims | Directory sync | Both |
|---|---|---|---|
| Source | the groups claim of the ID token the human signed in with | a scheduled job that reads users, groups and memberships and writes `entities.json` | the sync is the stored baseline; the ID token overrides it for that token |
| A removal takes effect | at the next sign-in (when the ID token in use expires) | at the next successful sync **and** engine reload | whichever comes first |
| Needs | the provider puts groups into ID tokens | a read-only directory credential, a scheduler | both |
| Fails how | an old ID token still lists the group until it expires | if the job stops, removed people keep the membership on disk; nothing alerts by itself | |
| Choose when | sign-ins are short-lived and groups fit in a token | the provider sends no groups (Google), sends too many (Entra ID above 200), or you need user attributes for row filters | you can |

Live membership from a token **replaces** the stored membership of that user
for that token; it is not added to it ([LIMITATIONS.md](LIMITATIONS.md), section 6).

### A2. Turn groups into roles with ceilings

A role names which of your groups hold it and the **most** an agent may be
handed under it. `bundle/roles.json` ([spec/ROLES.md](../spec/ROLES.md)):

```json
{"roles": {
  "support-agent": {
    "members": [{"type": "Group", "id": "support"}],
    "cap": {"actions": ["read", "create", "update"], "resources": ["crm.customer/*", "billing.refund/*"],
            "deny_labels": ["secret"], "budget": {"EUR": 10000}},
    "max_ttl": 600,
    "tasks": ["ticket-*"],
    "agents": ["support-bot"]
  }
}}
```

1. One role per job the humans actually delegate, not one per group.
2. Start each ceiling from what those humans may already do, then remove what
   an agent does not need. `sf-smartdelegate bridge ceiling` can lower a ceiling
   to what a cloud says the human may do; it never widens one
   ([BRIDGES.md](BRIDGES.md), "Inbound 3"; not run here: it needs a cloud's
   simulation results).
3. Set `max_ttl` on every role (300 to 900 seconds is what BRIDGES.md
   recommends), and `tasks` and `agents` where you can.
4. Set `"require_role": true` in the engine configuration. Without it a root
   token can be issued with a bare capability and no role
   ([THREAT_MODEL.md](THREAT_MODEL.md), threat 22).
5. Check that it loads: `sf-smartdelegate policy check`. An unknown key in
   `roles.json` fails the load on purpose.

If roles are authored elsewhere (an IGA tool, a reviewed repository), publish
them through a `RoleCatalog`: [interfaces/docs/RoleCatalog.md](../interfaces/docs/RoleCatalog.md).
`roles.json` is part of the bundle version: sign the bundle again and reload
after a change.

### A3. OIDC claims

**Engine path, no code.** Add your provider to the engine configuration
([spec/API.md](../spec/API.md), "Engine configuration"):

```json
{"idp": {"issuer": "https://idp.example.test", "audience": "smartdelegate-demo", "jwks_file": "jwks.json",
         "user_claim": "sub", "groups_claim": "groups",
         "group_map": {"sg-support": "support", "sg-supervisors": "supervisors"}},
 "require_role": true}
```

`audience` is your client id; use the **ID token**, never an access token.
The keys are a static file: after a key rotation at the provider, replace
`jwks.json` and reload. Then the ID token is the credential:

```bash
sf-smartdelegate token issue --id-token "$ID_TOKEN" --agent support-bot --role support-agent --task ticket-7 --raw
```

Over REST this is `POST /v1/token` with `{"id_token", "agent", "role", "task"}`
and no key. A human whom the provider reports in no mapped group gets
`DELEGATE-ROLE-NOT-HELD`.

**Token-service path**, when claims need more than a flat map (Entra ID group
overage, Keycloak group paths, roles in another claim). Your service verifies
the ID token and states user and groups with the admin key:

```python
import json
from interfaces.reference import JwksIdentitySource
from sf_smartdelegate import core

jwks = json.load(open("spec/conformance/oidc/jwks.json"))                 # your provider's signing keys
idp = JwksIdentitySource("https://idp.example.test", "smartdelegate-demo", jwks,
                         groups_claim="groups", group_map={"sg-support": "support"})
id_token = json.load(open("spec/conformance/oidc/id_tokens.json"))["alice_support"]   # in production: from the sign-in

who = idp.identify(id_token)                  # raises IdentityError unless signature, issuer, audience and expiry hold
engine = core.open_engine("spec/conformance/bundle")                     # in production: the daemon, with the admin key
grant = core.delegate(engine, user=who.user, groups=who.groups, agent="support-bot", role="support-agent", task="ticket-7")
print(grant.user, grant.role, grant.capability.budget)                   # alice support-agent {'EUR': 10000}
```

`rule=` takes a provider rule from `sf_smartdelegate.bridges.claims` (Entra ID,
Okta, Keycloak, Cognito, Auth0, Google). An Entra overage raises instead of
reading as "no groups". Whoever makes this call is trusted to tell the truth
about user and groups; the engine checks them against nothing
([THREAT_MODEL.md](THREAT_MODEL.md), threat 25). Contract and checks:
[interfaces/docs/IdentitySource.md](../interfaces/docs/IdentitySource.md).

### A4. Directory sync

One command per directory; all write `entities.json` through the same guarded
writer ([BRIDGES.md](BRIDGES.md), "Inbound 2"):

```bash
sf-smartdelegate bridge sync-scim --url "$SCIM_URL" --token-env SCIM_TOKEN --out bundle --dry-run
sf-smartdelegate bridge sync-scim --url "$SCIM_URL" --token-env SCIM_TOKEN --out bundle --revoke --config smartdelegate.json
```

(Run here against a stand-in SCIM server on loopback. `sync-okta`,
`sync-entra`, `sync-keycloak`, `sync-google` and `sync-aws-identity-center`
take their own options: `sf-smartdelegate bridge --help`. Not run here.)

1. Look at `--dry-run` first: it prints the diff and writes nothing.
2. `--group-map FILE` maps directory groups to the group ids your roles name;
   with a map, groups not in it are dropped.
3. `--attr-map FILE` names the user attributes to write. **Attributes that
   users had before a sync are not carried over.** A policy with a row filter
   on a user attribute (the example bundle filters customers by the user's
   `region`) then denies with `DELEGATE-OBLIGATION-UNRESOLVED` until the
   attribute is mapped.
4. The removal guard refuses a sync that removes more than 30% of users or
   leaves that share without any group. A tripped guard must reach a human;
   `--force` is not a fix.
5. After a successful sync a running engine must reload, and a signed bundle
   must be signed again (`entities.json` is part of the bundle version). With
   `--daemon-url URL --admin-key-env VAR` the sync calls the reload itself
   (not run here; `tests/test_bridges.py` covers it).
6. Schedule it (BRIDGES.md suggests every 5 to 15 minutes) and alert when it
   exits non-zero or when `synced_at` in `bundle/entities.sync.json` is older
   than two intervals. Nothing in SmartDelegate alerts on a stale sync; the
   MCP server's `status` tool reports the age.

A directory that has no bridge: implement `DirectorySource`
([interfaces/docs/DirectorySource.md](../interfaces/docs/DirectorySource.md)).

### A5. Offboarding

Three things together ([spec/ROLES.md](../spec/ROLES.md), "When the human loses the role"):

1. **No new tokens**: the human loses the group at the source, and the engine
   sees it (next sign-in, or sync and reload).
2. **Live tokens end**: `--revoke` on the sync, or directly, recording who asked:

```bash
sf-smartdelegate call revoke --input '{"user": "alice", "by": "jane.doe"}'
```

3. **The gap is bounded**: `max_ttl` on every role.

Revoke-by-user ends every token already issued for that human, sub-agent
tokens included, at every engine sharing the state directory. It does **not**
reach: an engine with its own state directory (carry revocations there:
[interfaces/docs/RevocationFeed.md](../interfaces/docs/RevocationFeed.md)), a
cloud credential already issued, or a token issued afterwards from membership
that was not yet removed ([LIMITATIONS.md](LIMITATIONS.md), section 5). The
procedure with verification: [skills/smartdelegate-offboard/SKILL.md](../skills/smartdelegate-offboard/SKILL.md).

### A6. Cloud credentials (AWS, Azure, Google Cloud)

When an agent must call a cloud API directly, give it a credential made from
its token and no wider: an STS session policy on AWS, On-Behalf-Of scopes on
Azure, a Credential Access Boundary on Google Cloud (Cloud Storage only).
[BRIDGES.md](BRIDGES.md), "Outbound" and "Providers", has the commands, the
mapping file and the limits. Three facts to carry with you: a cloud
credential never carries the deny lists or the budget; revoking the token
does not revoke a cloud credential already issued; and none of this was run
against a real cloud.

### A7. What is verified against a real provider

From [BRIDGES.md](BRIDGES.md) ("Status", "What was tested and what was not"):

- **Keycloak**: the claim rule, the directory adapter, `bridge sync-keycloak`
  with `--revoke` through a daemon, and the engine's own OIDC path were run
  against a real Keycloak 26.0.7 and 26.8.0 (suite in `live/idp/`).
- **Everything else** (AWS, Entra ID / Azure, Google, Okta, Auth0, generic
  SCIM): written from the providers' public documentation and tested against
  fake servers and fixtures only. Expect to fix details on first contact. The
  assumptions that could not be checked are listed under "UNVERIFIED".
- HTTPS to a directory or an upstream goes through the platform's TLS stack
  and was not exercised by any test (all test servers are plain HTTP on loopback).

### A8. Prove your pieces

```bash
PYTHONPATH=src:. python3 -m interfaces.contract --identity interfaces.reference:identity --directory interfaces.reference:directory --roles interfaces.reference:roles
```

Replace each `interfaces.reference:...` with your own factory
([interfaces/README.md](../interfaces/README.md)).

---

## Track B: connect your agent system

### B1. Choose where calls are decided

| Option | What it is | A boundary the agent cannot skip? | Languages |
|---|---|---|---|
| **In-process guard** | `smartdelegate.Guard`, `integrations/adapter.py`, the framework wrappers: the check runs inside the agent's process | **No.** It binds a cooperating agent. The agent, or code injected into it, can call the tool directly or read a credential the process holds | Python; `guardTool` in Node.js and the JavaScript client |
| **REST daemon** | `sf-smartdelegate serve`: your enforcement point asks it over HTTP | Only as much as the enforcement point that asks it. The daemon decides; it does not stand between the agent and the upstream | any (REST); daemons in Python, Rust, Node.js, Go, PHP |
| **HTTP proxy** | `sf-smartdelegate http-proxy`: a reverse proxy over a route table that holds the upstream credential | **Yes, when the deployment makes it one** (below) | Python and Rust |
| **MCP proxy** | `sf-smartdelegate mcp-proxy`: sits between the agent and an MCP server, hides unmapped tools, decides every `tools/call`, masks every result | **Yes, when the deployment makes it one** | Python and Rust; stdio only |

From [LIMITATIONS.md](LIMITATIONS.md), section 1, a proxy is a boundary only when:

- the agent's network egress is restricted to the proxy;
- the upstream credential exists only in the proxy;
- for MCP, the proxy is the only way the agent can start or reach the server.

SmartDelegate does not configure your network or your secrets. If the agent
can reach the upstream directly, the proxy is advisory. A common shape: the
in-process wrapper for good error messages and tool-list filtering, **and** a
proxy as the boundary.

### B2. Hand the agent its task token

The token service obtains the token (Track A) when the human starts a task
and hands it to the agent's runtime. The agent never asks for a root token
itself and never sees the admin key.

```python
from interfaces import ToolBinding
from interfaces.reference import SimpleRuntime
from sf_smartdelegate import core

engine = core.open_engine()                                   # in production: DaemonClient(url, pep_key=...)
grant = core.delegate(engine, user="alice", agent="support-bot", role="support-agent", task="ticket-7")   # the token service did this

runtime = SimpleRuntime(engine)
runtime.register("get_customer", ToolBinding("read", "crm.customer", id="customer_id"),
                 lambda customer_id: {"id": customer_id, "name": "Ada Lovelace", "ssn": "123-45-6789", "region": "EU"})
runtime.begin_task(grant.token)                               # one token per task; other threads do not see it
print(runtime.call("get_customer", {"customer_id": "c-1"}).value)           # {'id': 'c-1', 'name': 'Ada Lovelace', 'region': 'EU'}

child = runtime.spawn("summarizer", {"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["secret"]}, ttl=120)
print(child.call("get_customer", {"customer_id": "c-1"}).allowed)           # True: the sub-agent holds a narrower token of its own
runtime.end_task()
```

A sub-agent's capability must repeat the parent's deny lists (they can only
grow) or be omitted to inherit. Asking for more raises `SpawnRefused`
(`DELEGATE-WIDENING`). For your framework, implement the three hooks of
[interfaces/docs/AgentRuntime.md](../interfaces/docs/AgentRuntime.md):
task start, tool call, sub-agent start.

### B3. Bind the tools

Each tool is bound to an action and a resource; arguments that are record
data are checked strictly; spend is declared.

```python
import sys
sys.path.insert(0, "integrations")
from adapter import Adapter, ToolSpec, delegate_for_task, spend_from
from sf_smartdelegate import core

engine = core.open_engine()
grant = delegate_for_task(engine, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
adapter = Adapter(engine, token=lambda: grant.token)

read = ToolSpec("read", "crm.customer", id="customer_id")
refund = ToolSpec("create", "billing.refund", id="order_id", spend=spend_from("currency", "amount"))
print(adapter.call(read, lambda customer_id: {"id": customer_id, "name": "Ada Lovelace", "ssn": "123-45-6789", "region": "EU"},
                   {"customer_id": "c-1"}))                                  # no ssn
r = adapter.try_call(refund, lambda **kw: kw, {"order_id": "o-1", "currency": "EUR", "amount": 15000})
print(r.ok, r.denial.rule)                                                   # False DELEGATE-BUDGET-EXCEEDED
```

Wrappers on the same adapter ([integrations/README.md](../integrations/README.md)
says what each was tested with):

| Framework | Where | Note |
|---|---|---|
| LangChain | `integrations/langchain/tool.py` | `guard_tool` on real tools passed with langchain-core 1.6.6; skipped when the package is missing |
| LlamaIndex | `integrations/llamaindex/tool.py` | `guard_tool` on `FunctionTool` passed with llama-index-core 0.14.25 |
| OpenAI / Anthropic function calling | `integrations/function-calling/schema.py` | dispatcher and tool-list filtering; no request was sent to a model API |
| MCP | `sf-smartdelegate mcp-proxy` in front of each MCP server | the enforcement boundary for MCP |
| Flowise, VS Code, GitHub Actions, pre-commit | `integrations/` | partly tested; see the table there |

The MCP proxy, with the example mapping and stand-in server:

```bash
SMARTDELEGATE_TOKEN="$TOKEN" sf-smartdelegate mcp-proxy --tools examples/mcp_tools.json -- python3 examples/fake_mcp_server.py
```

The HTTP proxy holds the upstream credential and answers the agent on
`http://<proxy>/<upstream><path>` with `Authorization: Bearer <task token>`:

```bash
CRM_API_KEY=... sf-smartdelegate http-proxy --routes examples/routes.json --listen 127.0.0.1:8182
```

Take every resource attribute a policy restricts on from the upstream record
(`lookup` + `attrs_from_record`), not from the agent's request: an attribute
the agent supplies is a claim ([spec/API.md](../spec/API.md), "Proxy configuration").

### B4. Other languages

Run the daemon and call it. The daemon needs an admin key and a pep key of at
least 16 characters (`sf-smartdelegate init` writes both); it does not terminate
TLS: bind it to loopback or put it inside a mesh.

```bash
sf-smartdelegate serve --listen 127.0.0.1:8181
```

```bash
# token service (admin key): a role-scoped token for a verified human
curl -s -X POST http://127.0.0.1:8181/v1/token -H "Authorization: Bearer $SMARTDELEGATE_ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"user": "alice", "groups": ["support"], "agent": "support-bot", "role": "support-agent", "task": "ticket-7"}'
# enforcement point (pep key): decide and mask
curl -s -X POST http://127.0.0.1:8181/v1/filter -H "Authorization: Bearer $SMARTDELEGATE_PEP_KEY" -H 'Content-Type: application/json' \
  -d '{"token": "'"$TOKEN"'", "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}, "data": {"id": "c-1", "name": "Ada", "ssn": "1", "region": "EU"}}'
# agent runtime (no key: the parent token is the authority): a narrower token for a sub-agent
curl -s -X POST http://127.0.0.1:8181/v1/token -H 'Content-Type: application/json' -d '{"subject_token": "'"$TOKEN"'", "actor": "summarizer", "ttl": 120}'
```

A deny is HTTP 200 with `"effect": "deny"`; HTTP 400, HTTP 401, a timeout and
a refused connection are all "no decision", and no decision means no call.
The full surface is [spec/openapi.yaml](../spec/openapi.yaml). Native engines
and clients: [ports/README.md](../ports/README.md) (Java, Node.js, Go, PHP,
Rust, and a JavaScript REST client). The bridges, the SQL guard and the
adapter exist in Python only; the proxies in Python and Rust.

### B5. Approvals, audit, revocation

- **Approvals.** A policy with `@require_approval` holds the call; the agent
  gets `DELEGATE-APPROVAL-REQUIRED` and an approval id. Deliver it to a human
  through an `ApprovalChannel` and apply the verdict with `pump`
  ([interfaces/docs/ApprovalChannel.md](../interfaces/docs/ApprovalChannel.md)).
  The engine does not authenticate the approver; your channel must.
- **Audit.** The log is a local file. Ship it somewhere the engine's host
  cannot rewrite, and keep the head hash there
  ([interfaces/docs/AuditSink.md](../interfaces/docs/AuditSink.md)).
- **Revocation.** If every enforcement point asks one daemon, revocation is
  immediate there. If an engine verifies tokens with its own state, carry
  revocations to it ([interfaces/docs/RevocationFeed.md](../interfaces/docs/RevocationFeed.md)).

```python
import tempfile
from pathlib import Path
from interfaces.reference import JsonlAuditSink, WebhookApprovalChannel, pump, ship
from sf_smartdelegate import core

state = tempfile.mkdtemp()
engine = core.open_engine(state_dir=state)
grant = core.delegate(engine, user="alice", agent="support-bot",
                      capability={"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 20000}})
refund = dict(context={"spend": {"currency": "EUR", "amount": 15000}})
print(core.check(engine, grant.token, "create", "billing.refund", "o-9", **refund).rule)      # DELEGATE-APPROVAL-REQUIRED

outbox, delivered = [], set()
channel = WebhookApprovalChannel(outbox.append)               # outbox.append stands for your POST to chat or ticketing
pump(engine, channel, delivered)                              # delivers the held request
channel.receive({"approval_id": outbox[0]["approval_id"], "approve": True, "by": "bob"})     # your webhook handler, after authenticating bob
print(pump(engine, channel, delivered)["approved"] == [outbox[0]["approval_id"]])              # True
print(core.check(engine, grant.token, "create", "billing.refund", "o-9", **refund).rule)      # DELEGATE-POLICY-PERMIT

sink = JsonlAuditSink(Path(state) / "offsite-copy.jsonl")     # stands for your log store
print(ship(Path(state) / "audit.jsonl", sink)["head"][0])     # the sequence number of the newest record shipped
```

### B6. Operate it

- The MCP server (`integrations/mcp/server.py`) gives an agent the monitoring
  tools with `--ops`, privileged tools one by one with `--admin --allow-tools`,
  and with `--govern` decides every such call against the caller's own task
  token ([integrations/mcp/README.md](../integrations/mcp/README.md)).
- [skills/](../skills/) holds the procedures an agent follows; [agents/](../agents/)
  two agent definitions and the roles they run under.
- Where this control sits in a larger governance framework, and the signals
  to connect to one: [FRAMEWORK.md](FRAMEWORK.md).

### B7. Prove your pieces

```bash
PYTHONPATH=src:. python3 -m interfaces.contract --enforcement interfaces.reference:enforcement --runtime interfaces.reference:runtime --approval interfaces.reference:approval --audit interfaces.reference:audit --revocation interfaces.reference:revocation
```

---

## Minimum viable integration

Ten lines, in process, on the bundled example. It shows the whole loop and it
is **cooperative**: nothing here stops an agent that calls the tool directly.

```python
import sys; sys.path.insert(0, "integrations")
from adapter import Adapter, ToolSpec, delegate_for_task
from sf_smartdelegate import core

engine = core.open_engine("src/sf_smartdelegate/example_bundle")                        # 1. your bundle: catalog, roles, policies
grant = delegate_for_task(engine, user="alice", agent="support-bot",                 # 2. a human lends one role for one task
                          role="support-agent", task="ticket-7")
adapter = Adapter(engine, token=lambda: grant.token)                                 # 3. the agent holds only the task token
get_customer = lambda customer_id: {"id": customer_id, "name": "Ada Lovelace", "ssn": "123-45-6789", "region": "EU"}
print(adapter.call(ToolSpec("read", "crm.customer", id="customer_id"), get_customer, {"customer_id": "c-1"}))   # 4. authorize, run, filter
```

To make it enforced: move step 4 into a proxy that alone holds the upstream
credential, give the engine a state directory (audit log, revocation), issue
the token from a verified sign-in, and go through the checklist.

## Before you call it enforced

Identity and roles

- [ ] Root tokens are issued only by a component that verified the human's sign-in (an ID token, or your token service). No agent and no enforcement point holds the admin key.
- [ ] `require_role` is `true`. Every role has `max_ttl`; `tasks` and `agents` are set where they can be.
- [ ] Ceilings were reviewed by whoever owns the access model. `roles.json` changes are reviewed like IAM policy changes.
- [ ] ID-token lifetimes are short, or the directory sync runs on a schedule with an alert on failure and on a stale `synced_at`.
- [ ] Offboarding calls revoke-by-user, and someone knows what it does not reach.

Boundary

- [ ] The agent's network egress reaches the proxy and not the upstream.
- [ ] The upstream credential exists only in the proxy.
- [ ] For MCP, the proxy is the only way to start or reach the server.
- [ ] No policy restricts on an attribute the agent supplies; list routes that return records have a row filter in the deciding permit.
- [ ] The daemon and proxies are bound to loopback or sit inside a mesh that terminates TLS.

Bundle and engine

- [ ] `bundle_public_key` is set; bundles are signed by a key that is not on the engine's host; `policies.json` comes from the compiler.
- [ ] `mode` is `enforce`. `allow_test_clock` and `trust_caller_chain` are absent.
- [ ] Every policy you wrote has tests (`sf-smartdelegate policy test`), including the nearest request that must be denied.
- [ ] The state directory is on durable storage, is backed up, and is not shared between a Java or Node.js engine and any other port.

Evidence and operations

- [ ] The audit log is shipped off the host, and the head hash is kept where the host cannot change it.
- [ ] Someone watches denials, pending approvals and the sync's age ([skills/smartdelegate-monitor/SKILL.md](../skills/smartdelegate-monitor/SKILL.md)).
- [ ] The approval channel authenticates approvers.
- [ ] Your implementations pass `python3 -m interfaces.contract`.
- [ ] You have read [LIMITATIONS.md](LIMITATIONS.md) and [THREAT_MODEL.md](THREAT_MODEL.md) and accepted what they say this build does not do: bearer tokens without proof of possession, no HSM or key rotation procedure, one static admin key, budgets per token and not per human, no independent security review.
