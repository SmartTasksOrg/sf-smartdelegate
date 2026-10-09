# SmartDelegate as an MCP server

A small MCP server (stdio, newline-delimited JSON-RPC 2.0) that exposes
SmartDelegate itself as tools. It implements `initialize`, `ping`,
`tools/list` and `tools/call` with the standard library; the `mcp` package is
not needed.

```json
{"mcpServers": {"smartdelegate": {
  "command": "python3",
  "args": ["/abs/path/integrations/mcp/server.py", "--config", "/abs/path/smartdelegate.json"]
}}}
```

Options: `--config FILE` or `--bundle DIR --state DIR` (the same meaning as in
the `smartdelegate` command line), `--token-file FILE`, `--ops`, `--admin`,
`--allow-tools LIST`, `--govern`.

Always available:

| Tool | What it does |
|---|---|
| `whoami` | inspect a token: user, agent chain, role, task, capability, seconds left |
| `roles` | the roles of the bundle: who holds each and its ceiling |
| `check` | would this call be allowed? A dry run: nothing is spent, counted, approved or logged. With `data`, returns it masked |
| `explain` | the same, with every check and every field decision |
| `narrow` | a token for a sub-agent that carries part of what a token holds; asking for more is refused with `DELEGATE-WIDENING` |

Monitoring, only with `--ops`. These read and change nothing:

| Tool | What it does |
|---|---|
| `status` | version, policy version, mode, roles, counts (policies, resources, roles, audit records, pending and granted approvals), the audit head hash, the age of the last directory sync when `entities.sync.json` exists, and warnings: shadow mode, bundle not signature-checked, no audit log, `allow_test_clock` or `trust_caller_chain` on, `require_role` off, audit chain broken |
| `audit_tail` | the newest audit records; `n` (default 20, at most 2000) is how many of the newest to look at, and `event`, `rule`, `user`, `decision_id` select among them. Decision records carry `rule` |
| `audit_verify` | recompute the hash chain: `{"records", "head"}`, or an error naming the first bad line |
| `pending_approvals` | held requests with their age in seconds; the number of granted ones |
| `anomalies` | the newest `n` records (default 500, at most 5000) counted by rule id, event, user and agent, and `findings` where a count reaches a threshold |

Privileged, only with `--admin`:

| Tool | What it does | Listed and callable when |
|---|---|---|
| `delegate` | a human lends an agent one role for one task | `--admin` (and, if `--allow-tools` is given, named in it) |
| `approve` | approve a held request as the human `by` | `--admin --allow-tools approve` |
| `revoke_user` | end every token already issued for a human | `--admin --allow-tools revoke_user` |
| `reload` | reload the bundle and the identity provider's keys | `--admin --allow-tools reload` |

A tool's `token` argument defaults to `--token-file` (re-read on every call),
then to `SMARTDELEGATE_TOKEN`.

## How this differs from `sf-smartdelegate mcp-proxy`

They face opposite directions.

- `sf-smartdelegate mcp-proxy` is the enforcement boundary. It sits between an agent and
  some other MCP server, hides unmapped tools, authorizes every `tools/call`
  and masks every result. The agent cannot skip it.
- This server enforces nothing. It lets an orchestrator ask questions (who am
  I, which roles exist, would this be allowed and why) and mint narrower
  tokens for the sub-agents it starts. The calls those sub-agents then make
  must still go through the proxy or a guard.

A typical setup uses both: the orchestrator calls `narrow` here, starts the
sub-agent with the new token in `SMARTDELEGATE_TOKEN`, and the sub-agent's MCP
servers are each wrapped in `sf-smartdelegate mcp-proxy`.

## Monitoring: `--ops`

Without `--ops` the five monitoring tools are neither listed nor callable
(`ops_required`, `DELEGATE-OPS-REQUIRED`). They are opt-in because the audit
log names users, agents, resources and record ids, though never field values
and never tokens.

`anomalies` findings and their default thresholds (pass `thresholds` to
override by name; the values are starting points, not calibrated):

| Finding | Counts | Default |
|---|---|---|
| `deny_rate` | share of decisions that were denials, once there are `min_decisions` (20) | 50 percent |
| `capability_probing` | `DELEGATE-CAPABILITY-ACTION` / `-RESOURCE` by one agent | 5 |
| `revoked_token_in_use` | `DELEGATE-TOKEN-REVOKED` for one user | 3 |
| `expired_token_in_use` | `DELEGATE-TOKEN-EXPIRED` for one user | 10 |
| `invalid_tokens` | `DELEGATE-TOKEN-INVALID` | 5 |
| `budget_exhausted` | `DELEGATE-BUDGET-EXCEEDED` on one token | 3 |
| `rate_limited` | `DELEGATE-RATE-LIMITED` by one agent | 5 |
| `policy_error` | `DELEGATE-POLICY-ERROR` | 1 |
| `catalog_miss` | `DELEGATE-UNKNOWN-RESOURCE` / `-FIELD` by one agent | 3 |
| `user_revocations` | `user_revoked` events | 3 |
| `not_enforced` | denials logged in shadow mode | 1 |
| `issuance_refusals` | token requests this server process refused | 5 |
| `approval_backlog` | pending requests, or the age of the oldest | 5, or 900 seconds |
| `audit_chain_broken` | the chain does not verify | always |

Refused token requests (`DELEGATE-WIDENING`, `DELEGATE-ROLE-NOT-HELD`,
`DELEGATE-ROLE-EXCEEDED`, ...) are answered to the caller and are **not**
written to the audit log by the engine. The server counts the ones its own
`narrow` and `delegate` tools refused since it started and reports them under
`issuance_refusals`; refusals made elsewhere are not visible here.

## Privileged tools: `--admin` and `--allow-tools`

`--admin` alone exposes `delegate` only, as it always did. `--allow-tools` is
a comma-separated list from `delegate,approve,revoke_user,reload`; with it the
privileged tools are exactly the ones listed, so an operator can expose one:

```
python3 integrations/mcp/server.py --config smartdelegate.json --ops --admin --allow-tools revoke_user
```

`--allow-tools` without `--admin`, or with an unknown name, stops the server
at start (exit status 1). A privileged tool that is not exposed answers
`admin_required` or `tool_not_allowed` and does nothing.

Attribution. `approve`, `revoke_user` and `reload` require `by`; `delegate`
accepts it. What the engine records, as it does for every caller:

| Tool | Audit record | Holds `by` |
|---|---|---|
| `approve` | `approval_granted` | yes |
| `revoke_user` | `user_revoked` | yes |
| `reload` | `bundle_reloaded` | no: the engine's record has no such field. The server prints `reload ... by=<by>` on stderr |
| `delegate` | `token_issued` | no (THREAT_MODEL, threat 25). The server prints `delegate ... by=<by>` on stderr |

Without `--govern`, `by` is whatever the caller wrote; the server does not
authenticate it.

## `--govern`: the tools under the product's own rule

With `--govern`, every monitoring and privileged tool call is first decided
by the engine against the caller's capability token (the `token` argument,
else `--token-file`, else `SMARTDELEGATE_TOKEN`):

- action `read` for a monitoring tool, `operate` for a privileged one;
- resource `smartdelegate.ops/<tool name>`.

The decision is not a dry run, so each call leaves a `decision` record with
the human, the agent chain, the role and the task, directly before the record
of what the tool did. That is the attribution `reload` and `delegate` lack
otherwise. `by` becomes the token's user; a different `by` is refused.
A denial, an invalid token or shadow mode's would-be denial stops the call.

The bundle must define the resource `smartdelegate.ops` and permit what you
want permitted; without it every governed call is denied
(`DELEGATE-UNKNOWN-RESOURCE`). [`agents/bundle-example/`](../../agents/bundle-example/)
has roles for a read-only operator and an integrator, and nothing that
permits `operate`. The five question tools (`whoami`, `roles`, `check`,
`explain`, `narrow`) are not governed: they act on a token the caller
already holds.

`--govern` narrows what a caller may do with this server. It is not a
boundary by itself: whoever can start the process, or read the state
directory, is not bound by it.

## About `--admin`

Without `--admin` the server cannot create authority: `narrow` only hands on
part of a token the caller already holds, and `delegate` is neither listed nor
callable (`admin_required`, `DELEGATE-ADMIN-REQUIRED`).

With `--admin` the process issues root tokens for any user in the bundle,
within that user's roles (and, when named in `--allow-tools`, approves,
revokes users and reloads). The server does not authenticate the human; whoever
can write to its stdin decides the `user` argument. Start it with `--admin`
only where that caller is the trusted orchestrator, never where the model
itself chooses the arguments.

## State directory

Tokens are signed with the key in the state directory. Point `--state` (or the
config) at the same state directory as the enforcement point, or the tokens
issued here will not verify there. Without a state directory the key lives
only in this process and the server says so on stderr.

## Tested

`tests/test_integrations.py` starts the server as a subprocess and drives it
over stdio: handshake, tool list, `delegate` refused without `--admin`,
`whoami` / `roles` / `check` / `explain` / `narrow`, the dry-run property of
`check`, token from file and environment, and malformed requests (not JSON,
batches, missing method, unknown method, unknown tool, misspelt argument),
after which the server still answers. It was also driven once by hand with
the `mcp` 1.27.0 Python client. It was not run inside a desktop MCP client.

`tests/test_agent_surface.py` covers `--ops`, `--allow-tools` and `--govern`
the same way: which tools are listed under which flags, each monitoring tool
against a log with known content, the anomaly findings, privileged tools
refused unless both flags expose them, the audit records they leave, and a
governed server on the bundle of `agents/bundle-example` where the operator
role reads and cannot operate. These options were not driven by the `mcp`
client and not run inside a desktop MCP client.
