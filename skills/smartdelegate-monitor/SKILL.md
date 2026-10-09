---
name: smartdelegate-monitor
description: Watch a SmartDelegate engine - health, policy version, audit chain, pending approvals, and anomalies in the audit log such as bursts of capability denials, revoked tokens still in use, budget exhaustion or an approval backlog. Use when asked for the status of the delegation system, on a schedule, after a deployment, or when something looks wrong and must be reported or escalated.
---

# Monitor: read, summarise, escalate

Monitoring reads. It changes nothing. Everything here works from the command
line on the engine's host, or through the MCP server started with `--ops`
(`integrations/mcp/README.md`: tools `status`, `audit_tail`, `audit_verify`,
`pending_approvals`, `anomalies`).

Commands are written `smartdelegate ...`; from a clone without installing,
`PYTHONPATH=src python3 -m sf_smartdelegate ...`.

## Never without a human

- Never revoke a token or a user, approve a request, reload a bundle, issue a
  token or change policy because of something you saw. Report it and name the
  action a human could take.
- Never edit, truncate, rotate or "repair" `audit.jsonl` or `state.json`. A
  broken chain is evidence.
- Never quote a capability token. The audit log holds none; keep reports the same.
- Never call a finding an attack, or a quiet log healthy, on the counts
  alone. State the counts, the window and what they are consistent with.

## Commands

Health and what is loaded: version, policy version, mode, roles, key id.

```bash
sf-smartdelegate info
sf-smartdelegate policy check
```

The audit chain. Record the `head` somewhere the engine's host cannot change;
compare it next time. The chain alone cannot show that the newest records
were removed.

```bash
sf-smartdelegate audit verify
```

The newest records, and a summary by rule id, user and agent:

```bash
sf-smartdelegate audit tail -n 500 | python3 skills/smartdelegate-monitor/scripts/audit_summary.py
```

Requests waiting for a human:

```bash
sf-smartdelegate approvals
```

## Reading the summary

The thresholds are starting points, not calibrated values. Tune them to the
deployment's normal traffic.

| Finding | Consistent with | Escalate when |
|---|---|---|
| `capability_probing`: many `DELEGATE-CAPABILITY-ACTION` / `-RESOURCE` from one agent | an agent that was given too narrow a role for its task, a mis-bound tool, or a prompt-injected agent trying what it does not hold | the same agent and user repeat it across tasks, or the resources asked are sensitive |
| `revoked_token_in_use`: `DELEGATE-TOKEN-REVOKED` keeps appearing for a user | an agent that was not stopped at offboarding, or a copied token | always: someone still presents a dead credential |
| `invalid_tokens`: `DELEGATE-TOKEN-INVALID` | no token sent (a mis-wired enforcement point), another engine's tokens, or forgery attempts | the count is new, or the source is not a known enforcement point |
| `budget_exhausted`: `DELEGATE-BUDGET-EXCEEDED` repeats on one token | an agent retrying a spend in a loop | the retries continue, or several tokens of one human hit their budgets (budgets are per token, not per human) |
| `policy_error`: `DELEGATE-POLICY-ERROR` | a forbid reads an attribute the enforcement point does not send | always: a rule is not evaluating; requests are denied meanwhile |
| `catalog_miss`: `DELEGATE-UNKNOWN-RESOURCE` / `-FIELD` | catalog drift after an upstream change, or probing | it starts after a deployment |
| `user_revocations`: several `user_revoked` | an offboarding wave or a directory sync with revocation; also revoke used to stop work | the users are unexpected, or `by` is not the sync or a known administrator |
| `deny_rate` | a broken rollout, a wrong bundle | it follows a `bundle_reloaded` event |
| `not_enforced` | the engine runs in shadow mode | always, in production |
| approval backlog: pending requests, or an old one | nobody is watching the approval channel | work is blocked longer than the team accepts |

Also check, and report when true:

- `mode` is `shadow`; `bundle_signed_by` is null (the bundle is not signature-checked).
- `entities.sync.json` next to `entities.json` has an old `synced_at`: the
  directory sync stopped, and removed people keep the membership on disk.
- `audit verify` fails (`audit_broken`): stop summarising and escalate with the line it names.
- The record count went **down**, or the head differs from the one recorded for that count.

## What this does not see

- Refused token requests (`DELEGATE-WIDENING`, `DELEGATE-ROLE-NOT-HELD`,
  `DELEGATE-ROLE-EXCEEDED`) are not in the audit log. The MCP server counts
  the ones it refused itself (`anomalies`, `issuance_refusals`); otherwise ask
  the token service.
- Dry runs and `explain` calls.
- An engine with another state directory, and cloud credentials made from tokens.
- Whether a permitted call was a good idea. This is access control, not content inspection.

## Report format

Window (records, first and last timestamp), counts by rule, findings with
subject and count, what was checked and found normal, what could not be
checked, and for each finding the action a human could take (see
`skills/smartdelegate-offboard/SKILL.md` for revocation).
