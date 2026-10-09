---
name: smartdelegate-explain
description: Explain why SmartDelegate allowed or denied a request - the DELEGATE-* rule id, the check that failed, the deciding policies, and what to tell the human. Use when a tool call or a token request was refused, when someone asks "why can't the agent do X", or when a decision id from a refusal or from the audit log needs explaining.
---

# Explain a decision

Every decision carries `rule`: `DELEGATE-` plus the reason. The reason is the
first check that failed, in this order: token, catalog, tenant, capability,
policy, obligations (row filter, rate limit), budget, approval, fields
(`docs/SCOPE.md`, section 7).

Commands are written `smartdelegate ...`; from a clone without installing,
`PYTHONPATH=src python3 -m sf_smartdelegate ...`.

## Never without a human

- Explaining changes nothing. Never issue, widen, approve, revoke or edit
  policy as part of an explanation.
- Never suggest a way around a denial: another tool, another agent, another
  user, other groups, a longer chain. Say who can change the outcome.
- Never show a capability token, and never show record values. The audit log
  holds field names only; keep it that way in what you write.
- Never present a guess as the reason. If you have neither the token nor the
  audit record, say what you would need.

## Commands

With the token in hand, ask the engine for the trace. `explain` is a dry run:
it spends nothing and writes no audit record.

```bash
sf-smartdelegate explain --token "$TOKEN" --action read --resource hr.salary/e-1
```

The answer has `effect`, `rule`, `detail`, `policies`, and `explain`: one entry
per check with `pass` or `deny`. On an allow, `obligations.fields` lists every
catalogued field under `allow`, `deny` or `redact`; with `--data` the answer
also carries the masked record and `masked`.

Without the token, find the decision in the audit log by the `decision_id`
that the refusal carried, and look the rule up:

```bash
sf-smartdelegate audit tail -n 500 | python3 skills/smartdelegate-explain/scripts/rules.py --decision d-90ae617b8eeaa8c2
```

One rule, or the whole table:

```bash
python3 skills/smartdelegate-explain/scripts/rules.py DELEGATE-POLICY-FORBID
python3 skills/smartdelegate-explain/scripts/rules.py --all
```

## What is and is not in the audit log

- Decisions made by `authorize` and `filter` are records with event
  `decision`: user, agent chain, role, task, action, `path/id`, effect,
  reason, detail, deciding policies, masked field names.
- A dry run and an `explain` are not logged.
- A refused token request (`DELEGATE-ROLE-NOT-HELD`, `DELEGATE-ROLE-EXCEEDED`,
  `DELEGATE-WIDENING`, `DELEGATE-DELEGATION-DENIED`) is answered to the caller
  and is not logged. Ask whoever made the request for the error they received.

## What to tell the human

Four sentences, no more: what was asked (action, resource, on whose behalf),
the rule id and what it means, who can change the outcome, and that nothing
was done. Examples:

- `DELEGATE-CAPABILITY-RESOURCE`: "The agent asked to read hr.salary/e-1 for
  alice in the role support-agent. That role's token does not cover salary
  records. A role that does would have to be lent by someone who holds it.
  Nothing was read."
- `DELEGATE-APPROVAL-REQUIRED`: "The refund of 150.00 EUR is held for a second
  person (label refund-over-100-eur, approval id 43e1...). A supervisor other
  than alice can approve it; the agent then repeats the same call."
- `DELEGATE-POLICY-FORBID`: name the policy id from `policies`. A forbid is
  deliberate; its owner decides.

## Common misreadings

- `DELEGATE-NO-MATCHING-PERMIT` is default deny, not an error.
- `DELEGATE-POLICY-ERROR` is a policy or enforcement-point defect (a forbid
  read an attribute that was not sent); it is not something the agent did.
- `DELEGATE-TOKEN-REVOKED` after an offboarding is the intended result.
- `DELEGATE-OBLIGATION-UNRESOLVED` after a directory sync usually means the
  sync wrote users without the attribute a row filter needs (`--attr-map`).
