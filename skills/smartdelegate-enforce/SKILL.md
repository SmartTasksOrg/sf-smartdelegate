---
name: smartdelegate-enforce
description: Put a SmartDelegate decision in front of a tool call and mask what the tool returns - authorize, run, filter. Use when wrapping an agent's tool, when a call is refused with DELEGATE-FIELD-DENIED, DELEGATE-BUDGET-EXCEEDED or DELEGATE-APPROVAL-REQUIRED, or when deciding whether a call may happen before making it.
---

# Enforce: authorize, run, filter

One tool call is four steps, in this order:

1. **Authorize** the exact call with the task token: action, resource path,
   resource id, and `context.spend` when it spends money. Record data the
   tool is about to write is sent as `data` with strict mode on.
2. **Run** the tool only after `effect: allow`.
3. **Filter** what the tool returned through the decision's obligations
   before anything reaches the model.
4. A refusal is an answer with `reason`, `rule` (`DELEGATE-*`), `detail`, and
   an approval id when a human must approve.

An error from the engine, or an engine that cannot be reached, is a refusal.
Reference: `interfaces/docs/EnforcementPoint.md`, `integrations/adapter.py`.

Commands are written `smartdelegate ...`; from a clone without installing,
`PYTHONPATH=src python3 -m sf_smartdelegate ...`.

## Never without a human

- Never call the tool first and ask afterwards, and never call it when the
  decision could not be obtained.
- Never approve a held request yourself, and never ask the user you act for
  to approve it: the engine refuses them (`DELEGATE-SELF-APPROVAL`).
- Never drop a field from an input to get past `DELEGATE-FIELD-DENIED`
  without telling the human what was left out.
- Never split a spend across sub-agents or tasks to get under a budget.
- Never mark a tool's output as raw, or bind a tool to a weaker action or
  another resource, to make a denial go away.
- Never use `--dry-run` for a call that then happens: a dry run spends
  nothing, consumes no approval and writes no audit record.

## Commands

A runnable example of the four steps in Python (in memory, the bundled example):

```bash
python3 skills/smartdelegate-enforce/scripts/wrap_tool.py
```

The same decisions from the command line. Exit status: 0 allow, 2 deny, 1 error.

A read, with the record masked for this principal (`data`, `masked` in the answer):

```bash
sf-smartdelegate authorize --token "$TOKEN" --action read --resource crm.customer/c-1 --data @record.json
```

A write: strict mode denies an input that carries a field the principal may not use.

```bash
sf-smartdelegate authorize --token "$TOKEN" --action update --resource crm.customer/c-1 --data @changes.json --strict
```

A spend. Amounts are integers in minor units (6000 is 60.00):

```bash
sf-smartdelegate authorize --token "$TOKEN" --action create --resource billing.refund/r-1 --context '{"spend": {"currency": "EUR", "amount": 6000}}'
```

Planning only: would it be allowed? Nothing is spent, counted, approved or logged.

```bash
sf-smartdelegate authorize --token "$TOKEN" --action create --resource billing.refund/r-1 --context '{"spend": {"currency": "EUR", "amount": 6000}}' --dry-run
```

## Inputs

- Resource attributes a policy restricts on (owner, region, tenant) come from
  the upstream record, not from the agent's arguments. An attribute the agent
  supplies is a claim.
- `context` takes integers, strings, booleans, lists and objects. No floats,
  no nulls. `iam` is reserved: identity comes from the token only.
- Tool output must be a record (an object, a list of objects, or JSON text of
  one) to be field-checked. Plain text is withheld.

## Refusals

| Rule | What to do |
|---|---|
| `DELEGATE-APPROVAL-REQUIRED` | Tell the human the approval id and the label. Someone else, whom policy permits, approves. Then repeat the **same** call once; a changed argument needs its own approval |
| `DELEGATE-BUDGET-EXCEEDED` | Stop spending on this task. The budget covers this token and every token above it |
| `DELEGATE-FIELD-DENIED` | The detail names the fields. Remove them only if the task still makes sense, and say so |
| `DELEGATE-CAPABILITY-ACTION`, `DELEGATE-CAPABILITY-RESOURCE` | The token does not carry this. Do not look for another tool that reaches the same data |
| `DELEGATE-NO-MATCHING-PERMIT`, `DELEGATE-POLICY-FORBID` | Policy says no. Report the rule and the policy ids; a policy author decides |
| `DELEGATE-RATE-LIMITED` | Wait; do not loop |
| `DELEGATE-TOKEN-EXPIRED`, `DELEGATE-TOKEN-REVOKED`, `DELEGATE-TOKEN-INVALID` | Stop. The human starts a new delegation, if they still may |

## Limits to state honestly

A check inside the agent's own process binds an agent that cooperates. The
boundary an agent cannot skip is a proxy that alone holds the upstream
credential and is the agent's only network path (`docs/LIMITATIONS.md`,
section 1). Budget is charged when the decision is made: if the tool then
fails, the spend stays counted.
