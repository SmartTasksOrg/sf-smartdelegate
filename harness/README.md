# Scenario harness

A small harness that plays business scenarios against a SmartDelegate engine
and checks the answers. A human lends an agent a role for a task; agents hand
narrower tokens to sub-agents, call tools, wait for approvals; a human is
offboarded in the middle. Each step says what the company's rules require,
and the harness checks that this is what the engine did.

About 900 lines of Python in three files (`core.py`, `report.py`, `cli.py`),
standard library and the `smartdelegate` package only.

## Run it

From the repository root, with Python 3.10+ and `pip install cryptography`:

```bash
export PYTHONPATH=src
python3 -m harness list -v          # the scenarios, one paragraph each
python3 -m harness run              # each scenario once, on the reference engine in this process: under a second
python3 -m harness run --scenarios 01,07 --out harness/out
```

Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m harness run --out harness\out
```

`python harness/run.py ...` is the same command line without `PYTHONPATH`.

```text
PASS  01_refund_escalation          19 steps
PASS  02_procure_to_pay             32 steps
PASS  03_employee_onboarding        27 steps
PASS  07_offboarding_mid_task       17 steps
PASS  08_role_change                11 steps
PASS  11_budget_tree                18 steps
backend inprocess (python engine): 6 instances, 117 requests, 75 decisions in 0.2 s; audit records: 109 (74 decisions matched)
violations: 0; harness errors: 0
verdict: PASS
reports (no --out given: a new temporary directory):
  open this one   /tmp/smartdelegate-harness-report-xxxxxxxx/report.html
  for machines    /tmp/smartdelegate-harness-report-xxxxxxxx/report.json
```

Exit status: 0 every check passed, 1 at least one did not, 2 the harness
could not run (no verdict about the engine). `report.html` is one
self-contained file with a swimlane of each scenario: a column per business
unit, a card per step with its outcome written out. `report.json` holds the
same plus `trace`, every recorded step with its request and answer; capability
tokens are replaced by the name the scenario gave them. `harness/out/` is
git-ignored.

## The scenarios

They are about Kestrel Works, the fictional company of
[`examples/company/`](../examples/company/README.md): 7 business units, 35
people, 25 agents, 18 roles. Its README states the rules in plain words, and
every `why` in a scenario refers to one of them.

| Scenario | What it teaches |
|---|---|
| `01_refund_escalation` | a budget per task, an approval by a second human, which nobody can give for their own agent, and work handed to another unit as a work item |
| `02_procure_to_pay` | separation of duties: whoever requested an order can neither approve nor pay it; bank details for treasury only |
| `03_employee_onboarding` | three units work one record and each sees only its fields |
| `07_offboarding_mid_task` | a human is offboarded and every token issued for them, sub-agents included, stops working; what offboarding does not do |
| `08_role_change` | a human loses a group: the old role is refused with live membership, the new one works with less |
| `11_budget_tree` | sub-agents get narrower tokens; several of them spending at once never exceed the parent's budget |

## What is checked

| Id | What must hold |
|---|---|
| INV-J | every step got the outcome the scenario expects (`allow`, `deny:<reason>`, `ok`, `error:<code>`, and the fields that must be hidden or visible) |
| INV-B | no field with a label, or a name, that the token's role or capability denies came back in data |
| INV-C | the spend allowed on a token, and on each token it was derived from, stayed within that token's budget |
| INV-D | nothing was allowed for a token that was revoked, whose human was offboarded, or that expired |
| INV-I | the audit log verifies (`audit_verify`) and holds a record with the same effect and reason for every decision |

These checks are simple on purpose. They compare the engine with the scenario
file and with the bundle's `roles.json` and `catalog.json`, and they ask the
engine itself to verify its audit log.

**What is not here.** The project is also tested with a larger simulation
harness that is not part of this repository: hundreds of concurrent agents,
agents that misbehave on purpose, an independent model of the business rules
that judges every allowed request, deliberately broken engines to prove that
model catches them, and the same workload compared across all six engines.
Results obtained with it are quoted in the top-level README. None of that is
needed to run or to trust this small harness for what it claims: that the
six scenarios play out the way the company's rules say.

## Against your own daemon

```bash
# the daemon's keys, in environment variables of your choice
python3 -m harness run --backend url:http://127.0.0.1:8181 --admin-key-env SMARTDELEGATE_ADMIN_KEY --pep-key-env SMARTDELEGATE_PEP_KEY
```

PowerShell: `$env:SMARTDELEGATE_ADMIN_KEY = "..."; python -m harness run --backend url:http://127.0.0.1:8181`.

Any port's `serve` works (Python, Java, Node.js, Go, PHP, Rust). The daemon
must serve the bundle the scenarios are about (`"bundle_dir":
"examples/company"`) in `enforce` mode, and the harness needs its admin key:
it issues tokens, approves, revokes and reads the audit log. With
`"allow_test_clock": true` in the daemon's configuration every request
carries the scenario's clock; without it the harness uses real time, waits
where a scenario lets two seconds pass, and skips a scenario that needs more
(none of the six does). Use a daemon set up for this: the run revokes the
tokens of the bundle's people. Records that were in the audit log before the
run are left out of the audit check.

## Your own bundle and your own scenarios

```bash
python3 -m harness run --bundle path/to/your/bundle --scenario-dir path/to/your/scenarios
```

A scenario is a JSON file:

```json
{"id": "refund", "name": "Refund", "description": "...", "units": ["support"],
 "cast": {"agent": {"group": "support", "not_group": "support-supervisors"},
          "supervisor": {"group": "support-supervisors"}},
 "steps": [
  {"id": "s1", "actor": "agent", "op": "delegate", "agent": "support-orchestrator", "role": "support-agent",
   "task": "ticket-{n}", "save": "task", "expect": "ok", "why": "A support agent lends the orchestrator their role."},
  {"id": "s2", "actor": "support-orchestrator", "op": "call", "token": "task", "action": "create",
   "resource": "billing.refund/rf-{n}", "attrs": {"region": "{agent.region}"},
   "context": {"spend": {"currency": "{agent.currency}", "amount": 6000}},
   "expect": "deny:approval_required", "why": "60.00 is over 50.00: it waits for a supervisor."},
  {"id": "s3", "actor": "supervisor", "op": "approve", "request": "s2", "expect": "ok", "why": "A supervisor approves."}
 ]}
```

| Key | Meaning |
|---|---|
| `cast` | the humans, by job: `group`, `not_group` (a name or a list), `region_of` / `not_region_of` another cast member, `region`, or a fixed `user`. A different person is drawn for every instance (`--seed`) |
| `op` | `delegate` (a human lends an agent a role: `agent`, `role`, `task`, optional `cap`, `ttl`, `groups`, `tenant`; `save` names the token), `narrow` (an agent gets a sub-agent token for `to`, optional `cap`, `ttl`), `call` (a tool call: `token`, `action`, `resource` as `path/id`, optional `attrs`, `context`, `data`, `strict`, `dry_run`), `approve` (`request`: the id of the step that was held), `revoke_user` (`user`: a cast member), `revoke_token`, `handoff` (a work item for another agent; no request to the engine), `advance` (`seconds`), `parallel` (`steps`: calls sent at the same time; `expect`: `{"allow": N, "rest": "deny:..."}`) |
| `expect` | `ok`, `allow`, `deny:<reason>`, `error:<code>`, alternatives separated by a vertical bar; or an object `{"outcome": ..., "hidden": [fields], "visible": [fields], "rows": N}` |
| `why` | one line a business reader can check against the rules |
| `{n}`, `{name}`, `{name.region}`, `{name.other_region}`, `{name.<attribute>}`, `{name.currency}` | replaced per instance: a unique id, a cast member's user id and attributes. The currency comes from the region: EU is EUR, US and APAC are USD, or what the scenario's own `"currency_by_region"` says |

In a `narrow` step the `cap` may leave out what the parent already denies;
the harness adds the parent's `deny_labels` and `deny_fields` (`"cap_exact":
true` sends it as written). `attrs` are what an enforcement point would tell
the engine about the record; the engine believes them, so a real enforcement
point must look them up rather than take them from the agent
(`spec/API.md`, "Proxy configuration").

Write each `expect` from your rules, not from what the engine answers. If the
two disagree, find out which is right.

## Tests

`tests/test_harness.py`: the six scenarios pass on the reference engine and
through a daemon over `url:`; each of the five checks reports a deliberately
wrong scenario or answer; the reports are written; exit statuses.
