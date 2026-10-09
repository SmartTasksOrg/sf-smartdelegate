# Scenarios

Each file is one business process of the fictional company in [`../company/`](../company/README.md), written as steps.
The expected outcome of every step was written from the company's rules (the README there), not copied from what an engine answered.
`python -m harness list -v` prints this list from the files.

## Reading a scenario file

```json
{"id": "s6", "actor": "refund-worker", "op": "call", "token": "refund_work",
 "action": "create", "resource": "billing.refund/rf-{n}-2",
 "attrs": {"region": "{agent.region}"},
 "context": {"spend": {"currency": "{agent.currency}", "amount": 6000}},
 "expect": "deny:approval_required",
 "why": "60.00 is over 50.00: it waits for a support supervisor."}
```

| Key | Meaning |
|---|---|
| `cast` | The humans of the scenario, by job: `{"group": ..., "not_group": ..., "region_of": <other cast member>}` or `{"user": "bruno"}`. The runner draws a different person for every instance. |
| `actor` | A cast member (a human) or the name of a registered agent. |
| `op` | `delegate` (a human lends an agent a role for a task), `narrow` (an agent hands a sub-agent a narrower token), `call` (a tool call: an action on a resource), `approve`, `revoke_user`, `revoke_token`, `handoff` (a work item goes to another agent's mailbox; no request to the engine), `advance` (time passes), `parallel` (several calls at once). |
| `token`, `save` | The name of the token a step uses, and the name under which a new one is kept. An agent can use only a token it was given: by a `delegate` to it, a `narrow` to it, or a `handoff` that lists `tokens` (which is the mistake scenario 9 is about). |
| `resource` | `path/id`. `attrs` are the record's attributes as the enforcement point would state them (region, who requested, who approved). `context.spend` is money, in minor units. `data` is the record itself: sent with `strict` it is an input to be checked, otherwise a result to be masked. |
| `expect` | `ok`, `allow`, `deny:<reason>`, `error:<code>`; alternatives separated by a vertical bar. As an object it can add `hidden` (fields that must not come back), `visible` (fields that must) and `rows`. |
| `audit` | Fields the audit record of this step must carry. |
| `why` | One line a business reader can check against the company's rules. |
| `{n}`, `{name}`, `{name.region}`, `{name.currency}`, `{name.other_region}`, `{name.<attribute>}` | Replaced per instance: a unique number, a cast member's user id, and their attributes. |
| `requires: ["test_clock"]` | The scenario needs time to pass; it is skipped on a daemon that does not honour `allow_test_clock`. |
| `exclusive`, `settle_seconds` | Cast members no other instance may use at the same time (a rate limit is counted per human and agent), and how long after the instance their rate-limit window needs to empty. Offboarding a cast member makes them exclusive automatically. |

In a `narrow` step the `cap` leaves out what the parent already denies; the runner adds the parent's `deny_labels` and `deny_fields`, as a client library would. `"cap_exact": true` sends the capability exactly as written.

## The scenarios

### `01_refund_escalation`: Refund escalation

Units: support, finance. 19 steps.

A support agent's orchestrator hands refund work to a refund worker. A small refund goes through, a larger one waits for a supervisor, the task budget caps the total, and finance posts the payment under its own role. The human whose agent asked cannot approve, and neither can someone who is not a supervisor.

### `02_procure_to_pay`: Procure-to-pay with separation of duties

Units: procurement, finance. 32 steps.

A buyer's agent raises a purchase order, a procurement manager's agent approves it, a finance clerk's agent matches the invoice and pays after a finance approver releases the amount. Whoever requested an order can neither approve nor pay it. Vendor bank details are visible to treasury only.

### `03_employee_onboarding`: Employee onboarding

Units: hr, it-ops, finance, sales. 27 steps.

HR creates the employee record and raises the access request, a manager approves the access, IT provisions the account, an HR manager sets the salary and payroll picks it up. Each unit's agents see only their fields: IT never sees salary, national id or home address; finance never sees review notes or the emergency contact; an HR partner never sees salary figures.

### `04_quarter_end_audit`: Quarter-end audit

Units: compliance, support, finance, hr, sales, procurement, it-ops. 20 steps.

An internal auditor's agents read records of every unit. They can write nowhere and never receive card numbers, bank accounts, other secrets, salary figures or HR-confidential fields. A sampler and its evidence collector get narrower slices.

### `05_contract_review`: Sales contract review, three levels deep

Units: sales. 21 steps.

A sales orchestrator hands a read-only slice of one contract to a summarizer, which hands it on to a clause extractor. Narrowing holds at every hop, pricing never leaves the orchestrator, the third level cannot write, and there is no fourth level.

### `06_incident_break_glass`: Incident break-glass

Units: it-ops, support. 16 steps. Needs the test clock.

During an incident the on-call lead, the one person who holds the break-glass role, lends it to the incident responder for five minutes. Nobody else can, it works for incident tasks only, it is never passed to a sub-agent, and it expires mid-flow.

### `07_offboarding_mid_task`: Offboarding mid-task

Units: support, it-ops. 17 steps.

A support agent is offboarded while their orchestrator and two sub-agents are in the middle of a ticket. Every later step with those tokens fails. A colleague's agent picks the work item up under the colleague's own role. The scenario also shows what offboarding does not do: it is a cut-off in time, and the stored directory decides whether the leaver can still get a new token.

### `08_role_change`: Role change

Units: sales, it-ops. 11 steps.

A sales manager moves back to an account-executive job. The directory sync revokes their tokens; the old token dies, a new token under the old role is refused once the live membership is sent, and a token under the new role works with less.

### `09_handoff_done_wrong`: Cross-unit handoff done wrong: the token is passed along

Units: sales, finance, it-ops. 16 steps.

A sales orchestrator hands a deal to finance and passes its capability token with the work item, instead of letting a finance human delegate. The scenario records what the system prevents and what it does not. A capability token is a bearer token: whoever holds it can use it, as the agent it names, within its bounds, until it is revoked or expires.

### `10_prompt_injected_agent`: Prompt-injected agent

Units: support. 30 steps.

A support orchestrator with a valid token has been talked into a list of things outside its remit. Each is refused, each for its own reason, and afterwards its ordinary work still goes through.

### `11_budget_tree`: Budget across a delegation tree

Units: support. 18 steps.

A support orchestrator with a 200.00 task budget starts three sub-agents with 100.00 each and lets them refund at the same time. Each stays within its own 100.00, and together they never spend more than the parent's 200.00.

### `12_rate_limit_and_approval_reuse`: Rate limit and approval reuse

Units: it-ops, hr, sales. 29 steps. Needs the test clock.

An IT operator's agent resets passwords in a burst and hits the rate limit. Then it grants administrator access: the grant is held for an IT manager, the approval is good for that exact request and for one use.

### `13_payroll_run`: Payroll run

Units: hr, finance. 18 steps.

An HR manager's agent updates a salary, payroll calculates and raises the payroll payment, and a finance approver releases it. Payroll cannot raise other payments, accounts payable cannot raise payroll payments.

### `14_vendor_onboarding`: Vendor onboarding

Units: procurement, compliance, finance. 18 steps.

A buyer's agent onboards a vendor, compliance screens it, treasury enters the bank details and a procurement manager who did not onboard it activates it.

### `15_access_request`: Access request with manager approval

Units: it-ops, sales. 15 steps.

An IT operator raises an access request for an employee, the employee's manager approves it through the IT orchestrator, and IT grants it. Nobody approves a request they raised or that is for themselves, and nobody grants their own access.

### `16_month_end_close`: Month-end ledger close

Units: finance, compliance. 18 steps.

A controller's agents post an adjusting entry; a second controller approves it; closing the period waits for a finance approver; nothing is posted to a closed period; the auditor reads the result.

## Attributes the enforcement point must look up, not trust

A step's `attrs` are what the enforcement point tells the engine about the
record. The engine believes them: that is its contract
(`docs/THREAT_MODEL.md`). In these scenarios the harness plays a truthful
enforcement point. A real one must not let the agent supply any attribute a
rule restricts on, because **an attribute taken from the agent's request is
a claim**. The HTTP proxy can take them from the record instead (`lookup`
and `attrs_from_record`, `spec/API.md`, "Proxy configuration"). The
attributes the company's rules restrict on:

| Attribute | On | Rule that reads it (`company/README.md`) | If the agent could choose it |
|---|---|---|---|
| `region` | customers, tickets, refunds, opportunities, contracts | 9: regional roles stay in their region | it would state its own region for any record. For a single record, look the region up. For a **list** there is nothing to look up: the row filter on every regional read permit drops foreign rows whatever was stated (finding F-4 in `../FINDINGS.md` is what happened where one was missing) |
| `tenant` | every resource | 10: a token stays in its tenant | it would state its own tenant. Take it from the route (a path parameter), never from the body or the query. The company's policies have no tenant row filter: the records of the scenarios carry no tenant column |
| `customer_owner` | refunds | 21: nobody refunds their own customer account | it would leave it out or name someone else |
| `kind`, `requested_by`, `approved_by` | payments | 23 to 26: a payment names who asked and who approved; requester and approver do not pay | it would name two other people and pay its own human's request |
| `requested_by` | purchase orders | 33: the requester does not approve | it would name someone else and approve its own human's order |
| `onboarded_by` | vendors | 34: whoever onboarded a vendor does not activate it | as above |
| `posted_by`, `period_open` | ledger entries | 27: the poster does not approve; nothing is posted to a closed period | it would name another poster, or call a closed period open |
| `owner` | opportunities | 31: a manager does not approve a discount on their own deal | as above |
| `requested_by`, `employee_id`, `approved_by`, `level` | access requests | 37, 38: who may approve and grant, and when an IT manager is needed | it would state `level: standard` to avoid the IT manager's approval, or an approval nobody gave |

Every separation-of-duties step in the scenarios (`02`, `13`, `14`, `15`,
`16`) and every approval threshold that reads an attribute (`12`, `15`) is
therefore only as strong as the enforcement point's lookup. The harness
does not test an enforcement point; `live/` in this repository does, against
a real upstream.

## What the scenarios show the system does not prevent

Three steps (two in scenario 9, one in scenario 7) expect an outcome a reader might wish were different. Their `why` starts with NOT PREVENTED.

- `09_handoff_done_wrong`: a token passed to another agent works for that agent, as the agent the token names, within the token's bounds, and the holder can exchange it for sub-agent tokens of the original agent's own specialists. The capability, the policies, the delegation table and revocation still apply, and the audit log names the token's chain, not the process that used it.
- `07_offboarding_mid_task`: revoking a user ends the tokens issued so far. If the stored directory (`entities.json`) still lists the person and the request sends no live membership, a new token is issued. That is the case for issuance by user name with the admin key, which is what the scenario does. With OIDC sign-in it is narrower since 0.3.0: an ID token issued before the user's revoke cut-off is refused, so the leaver cannot reuse the sign-in they had; the remedy for the stored directory is a sync, or live membership (`groups`, `idp.groups_claim`).

Scenario `12_rate_limit_and_approval_reuse` used to end with a third: an approval given for a request with one set of resource attributes was usable for the same request with other attributes. That was finding F-3 (`../FINDINGS.md`); the approval id has included the attributes since the fix in 0.3.0, and the scenario now expects the request with other attributes to be held on its own.
