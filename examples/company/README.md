# Kestrel Works: an example company

Kestrel Works is a fictional mid-size distributor with seven business units, 35 people, 25 registered agents and one bundle of rules. This directory is that bundle, in the format every SmartDelegate engine loads, and this page is the plain-language version of it. The scenarios in [`../../harness/scenarios/`](../../harness/README.md) are written against this page: when a scenario says a step must be refused, the reason is a rule below. The live suites in `live/` use the same bundle.

| File | What it is |
|---|---|
| `entities.json` | people, their groups, the agents and the agent groups |
| `catalog.json` | 15 resources, their fields and the classification label of each field |
| `roles.json` | 18 roles: who holds each and the most an agent can be handed under it |
| `policies/*.cedar` | the rules, one file per unit, plus `company.cedar`, `fields.cedar` and `delegation.cedar` |
| `policies.json` | the same rules compiled by the Rust port (`smartdelegate bundle compile --bundle examples/company`); this is what engines evaluate |
| `tests/*.json` | 63 policy unit tests (`sf-smartdelegate policy test --bundle examples/company`) |

Money is in minor units everywhere: `5000` is 50.00. Regions and their currency: EU (EUR), US (USD), APAC (USD). All tokens are issued for the tenant `kestrel`.

## Org chart

### Support (`support`)

| Person | Job | Region | Cost center | Manager | Groups | Roles held |
|---|---|---|---|---|---|---|
| `anna` Anna Keller | Support agent | EU | CC-100 | `elena` | support | requisitioner, support-agent |
| `ben` Ben Okafor | Support agent | EU | CC-100 | `elena` | support | requisitioner, support-agent |
| `chloe` Chloe Martin | Support agent | US | CC-100 | `farid` | support | requisitioner, support-agent |
| `dmitri` Dmitri Volkov | Support agent | US | CC-100 | `farid` | support | requisitioner, support-agent |
| `elena` Elena Rossi | Support supervisor | EU | CC-100 | - | managers, support, support-supervisors | access-approver, requisitioner, support-agent, support-supervisor |
| `farid` Farid Haddad | Support supervisor | US | CC-100 | - | managers, support, support-supervisors | access-approver, requisitioner, support-agent, support-supervisor |

Agents (`support-agents`): `support-orchestrator` (orchestrator), `refund-worker`, `ticket-triager`.

### Finance (`finance`)

| Person | Job | Region | Cost center | Manager | Groups | Roles held |
|---|---|---|---|---|---|---|
| `gina` Gina Novak | Accounts payable clerk | EU | CC-200 | `ines` | finance, finance-clerks | ap-clerk, requisitioner |
| `hugo` Hugo Lindqvist | Accounts payable clerk | US | CC-200 | `jonas` | finance, finance-clerks | ap-clerk, requisitioner |
| `ines` Ines Duarte | Accounts payable manager | EU | CC-200 | - | finance, finance-approvers, finance-managers, managers | access-approver, ap-manager, controller, requisitioner |
| `jonas` Jonas Weber | Finance manager | US | CC-200 | - | finance, finance-approvers, finance-managers, managers | access-approver, ap-manager, controller, requisitioner |
| `karin` Karin Solberg | Treasury analyst | EU | CC-210 | `ines` | finance, treasury | requisitioner, treasury |
| `kofi` Kofi Mensah | Treasury analyst | US | CC-210 | `jonas` | finance, treasury | requisitioner, treasury |
| `liam` Liam Byrne | Payroll officer | EU | CC-220 | `ines` | finance, payroll | payroll-officer, requisitioner |
| `lucia` Lucia Ferrer | Payroll officer | US | CC-220 | `jonas` | finance, payroll | payroll-officer, requisitioner |

Agents (`finance-agents`): `finance-orchestrator` (orchestrator), `invoice-matcher`, `ledger-closer`, `payment-poster`, `payroll-calculator`.

### HR (`hr`)

| Person | Job | Region | Cost center | Manager | Groups | Roles held |
|---|---|---|---|---|---|---|
| `maya` Maya Cohen | HR partner | EU | CC-300 | `oskar` | hr | hr-partner, requisitioner |
| `noor` Noor Rahman | HR partner | US | CC-300 | `pia` | hr | hr-partner, requisitioner |
| `oskar` Oskar Nyberg | HR manager | EU | CC-300 | - | hr, hr-managers, managers | access-approver, hr-manager, hr-partner, requisitioner |
| `pia` Pia Lombardi | HR manager | US | CC-300 | - | hr, hr-managers, managers | access-approver, hr-manager, hr-partner, requisitioner |

Agents (`hr-agents`): `hr-orchestrator` (orchestrator), `onboarding-coordinator`, `review-summarizer`.

### Sales (`sales`)

| Person | Job | Region | Cost center | Manager | Groups | Roles held |
|---|---|---|---|---|---|---|
| `petra` Petra Havel | Account executive | EU | CC-400 | `sofia` | sales | requisitioner, sales-rep |
| `quinn` Quinn Harper | Account executive | US | CC-400 | `tariq` | sales | requisitioner, sales-rep |
| `rafael` Rafael Ito | Account executive | APAC | CC-400 | `tariq` | sales | requisitioner, sales-rep |
| `sofia` Sofia Marin | Sales manager | EU | CC-400 | - | managers, sales, sales-managers | access-approver, requisitioner, sales-manager, sales-rep |
| `tariq` Tariq Aziz | Sales manager | US | CC-400 | - | managers, sales, sales-managers | access-approver, requisitioner, sales-manager, sales-rep |

Agents (`sales-agents`): `sales-orchestrator` (orchestrator), `clause-extractor`, `contract-summarizer`, `quote-builder`.

### Procurement (`procurement`)

| Person | Job | Region | Cost center | Manager | Groups | Roles held |
|---|---|---|---|---|---|---|
| `uma` Uma Pillai | Buyer | EU | CC-500 | `wendy` | procurement | buyer, requisitioner |
| `viktor` Viktor Sandor | Buyer | US | CC-500 | `xavier` | procurement | buyer, requisitioner |
| `wendy` Wendy Clarke | Procurement manager | EU | CC-500 | - | managers, procurement, procurement-approvers | access-approver, buyer, po-approver, requisitioner |
| `xavier` Xavier Dupont | Procurement manager | US | CC-500 | - | managers, procurement, procurement-approvers | access-approver, buyer, po-approver, requisitioner |

Agents (`procurement-agents`): `procurement-orchestrator` (orchestrator), `po-drafter`, `vendor-screener`.

### IT Operations (`it-ops`)

| Person | Job | Region | Cost center | Manager | Groups | Roles held |
|---|---|---|---|---|---|---|
| `aiko` Aiko Tanaka | IT manager | APAC | CC-600 | - | it-managers, it-ops, managers | access-approver, it-operator, requisitioner |
| `basil` Basil Greene | IT manager | US | CC-600 | - | it-managers, it-ops, managers | access-approver, it-operator, requisitioner |
| `bruno` Bruno Costa | On-call lead | EU | CC-600 | `aiko` | it-ops | break-glass, it-operator, requisitioner |
| `yara` Yara Nasser | System administrator | EU | CC-600 | `aiko` | it-ops | it-operator, requisitioner |
| `zane` Zane Whitaker | System administrator | US | CC-600 | `basil` | it-ops | it-operator, requisitioner |

Agents (`it-agents`): `it-orchestrator` (orchestrator), `access-reviewer`, `incident-responder`, `onboarding-provisioner`.

### Compliance (`compliance`)

| Person | Job | Region | Cost center | Manager | Groups | Roles held |
|---|---|---|---|---|---|---|
| `carla` Carla Jensen | Internal auditor | EU | CC-700 | `emil` | compliance | auditor, requisitioner |
| `deniz` Deniz Kaya | Internal auditor | US | CC-700 | `emil` | compliance | auditor, requisitioner |
| `emil` Emil Brandt | Compliance officer | EU | CC-700 | - | compliance | auditor, requisitioner |

Agents (`compliance-agents`): `compliance-orchestrator` (orchestrator), `audit-sampler`, `evidence-collector`.

Groups nest: every unit group is inside `employees`; `support-supervisors`, `finance-managers`, `hr-managers`, `sales-managers`, `procurement-approvers` and `it-managers` are each inside their unit's group and inside `managers`; `finance-managers` is also inside `finance-approvers`; `finance-clerks`, `treasury` and `payroll` are inside `finance`.

Two more agent names matter for negative tests: `unassigned-bot` is registered and belongs to no unit, so no rule lets anybody hand it anything; `rogue-bot` is **not registered at all**.

## Roles

A human lends an agent one role for one task. The token never carries more than the role's ceiling. "Never sees" lists classification labels; the fields behind them are in `catalog.json`.

| Role | Held by | Lent to | For tasks | Ceiling: actions on resources | Never sees | Budget per task | Longest life |
|---|---|---|---|---|---|---|---|
| `support-agent` | group `support` (6 people) | `support-orchestrator` | `ticket-*` | read, create, update on `crm.customer/*`, `crm.ticket/*`, `billing.refund/*` | secret, card, bank, salary, hr-confidential, pricing | 200.00 EUR, 200.00 USD | 900 s |
| `support-supervisor` | group `support-supervisors` (elena, farid) | `support-orchestrator` | `ticket-*` | read, create, update on `crm.customer/*`, `crm.ticket/*`, `billing.refund/*` | secret, card, bank, salary, hr-confidential, pricing | 1,000.00 EUR, 1,000.00 USD | 900 s |
| `ap-clerk` | group `finance-clerks` (gina, hugo) | `finance-orchestrator` | `pay-*`, `invoice-*`, `refund-*` | read, create, update on `billing.invoice/*`, `billing.refund/*`, `finance.payment/*`, `procurement.po/*`, `procurement.vendor/*` | secret, card, bank, salary, hr-confidential, pricing | 5,000.00 EUR, 5,000.00 USD | 900 s |
| `ap-manager` | group `finance-managers` (ines, jonas) | `finance-orchestrator` | `pay-*`, `invoice-*`, `refund-*` | read, create, update on `billing.invoice/*`, `billing.refund/*`, `finance.payment/*`, `procurement.po/*`, `procurement.vendor/*` | secret, card, bank, salary, hr-confidential, pricing | 50,000.00 EUR, 50,000.00 USD | 900 s |
| `controller` | group `finance-managers` (ines, jonas) | `finance-orchestrator` | `close-*` | read, create, approve, close on `finance.ledger/*` | secret, card, bank, salary, hr-confidential, pricing | - | 900 s |
| `treasury` | group `treasury` (karin, kofi) | `finance-orchestrator` | `treasury-*`, `vendor-*` | read, update on `procurement.vendor/*`, `finance.payment/*`, `billing.invoice/*` | card, salary, hr-confidential, pricing | - | 600 s |
| `payroll-officer` | group `payroll` (liam, lucia) | `finance-orchestrator` | `payroll-*`, `onboard-*` | read, create on `hr.employee/*`, `hr.salary/*`, `finance.payment/payroll-*` | secret, card, bank, hr-confidential, pricing; field hr.employee.home_address | 300,000.00 EUR, 300,000.00 USD | 900 s |
| `hr-partner` | group `hr` (4 people) | `hr-orchestrator` | `onboard-*`, `offboard-*`, `review-*` | read, create, update on `hr.employee/*`, `hr.review/*`, `it.access_request/*` | salary, card, bank, pricing | - | 900 s |
| `hr-manager` | group `hr-managers` (oskar, pia) | `hr-orchestrator` | `onboard-*`, `offboard-*`, `review-*`, `salary-*`, `payroll-*` | read, create, update on `hr.employee/*`, `hr.review/*`, `hr.salary/*`, `it.access_request/*` | card, bank, pricing | - | 900 s |
| `sales-rep` | group `sales` (5 people) | `sales-orchestrator` | `deal-*`, `contract-*` | read, create, update on `sales.opportunity/*`, `sales.contract/*`, `crm.customer/*` | secret, card, bank, salary, hr-confidential | - | 900 s |
| `sales-manager` | group `sales-managers` (sofia, tariq) | `sales-orchestrator` | `deal-*`, `contract-*` | read, create, update, approve on `sales.opportunity/*`, `sales.contract/*`, `crm.customer/*` | card, bank, salary, hr-confidential | - | 900 s |
| `buyer` | group `procurement` (4 people) | `procurement-orchestrator` | `po-*`, `vendor-*` | read, create, update on `procurement.po/*`, `procurement.vendor/*` | secret, card, bank, salary, hr-confidential, pricing | - | 900 s |
| `po-approver` | group `procurement-approvers` (wendy, xavier) | `procurement-orchestrator` | `po-*`, `vendor-*` | read, approve on `procurement.po/*`, `procurement.vendor/*` | secret, card, bank, salary, hr-confidential, pricing | - | 900 s |
| `requisitioner` | group `employees` (35 people) | `procurement-orchestrator` | `req-*` | read, create on `procurement.po/*` | secret, card, bank, salary, hr-confidential, pricing, internal | - | 600 s |
| `it-operator` | group `it-ops` (5 people) | `it-orchestrator` | `onboard-*`, `offboard-*`, `access-*`, `it-*` | read, create, update, disable, grant, reset_password on `it.account/*`, `it.access_request/*`, `hr.employee/*` | secret, card, bank, salary, financial, hr-confidential, pricing | - | 900 s |
| `access-approver` | group `managers` (12 people) | `it-orchestrator` | `access-*` | read, approve on `it.access_request/*` | secret, card, bank, salary, financial, hr-confidential, pricing | - | 600 s |
| `auditor` | group `compliance` (carla, deniz, emil) | `compliance-orchestrator` | `audit-*` | read on `*` | secret, card, bank | - | 1800 s |
| `break-glass` | `bruno` (bruno) | `incident-responder` | `incident-*` | read, update, disable on `it.account/*`, `crm.customer/*` | secret, card, bank, salary, financial, hr-confidential, pricing, internal | - | 300 s |

`support-agent` and `support-supervisor` differ only in who holds them and in the budget; so do `ap-clerk` and `ap-manager`.
## The rules in plain words

A request is allowed only when a rule below allows it; everything else is refused.

### Delegation: who may start which agent, and who may hand work to whom

1. Nothing is delegated without a role.
2. A person starts **their own unit's orchestrator**, in a role of that unit that they hold. Two roles cross unit lines, each through the owning unit's orchestrator: any employee starts `procurement-orchestrator` as `requisitioner`, and any people manager starts `it-orchestrator` as `access-approver`.
3. `break-glass` is held by one person, `bruno`, and lent to `incident-responder` only, for tasks named `incident-...`, for at most five minutes.
4. An orchestrator hands work to the specialists **of its own unit**. Two specialists have a helper of their own: `contract-summarizer` hands to `clause-extractor`, `audit-sampler` to `evidence-collector`. Nobody else hands anything to anybody. In particular no agent hands authority to an agent of another unit: work crosses units as a work item, and the receiving unit's human delegates their own role.
5. A chain is at most three agents long (the engine is configured with `max_depth: 3`).
6. A sub-agent's token lives at most 900 seconds.
7. Break-glass authority is never passed to a sub-agent.
8. An agent three steps away from the human reads and does not write.

### Regions and tenants

9. Support and sales people (roles `support-agent`, `support-supervisor`, `sales-rep`, `sales-manager`) work customers, tickets, refunds, opportunities and contracts **of their own region only**. A request on one of these must state the record's region; without it, it is refused. The region a request states is what the caller says the record or the list is about; it is not proof. So every read of these five resources under a regional role also carries a row filter: whatever the request states, rows whose `region` is not the human's own are dropped from what comes back, and a single record of another region comes back empty. An enforcement point should take the region of a single record from the record itself (`attrs_from_record` in the proxies), and for a list rely on the row filter.
10. A token of tenant `kestrel` does not touch a record of another tenant.

### Fields

11. Bank account numbers (`bank`): the `treasury` role only.
12. Full card numbers (`card`): nobody.
13. Salary figures (`salary`): `hr-manager` and `payroll-officer`.
14. Review ratings and notes, HR's note on a salary, emergency contacts (`hr-confidential`): `hr-partner` and `hr-manager`.
15. Other secrets (`secret`: national id, tax id, contract margin, MFA seed): `treasury`, `hr-partner`, `hr-manager`, `sales-manager` only.
16. Secrets, internal notes (`internal`) and pricing (`pricing`) stop at the agent the human started: a sub-agent never receives them.
17. Unit views: IT agents see nine basic fields of an employee (id, name, email, unit, region, manager, job title, start date, status) and, under break-glass, six of a customer (id, name, email, phone, region, tier). Finance agents under the payroll role see id, name, unit, region, status, start date and job title of an employee. Sales agents see customers without internal notes and without card data.
18. What may be written: support writes a customer's email, phone and addresses, any ticket field, and every refund field except `status`. Finance writes payment and ledger fields, an invoice's `status` and `po_id`, a refund's `status`; treasury writes a vendor's `bank.iban` and `bank.bic` and nothing else. Sales writes opportunity fields and a contract's `status`, `term_months` and `clauses`. Procurement writes every purchase-order field except `approved_by`; of a vendor `id`, `name`, `region`, `status`, `contact_email`, `onboarded_by` at creation and `name`, `region`, `contact_email` afterwards. HR writes HR records and access requests; IT writes accounts and access requests.

### Support

19. Support agents (any agent of the unit) read customers, tickets and refunds, write tickets and create refunds; only the orchestrator updates a customer.
20. One refund of up to 50.00 needs nobody else. A larger one is held until a **support supervisor** approves it (`refund-over-50`). The role's budget caps the total per task (200.00 for an agent, 1,000.00 for a supervisor), and the budget is checked before anybody is asked to approve.
21. Nobody refunds a customer account that is their own (`customer_owner`).

### Finance

22. Accounts payable (`ap-clerk`, `ap-manager`) reads invoices, purchase orders, vendors, refunds and payments, updates invoices, and creates payments. Only `finance-orchestrator` and `payment-poster` create payments; only the orchestrator marks a refund paid.
23. A payment names its `kind` (`po` or `refund`), who requested the money (`requested_by`) and who approved that (`approved_by`). Without all three nothing is paid.
24. Up to 1,000.00 a payment needs nobody else. Above that it is held until a **finance approver** releases it (`payment-over-1000`).
25. **Separation of duties**: whoever requested the money does not pay it; whoever approved it does not pay it; a payment whose requester and approver are the same person is not paid.
26. Payroll (`payroll-officer`) reads employees and salaries and creates payments of kind `payroll` with ids `payroll-...`; every one is held until a finance approver releases it (`payroll-run`). Payroll raises no other payment and accounts payable raises no payroll payment.
27. The ledger (`controller`): an entry is posted only to an open period (`period_open`). Whoever posted an entry does not approve it. Closing a period is held until a finance approver releases it (`period-close`). Only the orchestrator approves or closes.
28. Treasury reads invoices, payments and vendors with bank details, and updates a vendor's bank details.

### HR

29. `hr-partner` and `hr-manager` read and write employees and reviews, and raise access requests. Only `hr-manager` reads or writes salaries.

### Sales

30. Sales agents read and write opportunities, read contracts and customers; only the orchestrator updates a contract.
31. A `sales-manager` approves a discount on an opportunity that someone else owns, never on their own (`owner`).

### Procurement

32. A `buyer` reads and writes purchase orders and vendors. A `requisitioner` (any employee) creates and reads purchase orders through the orchestrator, and nothing else.
33. A `po-approver` reads purchase orders and vendors and approves them, through the orchestrator. An approval must state who raised the order (`requested_by`); **the requester does not approve their own order**.
34. A vendor is activated (`approve`) by a `po-approver` who did not onboard it (`onboarded_by`).

### IT operations

35. `it-operator` reads, creates, updates and disables accounts; reads, creates and updates access requests; reads the basic fields of employees.
36. Password resets are limited to three per ten seconds for one operator's agent.
37. A people manager (`access-approver`) reads and approves access requests through the IT orchestrator, unless they raised the request (`requested_by`) or it is for themselves (`employee_id`).
38. IT grants access only after a manager approved (`approved_by`). Administrator access (`level: admin`) is also held until an **IT manager** releases it (`privileged-access`). Nobody grants their own access.
39. Break-glass: `incident-responder` reads, updates and disables accounts and reads customers' contact data of any region.

### Compliance

40. The `auditor` role reads every resource of every unit, in every region, and changes nothing. It never sees card numbers, bank accounts or other secrets (by its ceiling), nor salary figures or HR-confidential fields (rules 13 and 14).

### Approvals

41. A held request is approved by a human in the group the rule names: support supervisors for `refund-over-50`; finance approvers for `payment-over-1000`, `payroll-run` and `period-close`; IT managers for `privileged-access`.
42. The human an agent acts for never approves that agent's request.
43. An approval is for one exact request (the human, the agent chain, the action, the resource id, the resource's attributes and the context, which includes the amount) and for one use.

## Changing the company

Edit the `.cedar` files, `entities.json`, `catalog.json` or `roles.json`, then:

```bash
ports/rust/target/release/smartdelegate bundle compile --bundle examples/company   # only the Rust port compiles Cedar
PYTHONPATH=src python3 -m sf_smartdelegate policy test --bundle examples/company
```

and make the same change on this page, and in the scenarios of `harness/scenarios/` that state the old outcome. Stay inside the Cedar subset of `spec/POLICY_SUBSET.md`: no extension types, no templates, no entity tags.
