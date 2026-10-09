# SmartDelegate in a Flowise Custom Tool

[`SmartDelegateFilter.js`](SmartDelegateFilter.js) is the function body of a Flowise
Custom Tool. It fetches a customer record from an upstream, sends it to a
running `sf-smartdelegate serve` at `POST /v1/filter`, and returns the masked record, or
a one-line denial with the rule id (`DELEGATE-*`).

Setup:

1. Start the daemon: `sf-smartdelegate serve` (it needs `admin_key` and `pep_key`).
2. In Flowise create a Custom Tool with one input property, `customer_id`
   (string), and paste the file into the JavaScript function field.
3. Define the variables the body reads through `$vars`: `SMARTDELEGATE_URL`,
   `SMARTDELEGATE_PEP_KEY`, `SMARTDELEGATE_TOKEN`, `CRM_URL`, `CRM_API_KEY`.
4. Change the upstream call, `ACTION` and `RESOURCE` to your own tool.

The request it sends:

```
POST /v1/filter
Authorization: Bearer <pep key>
{"token": "<capability token>", "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}, "data": {...}}
```

Limits, stated plainly:

- The record is fetched before the decision, so this shape is for reads. For
  writes and spending, put `sf-smartdelegate http-proxy` in front of the upstream.
- The tool body holds the upstream key and the pep key. It binds a flow that
  cooperates; it is not a boundary.
- `SMARTDELEGATE_TOKEN` must be the token of the task in hand. How a per-task value
  reaches `$vars` depends on your Flowise setup and is not covered here.

Tested: `tests/test_integrations.py` runs the body under Node (18 or later,
for the global `fetch`) wrapped as an async function with `$customer_id` and
`$vars` as parameters, against a real daemon and the stand-in CRM in
`examples/`: allow and mask, a token that does not cover the resource, no
token, a wrong pep key, an upstream 404, and an unreachable daemon. It was not
run inside Flowise, so the paste step and the `$vars` wiring are unverified.
