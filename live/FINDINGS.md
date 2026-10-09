# Live findings — SmartDelegate 0.3.0

Defects and material differences the live tests (`live/`) found by running the
enforcement points against a real PostgreSQL 16 database, a real separate
upstream process, a kernel-enforced network boundary and sustained load on
2026-10-05 (Linux x86-64, Python 3.11, the Rust binary in
`ports/rust/target/release`). Nothing in the product was changed to make a
test pass. Each finding has a test that reproduces it; those tests are marked
`@finding("L-n")` (an expected failure) so the suite stays green only for what
works, and turn into an unexpected success the day the product is fixed.

The simulation harness the project is tested with (not part of this repository)
recorded its own findings, F-1..F-4, all fixed in 0.3.0 and listed in
`CHANGELOG.md`; these L-findings are from the parts it never exercised: a real
network boundary, a real SQL database behind `SqlGuard`, non-JSON and oversized
upstream responses, and load.

| Id | Severity | Where | In one line | Status on 2026-10-05 (end of day) |
|---|---|---|---|---|
| L-1 | medium | HTTP and MCP proxy | A route could build resource attributes from request parts the agent writes, and policy trusted them: an EU agent read a US refund and changed a US customer by stating `region=EU` | **fixed in 0.3.0**, Python and Rust: `lookup` + `attrs_from_record`; request attributes must be declared (`attrs_from_request`) and are listed at start |
| L-1b | medium | company policy + list routes | The list of refunds (and contracts, opportunities) returned every region to a regional agent: on a list route the region can only be a claim, and the permits had no row filter | **fixed** in the company bundle (`examples/company`, policy version 8155eccc…): `support-read-refund`, `sales-read-contract`, `sales-read-opportunity` carry `@row_filter`. There is no row filter on the tenant: the tenant comes from the route (below) |
| L-2 | medium | HTTP proxy | A repeated query parameter was read one way by the proxy and another by the upstream | **fixed in 0.3.0**, Python and Rust: ambiguous queries are refused (400), the query is forwarded as parsed |
| L-3 | low | engine API + proxies | Spend is charged when the decision is made; a write the upstream then rejects still counts | **kept by design, documented**; engine change requested below (owner: engine maintainer) |
| L-4 | medium | Rust HTTP proxy | A `passthrough` response over 32 MB was cut to 32 MiB and returned with 200 | **fixed** in the Rust port |
| L-5 | medium | Rust HTTP proxy | A `passthrough` response that is not UTF-8 was refused | **fixed** in the Rust port |
| L-6 | medium | Rust HTTP proxy | Four slow upstream calls stalled every other agent | **fixed** in the Rust port |
| L-7 | low | SqlGuard | No way to state resource attributes, so region and tenant policies denied every query | **fixed in 0.3.0**: `attrs=` and per-row `row_attrs=` / `id_column=`. Documented limit: a nested catalog field cannot be read from a flat column |
| L-8 | medium | SqlGuard | A JSON column was returned whole: `addresses[].geo` reached principals who may not see it | **fixed in 0.3.0**: every returned row goes through the decision's field mask |
| L-9 | low | Rust daemon | Nagle left on: token issuance stalled ~45 ms | **fixed** in the Rust port (its HTTP server was replaced); re-measured in `load/RESULTS.md` |
| L-10 | medium | MCP proxy (reference), HTTP proxy | A mapping value that is not an expression was read as a constant: `"input": "args"` meant the string "args", so the arguments were **not field-checked**; a misspelt key (`"spnd"`) was ignored | **fixed in the reference**: `"args"` is the whole arguments and is checked; any value that is not an expression, and any unknown key, stops the proxy at start; a call without the record object is refused. Reported by the Rust maintainer. **Rust: to mirror** (`spec/API.md`, "Expressions") |
| L-11 | low | Rust HTTP proxy | A request body sent with `Transfer-Encoding: chunked` is accepted and decoded | **fixed** (reference and Rust port). The reference ignored `Transfer-Encoding`, read no body and left the chunk bytes on the connection to be read as a second request; it now refuses such requests (411 / 400) and closes the connection, and `spec/API.md` step 1 requires that of every port. The Rust proxy used to decode the body and field-check it, which did not let anything through in the live test (both requests were refused on their fields), but a proxy that decodes chunked bodies can disagree with a server in front of it about where a request ends. It now refuses these requests like the reference (411 / 400, one response, connection closed, nothing read after it), and so does the Rust daemon; `ports/rust/cli/tests/servers.rs` and live `HttpProxyRust.test_09b` |

All `@finding` marks for fixed findings are gone: those cases are ordinary tests now, for both proxies. No mark
is left: L-11, the last one (on the Rust class), is fixed.

## What was fixed, and how to see it

- **L-1** `tests/test_proxies.py` (`test_attributes_from_the_upstream_record`, `RoutesFile`), and live:
  `HttpProxyPython.test_05`, `test_06`, `test_08`, `test_11` (a refund is judged on the customer's region, whatever
  the body says), `McpProxyPython.test_03`, `test_07`. The old behaviour is kept on purpose in one route and one
  tool (`company_claims`, `update_customer_as_claimed`) and shown by `test_08b` / `test_07b`: the write goes
  through, and the proxy named the route when it started. `live/upstream/routes.json` and `mcp_tools.json` are in
  the safe form and are used for both proxies.
- **L-1b** live `test_06b` (whole tables of refunds, opportunities and contracts, counted against SQL, for EU and
  US agents, both proxies) and `test_06c`: every route has `"attrs": {"tenant": "{tenant}"}` and every tool
  mapping a fixed `tenant`, never from the request or the record, so the engine's tenant check always runs; no
  row of another tenant arrives and `/osprey/...` is `tenant_mismatch`.
- **L-10** `tests/test_proxies.py` (`McpToolsFile`, `RoutesFile.test_a_value_that_is_not_an_expression_stops_the_proxy`).
- **L-11 / chunked bodies** `tests/test_proxies.py` (`test_a_body_not_framed_by_content_length_...`) and live
  `test_09b` against the real upstream: nothing reaches it, the row is unchanged, one response per connection.
- **L-2** `tests/test_proxies.py` (`test_a_query_the_upstream_could_read_differently_is_refused`,
  `test_query_parsing_and_what_is_forwarded`), live `HttpProxyPython.test_09` (the self-checking upstream:
  `?region=US&region=EU` is now `400 query_duplicate`, nothing reaches the upstream, the row is unchanged; and the
  upstream's request log shows the query as the proxy parsed it).
- **L-7, L-8** `tests/test_guard_sql.py` (`NestedAndAttributes`, on SQLite and on PostgreSQL), live
  `SqlGuardPostgres.test_03`, `test_05`, `test_08` (3000-row table mixing tenants and regions: 6 decisions, the
  right rows, masked).

## L-3: what was decided, and the engine change it needs

A two-phase path in the proxy (ask with `dry_run`, call the upstream, then record the spend with a real call) was
considered and **not** implemented: the second engine call can be refused (another agent used the budget, or the
one-use approval, in between), and by then the write has happened. That is a budget overrun, which is worse than
today's under-use. The proxies therefore keep charge-before-call; `spec/API.md` ("Spend is reserved before the
upstream is called") and `docs/LIMITATIONS.md` §11 now say so, and live `test_11` asserts it. Where the proxy can
see the problem *before* deciding, it now costs nothing: a refund for a customer that does not exist is `404` from
the lookup and reserves nothing.

**Engine change requested** (owner: engine maintainer; needs every port):

```text
reserve   authorize/filter with "reserve": true   -> decision + "reservation": {"id", "expires_at"}
          charges the ledger and holds the approval, exactly as an allow does today
commit    {"reservation_id"}                        -> makes it permanent (idempotent)
release   {"reservation_id"}                        -> gives the amount and the approval back (idempotent)
          a reservation neither committed nor released by expires_at is committed (fail-safe for the budget)
```

with an audit record for each, so that "reserved, released because the upstream answered 409" is visible.

Everything below is reproducible with the stack `live/upstream/stack.py` brings
up; the test names are in `live/upstream/test_live_upstream.py`,
`live/boundary/test_boundary.py` and `python3 -m live.load`.

---

# The findings as found

The sections below are the record of what was found, with the reproduction as it was then. Where a finding is
fixed, the "Reproduce" block reproduces it only against the Rust port's proxy (routes in the previous form).

## L-1 — regional resources without a row filter trust the agent's stated region

**Severity: medium.** `tests`: `test_06_a_refund_of_another_region_does_not_reach_a_regional_agent`,
`test_08_a_regional_agent_cannot_change_a_record_of_another_region`,
`McpProxyCases.test_07_...` (all expected failures tied to L-1).

**What.** README rule 9 says support and sales work records of their own region
only. Two different mechanisms enforce it:

- Customers and tickets carry a **row filter** on the *token's* region
  (`@row_filter("region == context.iam.user_attrs.region")`). This is sound:
  the region compared is the one in the signed token, and a single-record read
  of another region's customer returns `null` (the row is dropped). The live
  test confirms this holds on whole tables (`test_04`, thousands of rows).
- Refunds, and the *update* of a customer, carry **no row filter**. Their only
  regional control is the forbid `regional-roles-stay-in-their-region`, which
  compares `resource.region` — a value the enforcement point supplies — with
  the token's region. At the HTTP proxy that value comes from the request
  (`attrs.region = query.region` / `body.region`), which the agent controls.

So an EU support agent reads a US refund by asking for it with `?region=EU`,
and updates a US customer by stating `region=EU`. The record is a real row in
PostgreSQL; the test verifies by SQL that the row was read or changed.

**Reproduce.**
```
# EU agent, US refund, agent states EU:
GET  /company/kestrel/refunds/<a US refund id>?region=EU      -> 200, the US refund
GET  /company/kestrel/refunds?region=EU&limit=200             -> rows of EU, US and APAC
# EU agent changes a US customer through an upstream that does not re-check:
PATCH /company/kestrel/legacy/customers/<a US customer id>?region=EU {"phone": "..."}  -> 200, row changed
```
Observed regions of refunds an EU agent received by stating `region=EU`:
`['APAC', 'EU', 'US']` (both Python and Rust proxies).

**Why it matters.** The threat model (threats 10, 18 and the trust assumption
"enforcement points are trusted to describe the call truthfully") places this
trust on the enforcement point. The finding is that for *region* the HTTP proxy
has no truthful source: it cannot know a refund's region without first fetching
the refund, so it relays the agent's claim. The safe pattern already exists in
the bundle — the customer/ticket row filter on `user_attrs.region` — and is
simply missing from the refund, opportunity and contract permits and from the
customer-update permit.

**Not a workaround.** The tests assert the correct behaviour (the foreign-region
record must not arrive / must not change) and are marked expected-failure; they
flip to unexpected-success if the policies gain a row filter on the token's
region, or the proxy learns a trustworthy region.

---

## L-2 — a duplicated query parameter desynchronises the proxy and the upstream

**Severity: medium.** `test`: `test_09_a_repeated_query_parameter_cannot_split_the_proxy_and_the_upstream` (expected failure).

**What.** The proxy validates that every query parameter is on the route's
allow-list, then forwards the **raw query string** unchanged and authorises on
its *own* parse of it. The proxy's `query_map` keeps the **last** value of a
repeated key; a typical web framework (and this upstream, via
`parse_qs(...)[name][0]`) keeps the **first**. So `?region=US&region=EU` is
authorised by the proxy as `EU` (allowed for an EU agent) and acted on by the
upstream as `US`. An upstream that defends itself — this one returns 409 when
the stated region does not match the record — is still defeated, because the
region it checks is not the region the proxy authorised.

**Reproduce.**
```
PATCH /company/kestrel/customers/<US id>?region=EU            -> 409 (upstream's own check holds)
PATCH /company/kestrel/customers/<US id>?region=US&region=EU  -> 200, the US row is changed by an EU agent
```

**Why it matters.** It is listed under the threat model's residual
("upstream-specific parsing quirks beyond these"), but the live test makes it
concrete and shows it beats an upstream that does the right thing. The fix is
for the proxy to forward only its own normalised query (one value per key),
never the raw string.

---

## L-3 — spend is charged before the upstream call, so a rejected write still counts

**Severity: low.** `test`: `test_11_budget_spent_equals_money_moved_when_the_upstream_refuses` (expected failure).

**What.** The proxy asks the engine to decide (which commits the spend to the
ledger) and then forwards the request. If the upstream rejects the write
(here, a refund for a customer id that does not exist → 404), the spend stays
on the ledger although no money moved. After one such refund of 50.00 the
ledger reads `{"EUR": 5000}` with no row written.

**Why it matters.** `docs/LIMITATIONS.md` §12 notes spend is committed before
the audit record; this extends it: spend can also diverge from what the
*upstream* accepted. For a budget meant to bound money actually moved, a flaky
or validating upstream inflates the count. The honest fix is a compensating
release when the upstream refuses, which the proxy does not do.

---

## L-4 / L-5 / L-6 — the Rust HTTP proxy differs from the Python proxy on hard responses

All three are in `ports/rust` (`cli/src/httpproxy.rs`) and are shown by running
the *same* live cases against `ports/rust/target/release/smartdelegate http-proxy`.

**L-4 — oversized passthrough is truncated, not refused (medium).**
`test_19b` (Rust, expected failure). A `"response": "passthrough"` body larger
than 32 MB: the Python proxy refuses it (`502 unfilterable_response`), the Rust
proxy reads `.take(32*1024*1024)` and returns **HTTP 200 with the body
silently truncated** to 32 MiB. A silent truncation on a passthrough route is
worse than a refusal: the agent cannot tell the data is incomplete.

**L-5 — binary passthrough is refused (medium).** `test_14b` (Rust, expected
failure). The Rust proxy reads the upstream response with `read_to_string`
(UTF-8), so a passthrough route for a real binary (a PDF export) fails with
`502 upstream_unreadable`; the Python proxy reads bytes and passes them through
byte-for-byte (verified identical to a direct fetch). A passthrough route is
exactly where binaries are expected.

**L-6 — a few slow upstreams stall the proxy (medium).** `test_17b` (Rust,
expected failure). The Rust proxy serves on a fixed pool of 4 threads, each
looping on `server.recv()`; while 6 requests wait on a slow upstream route, an
ordinary request waits with them (measured ~2.5 s). The Python proxy
(`ThreadingHTTPServer`, one thread per connection) answers the ordinary request
in ~0.01 s. Four slow upstream calls are enough to make the Rust proxy
unavailable to every other agent.

---

## L-7 — SqlGuard cannot state resource attributes (fails closed)

**Severity: low (fails closed).** `tests`: `SqlGuardPostgres.test_02...`,
`test_06...`.

**What.** `SqlGuard.build_select` calls `backend.authorize(token, action,
resource, id)` with no way to pass `resource.attrs`. Every policy in the
company that requires `resource has region` (all of support and sales) or a
tenant match therefore finds no permit and denies, and any nested catalogued
field (`bank.iban`, `card.number`) cannot be named as a column. It is the safe
failure — it denies rather than leaks — but it means `SqlGuard` as shipped
cannot serve the regional or nested resources of this company at all. The live
tests use a thin wrapper that supplies the attributes to exercise the rest of
the connector; that wrapper is the only place in the suite that stands in for a
missing feature, and it is clearly marked.

---

## L-8 — SqlGuard does not mask inside a column

**Severity: medium.** `test`: `SqlGuardPostgres.test_05_a_json_column_is_masked_inside...` (expected failure).

**What.** `SqlGuard` enforces which **columns** a principal may select and adds
the policy's **row filter**, and that is all. It does not apply the per-field
mask that the engine and both proxies apply *inside* a value. `crm.customer`
has `addresses` (allowed for a sales rep) with `addresses[].geo` labelled
`internal` (not allowed for a sales rep, and not for any sub-agent). Through the
proxy the same read drops `geo`; through `SqlGuard` the `addresses` column is
selected whole and every `geo` arrives. Observed: 39 address entries with `geo`
in 20 rows, for both a sales rep and a support sub-agent.

**Why it matters.** A reader could reasonably believe `SqlGuard` gives the same
field protection as the other enforcement points. It does not: it is
column-and-row only. Either the connector should refuse a column whose
catalogued sub-fields are not all permitted, or it should post-mask the rows it
returns (it already has the decision's obligations to do so).

---

## L-9 — the Rust daemon leaves Nagle on; token issuance stalls ~45 ms

**Severity: low (performance).** Found by `python3 -m live.load --targets rust`
and confirmed with a direct probe.

**What.** `src/sf_smartdelegate/daemon.py` sets `disable_nagle_algorithm = True`
with a comment explaining the 40 ms delayed-ACK stall it avoids. The Rust
daemon (`tiny_http`) does not set `TCP_NODELAY` on its connections. Responses
that fit in one TCP segment (`authorize` ~3–4 ms, small `filter`) are
unaffected, but a response that spills past one segment — `issue_token` and
`exchange_token`, whose body carries a freshly signed JWT — stalls on the
client's delayed ACK at ~45 ms, versus ~1.5–3 ms on the Python and Node
daemons.

**Reproduce.** On one keep-alive connection with `TCP_NODELAY` set on the
client, median latency per operation:

| daemon | authorize | filter | issue_token |
|---|--:|--:|--:|
| rust | 3.5 ms | 3.9 ms | **45.1 ms** |
| node | 2.7 ms | 3.4 ms | 2.3 ms |
| python | 3.0 ms | 3.3 ms | 1.5 ms |

A token-issuance-heavy workload on the Rust daemon pays this on every mint. The
fix is one `set_nodelay` on accepted connections.

---

## L-10 — a value that is not an expression was read as a constant

**Severity: medium.** Reported by the Rust maintainer against the reference MCP proxy; the HTTP proxy had the
same class of problem.

**What.** `resolve_expr` treated any string it did not recognise as a literal. In a tools file,
`"input": "args"` (meant: all the arguments are the record) is not `args.<name>`, so it resolved to the string
`"args"`; `decide_call` then saw "not an object" and fell back to `authorize` without data. The call was
forwarded with **no strict field check**: an agent could write `tier`, `notes` or any other field through a
tool whose mapping looked as if it checked them. The same reading made `"spend": {"amount": "amount"}` a
constant, and an unknown key (`"spnd"`, `"inptu"`, or `"input"` in an HTTP route, where it means nothing) was
ignored without a word.

**Reproduce (before the fix).** `{"update_customer": {"action": "update", "resource": "crm.customer", "input": "args"}}`,
then `tools/call update_customer {"tier": "platinum"}`: forwarded. Now: `field_denied`.

**Fix.** `"args"` (and only for `input`) is the whole arguments and is checked. Everywhere a value is taken from
the request it must be an expression, `{"literal": v}`, a number or a boolean; anything else, and any unknown
key, stops the proxy at start with the tool or route named. A call that does not carry the object `input`
points at is refused (`invalid_input`), not forwarded unchecked. An `env:NAME` that is not set is a start-up
error as well.

## L-11 — request bodies with Transfer-Encoding

See the table. The reference before the fix, by its code (not measured then): the body was read by
`Content-Length` only, so a chunked request had "no body"; it was authorised as a body-less call (no field
check, because there was nothing to check) and forwarded without a body, and the chunk bytes stayed on the
connection, where the server read them as the next request. Now, measured against the real upstream (live
`test_09b`): `411 length_required` for chunked, `400` for chunked with a `Content-Length` and for two
`Content-Length` headers; one response, connection closed, no call to the upstream, row unchanged. The Rust
proxy on the same three requests, before its fix: `403` twice on each connection (it decoded the body, refused
it on its fields, then served the request that followed and refused that too), two lookups at the upstream.
After its fix it answers as the reference does (live `HttpProxyRust.test_09b` passes without a mark).

## About the tests themselves: daemons left running

Other workers found `sf-smartdelegate serve` processes under `/tmp/smartdelegate-live-*` after live runs. Cause:
`McpProxyCases` in `live/upstream/test_live_upstream.py` created a stack per class and had no `tearDownClass`,
so one daemon per MCP class (one Python, one Rust) outlived every run of the upstream suite made before the
exit handler was added. Fixed: the class stops its stack; every stack is also stopped at exit and on SIGTERM,
and children are started with `PR_SET_PDEATHSIG`. `live/run.sh` now records every pid the test code starts and
fails the run (exit 1, each survivor listed and stopped) if one is alive at its end. The two that were found
(pids 13993 and 14113, started 18:03, cwd `/tmp/smartdelegate-live-python-…` and `…-rust-…`) were stopped by pid.
