# Operations

Every operation is JSON in, JSON out, and identical through:

| Surface | How |
|---|---|
| Python (reference) | `Engine(config).call(op, input)` or `DaemonClient(url, ...).call(op, input)` |
| Java | `new Engine(config).call(op, input)` or `new Client(url, ...).call(op, input)` |
| Node, Go, PHP | `engine.call(op, input)` / `Call` / `call`; each also has a REST client. See `ports/<lang>/README.md` |
| Rust | `Engine::call(op, &input)`; C ABI `smartdelegate_call(engine, op, input_json)` |
| REST | see the route for each operation; `spec/openapi.yaml` |
| CLI | `smartdelegate <command>` (Python and Rust); `smartdelegate-node`, `smartdelegate-go`, `smartdelegate-php` have the same token, decision, audit, bundle and `serve` commands |

Success: `{"ok": true, ...}`. Failure of the request itself:
`{"ok": false, "error": {"code": "...", "message": "...", "rule": "DELEGATE-..."}}`. A deny is a success
with `"effect": "deny"`. Every decision carries `"rule"`: `DELEGATE-` plus the reason in upper case with dashes.

## Engine configuration

```json
{
  "bundle_dir": "bundle",
  "state_dir": "state",
  "issuer": "smartdelegate://local",
  "mode": "enforce",
  "default_ttl": 900, "max_ttl": 3600, "max_depth": 4, "approval_ttl": 900,
  "bundle_public_key": "<base64 Ed25519 public key; when set, the bundle must be signed>",
  "idp": {"issuer": "https://idp.example", "audience": "my-client-id", "jwks_file": "jwks.json", "user_claim": "sub",
          "groups_claim": "groups", "group_type": "Group", "group_map": {"<name at the provider>": "<group id in entities.json>"}},
  "require_role": false,
  "trusted_keys": ["<base64 public key of another issuer instance>"],
  "verify_only": false,
  "trust_caller_chain": false,
  "allow_test_clock": false,
  "audit": true
}
```

| Key | Meaning |
|---|---|
| `state_dir` | Signing key, `state.json` (revocations, approvals, spend), `audit.jsonl`, `lock`. Without it the engine is in-memory, has an ephemeral key and no audit log |
| `mode` | `enforce` or `shadow` |
| `verify_only` + `trusted_keys` | An engine that checks tokens issued elsewhere and cannot issue |
| `trust_caller_chain` | Accept `chain` instead of `token`. For policy unit tests and for a caller that has already authenticated the principal. Off by default |
| `allow_test_clock` | Honour `now` in inputs. Tests only |
| `signing_key` | The private key itself (base64 PKCS#8), instead of the file in `state_dir`. For deployments that inject the key from a secret store |
| `idp.jwks` / `idp.jwks_file` | The provider's signing keys, inline or as a file |
| `idp.groups_claim` | When set, the provider's group claim is the human's membership for that token and replaces what `entities.json` says. A dotted name reads a nested claim (`realm_access.roles`). See `ROLES.md` |
| `idp.audience` | Your client id at the provider. The ID token's `aud` must contain it, and its `azp`, when present, must equal it. Use the ID token, never an access token |
| `require_role` | Refuse to issue a root token that names no role |

The daemon and CLI read the same file and add `listen`, `admin_key`, `pep_key`
(or `SMARTDELEGATE_ADMIN_KEY`, `SMARTDELEGATE_PEP_KEY`).

## Decisions

### `authorize` — `POST /v1/authorize` (pep key)

Input

| Field | Type | |
|---|---|---|
| `token` | string | capability token |
| `action` | string | required |
| `resource` | `{path, id?, attrs?}` | `path` must be in the catalog; `id` defaults to `"any"` |
| `context` | object | integers, strings, booleans, lists, objects. No floats, no nulls. `iam` is reserved. `spend: {currency, amount}` triggers the budget check |
| `fields` | string[] | limit field decisions to these; default is every catalogued field |
| `dry_run` | bool | no spend, no rate count, no approval consumed, no audit record |
| `explain` | bool | add the trace |

Output: see `docs/SCOPE.md` section 7.

### `filter` — `POST /v1/filter` (pep key)

`authorize` plus `data` (one record or a list) and optional `strict`. Returns the
decision with `data`, `masked`, `rows_dropped`. On deny `data` is `null`.

### `apply_obligations` — `POST /v1/obligations/apply` (pep key)

`{"obligations": <from an allow decision>, "data": ..., "decision_id": "..."}` →
`{"data", "masked", "rows_dropped"}`. Authorises nothing by itself. Use it for a
tool result that arrives after the decision.

### `explain` — `POST /v1/explain` (pep key)

`authorize` with `explain` and `dry_run` forced on.

## Tokens

### `issue_token` — `POST /v1/token`

`{"user" | "id_token", "agent", "cap"?, "role"?, "groups"?, "ttl"?, "tenant"?, "task"?}`.
`cap` is required unless `role` is given; with a role the capability can never
exceed the role's ceiling (`ROLES.md`).
Over REST: with `id_token`, no key is needed and `user` is ignored (and the
engine ignores `groups`); with `user`, the admin key is required.
Errors: `invalid_cap`, `unknown_agent`, `delegation_denied`, `id_token_invalid`, `no_idp`,
`unknown_role`, `role_not_held`, `role_exceeded`, `role_required`.

### `exchange_token` — `POST /v1/token` (no key; the subject token is the authority)

`{"subject_token", "actor", "cap"?, "ttl"?, "task"?, "role"?}`. `cap` omitted inherits the parent's.
The new token's `lim` claim is the parent's `lim` plus `{parent token id: parent budget}` when the parent has a budget; it is absent when no ancestor has one. Verification rejects a `lim` that is not an object of `{currency: non-negative integer}` objects.
The role and live membership are inherited; a different `role` is `widening`.
Errors: `token_invalid`, `token_expired`, `token_revoked`, `invalid_cap`, `widening`,
`depth_exceeded`, `unknown_agent`, `delegation_denied`.

Both return `{"token", "token_type", "issued_token_type", "token_id", "expires_at", "expires_in", "user", "chain", "role", "task", "cap"}` (`role` and `task` are `null` when the token has none).

### `inspect_token` — `POST /v1/token/inspect` (pep key)

`{"token"}` → `{"valid": true, "claims", "chain", "user", "expires_in"}` or `{"valid": false, "reason", "detail"}`.

### `revoke` — `POST /v1/admin/revoke` (admin key)

`{"token_id"}` or `{"token"}`: revokes the token and everything derived from it → `{"revoked": id}`.

`{"user": U, "by"?}`: offboarding. Every token whose subject is that user and whose `iat` is at or
before the time of the call is revoked, sub-agent tokens included → `{"revoked_user": U, "issued_up_to": ts}`.
The cut-off never moves back: a second call with an earlier clock keeps the later value and returns it.
Tokens issued later are unaffected; whether the user can get one is a matter of role membership.
`user` takes precedence over `token` and `token_id`; a `user` that is not a non-empty string is `invalid_input`.

## Approvals

### `approvals` — `GET /v1/admin/approvals` (admin key)

`{"pending": {id: {label, user, agent, action, resource, requested_at}}, "granted": {id: {by, exp}}}`.

### `approve` — `POST /v1/admin/approve` (admin key)

`{"approval_id", "by", "ttl"?}`. Errors: `unknown_approval`, `self_approval`, `approval_denied`.

## Audit and administration

| Operation | REST | |
|---|---|---|
| `audit_verify` | `GET /v1/admin/audit/verify` | `{"records", "head"}` or error `audit_broken` naming the line |
| `audit_tail` | `GET /v1/admin/audit/tail?n=20` | `{"records": [...]}` |
| `info` | `GET /v1/info` (pep key) | version, policy version, roles, mode, key id, public key |
| `reload` | `POST /v1/admin/reload` | reload the bundle and `idp.jwks_file`; if either fails to load the old ones stay in force |

`GET /healthz` needs no key.

## Proxy configuration

This section is normative for every port that has proxies (Python, Rust).
"MUST" and "MUST NOT" are meant literally; status codes, error codes and the
order of the steps are part of the contract.

### HTTP proxy (`sf-smartdelegate http-proxy --routes routes.json`)

```json
{
  "upstreams": {"crm": {"base_url": "env:CRM_URL", "headers": {"X-Api-Key": "env:CRM_API_KEY"}}},
  "routes": [
    {"upstream": "crm", "method": "GET", "path": "/{tenant}/customers/{id}",
     "action": "read", "resource": "crm.customer", "id": "{id}",
     "attrs": {"tenant": "{tenant}"},
     "lookup": "/{tenant}/customers/{id}", "attrs_from_record": {"region": "region"}},
    {"upstream": "crm", "method": "GET", "path": "/{tenant}/customers",
     "action": "read", "resource": "crm.customer", "attrs": {"tenant": "{tenant}"},
     "attrs_from_request": {"region": "query.region"},
     "data_key": "items", "keep": ["next"], "query": ["region", "cursor", "limit"]},
    {"upstream": "crm", "method": "POST", "path": "/{tenant}/refunds",
     "action": "create", "resource": "billing.refund", "id": "body.id",
     "attrs": {"tenant": "{tenant}"},
     "lookup": "/{tenant}/customers/{body.customer_id}",
     "attrs_from_record": {"region": "region", "customer_owner": "owner.id"},
     "spend": {"currency": "body.currency", "amount": "body.amount"}}
  ]
}
```

The agent calls `http://<proxy>/<upstream><path>` with `Authorization: Bearer <capability token>`.

| Key | Meaning |
|---|---|
| `upstreams.<name>.base_url` | Where the upstream is. `"env:NAME"` is the value of the environment variable `NAME` |
| `upstreams.<name>.headers` | Headers the proxy adds to every call it makes to that upstream (the upstream's credential). `"env:NAME"` as above. Nothing from the agent's request headers is forwarded |
| `method`, `path`, `action`, `resource` | required, non-empty strings. Methods served: `GET`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `id`, `spend.currency`, `spend.amount` | an *expression* (below) |
| `attrs` | Resource attributes the route itself fixes: a constant (string, integer, boolean), or `{param}`. Never `body.…` or `query.…` |
| `attrs_from_request` | Resource attributes taken from the request: `body.a.b` or `query.name`. **A claim by the agent** (see below) |
| `lookup` | A path on the same upstream that returns the record the call is about as one JSON object. Placeholders: `{param}`, `{body.a.b}`, `{query.name}` |
| `attrs_from_record` | Resource attributes taken from that record: `{"attr": "field"}` or `"a.b"` for a nested member. Needs `lookup` |
| `request` | default: a JSON object body is field-checked strictly. `"unchecked"` skips that |
| `response` | default `"filter"`. `"passthrough"` returns the upstream body untouched; use only where the response holds no record data |
| `data_key`, `keep` | for envelopes: which key holds the records, and which other keys survive |
| `query` | query parameter names that may be sent. Default none |

**Expressions.** Where a route takes a value from the request (`id`,
`spend.currency`, `spend.amount`), the value in the routes file MUST be one of:

| Form | Means |
|---|---|
| `"{name}"` | the path parameter `name` of this route's `path` |
| `"body.a.b"`, `"query.name"` | member `b` of member `a` of the JSON body; the query parameter `name` (decoded). At least one name after the dot, none empty |
| `{"literal": <any JSON value>}` | that value |
| a JSON number or boolean | itself |

Any other value is a start-up error: a plain string that is none of the
above (`"amount"`, `"body"`, `"bdy.amount"`, `"EUR"`), `null`, a list, another
object. A constant must be written `{"literal": "EUR"}`. The reason is that a
misspelt expression read as a constant would silently switch a check off.
The MCP proxy uses the same table with `args` as its only source, plus the
whole-object form `"args"` for `input` (below). `attrs` is the one key whose
string values are constants by definition; `attrs_from_request` takes only
`body.…` / `query.…`.

The set of keys is closed. A key that is not in the tables of this section, at
the top level (`upstreams`, `routes`, `listen`), in an upstream (`base_url`,
`headers`) or in a route, is a start-up error: a misspelt `spend` or `lookup`
must not be ignored.

**Where a resource attribute comes from decides what it is worth.**

- `attrs` (literal or path parameter): the route's own statement. A path
  parameter is part of the path that is forwarded, so the upstream is asked
  about exactly what was authorised.
- `attrs_from_record`: the upstream's statement, fetched with the proxy's
  credential before the decision. This is the source for any attribute a
  policy *restricts* on (region, owner, status, tenant of a record).
- `attrs_from_request`: the agent's statement. **An attribute the agent
  supplies is a claim.** Use it only where a lie gains nothing: where the same
  value is also what the upstream stores (the `kind` of a payment being
  created), or where the deciding policy carries a row filter that is
  evaluated on the returned records whatever was claimed. A policy of the form
  "forbid when `resource.region` is not the user's region" is satisfied by a
  false claim.
- List routes return many records, so there is no one record to look up. On
  a list route **the row filter of the deciding policy is the only per-record
  control**; an attribute on a list route is at best a claim. The proxy cannot
  tell from the route table whether the policy that will decide carries a row
  filter (policies are evaluated per request, on the principal), so it does
  not pretend to: it prints a warning for every list route (`data_key`) that
  has `attrs_from_request`, and the bundle's author must check that the
  permits for that resource carry `@row_filter`.

**Start-up.** The proxy MUST refuse to start (exit status 1, a message on
stderr naming the route and the reason) when the routes file has: no
`upstreams` object or no `routes` list; an unknown key (above); an upstream
that is not an object with a string `base_url`; a route whose `upstream` is
not in `upstreams`, or that lacks `method`, `path`, `action` or `resource`;
an `id` or `spend` value that is not an expression; a `spend` that is not
exactly `{"currency", "amount"}`; `request` other than `"checked"` /
`"unchecked"`; `response` other than `"filter"` / `"passthrough"`; `query` or
`keep` that is not a list of strings; `data_key` that is not a string; a
route that is not an object; `attrs`,
`attrs_from_request` or `attrs_from_record` that is not an object; an `attrs`
value of the form `body.…` or `query.…`, or `{name}` where the path has no
such parameter; an `attrs_from_request` value that is not `body.…` or
`query.…`; an empty or non-string `attrs_from_record` value;
a non-empty `attrs_from_record` without `lookup` (an empty object is the same
as no key); a `lookup` that is not a string starting
with `/`, or that has a placeholder that is neither a path parameter of the
route nor `{body.…}` / `{query.…}`; the same attribute name under two of the
three keys. It MUST also refuse to start when a `base_url` or a header value
is `"env:NAME"` and the variable `NAME` is unset or empty (the message names
the upstream and the variable): a proxy that starts without its upstream's
address or credential would answer every request with a 502. After the line `smartdelegate http proxy listening on
http://host:port` (which MUST stay the first line on stderr) it prints one line
per route that has `attrs_from_request`:

```text
smartdelegate http proxy: route 4 (POST /crm/{tenant}/payments) trusts request-supplied attributes: approved_by, kind, requested_by
smartdelegate http proxy: warning: route 1 (GET /crm/{tenant}/customers) is a list route decided on request-supplied attributes; only a row filter in the deciding policy controls which records come back
```

(`route N` is the index in `routes`; attribute names sorted.)

**A request is handled in this order.** The first step that fails answers; nothing later happens.

0. A request that is not valid HTTP/1.x, or whose method is not one of the
   five served, is answered by the HTTP layer with a 4xx or 5xx status (the
   reference: `400` for a malformed request line, `431` for an oversized
   header, `501` for another method, `CONNECT` included). The status and the
   body of these answers are not specified, except that the status is never
   2xx or 3xx, the engine is not asked and nothing is sent to an upstream.
1. **Framing.** The body is delimited by `Content-Length` and by nothing
   else. A request with a `Transfer-Encoding` header (any value) and no
   `Content-Length`: `411 length_required`. With `Transfer-Encoding` and
   `Content-Length`: `400 invalid_input`. More than one `Content-Length`
   header, or one that is not a decimal number: `400 invalid_input`. A
   `Content-Length` over 8 MiB: `400 invalid_input`. In all four cases the
   proxy closes the connection after the answer (`Connection: close`
   semantics) and MUST NOT read what follows on it as another request. A
   chunked body is not decoded: a proxy and a server in front of or behind it
   that disagree on where a request ends can be made to see two different
   requests, and no upstream call of this proxy needs chunked input.
2. The first path segment names the upstream; unknown: `403 no_route`. The
   first route with that upstream, the same method and a matching path is
   used; none: `403 no_route`. A path parameter matches one segment of
   `[A-Za-z0-9-_.~:@]+` other than `.` and `..`.
3. **The query string** is split at `&`; empty pieces are skipped; each piece
   is split at its first `=` into name and value (no `=`: the value is
   empty). The request is refused with status 400 when
   - the query string contains `;` anywhere: `query_ambiguous`;
   - a name is empty, or is not made of `[A-Za-z0-9_.-]` only (so a name with
     a percent-escape, `+` or a space is refused, whatever it would decode
     to): `query_ambiguous`;
   - a name is not in the route's `query` list (compared exactly): `query_not_allowed`;
   - a name appears more than once, compared without regard to ASCII case: `query_duplicate`;
   - a value has `%` not followed by two hex digits, a raw byte outside
     `0x21`–`0x7E`, bytes that are not UTF-8 after percent-decoding, or a
     decoded character below U+0020 or U+007F: `query_ambiguous`.

   The checks are made per piece, left to right, in the order listed. Values
   are percent-decoded; `+` is a plus sign, not a space. From here on **the
   query is the list of (name, decoded value) pairs**: `query.name` in a route
   expression is the decoded value, and what is forwarded is that list written
   out again as `name=value` joined with `&`, in the order received, every
   byte of a value percent-encoded except `A-Z a-z 0-9 - _ . ~`. The raw query
   string MUST NOT be forwarded. The proxy authorises on exactly what it sends.
4. No `Authorization: Bearer …` header: `401 token_invalid`.
5. A body that is not empty MUST be JSON: otherwise `415 invalid_input`.
6. `id`, `attrs` and `attrs_from_request` are resolved. A `body.…` or
   `query.…` expression whose value the request does not have: `400
   invalid_input`. An `id` that is missing or not a string is `"any"`.
7. Only on a route with `lookup`:
   1. **What does not depend on the record is decided first.** The proxy asks
      the engine `authorize` with `dry_run: true`, the route's action and
      resource, the id, and the attributes of step 6 (no spend, no data). If
      the engine reports an error: `400` with its code. If it denies with one
      of `token_invalid`, `token_expired`, `token_revoked`, `unknown_resource`,
      `tenant_mismatch`, `capability_action`, `capability_resource`, the proxy
      repeats the same `authorize` without `dry_run` (so that the refusal is in
      the audit log) and answers `403` with that reason, in the body of step 9
      (`decision_id` of the repeated call; `approval` is `null`). No call to the
      upstream has been made: whoever is outside the tenant or the capability
      gets the same answer for a record that exists and one that does not. Any
      other outcome (allow, or a denial that the missing attributes may
      explain) continues.
   2. The lookup path is built from the template; a `{body.…}` or `{query.…}`
      placeholder whose value is missing, not a string, or not a legal path
      parameter (step 2): `400 invalid_input`. The proxy sends `GET <base_url><lookup path>`
      with the upstream's headers, no query, no body, redirects not followed.
      - not reachable, or no answer in 60 s: `502 upstream_unreachable`;
      - status 404: **`404 not_found`**, message `the upstream has no such record`, nothing of the upstream's body;
      - any other status than 200, a body over 32 MiB, a body that is not one JSON object: `502 lookup_failed`.

      Inside the tenant and the capability the caller can therefore tell an
      absent record (`404`) from one it may not touch (`403`). Record ids are
      not treated as secrets beyond step 7.1.
   3. Every `attrs_from_record` entry is read from the record (`a.b`: member
      `b` of member `a`). A member that is missing, or whose value is not a
      string, an integer or a boolean: `502 lookup_failed`. These attributes
      are added to those of step 6.
8. `spend`: currency and amount are resolved; the currency MUST be a string
   and the amount an integer (not a boolean): otherwise `400 invalid_input`.
9. **The decision.** `filter` with `strict: true` and the body as `data` when
   the body is a JSON object and `request` is not `"unchecked"`; `authorize`
   otherwise. `context.http` is `{method, upstream, path}`. An engine error:
   `400` with its code. A denial: `403`,
   `{"error": {"code": <reason>, "message", "by": "smartdelegate", "decision_id", "approval"}}`.
   This step also **reserves the spend and uses up an approval** (below).
10. **The upstream call.** Method, `<base_url><path>`, the query of step 3,
    the upstream's headers, and the body re-serialised from the parsed JSON
    with `Content-Type: application/json`. Redirects are not followed.
    The form of the forwarded JSON is not specified beyond its value: the
    upstream receives a JSON text equal, as a value, to what was checked
    (whitespace, the escaping of strings and the spelling of numbers may
    differ from what the agent sent; where the agent repeated a key in an
    object, only the last occurrence was checked and only it is sent).
    Exception: a `GET` on a route whose lookup path equals the request path,
    with an empty query and without `"response": "passthrough"`, is answered
    from the record of step 7 as if the upstream had returned it with status
    200; no second call is made. "Equals" is equality of the two strings: the
    path of the request exactly as received, after the upstream's name, and
    the lookup path as built in step 7.2 (`/` + segments joined by `/`). A
    request path with a trailing slash still matches the route (step 2) but
    is not equal, and takes the ordinary path: the second call.
11. **The response.** Not reachable: `502 upstream_unreachable`. More than
    32 MiB: `502 unfilterable_response`, on every route, `passthrough`
    included; a body MUST NOT be cut. `passthrough`: status, `Content-Type`
    and the bytes exactly as received (they need not be text). Otherwise: an
    empty body is passed on with its status; a body that is not JSON:
    `502 unfilterable_response`; status 400 or above: that status with
    `upstream_error` and nothing of the body; else the records (`data_key`, or
    the whole body) go through `apply_obligations` and are returned with the
    upstream's status and the headers `X-SmartDelegate-Decision` and
    `X-SmartDelegate-Masked`.

Every refusal by the proxy has the body
`{"error": {"code": "...", "message": "...", "by": "smartdelegate"}}`.

A slow upstream call MUST NOT delay requests of other clients.

**Between the lookup and the write** the record can change in the upstream:
the decision is about the record as it was fetched. An upstream that offers
conditional writes should be given them by the route's own design; the proxy
does not add one.

**Spend is reserved before the upstream is called.** The decision of step 9
adds the amount to the ledger of the token and of every token above it, and
uses up a one-use approval, before step 10. If the upstream then refuses the
write, or cannot be reached, the reservation stays: **a rejection by the
upstream does not refund the budget**. The other order (ask with `dry_run`,
call the upstream, then record the spend) would let a write happen that the
second engine call then refuses, because another agent used the budget or the
approval in between; a budget that can be overrun is worse than one that is
sometimes under-used. Doing both needs a reserve / commit / release operation
in the engine, which does not exist in 0.3.0.

### MCP proxy (`sf-smartdelegate mcp-proxy --tools tools.json -- <server command>`)

```json
{
  "server": "crm",
  "allow_methods": [],
  "tools": {
    "get_customer": {"action": "read", "resource": "crm.customer", "id": "args.customer_id",
                     "attrs": {"tenant": "acme"},
                     "lookup": {"tool": "get_customer", "arguments": {"customer_id": "args.customer_id"}},
                     "attrs_from_record": {"region": "region"}},
    "list_customers": {"action": "read", "resource": "crm.customer", "attrs_from_request": {"region": "args.region"}},
    "update_customer": {"action": "update", "resource": "crm.customer", "id": "args.customer_id", "input": "args.changes",
                        "lookup": {"tool": "get_customer", "arguments": {"customer_id": "args.customer_id"}},
                        "attrs_from_record": {"region": "region"}},
    "refund": {"action": "create", "resource": "billing.refund", "spend": {"currency": "args.currency", "amount": "args.amount"}}
  }
}
```

The keys of a tool mapping are `action`, `resource` (both required), `id`,
`attrs`, `attrs_from_request`, `lookup`, `attrs_from_record`, `spend`, `input`,
`response`; the top level has `server`, `allow_methods`, `tools`; `lookup` has
`tool`, `arguments`. Any other key stops the proxy at start (exit status 1).
`id`, `spend.currency`, `spend.amount` and the values of `lookup.arguments`
are expressions as defined for the HTTP proxy, with `args.a.b` as the only
source: `"args.x"`, `{"literal": v}`, a number or a boolean; anything else is
a start-up error.

`input` names the part of the arguments that is record data, checked
strictly. It MUST be `"args"` (all the arguments are the record) or
`"args.a.b"` (that member); any other value, `{"literal": …}` included, is a
start-up error. A call whose `input` does not resolve to a JSON object (the
member is missing, or is not an object) is refused with
`Denied by SmartDelegate (invalid_input): …`; it is never forwarded
unchecked. `"response": "passthrough"` disables result masking for a tool;
any other `response` than `"filter"` or `"passthrough"` is a start-up error. The token is read
from `SMARTDELEGATE_TOKEN`, or from `--token-file` on every call.

Attributes follow the same three sources as in the HTTP proxy, with the same
meaning: `attrs` (literals only; an `args.…` value there stops the proxy at
start, exit status 1), `attrs_from_request` (`args.…`: a claim by the agent;
one line per such tool on stderr at start,
`smartdelegate mcp proxy: tool <name> trusts request-supplied attributes: <names>`),
and `attrs_from_record` with `lookup: {"tool": <a tool of the same server>, "arguments": {<name>: "args.…" or a literal}}`.

A `tools/call` on a mapping with `lookup` is handled in this order: (1) the
dry-run `authorize` and the early refusals of step 7.1 above; (2) the proxy
itself sends `tools/call` for the lookup tool to the server, with a request id
of its own (`"smartdelegate-lookup-<n>"`; a request from the agent whose id
starts with `smartdelegate-lookup-` is answered with JSON-RPC error `-32600`),
waits at most 60 s, and takes as the record the result's `structuredContent`
when it is an object, otherwise the first text item when it parses as a JSON
object; a JSON-RPC error, `isError`, a timeout or no such object is a refusal
`lookup_failed`; (3) `attrs_from_record` as in step 7.3; (4) the decision;
(5) the agent's own call is forwarded. Nothing of the lookup's answer, and no
notification the server sends while answering it, reaches the agent. A
refusal is a tool result with `isError: true` and the text
`Denied by SmartDelegate (<reason>): <detail>.` The lookup is a second call to
the server: the record is not reused for the agent's call.

## SQL connector (`smartdelegate.SqlGuard`, Python only)

```python
guard = SqlGuard(backend, connection, paramstyle="format")       # "qmark" for sqlite3
rows = guard.select(token, "customers", "crm.customer", columns=[...],
                    where={"id": "c-1"}, limit=50,
                    attrs={"tenant": "acme"},                      # the caller vouches for these
                    row_attrs={"region": "region"}, id_column="id")  # read from each row
```

Column names are the catalog's field names. Table and column names must be
plain identifiers (`[A-Za-z_][A-Za-z0-9_]*`; anything else is `ValueError`);
values are always bound parameters.

**Every row is masked.** Each row fetched is passed through the field mask of
the decision that allows it, by the same walk the engine's `filter` and
`apply_obligations` use: nested paths (`card.number`), `[]` paths
(`addresses[].geo`) and redaction apply inside a column that holds structured
data (JSON/JSONB, arrays of records). Naming only permitted columns in the
`SELECT` is an optimisation; the mask is the control. A column the catalog
describes member by member whose value arrives as text is parsed as JSON
first; text that does not parse cannot be checked and is left out of the row.

Two ways to decide:

- **One decision per query** (default). `authorize(read, resource, id, attrs)`
  once. Only permitted columns are selected; `where` on a column that is not
  permitted is `Denied`; the decision's row filter is added to the `WHERE`
  clause as bound parameters. `attrs` are stated by the caller and are not
  checked against the rows: they must be true of every row the query can
  return (a table or view per tenant, a `where` on the same value).
- **One decision per row** (`row_attrs` and/or `id_column`). The query
  selects the requested columns plus the columns named by `row_attrs`,
  `id_column` and `where`, with `where` and `limit` only. For each row the
  attributes are `attrs` plus the row's own values (`row_attrs` maps attribute
  name to column name; the columns need not be catalog fields and are not
  returned unless also requested), and the resource id is the row's
  `id_column`. Rows are decided in groups of equal (id, attribute values):
  one `authorize` and one audit record per distinct group, not per row. A row
  is dropped when its decision denies, when an attribute value is not a
  string, integer or boolean, when a `where` column is not permitted by its
  decision, or when the decision's row filter does not hold on the row (a
  filter column that was not fetched counts as not holding). A denial for
  `token_invalid`, `token_expired` or `token_revoked` raises `Denied` instead.
  Cost: candidate rows are read from the database before they are decided, so
  narrow the query with `where`; with `id_column` there is one decision per
  row.

Limits: a nested catalog field can be read only inside a structured column,
not from a flat column of another name (`bank.iban` is not `bank_iban`);
reads only; row filters are equality tests.
