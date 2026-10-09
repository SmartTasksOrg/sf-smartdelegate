# Rust port

A port of the SmartDelegate engine at spec 0.3 (`info` reports
`"version": "0.3.0"`, `"implementation": "rust"`): engine, CLI, REST daemon,
HTTP proxy, MCP proxy, and a C ABI. The reference implementation is the
Python package in `src/sf_smartdelegate`; this port must behave identically.

It differs from the other ports in one way that matters to the whole project:
it embeds the real Cedar engine (`cedar-policy` 4). That gives it two jobs no
other port can do.

- **Compile policies.** `smartdelegate bundle compile --bundle <dir>` turns
  `policies/*.cedar` into the `policies.json` every port loads.
- **Referee.** `smartdelegate spec eval-gen <cases.src.json> <cases.json>`
  records Cedar's answers for the policy-evaluation vectors, and `cargo test`
  re-checks the committed file against Cedar.

## Layout

```
Cargo.toml              workspace, version 0.3.0 for both crates
core/                   crate smartdelegate-core (rlib, cdylib, staticlib)
  src/engine.rs         operations, decision order, roles, live group membership
  src/bundle.rs         bundle loading, roles.json, manifest/version, signing, compile
  src/token.rs          capability (narrowing), EdDSA JWT, OIDC ID tokens
  src/fields.rs state.rs audit.rs canon.rs
  src/conformance.rs    vector runner (case_config, run_case), bundle tests
  src/evalspec.rs       eval vectors: generate from Cedar, verify against Cedar
  src/ffi.rs            C ABI; header in include/smartdelegate.h
  tests/conformance.rs  vectors, eval cases vs Cedar, compiled bundle is current
  tests/strictness.rs   the "Strictness (0.3)" rules of spec/PORTING.md
  examples/roles.rs     the example below
cli/                    crate smartdelegate: the `smartdelegate` binary
  src/main.rs           commands; serve.rs (daemon), httpproxy.rs, mcpproxy.rs, util.rs
  src/http.rs           the HTTP/1.1 server under the daemon and the HTTP proxy
  tests/servers.rs      the daemon and the proxies as processes
c/conformance.c         C ABI check
```

Paths into the repository: the tests read `../../spec/conformance`, and the
CLI embeds `spec/conformance/bundle` (including `roles.json` and
`policies/roles.cedar`) as the example bundle written by `init`.

## Requirements

Rust 1.89 or newer and cargo. A C compiler only for the C ABI check. Python 3
with `cryptography` only for the cross-port tests in `tests/`.

```
cargo build --release          # a first build compiles Cedar: a few minutes
target/release/smartdelegate help
```

## Using the engine from code

Every operation is JSON in, JSON out. `Engine::call` never panics on bad input;
a failure is `{"ok": false, "error": {"code", "message", "rule"}}`.

```rust
use serde_json::json;
use smartdelegate_core::Engine;

let mut engine = Engine::new(&json!({"bundle_dir": "bundle", "state_dir": "state"})).expect("bundle loads");

// alice lends support-bot her role for one task; the token cannot carry more
// than the role's cap, and lives at most the role's max_ttl
let issued = engine.call("issue_token", &json!({"user": "alice", "agent": "support-bot", "role": "support-agent", "task": "ticket-42"}));
let token = issued["token"].as_str().unwrap().to_string();

let decision = engine.call("authorize", &json!({"token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}}));
assert_eq!(decision["effect"], json!("allow"));     // decision["rule"] == "DELEGATE-POLICY-PERMIT"

let filtered = engine.call("filter", &json!({
    "token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"},
    "data": {"id": "c-1", "email": "ada@example.com", "ssn": "123-45-6789"},
}));
// filtered["data"] has no "ssn"; filtered["masked"] == ["ssn"]
```

A runnable version: `cargo run --release -p smartdelegate-core --example roles`.
From C: `smartdelegate_engine_new(config_json)`, `smartdelegate_call(engine, op, input_json)`,
see `core/include/smartdelegate.h`.

## Roles on the command line

```
smartdelegate init demo && cd demo
smartdelegate info                                   # "roles": ["auditor", "break-glass", "supervisor", "support-agent"]

# the role's cap is the token's cap
smartdelegate token issue --user alice --agent support-bot --role support-agent --raw

# a narrower cap under the role; more than the role allows is role_exceeded
smartdelegate token issue --user alice --agent support-bot --role support-agent \
    --cap '{"actions":["read"],"resources":["crm.customer/*"]}'

# live group membership for this token: it replaces alice's stored groups
# (unknown groups are dropped; --groups "" means member of nothing)
smartdelegate token issue --user alice --agent support-bot --role supervisor \
    --task escalation-7 --groups support,supervisors

# offboarding: every token already issued for alice, sub-agents included
smartdelegate token revoke --user alice

# any operation of spec/API.md; input inline, @file, or - for stdin
smartdelegate call issue_token --input '{"user":"alice","agent":"support-bot","role":"support-agent"}'
smartdelegate call info
```

`token issue` needs `--cap` or `--role`. `bundle sign` signs the manifest,
which covers `roles.json`; a `roles.json` edited after signing fails to load
with `bundle_signature`. Engine config keys new in 0.3: `require_role`,
`idp.groups_claim`, `idp.group_type`, `idp.group_map`, and `idp.jwks` (inline
JWKS) as an alternative to `idp.jwks_file`. Rust only: `signing_key_wait_ms` (default 30000), how long an
empty `signing_key.pk8.b64` is waited for before the engine fails with `state_io`.

## Tests

From `ports/rust`:

```
cargo build --release
cargo test --release -p smartdelegate-core -- --nocapture
```

`tests/conformance.rs`, three tests: the engine conformance vectors (78 cases, 327 steps, each case
with a fresh engine and state directory, the vector file's top-level `config`
merged over the standard one); the 95 policy-evaluation cases re-checked
against Cedar; and the conformance bundle's `policies.json` is current with
its `.cedar` sources.

`tests/strictness.rs`, 20 tests: `reload` re-reads `idp.jwks_file` (key rotation; a
broken file keeps the old keys and the old bundle); an approval is bound to the resource
attributes of its request; a verify-only engine with its own state
enforces an ancestor's budget from the token's `lim` claim, and a malformed
`lim` is `token_invalid`; an empty signing key file is waited for and
never read as "no key"; revoke by user (state files without
`revoked_users`, unknown state keys kept, no pruning) and the "Strictness (0.3)" rules of
`spec/PORTING.md`: audit records containing U+2028/U+2029/U+0085 (verify,
tail, a second engine on the same state directory); strict base64url in every
token part; entity type names matched in full in requests, configuration and
every bundle file; malformed compiled-policy shapes are `policy_parse`;
malformed claims (`anc` as a string, a list for `cap`, ...) are
`token_invalid`; non-UTF-8 `state.json`, audit log and bundle files;
`entities.json` that is not a list of distinct, well-formed objects; and eight
processes (and eight threads) starting on an empty state directory end up with
one signing key and one unbroken audit chain. `containsAll`/`containsAny` are
covered by the eval cases.

The same vectors through the CLI:

```
target/release/smartdelegate conformance ../../spec/conformance/vectors ../../spec/conformance/bundle
```

The daemon and the proxies (`cargo test --release -p smartdelegate`): 5 unit
tests in `cli/src/httpproxy.rs` and `cli/src/mcpproxy.rs` (what a routes or
tools file is refused for, strict query parsing and what is forwarded, path
parameters, the record of an MCP lookup) and 9 tests in `cli/tests/servers.rs`
that start the binary against an upstream of their own:

```
cargo test --release -p smartdelegate -- --nocapture
```

A passthrough route hands on binary bytes unchanged; a response over 32 MiB is
refused with `502 unfilterable_response`, never cut (exactly 32 MiB is
delivered whole); a filtered route withholds what is not JSON; 40 slow
upstream calls in flight do not delay other calls; with every slot taken
further requests get `503 overloaded` at once and none reaches the upstream;
clients stalled in the middle of a request body do not hold up the daemon; the
median `issue_token` over one keep-alive connection is under 20 ms
(TCP_NODELAY; the test prints the medians); raw non-ASCII bytes, `;`,
duplicates and unlisted names in a query get the proxy's own `400`, and what is
forwarded is the query as parsed; a body not framed by one `Content-Length`
(chunked, two lengths, a non-numeric one) is refused by the proxy and by the
daemon with one response and nothing that follows it is served; and a routes
or tools file in the form used before 0.3 stops the proxy at start with the
reason. The unit tests cover every start-up rule.

The reference's own proxy tests run against this binary (`tests/test_proxies.py`
with `SMARTDELEGATE_TEST_CLI`, below), and so does the live suite
(`live/run.sh upstream`, which needs PostgreSQL).

C ABI (78 cases through `smartdelegate_call`, plus direct calls):

```
mkdir -p target/c
cc -Wall -Wextra -I core/include c/conformance.c -L target/release -lsmartdelegate_core -o target/c/conformance
SCRATCH=$(mktemp -d)
LD_LIBRARY_PATH=target/release DYLD_LIBRARY_PATH=target/release target/c/conformance ../.. "$SCRATCH"
rm -rf "$SCRATCH"
```

Cross-port tests, driven from Python (`$ROOT` is the repository root):

```
cd $ROOT/tests
python3 -m unittest test_interop        # tokens, signed bundles, audit logs, shared state: Rust <-> reference
SMARTDELEGATE_TEST_CLI='["'$ROOT'/ports/rust/target/release/smartdelegate"]' \
    python3 -m unittest test_proxies test_conformance.DaemonConformance   # daemon, HTTP proxy, MCP proxy
```

Tests create temporary directories and remove them. `target/` is ignored by git.

## The proxies

`http-proxy` and `mcp-proxy` implement spec/API.md "Proxy configuration"; the
Python proxies (`src/sf_smartdelegate/httpproxy.py`, `mcpproxy.py`) are the
reference and this port follows them step for step, with the same status
codes, error codes and messages for everything the proxy itself says.

- Resource attributes have three sources: `attrs` (a literal or a path
  parameter: the route's own statement), `attrs_from_record` with `lookup`
  (the upstream's statement, fetched with the proxy's credential before the
  decision) and `attrs_from_request` (the agent's claim). A file that takes a
  request value under `attrs`, or is otherwise not in this form, stops the
  proxy at start (exit status 1, the routes and reasons on stderr).
- Both files have closed key sets: an unknown key at the top level, in an
  upstream, a route, a tool mapping or a `lookup` stops the proxy, as does a
  missing `method`, `path`, `action` or `resource`, a route whose `upstream`
  does not exist, a `request` / `response` / `spend` / `query` / `keep` /
  `data_key` of the wrong form, and an `env:NAME` whose variable is unset or
  empty. `id`, `spend.currency`, `spend.amount` and MCP `lookup.arguments`
  values are expressions: `{param}` (HTTP only), `body.a.b` / `query.name` /
  `args.a.b`, `{"literal": v}`, or a JSON number or boolean; any other string
  is refused, so a misspelt expression never becomes a constant. MCP `input`
  is `"args"` (all arguments) or `"args.a.b"`, and a call whose `input` is not
  a JSON object is refused (`invalid_input`), never forwarded unchecked.
- A request body is framed by exactly one numeric `Content-Length` of at most
  8 MiB. `Transfer-Encoding` without `Content-Length` is `411
  length_required`; with it, or with two `Content-Length` headers or a
  non-numeric one, `400 invalid_input`. Chunked bodies are not decoded; the
  connection is closed and what follows is never read as a request. The
  daemon applies the same rule (see below).
- After the line `smartdelegate http proxy listening on http://host:port`
  (always the first line on stderr) there is one line per route that trusts
  request-supplied attributes, and a warning for a list route that does. The
  MCP proxy prints `smartdelegate mcp proxy: tool <name> trusts ...` lines.
- `base_url` and upstream header values may be `env:NAME`.
- The query is parsed strictly (`query_ambiguous`, `query_not_allowed`,
  `query_duplicate`) and forwarded as parsed, never as received.
- Lookup routes: what does not depend on the record is decided first, with no
  upstream call; `404 not_found`, `502 lookup_failed`; a `GET` of the record
  that was just looked up is answered from it.
- MCP lookups are the proxy's own `tools/call` (`smartdelegate-lookup-<n>`,
  60 s); nothing of the lookup's answer reaches the agent.

Where this port differs from the Python proxy, all found by running both on
the same generated requests (statuses and what reaches the upstream were the
same in every case):

- A request that is not HTTP enough to route (a space in the target, a bad
  version or header line) and a method other than GET, POST, PUT, PATCH,
  DELETE get the same status (400, 501), but with a JSON error in the proxy's
  shape; Python's `http.server` answers those with an HTML page.
- JSON is written compactly, with object keys in sorted order and non-ASCII
  characters as themselves; Python writes `", "` / `": "` separators, keeps
  the upstream's key order and escapes non-ASCII. The values are the same.
  The same holds for the request body sent to the upstream.
- Message texts that come from the engine (the detail of `token_invalid`, a
  Cedar error) or from the HTTP client (`upstream_unreachable`) are worded
  differently; codes are the same.
- Start-up messages show a value that is not a string in JSON form
  (`{"a":1}`), Python in its own (`{'a': 1}`); the files refused are the same.
- When two attributes are missing from a request the message names the first
  in sorted order, not in file order.

## Daemon and HTTP proxy: concurrency and limits

Both run on the small HTTP/1.1 server in `cli/src/http.rs`.

- Every connection has a thread of its own, so a slow upstream call or a slow
  client holds up nobody else. Engine decisions are still serialised (one
  engine, one lock); the upstream call is made outside that lock.
- At most `max_concurrent` requests are in progress at once (default 256;
  `--max-concurrent N` for both, or `"max_concurrent"` in the config of
  `serve`; the routes file has a closed set of keys). A request beyond that is answered at once
  with `503`, `Retry-After: 1` and error code `overloaded`; it is not queued.
  Connections are capped too (`max_concurrent` + 1024, to leave room for idle
  keep-alive ones).
- The daemon refuses a request that is not framed by exactly one numeric
  `Content-Length` in the same way as the proxy (`411 length_required`,
  `400 invalid_input`, connection closed), for every path and method. The
  reference daemon reads `Content-Length` only and ignores
  `Transfer-Encoding`: a chunked request has no body for it and the chunk
  bytes are read as the next request. No test of the reference daemon sends
  such a request, so the stricter rule is used here.
- A client that stops sending, in the head or in the body of a request, is
  dropped after 30 seconds, as is an idle keep-alive connection. A request
  head is at most 64 KiB, a body 8 MiB.
- TCP_NODELAY is set on every accepted connection.
- The proxy buffers an upstream response whole, up to 32 MiB; a larger one is
  refused (`502 unfilterable_response`). With the default cap that is a worst
  case of 256 x 32 MiB held at once: lower `max_concurrent` on a small machine.
- Upstream calls time out after 60 seconds.
- No TLS: bind to loopback or put it behind something that terminates TLS.

## Not included / not tested

- No per-human budget across tokens, and no cloud bridges. Roles are fully
  implemented; only a role's `bindings` object (data for bridges) is
  validated as an object and otherwise not used by the engine, as in the
  reference.
- A token with live membership (`grp`) rebuilds the entity set for each
  request from `entities.json`. This is correct but not optimised; not
  benchmarked with large entity files.
- Role tokens carrying `grp` and signed bundles containing `roles.json` crossing between ports are not in
  `tests/test_interop.py`; `ports/conformance/matrix.py` checks them for every pair of ports.
- OIDC: a static JWKS only (inline or file); no discovery, no key refresh.
  `idp.groups_claim` is exercised by the conformance vectors only.
- The C harness has no JSON library: the step logic runs inside the core
  (`conformance_case`), so it tests the ABI, not a second implementation.
- Windows and macOS builds are not tested here.
- The 60-second wait for an MCP lookup, the 60-second upstream timeout and the
  30-second client timeouts are implemented but not exercised by a test here
  (the live suite's 60-second upstream case runs only without `--quick`).
- The HTTP server is HTTP/1.1 only, with `Content-Length` request bodies; no
  pipelining guarantees beyond answering requests in order, no HTTP/2, no TLS.
- The entity type check for group names and role members is the portable
  subset's (`Name` or `A::B`); Cedar itself may reject a few more names
  (reserved words), which then fails closed with an error.
