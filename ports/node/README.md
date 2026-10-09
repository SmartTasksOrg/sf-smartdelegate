# SmartDelegate for Node.js

A native port of the SmartDelegate engine (`src/sf_smartdelegate`, the Python
reference) to Node.js: capability tokens, narrowing-only delegation, Cedar
policy evaluated from compiled JSON, field masking, budgets, human approval,
the hash-chained audit log and role-scoped task tokens. It also contains the
REST daemon, a REST client, and a command line.

- Plain JavaScript (ES modules), hand-written `index.d.ts`.
- No npm dependencies; only `node:` built-ins (`node:crypto` for Ed25519, RSA
  and ECDSA, `node:http` for the daemon).
- `info` reports `"version": "0.3.0"`, `"implementation": "node"`.

## Requirements

- Node.js 18 or newer. **Developed and tested on Node 22.22 only**; 18 and 20
  were not run (see "Not included / not tested").
- For the interoperability tests: `python3` with the `cryptography` package
  (the reference needs it). Without them those tests are skipped and say so.

## Layout

```
bin/cli.mjs          the command line (smartdelegate-node)
lib/json.mjs         JSON with exact integers: parse, write, canonical key order
lib/canon.mjs        canonical JSON, SHA-256
lib/cedar.mjs        evaluator for Cedar's JSON policy form, with the load-time subset check
lib/fields.mjs       field mask and row filter
lib/tokens.mjs       capabilities, EdDSA JWTs, OIDC ID token verification
lib/bundle.mjs       bundle loading, version, signing, roles; Ed25519 keys
lib/state.mjs        state.json
lib/audit.mjs        audit log
lib/lock.mjs         state-directory lock
lib/engine.mjs       class Engine
lib/server.mjs       REST daemon
lib/client.mjs       REST client, guardTool
lib/api.mjs          the convenience methods shared by Engine and Client
lib/conformance.mjs  runners for the eval cases, the vectors, bundle tests
lib/index.mjs        public API
test/                node:test files
tools/               test helpers (not part of the package)
run_conformance.sh   eval cases + vectors, exit code 1 on failure
```

## Using the engine

```js
import { Engine } from 'smartdelegate';        // or '../ports/node/lib/index.mjs'

const iam = new Engine({ bundle_dir: 'bundle', state_dir: 'state' });   // throws EngineError if unusable

// The human lends the agent one of their roles for this task.
const { token } = iam.issueToken({ user: 'alice', agent: 'support-bot', role: 'support-agent', task: 'ticket-4711' });

// Decide.
const d = iam.authorize({ token, action: 'read', resource: 'crm.customer', id: 'c-1' });
if (d.effect !== 'allow') throw new Error(`${d.rule}: ${d.detail}`);

// Decide and mask data in one step.
const f = iam.filter({ token, action: 'read', resource: 'crm.customer', id: 'c-1',
  data: { id: 'c-1', email: 'ada@example.com', ssn: '123-45-6789', region: 'EU' } });
console.log(f.data, f.masked);                 // { id, email, region }  [ 'ssn' ]

iam.close();
```

There are two levels:

- `engine.call(op, payload)` is the operation interface of `spec/API.md`: JSON
  in, JSON out. It is synchronous and **never throws**; a failure is
  `{ok: false, error: {code, message, rule}}` and a deny is
  `{ok: true, effect: "deny", ...}`.
- `authorize`, `filter`, `explain`, `applyObligations`, `issueToken`,
  `exchangeToken`, `inspectToken`, `revoke`, `revokeUser`, `approve`, `info` wrap `call` and
  throw `SmartDelegateError` (with `.code`) when `ok` is false. A deny is
  returned, not thrown.

`Client` (REST) has the same methods, returning promises, with the same public
API as the REST-only client in `ports/js`, so code can move between
`ports/js`, this `Client` and the in-process `Engine`:

```js
import { Client, guardTool } from 'smartdelegate';

const client = new Client({ url: 'http://127.0.0.1:8181', pepKey: process.env.SMARTDELEGATE_PEP_KEY });
const getCustomer = guardTool(client /* or an Engine */, () => taskToken,
  { action: 'read', resource: 'crm.customer', id: (a) => a.customerId },
  async ({ customerId }) => db.get(customerId));   // the result is masked before it is returned
```

In-process checks bind an agent that cooperates. The boundary an agent cannot
skip is a proxy; this port has none (see below).

## Integers

SmartDelegate integers are 64-bit (Cedar longs, budgets, timestamps) and a
JavaScript `Number` is exact only up to 2^53 - 1. This port does not use
`JSON.parse` / `JSON.stringify` for anything that matters:

- Internally every JSON integer is a `BigInt` and every `Number` is a float
  (`lib/json.mjs`). `1` and `1.0` stay different, as in the reference: `1.0` in
  `context` is refused as a float.
- Policy arithmetic (`+`, `-`, `*`, unary `-`) is done on `BigInt` and checked
  against the i64 range; overflow is an evaluation error. A context integer
  outside the i64 range is `invalid_context`. Spend ledgers are exact.
- At `engine.call` and `Client.call`: in the **input**, integer-valued Numbers
  and BigInts are integers. In the **result**, an integer is a `Number` when
  that is exact and a `BigInt` otherwise. So a budget of
  `9223372036854775807n` comes back as that `BigInt`; `JSON.stringify` cannot
  print it, use the exported `stringify`.
- `engine.callExact(op, payload)` with the exported `parse` / `write`-style
  model keeps every integer a `BigInt`. The daemon and the CLI use it, so
  bytes on the wire are exact in both directions.

### Member order of objects with integer-like keys

JavaScript lists integer-like keys of an object (`"10"`, `"9"`) first, in
numeric order, whatever order they were written in. Canonical JSON (hashes,
audit log, signatures) is never affected: keys are sorted by code point there.
For JSON that is echoed back (data from `filter` / `apply_obligations`, token
claims from `inspect_token`):

- **Daemon and CLI: the written order is kept**, as in the reference. `parse`
  records the order of objects that have such keys, masking carries it over,
  and the writer follows it (tested against the reference).
- **`engine.call()` and `Client.call()` with ordinary JavaScript objects: the
  order is JavaScript's.** The input object has already lost its written order
  before the engine sees it, and the result is an ordinary object again. For
  example `engine.filter({..., data: {b: 1, 10: 2, 9: 3}}).data` has the keys
  `9, 10, b`. Only objects with integer-like keys are affected, and only their
  member order, never their content. `callExact` with values from `parse`
  keeps the order.

## Command line

```
node bin/cli.mjs help
```

Same commands, flags, output format and exit codes as the reference CLI for
what it implements: `info`, `policy check|test`, `bundle keygen|sign`,
`token issue|exchange|inspect|revoke` (with `--role`, `--groups`, `--raw`,
...), `authorize`, `explain`, `approvals`, `approve`, `audit verify|tail`,
`call <op> [--input JSON|@file|-]`, `serve`, `conformance`, `version`.

Configuration is resolved as in the reference: `--config FILE`, or
`SMARTDELEGATE_CONFIG`, or `./smartdelegate.json`; `bundle_dir`, `state_dir`
and `idp.jwks_file` inside a config file are relative to that file;
`--bundle DIR`, `--state DIR` and `--shadow` override it;
`SMARTDELEGATE_ADMIN_KEY` / `SMARTDELEGATE_PEP_KEY` override the keys.

Exit codes: 0 allow / ok, 2 deny, 1 error.

`conformance` with no arguments runs the repository's 95 policy evaluation
cases and 78 engine cases; `conformance <vectors dir> <bundle dir>` runs the
given vectors (and `<vectors dir>/../eval/cases.json` when it exists).

## Daemon

```
node bin/cli.mjs serve --config smartdelegate.json --listen 127.0.0.1:8181
```

The routes, keys (admin key / pep key as bearer tokens, compared in constant
time; `/v1/token` with an `id_token` needs no key and ignores `user`), status
codes (200, 400, 401, 404), the 8 MiB body limit and the startup line on
stderr are those of the reference daemon (`src/sf_smartdelegate/daemon.py`,
`spec/openapi.yaml`). The reference's own daemon conformance test passes
against it (command below). TLS is not terminated: bind to loopback or put it
behind something that does.

The daemon is one process and one thread; engine calls are synchronous, so
requests are served one at a time.

## State directory and locking

`state.json`, `audit.jsonl`, `signing_key.pk8.b64` and `signing_key.pub.b64`
have the formats of `spec/PORTING.md`, and a state directory written by this
port can be read by the reference and the reverse (tested, one port at a
time).

**Do not let this port and another port use the same state directory at the
same time.** Node.js has no `flock()`, so this port cannot take the lock the
Python and Rust ports take on `<state>/lock`. It uses its own lock, the file
`<state>/lock.node`, which only other Node.js engines honour. (The Java port
has the same restriction for the same kind of reason.) Using one directory
from several ports one after the other is fine.

The signing key is created as the reference creates it (temporary file,
hard link into place), outside the lock, so that is safe with other ports too.
A key file found empty is waited for (`key_wait_ms`, default 30 s) and then is
`state_io`; it is never read as "no key".

Between Node.js processes the lock works as follows (`lib/lock.mjs`):

- Each call creates `lock.node` with `O_EXCL`, writes
  `<pid> <process start time> <nonce>`, and removes it at the end of the call.
  A waiter retries for up to `lock_timeout_ms` (default 30 s), then the call
  fails with `state_io`.
- A lock whose holder is gone (no such pid, or on Linux a different process
  start time for that pid) is removed and taken. Removal is serialised through
  a guard directory `lock.node.steal` and re-checked under it.
- Without `/proc` (macOS, Windows) only the pid is checked, so a recycled pid
  can make a dead holder look alive; such a lock is taken over after
  `lock_stale_ms` (default 10 minutes).
- It assumes all engines run on one host and a local file system.

## Tests

```
npm test                          # = node --test test/        (everything, 332 tests)
node --test test/*.test.mjs       # the same, one process per file
./run_conformance.sh              # eval cases + vectors only
```

| File | What | Tests |
|---|---|---|
| `test/eval.test.mjs` | the 95 policy evaluation cases (+1 count check) | 96 |
| `test/conformance.test.mjs` | the 78 engine cases (327 steps) in-process (+1 count check) | 79 |
| `test/rest.test.mjs` | the 78 engine cases over REST: this daemon, this client | 78 |
| `test/interop.test.mjs` | against the Python reference: tokens both ways (incl. a role token with `grp`), signed bundles both ways, bundle version, audit logs both ways and tampering, approval ids, filtered data, revoking a user, ancestor budgets through `lim` with a verify-only engine of the other port, member order of echoed data, the audit tail with U+2028, OIDC ID tokens of every algorithm, the OIDC rules beyond the signature (azp, several audiences, `iat` against the revoke cut-off, nested group claims), `reload` re-reading `jwks_file`, canonical JSON bytes, and a differential run (3 seeds x 1500 random operations, every result compared) | 20 |
| `test/canon.test.mjs` | JSON and canonical JSON: big integers, floats, non-ASCII, control characters, key order, member order | 13 |
| `test/strictness.test.mjs` | one test per bullet of "Strictness (0.3)" in `spec/PORTING.md` (the signing-key bullet has two) | 9 |
| `test/lock.test.mjs` | four processes on one state directory keep one valid audit chain and one exact ledger; stale and held locks | 3 |
| `test/engine.test.mjs` | integers, never-throws, roles, shadow mode, signed bundles, audit tampering, revoking a user, ancestor budgets (`lim`), approvals bound to `resource.attrs`, keys, OIDC algorithms and claim rules, `reload` with key rotation, shared state, failing closed | 20 |
| `test/cli.test.mjs` | commands, flags, config resolution, exit codes, `serve`, `conformance` | 9 |
| `test/client.test.mjs` | client and daemon: keys, routes, status codes, body rules, ID tokens, `guardTool` | 5 |

Tests create their state in temp directories and remove them.

The reference's daemon test against this port's CLI:

```
cd ../../tests && SMARTDELEGATE_TEST_CLI='["node","'$PWD'/../ports/node/bin/cli.mjs"]' \
  python3 -m unittest test_conformance.DaemonConformance
```

More differential testing: `node tools/differential.mjs <seed> <count>`.

`node --test test/` needs `test/index.js` on Node 22 and later, where the
argument is no longer scanned as a directory; that file loads the test files
when it is the entry point and does nothing otherwise.

## Differences from the reference

Outputs, error codes, reasons and byte formats follow the reference (0.3.0,
including the "Strictness (0.3)" rules of `spec/PORTING.md`); messages do not.
The differences that remain, each re-checked against the current reference:

- **Lock**: `lock.node` instead of `flock` on `lock`; see above.
- **Member order** of objects with integer-like keys, for in-process calls
  with ordinary JavaScript objects only; see "Integers".
- **Wrong value types inside `state.json`** (for example a revocation time
  that is a string) are `state_io` here; the reference answers `internal`
  (a `TypeError`). Both refuse the request.
- **Daemon**:
  - a request body over the limit is read and discarded (up to 32 MiB or 10 s)
    before the 400 is sent, so a client that is still sending sees the answer
    instead of a connection reset; the reference answers without reading;
  - chunked request bodies are read; the reference ignores them and treats
    the body as empty;
  - methods other than GET and POST get a JSON 501; the reference's 501 is
    the HTML page of Python's `http.server`.
- `close()` does not disable locking for later calls (this port holds nothing
  between calls); the reference stops locking after `close()`.

## Not included / not tested

- **No HTTP proxy and no MCP proxy** (`http-proxy`, `mcp-proxy`). Use the
  Python reference or the Rust port for those.
- No `init`, `bench`, `bundle compile` (compiling `.cedar` needs the Cedar
  toolchain: the Rust port), no SQL guard, no bridges.
- No Cedar text parser, no schema validation: policies are evaluated from
  `policies.json` (the subset of `spec/POLICY_SUBSET.md`), as in the reference.
- Not run on Node 18 or 20 (only 22.22), on macOS or on Windows. The lock's
  pid-only fallback and the Windows file-mode behaviour are untested.
- The lock was tested with four processes on one local Linux file system; not
  on network file systems, not across hosts, not with worker threads.
- The daemon was not load-tested; there is no TLS, no rate limiting, no
  request timeout beyond Node's defaults.
- Not published to npm; `npm pack` was not exercised.
