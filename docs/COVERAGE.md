# Scope against build

What build 0.3.0 implements of [SCOPE.md](SCOPE.md), per engine.

Checked on 2026-10-05 on Linux x86-64 (2 vCPU VM) with Python 3.11.15,
OpenJDK 21.0.10, Node 22.22.2, Go 1.24.7, PHP 8.4.21, Rust 1.95.0 and gcc 13.3:
`./test_all.sh` ended with pass=16, skip=3, fail=0. The three skips are tests
inside the Python suite that need something not installed there (PostgreSQL
connection, `langchain-core`, `llama-index-core`). Nothing here has been run
on Windows or macOS.

How each cell was established: by running the suites named under
[Test inventory](#test-inventory), by reading the code, or, for what a port
leaves out, from the "Not included" section of that port's README.

Status words in the scope tables: **Built** = implemented and covered by a
test that runs in `test_all.sh`. **Partial** = some of it works; the gap is
stated. **Not built** = no code.

## Implementations

Six engines and one REST client. "yes" means the code is there and a test of
it ran; "no" means the port does not have it.

| | Python (reference) | Java | Node.js | Go | PHP | Rust | JS client (`ports/js`) |
|---|---|---|---|---|---|---|---|
| Location | `src/sf_smartdelegate` | `ports/java` | `ports/node` | `ports/go` | `ports/php` | `ports/rust` | `ports/js` |
| Engine: every operation of `spec/API.md` | yes | yes | yes | yes | yes | yes | no: decisions are made by a daemon |
| Policy evaluation, 95 cases with real Cedar's answers | pass, own evaluator | pass, own evaluator | pass, own evaluator | pass, own evaluator | pass, own evaluator | embeds real Cedar; generates the cases and re-checks them | n/a |
| Engine conformance, 78 cases, 327 steps, in-process | pass | pass | pass | pass | pass | pass; also through the C ABI | n/a |
| The same 78 cases over REST | own daemon | `Client` against the reference daemon | own daemon and client; the reference's daemon test against its daemon | own daemon and client; own client against the reference daemon; the reference's daemon test against its daemon | own daemon and client; the reference's daemon test against its daemon; 68 of them through `public/index.php` | the reference's daemon test against its daemon | against the reference daemon and the Rust daemon |
| Cross-port matrix (158 checks, 0 failed) | issuer and verifier | issuer and verifier; verifier only for signed bundles | issuer and verifier | issuer and verifier | issuer and verifier | issuer and verifier | n/a |
| "Strictness (0.3)" rules, own test for each | yes (8 tests) | yes | yes (8 tests) | yes (8 tests) | yes | yes (13 tests, with revoke by user) | n/a |
| Command line | yes | no | yes | yes | yes | yes | n/a |
| `call <op>` on the command line | yes | no | yes | yes | yes | yes | n/a |
| `init`, `bench` | yes | no | no | no | no | yes | n/a |
| `--demo` | yes | no | no | no | no | no | n/a |
| REST daemon | yes | no | yes (one request at a time) | yes | yes (`serve`, one request at a time; or `public/index.php`) | yes | n/a |
| HTTP proxy, MCP proxy | yes | no | no | no | no | yes; pass the reference's 22 proxy tests | n/a |
| REST client | `DaemonClient` | `Client` | `Client` | `NewClient` | `Client` | no | `Client` |
| Tool middleware | `Guard` | no (`Client.require` throws on a deny) | `guardTool` | no | no | no | `guardTool` |
| SQL connector | `SqlGuard` | no | no | no | no | no | no |
| Sign a bundle | yes | no (verifies; cannot sign through `Engine.call`) | yes | yes | yes | yes | n/a |
| Compile `.cedar` to `policies.json` | no (needs Cedar) | no | no | no | no | yes | n/a |
| Bridges (`sf_smartdelegate.bridges`) | yes | no | no | no | no | no | no |
| `sf_smartdelegate.core`, `sf_smartdelegate.models` | yes | no | no | no | no | no | no |
| C ABI | no | no | no | no | no | yes | no |
| State directory can be shared at the same time with | Rust, Go, PHP (`flock`) | other Java engines only | other Node.js engines only (`lock.node`) | Python, Rust, PHP (`flock`) | Python, Rust, Go (`flock`) | Python, Go, PHP (`flock`) | n/a |
| Dependencies | `cryptography` | none | none | none | PHP extensions `sodium`, `openssl`, `json`, `mbstring` | Cedar and 9 other crates | none |
| Lines of implementation, without tests | about 4,100, plus 2,800 for the bridges | about 3,300 | about 4,300 | about 6,800 | about 6,200 | about 4,000 | about 130 |

Kotlin can use the Java classes; no Kotlin code was compiled or run.

### New in 0.3, per engine

Each row is covered by conformance vectors that all six engines pass, unless
the notes say otherwise.

| | Six engines | JS client | Vectors | Notes |
|---|---|---|---|---|
| Role-scoped tokens: `roles.json`, `role` at issuance, the human must hold the role, ceiling, `max_ttl`, `tasks`, `agents` | yes | through `call` only: `issueToken` has no `role` parameter | `06_roles` | `roles.json` validation (`roles_parse`) has no test in `tests/`; the Java harness (61 checks) and the Go harness compare verdicts with the reference |
| `context.iam.role` in policy; `principal.role` in decisions | yes | passes through; `index.d.ts` does not declare `role` | `06_roles` | |
| `require_role` | yes | n/a | `07_require_role` | |
| Live membership from `groups` at issuance | yes | through `call` only | `06_roles` | |
| Live membership from the ID token: `idp.groups_claim`, `idp.group_map`, `idp.group_type` | yes | n/a | `09_oidc_groups` | `idp.group_type` is set in no vector and in no test in `tests/`: the vectors use the default type `Group` |
| Sub-agent tokens inherit `role` and `grp` | yes | n/a | `06_roles` | |
| Revoke by user | yes | through `call` only: `revoke` takes a token id | `10_offboarding` | Helpers: Python `revoke_user`, Java `Client.revokeUser`, Node.js `revokeUser`. On a shared state directory across ports it is tested by Go and by PHP, each with the reference |
| Rule ids: `rule` in decisions, `error.rule` in errors | yes | passes through; `index.d.ts` does not declare `rule` | 4 expectations in the vectors; compared between every pair of ports in the matrix | |
| `task` and `role` in the result of `issue_token` and `exchange_token` | yes | passes through; not in `TokenResult` in `index.d.ts` | `06_roles` | |
| `role` and `groups` with `trust_caller_chain` | yes (code) | n/a | none | The Java README says so for Java; no shared vector exists for any engine |

## Against the scope

| Scope section | Status |
|---|---|
| 5.1 Identity and delegation | Partial |
| 5.2 Policy decision point | Built, on a declared subset of Cedar, no schema validation |
| 5.3 Field-level control | Built (buffered JSON only) |
| 5.4 Enforcement points | Partial: MCP stdio proxy and HTTP reverse proxy (Python, Rust), middleware (Python, Node.js, JS client), SQL connector (Python), framework wrappers. No S3, no OpenAPI import, no MCP-over-HTTP |
| 5.5 Audit | Partial: hash chain, explain, shadow mode. No OpenTelemetry |
| 5.6 Languages | Partial: six engines, a JS client, REST. No gRPC. Proxies in two engines only. Java has no command line or daemon |
| 5.7 Operations | Partial: command line, signed bundles. No console, no container image, no bundle distribution |
| 5.8 Bridges | Partial: written, tested against fakes only. The scope's acceptance (a run against the real service) is met by none |
| 10 Performance targets | Met on the test machine, single client (figures below) |

### 5.1 Identity and delegation

| Item | Status | Notes |
|---|---|---|
| Human signs in through existing OIDC provider | Partial | ID tokens are verified (RS256/384/512, ES256/384, EdDSA; issuer, audience, expiry) against a **static JWKS**, a file or inline. No discovery, no JWKS fetch or rotation. No nonce or `jti` check. The shared fixtures are RS256; the other algorithms are tested by the Node.js, Go and PHP suites, each also against the reference; Java and Rust are tested with RS256 only |
| Workload identity for agents | Partial | An agent is an entry in `entities.json`. No attestation (no SPIFFE, no mTLS): whoever holds a token is the agent it names |
| Capability tokens by token exchange | Partial | RFC 8693 *semantics* (`act` chain, subject token, actor). The endpoint takes JSON, not the RFC's form-encoded request |
| Narrowing on every hop | Built | Vectors `02_delegation` |
| Delegation governed by policy | Built | Action `delegate` |
| Roles: held, ceiling, policy | Built | Vectors `06_roles`, `07_require_role`. Roles are opt-in per request unless `require_role` is set |
| Live group membership | Built | Vectors `06_roles`, `09_oidc_groups`. Checked at issuance only; the token carries it for its lifetime |
| Revocation of a token and its descendants | Built | Immediate for processes sharing a state directory; other verifiers wait for expiry |
| Revocation of all of a user's tokens | Built | Vectors `10_offboarding`. Same reach as above. A cut-off in time, not a ban |
| Budget per human across tokens | Not built | Each token has its own budget |
| Proof-of-possession | Not built | Bearer tokens |

### 5.2 Policy decision point

| Item | Status | Notes |
|---|---|---|
| One request/response shape | Built | Same JSON in all six engines, the C ABI and REST. `spec/openapi.yaml` was checked against the daemons of Python, Rust, Node.js, Go and PHP: 66 requests over all 14 routes, every answer fits its schema |
| Cedar, default deny, forbid overrides | Built | Python, Java, Node.js, Go and PHP evaluate Cedar's JSON policy form with their own code; 95 cases check them against the real engine's answers. Rust uses the real engine |
| Portable subset | Built | `spec/POLICY_SUBSET.md`. Extension types (ip, decimal, datetime), entity tags and templates are refused at load |
| Fail closed | Built | Erroring forbid denies; corrupt state, unwritable audit log, bad bundle signature, stale compiled policies, files that are not UTF-8 and malformed input all refuse. Tested |
| Versioned policies | Built | Bundle hash in every decision and audit record; identical across ports (matrix check d). `roles.json` is part of it |
| Rule ids | Built | `DELEGATE-*` on every decision and every engine error |
| Policy unit tests | Built | `policy test` on the command line of Python, Rust, Node.js, Go and PHP |
| Editing policy | Partial | `.cedar` sources must be compiled with the Rust port. An install without it can run and test a bundle but not change its policies |
| Cedar schema validation | Not built | Policies are not type-checked |

### 5.3 Field-level control

| Item | Status | Notes |
|---|---|---|
| `service.resource.field` addressing, labels, default deny | Built | |
| Nested objects and arrays (`a.b`, `a[].b`) | Built | |
| Drop and redact | Built | |
| Row filter | Built | `column == context.key` or a literal, joined by `&&`. Equality only |
| Spend limit across the delegation tree | Built | Ledger is per state directory. Per token, not per human |
| Rate limit | Built | Counter is per process, in memory. Through PHP's `public/index.php` it never denies |
| Human approval | Built | Single-use, expiring, approver authorised by policy, no self-approval. No notification channel |
| Strict input checking | Built | |
| Streamed responses | Not built | Bodies are buffered; non-JSON is withheld |

### 5.4 Enforcement points

| Item | Status | Notes |
|---|---|---|
| MCP proxy | Partial | Python and Rust. stdio transport, newline-delimited JSON-RPC. Tested against a stand-in server written for this repo, **not against a third-party MCP server or client**. Resources, prompts, sampling and server notifications are blocked rather than mediated |
| HTTP egress proxy | Partial | Python and Rust. A reverse proxy with a route table. Not a transparent forward proxy, no TLS termination, no OpenAPI import. HTTPS upstreams untested |
| SDK middleware | Partial | Python `Guard`, Node.js `guardTool`, JS client `guardTool`. None in Java, Go, PHP, Rust |
| Framework wrappers | Partial | See [Integrations](#integrations) |
| Postgres connector | Partial | Python. Builds a parameterised `SELECT` with permitted columns and the row filter. Tested on SQLite. Three PostgreSQL tests exist and were skipped in the run recorded here (no `SMARTDELEGATE_PG_DSN`). Read only. Not a wire-protocol proxy |
| S3-compatible connector | Not built | |

### 5.5 Audit

| Item | Status | Notes |
|---|---|---|
| Append-only hash-chained log | Built | Edit, delete, reorder detected. One format: a log written by any of the six engines verifies in the other five with the same record count and head (matrix check e) |
| No field values, no tokens in the log | Built | Tested in the reference |
| Role and user revocation in the log | Built | `role` in decision and token records; event `user_revoked`. The groups supplied at issuance are not recorded |
| Explain | Built | In all six engines. No conformance vector calls it. In `tests/` it is exercised through the MCP-server integration and the VS Code task; the OpenAPI check called `/v1/explain` on five daemons |
| Shadow mode | Built | In all six engines. Tested in Python, Node.js, Go and PHP. No test of it in the Java harness or the Rust tests |
| OpenTelemetry export | Not built | |

### 5.7 Operations

| Item | Status |
|---|---|
| Command line | Built (Python, Rust, Node.js, Go, PHP) |
| Signed bundles | Built; a bundle signed by Python, Node.js, Go, PHP or Rust verifies in all six engines, and a `roles.json` edited after signing is refused by all six (matrix check d) |
| Admin console, bundle distribution, container image | Not built |

### 5.8 Bridges

Python only. "Fakes" are servers, clients and fixtures written for the tests
(`tests/bridges_fixtures/fakes.py`, `tests/test_bridges.py`: 79 tests, all
run). **No row has been run against the real service.**
[BRIDGES.md](BRIDGES.md) lists per provider what was not verified.

| Item | Status | Tested against |
|---|---|---|
| Claims to groups: presets `entra`, `okta`, `keycloak`, `cognito`, `auth0`, `google`, `generic`; Entra overage is an error | Partial | Hand-written claim sets. No real token from any provider |
| Directory sync: SCIM 2.0, Okta, Entra ID, Keycloak, Google, AWS Identity Center | Partial | Fake servers: several pages, nested groups, inactive users, HTTP 429 and 500, truncated and looping listings, wrong credential |
| Directory sync: Auth0 | Not built | |
| Writing `entities.json`: atomic, removal guard, `entities.sync.json` | Built | Real files, injected failures; the result loads in the reference engine |
| `--revoke` after a sync, and reload through a daemon | Built | The reference engine and a real `sf-smartdelegate serve` on loopback. Not as seen by a verify-only engine |
| AWS SigV4 signing | Partial | The three worked examples in the S3 documentation. No signature was accepted by AWS |
| Role ceiling from AWS (`SimulatePrincipalPolicy`), Google (`testIamPermissions`), Azure (RBAC permissions) | Partial | Hand-written results and permission lists |
| `ceiling.intersect`, `cap_role` (never widens a role) | Built | 400 random pairs; the capped bundle loads |
| AWS session policy and `AssumeRole` request with session tags | Partial | 300 seeded random cases judged by an evaluator in the test file; a fake STS client. AWS did not evaluate a policy |
| Google Credential Access Boundary and STS exchange | Partial | 300 seeded random cases; a fake transport. Cloud Storage only by design |
| Azure On-Behalf-Of scopes | Partial | 300 seeded random cases. Azure has no per-token policy, so no down-scoped ARM credential exists |
| `sf-smartdelegate bridge ...` command line | Partial | Subprocess runs of every subcommand that needs no network; `sync-scim` against a loopback fake; `sync-okta` with a fake transport |
| HTTP transport (TLS verification, https only, no cross-host redirect) | Partial | A loopback `http.server`. TLS itself was not exercised |

### Integrations

In `integrations/`; tests in `tests/test_integrations.py` (53 tests; 2
skipped in the run recorded here). All wrappers run in the agent's process
(see [LIMITATIONS.md](LIMITATIONS.md) section 1).

| Item | Status | Tested |
|---|---|---|
| `adapter.py` (authorize, run, mask, structured denial) | Built | Fake tools against the conformance bundle, in-process and through a real `sf-smartdelegate serve` |
| LangChain `guard_tool` | Partial | `guarded_call` with fake tools: run. `guard_tool` on real LangChain tools: **skipped here**, `langchain-core` not installed. integrations/README.md reports a pass with langchain-core 1.6.6 |
| LlamaIndex `guard_tool` | Partial | Same split. **Skipped here**, `llama-index-core` not installed. integrations/README.md reports a pass with llama-index-core 0.14.25 |
| OpenAI / Anthropic function calling | Partial | Fake tools and hand-written tool definitions. No request was sent to a model API |
| MCP server (`integrations/mcp/server.py`) | Partial | Driven over stdio with hand-written JSON-RPC. Not run inside a desktop MCP client |
| GitHub Action | Partial | The shell of each `run:` step, under bash. Not run on GitHub |
| pre-commit hooks | Partial | Each hook's command line is run. `pre-commit` itself was not |
| VS Code tasks | Partial | Each task's command line is run. Not run inside VS Code |
| Flowise tool | Partial | The tool body under Node against a real daemon. Not run inside Flowise |
| Browser playground (`site/playground.html`) | Built | 5 tests: the page loads nothing from the network, embeds the example bundle, and its verdicts agree with the reference engine on random requests. It shows the delegation rules only; it is not an engine |

### Performance (section 10)

Measured on 2026-10-05: 2 vCPU Xeon 2.1 GHz VM, example bundle (21 policies,
12 field decisions per call), audit log on, 5,000 sequential calls from one
client. Release build for Rust.

| | p50 | p99 | Target |
|---|---|---|---|
| Python engine, in-process (`sf-smartdelegate bench -n 5000`) | 0.96 ms | 1.59 ms | under 5 ms |
| Rust engine, in-process (`sf-smartdelegate bench -n 5000`) | 0.90 ms | 1.42 ms | under 5 ms |
| Python daemon over loopback, `DaemonClient`, a new connection per call | 2.05 ms | 3.07 ms | under 20 ms |

The Java, Node.js, Go and PHP engines were not benchmarked. Not measured
anywhere: concurrent load, large entity stores, large bundles, tokens with
live membership. Every engine takes one lock per call, so throughput does not
scale with cores.

### Milestones (section 14)

| | Status |
|---|---|
| a Spec, API, token format, vectors | Met for what it lists. Every deny reason of section 7 has a vector, and removing any one of the 21 example policies makes at least one vector fail |
| b Reference engine, CLI, audit | Met |
| c Second implementation, TypeScript client, MCP proxy | Met, with the MCP caveat above. The TypeScript types lack `role`, `rule` and `task` |
| d HTTP proxy, connectors, masking | Partial (see 5.4) |
| e Further ports, console, shadow mode | Partial: five ports and shadow mode; no console |
| f Threat model, benchmarks, 1.0 | Partial: this is 0.3, not 1.0 |
| g Roles, live membership, offboarding | Met: all six engines pass `06` to `10`; matrix check a compares role tokens with live groups between every pair |
| h Bridges | Not met: no adapter has been run against a real service; the UNVERIFIED list is not empty |

### Risks (section 15)

One mitigation the scope names is not in place: the README's first example is
the in-process `sf_smartdelegate.core`, not a proxy.

## Test inventory

What `./test_all.sh` ran on 2026-10-05, with the counts each suite printed.

| Suite | What ran |
|---|---|
| Python (`tests/`) | 219 tests, 5 skipped. Evaluator against Cedar's answers (1, all 95 cases); conformance in-process and over REST (2); engine: shadow mode, signed bundles, OIDC, audit, keys, shared state (33); strictness (8); middleware and SQL (16, of which 3 PostgreSQL tests skipped); HTTP proxy (13); MCP proxy (9); interoperability with the Rust port (5); bridges (79); integrations (53, of which 2 skipped) |
| Bundle policy tests | 4 tests of `spec/conformance/bundle/tests` |
| Java | 95 evaluation cases; 78 conformance cases in-process; 29 interoperability checks with the reference; 6 OIDC checks; 61 `roles.json` validation checks; 209 strictness checks in six groups; 78 conformance cases through `Client` against the reference daemon; 16 client checks |
| Node.js | 304 tests (`npm test`), none skipped |
| Go | `go vet` and `go test`: ok |
| PHP | 1,266 checks in 7 sections, 0 failed. Through `public/index.php`, 72 of the 78 cases pass; the rate-limit case differs, as its README documents |
| Rust | `cargo test`: 3 conformance tests (78 cases; the 95 evaluation cases re-checked against real Cedar; the compiled bundle matches its sources) and 13 strictness tests. The reference's 22 proxy tests and its daemon conformance test against the Rust binary. C ABI: 78 cases and its direct checks |
| JavaScript client | 4 tests, against the reference daemon and again against the Rust daemon |
| Daemons of other ports | The reference's daemon conformance test (78 cases over REST) against the Node.js, Go and PHP daemons |
| Cross-port matrix | 158 checks passed, 0 failed (Java signs bundles through its own CLI since it got one). One state directory shared by Python, Rust, Go and PHP: spend, revocation by token, approval, concurrent spend, one audit chain |

Not part of `test_all.sh`, run once for this document: `spec/openapi.yaml`
validated with `openapi-spec-validator` and against the five daemons; each of
the 21 example policies removed in turn (see milestone a).

No code in this repository has had an independent security review.
