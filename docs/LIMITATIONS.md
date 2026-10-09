# Limitations

Read this before relying on SmartDelegate for anything. Every statement is
about build 0.3.0.

## 1. In-process checks do not contain an agent

`Guard` (Python), `guardTool` (Node.js and the JavaScript client) and the
wrappers in `integrations/` run inside the agent's process. An agent, or code
injected into it, can call the tool function directly, read the upstream
credential if the process has one, or skip the check. In-process checks bind
**cooperating** agents only.

The boundary an agent cannot skip is a proxy, and only when the deployment makes
it one:

- the agent's network egress is restricted to the proxy;
- the upstream credential exists only in the proxy;
- for MCP, the proxy is the only way the agent can start or reach the server.

SmartDelegate does not configure your network or your secrets. If the agent can reach
the upstream directly, the proxy is advisory.

## 2. This is build 0.3.0

- No independent security review of any part: engine, ports, proxies, bridges.
- [COVERAGE.md](COVERAGE.md) lists what the scope asks for and this build lacks, per engine.
- [THREAT_MODEL.md](THREAT_MODEL.md) lists, per threat, what the system does not do.

## 3. Platforms

- Built and tested on Linux x86-64 only.
- Nothing has been run on Windows or macOS: not the reference, not a port.
- `test_all.ps1`, the Windows counterpart of `test_all.sh`, was written but never run.
- The Windows file locking of the reference (`msvcrt`) and of the Go port (`LockFileEx`) has never executed.
- On Windows PHP's `flock()` is a different lock from the one the other ports take.
- The Node.js lock falls back to a pid-only check without `/proc` (macOS, Windows). That fallback is untested.
- Each port was run on one runtime version: Java 21, Node 22, Go 1.24, PHP 8.4, Rust 1.95. The older versions their READMEs declare (JDK 17, Node 18, Go 1.21, PHP 8.1, Rust 1.89) were not run.
- The reference's tests were run on Python 3.11. BRIDGES.md reports the bridge tests also on 3.12. Python 3.10 is declared and was not run.

## 4. Six engines

Python (the reference), Java, Node.js, Go, PHP and Rust are separate code.

What keeps them the same:

- 95 policy-evaluation cases whose answers come from the real Cedar engine.
- 73 engine conformance cases (327 steps), run by `ports/conformance/run.sh`.
- The "Strictness (0.3)" rules of `spec/PORTING.md`, each with a test in every port.
- The cross-port matrix, `ports/conformance/matrix.py`: for every ordered pair of ports, one port's role token with live groups, sub-agent token, tampered token, signed bundle and audit log are checked by the other. On 2026-10-05: 158 checks passed, 0 failed.

What that does not give:

- Behaviour no case exercises can differ between ports.
- The conformance vectors call `explain`, `apply_obligations`, `approvals` and `reload` in one suite only (`11_operations`): the common paths, not every option.
- 95 cases are evidence, not proof, that the five hand-written evaluators match Cedar everywhere in the subset (`spec/POLICY_SUBSET.md`). The Rust port uses the real Cedar engine.
- The matrix runs one fixed scenario per pair of ports. It is not a differential fuzzer.
- In the matrix Java only verifies signed bundles: the Java port cannot sign one through `Engine.call`.
- Each port's README lists known differences from the reference: message texts, integers beyond 64 bits, nesting depth, daemon edge cases.
- Removing any one of the 21 example policies breaks at least one conformance case. That says the example bundle is covered, not that your own policies are: write tests for them (`sf-smartdelegate policy test`).

State directories:

- Python, Rust, Go and PHP take the same `flock` and can share one state directory at the same time. The matrix tests this on Linux.
- **Node.js must not share a state directory with another port.** It uses its own lock file (`lock.node`), which only Node.js engines honour.
- **Java must not share a state directory with another port.** The JVM file lock is a different lock on Linux.
- Sharing with either would let two engines write at once and could corrupt `state.json` or the audit chain.
- Any two ports can use one directory one after the other.

What each port contains:

- HTTP proxy and MCP proxy: Python and Rust only.
- REST daemon and command line: Python, Rust, Node.js, Go, PHP.
- Java is a library and a REST client: no command line, no daemon, no proxies.
- SQL connector, bridges, `sf_smartdelegate.core`, `--demo`: Python only.
- `ports/js` is a REST client, not an engine. Its typed helpers do not take `role` or `groups` and cannot revoke by user; use `client.call(...)` for those.
- PHP behind a web server (`public/index.php`) builds a fresh engine per request: a `@rate_limit` policy never denies there, and decision ids can repeat.
- The Node.js and PHP daemons answer one request at a time.

Policies:

- Editing policy needs the Rust port: only it turns `.cedar` text into the `policies.json` every engine runs.
- An engine refuses a bundle whose `.cedar` files changed since compilation. It cannot tell whether a hand-edited `policies.json` still means what its `.cedar` source says. Sign bundles, and review `policies.json` changes like code.

## 5. Tokens

- Capability tokens are **bearer** tokens. Anyone who obtains one can use it until it expires or is revoked. There is no proof-of-possession.
- Agent identity is a name in `entities.json`. Nothing attests that the process presenting a token is that agent.
- The signing key is a file in the state directory (mode 0600 on Unix; default ACLs on Windows). No HSM or KMS, no rotation procedure.
- Whoever holds the admin key, or calls the engine in-process, can issue a root token for any user name and can state that user's groups. Both statements are trusted.
- OIDC keys come from a static JWKS, inline or a file. No discovery, no fetch. Key rotation at the provider needs a configuration change and a restart.
- Issuance with an ID token over REST needs no key. An ID token can be used any number of times until it expires: no nonce, no `jti` record.
- ID tokens signed with RS384, RS512, ES256, ES384 and EdDSA are tested by the Node.js, Go and PHP suites (each also against the reference). Java and Rust are tested with RS256 only.
- `allow_test_clock` and `trust_caller_chain` are for tests. With the first, any caller sets the clock; with the second, any caller states user, role and groups without a token.

Revocation:

- There are two kinds: by token (it covers every token derived from it) and by user (`revoke {"user"}`, every token already issued for that human, sub-agent tokens included).
- Both take effect on the next decision of every engine that shares the state directory, and of everything behind the same daemon.
- **Budgets across separate verifiers are not summed.** A verify-only engine with its own state enforces a token's budget and every ancestor's (carried in the token's `lim` claim) over the spends it sees. Two such engines that do not share a state directory each keep their own ledger: in a test with two verify-only engines that did not share state, 300.00 was spent against a parent budget of 200.00 that way. Put spending behind engines that share state.
- **Neither is immediate anywhere else.** A verify-only engine with its own state (`verify_only` + `trusted_keys`) honours a revoked token until it expires. There is no channel that distributes revocations.
- Revoke by user is a cut-off in time, not a ban. A token issued after the call is valid if the human still passes the membership check at issuance.
- Revoke by user ends **all** of that user's tokens, also those under roles the user still holds. Their agents must ask for new ones.
- The user is matched by the exact string in the token. If the directory id and the login name of one person are both in use as user ids, they are two users.
- Entries in `revoked_users` are never pruned.

## 6. Roles and live membership

- Roles are opt-in per request unless the engine has `require_role`. A root token issued without a role is bounded by its requested capability and the delegation policy only.
- Membership is checked when a token is issued, not on each call. A token carries its role, and its group list when membership was live, for its whole lifetime.
- A human who loses a role keeps the tokens already issued until they expire or someone revokes them. Set `max_ttl` on every role; without it the engine's `max_ttl` applies (default 3600 seconds).
- The engine does not ask AWS, Azure or Google what the human can do at decision time.
- A budget is per token. A human can start several agents under the same role and each token gets the role's full budget. A budget per human across tokens is not implemented.
- Live membership **replaces** the stored membership of that user for that token. A group missing from the claim, from `idp.group_map` or from `entities.json` is dropped. That is safe for rules that grant on membership. A `forbid` that depends on membership in a dropped group stops applying to that token.
- `groups` passed with `user` is not verified by the engine. It is whatever the admin-key holder says.
- With live groups, a user who is not in `entities.json` at all can hold a role.
- An ID token issued before the human lost a group still lists the group. The engine accepts it until it expires, and it overrides both a newer sync and an earlier revoke-by-user. Keep ID-token lifetimes short.
- On the engine's own `idp.groups_claim` path a group-claim overage (Entra ID leaves the groups out above 200) reads as "no groups": the request fails with `role_not_held`. For such tenants use the bridge path, which raises `claims_overage`.
- Google ID tokens carry no groups. For Google, membership comes from the directory sync only.
- With `trust_caller_chain`, role and groups come from the caller and no ceiling is applied.

## 7. Directory sync

- `entities.json` is as old as the last successful sync. If the sync stops (expired credential, removal guard tripped, missing re-sign step), a removed human keeps the membership on disk. Nothing in SmartDelegate alerts on this; monitor `synced_at` in `entities.sync.json`.
- A running engine keeps the bundle it loaded. After a sync it must `reload` or be restarted. With `--daemon-url` the sync calls the reload itself.
- `entities.json` and `roles.json` are part of the bundle version. A signed bundle must be re-signed after a sync or after `bridge ceiling --write`; until then an engine that requires a signature refuses the new files and keeps serving the old ones.
- `--revoke` acts on the difference this sync found. If an earlier sync wrote the change without `--revoke`, or the sync is not running, nobody is revoked.
- A user who loses one group has all tokens revoked by `--revoke`, also those under roles still held.
- An engine that has not reloaded can issue a new token from the old membership right after the revoke.
- The trigger is the scheduled sync. SCIM push and deprovisioning events are not received.
- A failed sync is not retried: no back-off on HTTP 429 or 5xx. Run it again.
- The removal guard refuses a sync that removes more than 30% of users or leaves that share without any group. A real mass removal needs `--force`.
- Attributes that User entities had before a sync are not carried over; only those named in `--attr-map` are written.
- No Auth0 sync. Ping, OneLogin and JumpCloud are reached through SCIM only and were not tested.

## 8. Bridges

- The Keycloak adapter, claim rules and the sign-in path are verified against a real Keycloak (26.0.7 and 26.8.0, `live/idp`). Every other bridge was written from the provider's public documentation and tested **against fakes only**: none has been run against a real AWS, Azure, Google, Okta or Auth0 service.
- The assumptions that could not be checked are listed in [BRIDGES.md](BRIDGES.md) under "UNVERIFIED". The ones marked "(wider)" would leave access wider than intended if wrong.
- The fake servers encode the author's reading of the documentation. Where that reading is wrong, the fake is wrong in the same way.
- The bridges exist in Python only.
- The mapping files (`cloud_map.json`, `group_map.json`, the claims rule) are not covered by the bundle signature. A wrong line widens access.
- A cloud credential carries only actions on resources. `deny_labels`, `deny_fields` and `budget` are not enforced by any cloud; the generators list them under `not_enforced`.
- **A cloud credential already issued is not revoked** by revoking the token or the user. It lives until its own expiry.
- AWS: `DurationSeconds` has a minimum of 900 seconds. A token with less time left gets a session that outlives it by up to the difference.
- AWS: a session policy is limited to 2,048 characters, and can only remove permissions the assumed role has.
- Azure: RBAC has no per-token session policy, so there is no down-scoped ARM credential. The bound is the On-Behalf-Of scopes, which are coarse, plus the role ceiling and the proxy.
- Google: a Credential Access Boundary works for Cloud Storage only, with at most 10 rules. No other Google API accepts a down-scoped token.
- A role ceiling computed from cloud permissions is a snapshot, as old as the simulation it came from.
- Credentials for the sync are read from environment variables only. Not supported: AWS profiles and instance metadata, Okta OAuth service apps, Google service-account signing, Azure managed identity.

## 9. Policies

- Policies are not validated against a Cedar schema. A misspelt attribute in a **permit** makes that permit never apply (safe, but silent apart from `policy_errors` in the result). A misspelt attribute in a **forbid** makes requests that reach it fail with `policy_error`.
- Obligations come from annotations on the permits that decided a request. If two permits match and only one carries an obligation, the obligation applies.
- Row filters are equality tests only.
- Field obligations are computed once per request from the resource in the request, not per record. For a list of records the only per-record control is the row filter.
- Allowing a container field (`addresses`) allows everything inside it except children the catalog lists separately.

## 10. Data

- The SQL connector (`SqlGuard`) masks every row it returns with the decision's field mask, inside JSON columns too. A text column that holds JSON which does not parse is left out of the row. A nested catalog field can be read only inside a structured column: `bank.iban` is not a flat column `bank_iban`.
- `SqlGuard` with `attrs=` trusts the caller: the attributes are not checked against the rows. With `row_attrs=` each row is decided on its own values, but the database returns candidate rows before they are decided (narrow with `where`), and there is one decision and one audit record per distinct combination of values (per row with `id_column`).
- Only JSON records can be field-checked. Plain text, images and other tool output are withheld on filtered routes.
- A sensitive value inside a permitted free-text field (an SSN typed into `notes`) is **not** detected: this is access control on structure, not content inspection.
- Responses are buffered in memory (32 MB cap in the HTTP proxy, `passthrough` routes included: a larger response is refused, never cut). No streaming.
- Dropping unlisted fields is the safe failure, but a schema change upstream can remove data from an agent's view until the catalog is updated. Use shadow mode and `would_mask` to see drift.

## 11. Proxies and daemons

- The HTTP proxy is a reverse proxy over a route table. It does not terminate TLS; bind it to loopback or put it inside a mesh.
- HTTPS upstreams go through the platform's TLS stack but were **not tested**: every test upstream is plain HTTP on loopback. No private CAs, no certificate pinning.
- No daemon in any port terminates TLS.
- The reference daemon and HTTP proxy are small HTTP/1.1 servers (Python's `http.server`, one thread per connection, no connection limit). They are not hardened against slow or hostile clients. Do not expose them beyond the host or the mesh.
- The MCP proxy speaks stdio only, was tested against the stand-in server in `examples/` and the database-backed one in `live/upstream/`, and blocks (rather than mediates) resources, prompts, sampling and server notifications.
- Path parameters are restricted to `[A-Za-z0-9-_.~:@]` and query parameters to those a route lists. Upstreams with other id formats need a wider rule, which is not configurable.
- The HTTP proxy accepts request bodies framed by one `Content-Length` only. A chunked request (`Transfer-Encoding`) is refused with 411 (400 when it also has a `Content-Length`) and the connection is closed; a client library that insists on chunked uploads cannot be used through it.
- The routes file and the MCP tools file are read strictly: an unknown key, a value that is not an expression (a constant must be written `{"literal": …}`), or an `env:NAME` whose variable is not set stops the proxy at start. Files written for 0.2 with plain-string constants in `id` or `spend` must be edited.
- The HTTP proxy refuses a query it and an upstream could read differently (a repeated name, a `;`, a percent-encoded name, a malformed escape) and forwards the query as it parsed it, not as it was written. An upstream that needs repeated parameters (`?tag=a&tag=b`) cannot be reached through it.
- **A resource attribute taken from the request (`attrs_from_request`) is a claim by the agent.** A policy that restricts on such an attribute ("only records of the user's region") is satisfied by a false claim. For single records take the attribute from the upstream (`lookup` + `attrs_from_record`); the proxy lists at start every route and tool that trusts the request.
- On list routes there is no record to look up: **the row filter of the deciding policy is the only per-record control.** The proxy cannot tell from the routes file whether the policy that will decide carries one; it warns about list routes decided on request-supplied attributes and checks nothing more. A resource whose read permit has no row filter is returned whole to whoever may list it.
- A `lookup` is a second call to the upstream for every request on that route (one, for a read of the same record), and the record can change between the lookup and a write. Inside the tenant and the capability, `404` versus `403` tells a caller whether a record id exists.
- **Budget is reserved before the upstream call.** The HTTP and MCP proxies charge the spend, and use up an approval, when the decision is made; if the upstream then rejects the write or cannot be reached, the budget is not refunded. This never lets a budget be overrun; it can leave one under-used. A reserve/commit/release operation would need an engine change.
- MCP: a mapping with `lookup` calls a read tool of the same server before the agent's call; the record is not reused, so such a call costs two server calls.

## 12. Audit

- The hash chain detects edits, deletions and reordering. It cannot detect removal of the newest records unless you keep the head hash (`sf-smartdelegate audit verify` prints it) somewhere the writer cannot change.
- Anyone who can write the file and recompute hashes can forge a whole new chain; anchor the head externally.
- Spend and approval state changes are committed just before the audit record is written. If the audit write then fails, the request is refused, but the spend stays counted.
- The record of an issued token holds user, role and capability. It does not hold the groups that were supplied, nor who supplied them.
- The log is a local file. No OpenTelemetry export.

## 13. State and scale

- Every operation takes one lock per state directory and re-reads `state.json`. Throughput does not scale with cores.
- Rate-limit counters are in memory, per process: two proxies each allow the full limit, and a restart resets it.
- Spend ledger entries and user revocations are never pruned.
- The entity store is loaded in memory and copied per request. Fine for hundreds of entities; not designed for millions.
- One bundle per engine. Multi-tenancy is a tenant claim checked against a resource attribute, nothing more.
- No load test of any engine or daemon. No benchmark of the Java, Node.js, Go or PHP engines.

## Known and not fixed in 0.3.0

- **`typ` is not checked on ID tokens.** If your provider puts the engine's client id into the audience of that client's own *access* tokens, such an access token is accepted as an ID token. Same client, same user; it matters only if that access token is forwarded elsewhere.
- **The user revoke cut-off is in whole seconds, on the engine's clock.** A sign-in in the same second as the revoke is refused once. A provider clock behind the engine's delays fresh sign-ins by the difference.
- **A JWKS with an empty `keys` list loads**, and then every sign-in is refused. Check the file before `reload`.
- **Budget is reserved before the upstream call** in the proxies; an upstream rejection does not give it back.
- **`idp.group_map` cannot add parent groups** of a group named in a claim; put the nesting in `entities.json`.
