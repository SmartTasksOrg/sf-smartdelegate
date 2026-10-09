# SmartDelegate: Java port

`dev.smartdelegate.Engine` is a native Java port of the Python reference
engine in `src/sf_smartdelegate` (spec version 0.3: capability tokens,
narrowing-only delegation, Cedar policy from compiled JSON, field masking,
budgets, human approval, hash-chained audit, roles and live group membership,
rule ids). Around it:

| Class | What it is |
|---|---|
| `dev.smartdelegate.Engine` | the engine: `new Engine(config).call(op, input)` |
| `dev.smartdelegate.Client` | a thin REST client for a running daemon (any port's) |
| `dev.smartdelegate.Server` | the REST decision daemon (`serve`), on the JDK's `com.sun.net.httpserver` |
| `dev.smartdelegate.Cli` | the command line, same commands and exit codes as the other ports |
| `dev.smartdelegate.Vectors` | runner for conformance vectors and a bundle's own tests |

This directory is `ports/java` in the repository. Paths below are relative to
it unless they start with the repository root (`../..`).

## Requirements

- JDK 17 or newer (developed and tested with OpenJDK 21 on Linux). No
  third-party libraries. No Maven or Gradle needed: `build.sh` uses `javac`
  and `jar`. A `pom.xml` is there for Maven users (see "Maven").
- To run: a JRE 17+ that includes the `jdk.httpserver` module (every full
  JDK/JRE does; a `jlink` image must add it for `serve`).
- For the tests only: `python3`, to run the reference implementation
  from `../../src`, and `bash` for `run_conformance.sh`.

## Build

```
./build.sh
```

compiles `src/main/java` with `javac -Xlint:all -Werror --release 17` into
`build/classes`, and writes `build/smartdelegate.jar` (`Main-Class:
dev.smartdelegate.Cli`) and `build/smartdelegate.jsa`, a class-data archive
that shortens JVM start-up. `build/` is ignored by git. `build.cmd` does the
same on Windows (not tested, see the end of this file).

```
bin/smartdelegate-java --version          # smartdelegate 0.3.0 (java)
java -jar build/smartdelegate.jar --help  # the same program without the launcher
```

## Command line

`bin/smartdelegate-java` (POSIX sh) and `bin\smartdelegate-java.cmd` (Windows)
run the jar. Commands, options, configuration and exit codes are those of the
reference (`python -m sf_smartdelegate`) and of the Go, Node and PHP ports:

```
info                                  version, policy version, mode, key id
policy check | policy test            load the bundle | run the bundle's tests/*.json
bundle keygen <prefix>                write <prefix>.key (owner-only) and <prefix>.pub
bundle sign --key <file>              sign the bundle (writes bundle.sig.json)
token issue --user U --agent A (--cap JSON | --role R [--cap JSON]) [--groups g1,g2]
            [--ttl S] [--tenant T] [--task X] [--id-token JWT] [--raw]
token exchange --token T --actor A [--cap JSON] [--ttl S] [--raw]
token inspect --token T
token revoke --id TOKEN_ID | --token T | --user U
authorize --token T --action A --resource path/id [--attrs JSON] [--context JSON]
          [--data JSON] [--strict] [--dry-run]
explain   (same options)
approvals | approve <approval_id> --by USER
audit verify | audit tail [-n N]
call <op> [--input JSON|@file|-]      any operation of spec/API.md, JSON in, JSON out
conformance [<vectors dir> <bundle dir>] [--root DIR]
serve [--listen 127.0.0.1:8181]
--version | --help
```

- **Exit code**: 0 allow / ok, 2 deny, 1 error. (`audit tail` exits 0 and
  prints no records when the engine has no audit log, as the reference does;
  this port also says why on stderr.)
- **Configuration**: `--config FILE`, or the environment variable
  `SMARTDELEGATE_CONFIG`, or `./smartdelegate.json`. Relative `bundle_dir`,
  `state_dir` and `idp.jwks_file` in the file are relative to the file (to
  the real file when it is a symlink). `--bundle DIR` and `--state DIR`
  override the file; `--shadow` sets `mode: shadow`;
  `SMARTDELEGATE_ADMIN_KEY` / `SMARTDELEGATE_PEP_KEY` override the keys.
- JSON options accept `@file`; `call --input -` reads standard input.
- Output is UTF-8. Results are printed as indented JSON; `--raw` prints only
  the token; `audit tail` prints one record per line.

Signing from Java code: `Engine.keygen()` returns `{private, public}` and
`Engine.signBundle(bundleDir, privateKey)` writes `bundle.sig.json`.

Not in this port's command line: `init`, `bench`, `--demo`, `http-proxy`,
`mcp-proxy`, `bridge ...` (use the Python package; the command says so and
exits 1) and `bundle compile` (Rust port).

## Daemon

```
bin/smartdelegate-java serve --config smartdelegate.json --listen 127.0.0.1:8181
```

The same REST interface as `python -m sf_smartdelegate serve`
(`../../spec/openapi.yaml`, `../../src/sf_smartdelegate/daemon.py`): the same
routes, the same two keys (`admin_key`, `pep_key`, 16+ characters, in the
config file or the environment), the same status codes and error bodies.

- `Authorization: Bearer <key>`, compared in constant time. The pep key (or
  the admin key) opens `/v1/authorize`, `/v1/filter`, `/v1/explain`,
  `/v1/obligations/apply`, `/v1/token/inspect`, `/v1/info`; the admin key
  opens `/v1/admin/*` and root-token issuance on `/v1/token`. Token exchange
  (`subject_token`) needs no key; neither does issuance with an `id_token`,
  and then `user` in the body is dropped: the identity comes from the ID
  token alone. `/healthz` needs no key.
- 200 when the engine answers `ok: true` (a deny is a normal answer), 400 for
  an engine error or a body that is not JSON, 401 for a missing or wrong key,
  404 for an unknown path. Every error body is
  `{"ok": false, "error": {"code", "message"}}`. An exception inside a handler
  is answered with 500 and such a body, never with a 200.
- Request bodies are limited to 8 MiB (`Server.MAX_BODY`). A larger
  `Content-Length` is refused with 400 without reading the body.
- The first line on stderr is `smartdelegate daemon listening on
  http://HOST:PORT` (`--listen 127.0.0.1:0` picks a free port); tests and the
  live suites read the URL from it. The daemon writes nothing else:
  decisions are in the audit log.
- Requests run on a thread pool (at most 256 threads). The engine serialises
  its own calls with a lock per state directory, so decisions are made one at
  a time; the pool only keeps slow peers from blocking each other.
- TLS is not terminated here: bind to loopback or put it behind a mesh.
- Stop it with SIGTERM (exit status 143) or Ctrl-C.

Where it differs from the reference daemon:

- Methods other than GET and POST get 501 with a JSON error body (the
  reference answers 501 with Python's HTML error page).
- A request whose headers or body stop arriving is dropped after 30 seconds
  (the JDK server's `sun.net.httpserver.maxReqTime`, set by `Server` unless
  you set it yourself); the reference waits for ever.
- A chunked request body is read (and bounded by the same 8 MiB); the
  reference ignores it.
- Integers beyond 64 bits, `NaN` and `Infinity` in a request body are refused
  as "body is not JSON"; the reference's JSON reader accepts them and its
  engine then refuses or uses them.

From Java code:

```java
try (Engine engine = new Engine(config); Server server = Server.listen(engine, "127.0.0.1:0", adminKey, pepKey)) {
    System.out.println(server.url());      // http://127.0.0.1:<port>
    // ... the daemon answers until close()
}
```

## Launchers and start-up time

`bin/smartdelegate-java` finds Java in `JAVA_HOME` or on `PATH`, and runs
`build/smartdelegate.jar` (it says to run `build.sh` when the jar is missing).

- `SMARTDELEGATE_JAVA_OPTS`: extra JVM options, split on whitespace.
- `JAVA_TOOL_OPTIONS`: the launcher passes its content on the command line
  and unsets the variable. The effect is the same, but the JVM does not print
  its "Picked up JAVA_TOOL_OPTIONS" banner, which would otherwise be the
  first line on stderr, where the daemon's URL has to be. The content is
  split on whitespace; quoting inside it is not interpreted.
- Start-up: the launcher maps `build/smartdelegate.jsa` when it exists (the
  JVM ignores an archive that does not match the jar or the JVM), and runs
  every command except `serve` with `-XX:TieredStopAtLevel=1`. `serve` keeps
  the full JIT; for short-lived test daemons
  `SMARTDELEGATE_JAVA_OPTS=-XX:TieredStopAtLevel=1` starts faster.

Measured on the development machine (2 cores, OpenJDK 21, medians; yours
will differ):

| | time |
|---|---|
| `--version` through the launcher | about 90 ms |
| `info` with a state directory, `java -jar` without options | about 400 to 440 ms |
| the same through the launcher | about 210 to 260 ms |
| `serve`: process start to the URL line, `java -jar` | about 440 to 500 ms |
| the same through the launcher | about 370 to 420 ms |
| the same with `SMARTDELEGATE_JAVA_OPTS=-XX:TieredStopAtLevel=1` | about 260 to 300 ms |
| the reference (`python3 -m sf_smartdelegate serve`) | about 100 ms |

`bin\smartdelegate-java.cmd` does the same on Windows, with these differences:
it uses `java` from `PATH` first (the one `build.cmd` compiled with) and `JAVA_HOME`
only when `PATH` has none, because a `JAVA_HOME` left pointing at an older JDK
fails with `LinkageError`; `SMARTDELEGATE_JAVA` forces a specific `java.exe`;
the class-data archive is used only with `SMARTDELEGATE_JAVA_CDS=1`;
it looks for `serve` only in the first argument, and it leaves
`JAVA_TOOL_OPTIONS` alone (clear it yourself when something reads the URL
from the first line of stderr).

## Maven

`pom.xml` builds the same classes into `target/smartdelegate-0.3.0.jar` with
`mvn package` (no dependencies; `Main-Class` set). It was validated with
`mvn -o validate` only: on the development machine Maven could not download
its own plugins, so `mvn package` has not been run. The tested build is
`build.sh`, and the launchers use `build/`, not `target/`.

## Using the engine

Every operation of `spec/API.md` is JSON in, JSON out, as
`Map<String, Object>` (integers are `Long`). `call` never throws on bad input:
errors come back as `{"ok": false, "error": {"code", "message", "rule"}}`.

```java
import dev.smartdelegate.Engine;
import java.util.List;
import java.util.Map;

try (Engine iam = new Engine(Map.of("bundle_dir", "../../spec/conformance/bundle", "state_dir", "state"))) {
    // alice lends the agent her role "support-agent" for one task. The token
    // can never carry more than the role's cap in roles.json.
    Map<String, Object> t = iam.call("issue_token", Map.of(
            "user", "alice", "agent", "support-bot", "role", "support-agent", "task", "ticket-7"));
    if (!Boolean.TRUE.equals(t.get("ok"))) throw new IllegalStateException(String.valueOf(t.get("error")));
    String token = (String) t.get("token");                    // t.get("role") is "support-agent"

    Map<String, Object> resource = Map.of("path", "crm.customer", "id", "c-1");

    // authorize: a deny is a normal result, not an exception
    Map<String, Object> d = iam.call("authorize", Map.of("token", token, "action", "read", "resource", resource));
    // d.get("effect") is "allow", d.get("rule") is "DELEGATE-POLICY-PERMIT",
    // ((Map) d.get("principal")).get("role") is "support-agent"

    // filter: decide and mask the record in one call
    Map<String, Object> f = iam.call("filter", Map.of("token", token, "action", "read", "resource", resource,
            "data", Map.of("id", "c-1", "region", "EU", "email", "ada@example.com", "ssn", "123-45-6789")));
    Object safe = f.get("data");                                // no "ssn"; f.get("masked") is ["ssn"]
    // (the conformance bundle also row-filters customers to the user's region: a record
    // of another region comes back as null with "rows_dropped": 1)
}
```

Live group membership from an identity provider: pass `"groups", List.of("support")`
to `issue_token`, or configure `idp` (`issuer`, `audience`, `jwks` inline or
`jwks_file`, optional `user_claim`, `groups_claim`, `group_type`, `group_map`)
and pass `id_token`. The token then carries `grp`, which replaces the user's
parents from `entities.json` for every evaluation of that token. Set
`"require_role": true` in the config to refuse tokens that name no role.
ID tokens follow "OIDC ID tokens (0.3 ...)" in `../../spec/PORTING.md`: `azp`,
when present, must equal `idp.audience`, and several audiences without `azp`
are refused; an ID token issued at or before its user's revoke cut-off is
refused; a dotted `groups_claim` (`realm_access.roles`) reads a nested claim
when no top-level claim has that exact name; `reload` re-reads
`idp.jwks_file` together with the bundle, and replaces neither if either
fails to load. See
`../../spec/ROLES.md` and `../../spec/API.md`.

`info` reports `"version": "0.3.0"`, `"implementation": "java"`.

## Using the REST client

```java
Client iam = new Client("http://127.0.0.1:8181", pepKey, adminKey);
Map<String, Object> t = iam.issueToken("alice", "support-bot", "support-agent", null, "ticket-7", null);
Map<String, Object> d = iam.require((String) t.get("token"), "read", "crm.customer", "c-1", null);  // throws DeniedException on deny
Object safe = iam.applyObligations(d, record);
String role = Client.roleOf(d);                                 // "support-agent"
iam.revokeUser("alice", "hr");                                  // ends every token already issued for alice
```

`Client.call(op, payload)` passes any operation through unchanged.

## Running the tests

```
./run_conformance.sh
```

runs `build.sh`, compiles `src/test/java` into `build/test-classes` with
`javac -Xlint:all -Werror`, runs the harness against the reference in
`../../src`, prints its summary and exits non-zero if anything fails (about
a minute and a half). By hand, from this directory:

```
./build.sh
mkdir -p build/test-classes && javac -cp build/classes -d build/test-classes $(find src/test -name '*.java')
PYTHONPATH=../../src java -Dsmartdelegate.launcher=$PWD/bin/smartdelegate-java -Dsun.net.httpserver.maxReqTime=5 \
  -cp build/classes:build/test-classes dev.smartdelegate.Conformance ../.. python3 -m sf_smartdelegate
```

The harness (`src/test/java/dev/smartdelegate/Conformance.java`, then
`DaemonChecks.java`) runs, in order:

1. Policy evaluation: `spec/conformance/eval/cases.json` (95 cases; expected
   answers recorded from the real Cedar engine).
2. Engine conformance, in-process: every file in `spec/conformance/vectors`
   (78 cases, 327 steps), a fresh engine and state directory per case, the
   file's top-level `config` merged over the standard configuration.
3. Interoperability with the reference: tokens in both directions, including
   a role token carrying `grp`; identical bundle version and role list; bundle
   signatures in both directions and refusal of a changed bundle; audit logs
   in both directions and detection of a tampered log; a user revoked by
   one engine (`revoke {"user"}`) is refused by the other on the same state
   directory, used one after the other.
4. OIDC issuance with the shared ID-token fixtures (`idp.jwks_file`; suites 08
   and 09 in step 2 use inline `idp.jwks` and group claims).
5. `roles.json` validation: malformed documents are refused with `roles_parse`
   by Java and by the reference alike; `roles.json` is part of the bundle version.
   Then ancestor budgets across engines: a child token carries its
   ancestors' budgets in `lim`, so a verify-only engine with its own state
   directory enforces them (Java issues and the reference verifies, and the
   reverse); a malformed `lim` is `token_invalid`.
   Then approval ids: Java and the reference compute the same id for the
   same request with and without `resource.attrs` (nested object, non-ASCII
   strings, integers, shuffled key order).
6. The "Strictness (0.3)" section of `spec/PORTING.md`, bullet by bullet:
   audit records containing U+2028/U+2029/U+0085 (verify, tail, a second
   engine on the same state directory, and both directions with the
   reference); strict base64url in every token part; `anc` of the wrong
   shape; entity type names; `entities.json` and policy JSON of the wrong
   shape (verdicts compared with the reference); non-UTF-8 `state.json`,
   audit log and bundle files; 8 processes (3 rounds) and 8 threads racing to
   create the signing key on an empty state directory; an empty key file
   (filled 400 ms later: the engine starts with that key; empty forever:
   `state_io` after the wait, 30 s by default, shortened in the test). The `containsAll` /
   `containsAny` bullet is covered by eval cases 92 to 95 in step 1.
7. The same 78 vector cases through `Client` against a reference daemon
   started per case with a config file.
8. The client's typed helpers, including issuance under a role and `revokeUser`.
9. The same 78 vector cases through `Client` against the Java daemon
   (`Server`, a fresh engine, state directory and port per case).
10. The daemon's rules: each of the 12 routes with no key, eight kinds of
    wrong key, the pep key and the admin key; the other method on each route
    (404); `/v1/token` (root issuance needs the admin key; exchange needs
    none; with an ID token `user` is dropped; expired, forged and
    wrong-audience ID tokens issue nothing); bodies that are not JSON, not
    UTF-8 or not an object; allow and deny are 200, engine errors 400; a body
    of exactly 8 MiB is read and `Content-Length` one byte larger is refused
    unread; a peer that stops sending is disconnected; `audit tail?n=`;
    short keys, bad listen addresses and a port in use are refused at start.
11. Concurrency: 48 client threads against one daemon, 240 requests of 5.00
    against a budget of 200.00 (exactly 40 allowed, the rest
    `budget_exceeded`), mixed with refunds under a policy rate limit of 3 per
    minute (exactly 3 allowed) and with issuance, exchange and revocation of
    other tokens; every request answered; the audit chain valid, accounting
    for exactly the budget, and verified by the reference with the same
    record count and head. Then two engines in one JVM on one state
    directory, 16 threads: exactly 40 allowed, one chain of 129 records.
12. The command line (in the test JVM, through `Cli.run`): every command,
    configuration resolution (BOM, relative paths, symlinked file,
    environment, overrides), exit codes 0 / 2 / 1, and cross-checks with the
    reference command line: `info` reports the same values for one config
    file; `policy test` and `audit tail` print the same text; tokens are
    accepted in both directions; a bundle signed by either command line
    loads in the other with `bundle_public_key`, a changed file is refused
    by both; the reference verifies the audit log the Java command line
    wrote (same count and head) and its next record continues the chain.
13. OIDC with RS256 ID tokens minted in the test with the JDK: `reload`
    re-reads `idp.jwks_file` (after a rotation the old key's tokens are
    refused and the new key's accepted; a missing, malformed or non-UTF-8
    file is `invalid_config` and the old keys stay; a bundle and a JWKS are
    replaced together or not at all; inline `idp.jwks` reads no file); `azp`
    and several audiences; an ID token issued at or before a user's revoke
    cut-off; a dotted `groups_claim`.
14. The launcher: `bin/smartdelegate-java serve` with `JAVA_TOOL_OPTIONS`
    set prints the URL as its first stderr line, decides, shares the state
    directory with command-line runs next to it, and stops on SIGTERM.

Expected summary:

```
java policy evaluation (against real Cedar's answers): 95 cases, 0 failed
java engine conformance (in-process): 78 cases, 327 steps, 0 failed
java interoperability with the reference: 29 checks passed
java OIDC issuance: 6 checks passed
java roles.json validation (same verdicts as the reference): 61 checks passed
java ancestor budgets across engines (lim claim, both directions): 42 checks passed
java approval ids (same as the reference, bound to resource.attrs): 16 checks passed
java strictness: audit lines end at \n only: 11 checks passed
java strictness: strict base64url, anc is an array of strings: 54 checks passed
java strictness: entity type names, entities.json is a list of objects: 25 checks passed
java strictness: policy JSON shapes: 42 checks passed
java strictness: files that are not UTF-8: 18 checks passed
java strictness: racing to create the signing key: 59 checks passed
java strictness: an empty signing key file is not "no key": 14 checks passed
java client conformance (REST, reference daemon): 78 cases, 327 steps, 0 failed
java client checks: 16 checks passed
java daemon conformance (REST, java daemon, java client): 78 cases, 327 steps, 0 failed
java daemon: keys, status codes, body limit, error bodies: 234 checks passed
java daemon: concurrent requests (budget never exceeded, audit chain valid): 10 checks passed
java command line (commands, config, exit codes, cross-checks with the reference): 102 checks passed
java OIDC: reload re-reads idp.jwks_file (rotation, broken file), azp, revoked users, nested group claim: 90 checks passed
java launcher (bin/smartdelegate-java: serve, exit codes, SIGTERM): 10 checks passed
java port: all suites passed
```

The tests create temporary directories and remove them; they write nothing
into the repository except `build/`. Every daemon they start is stopped.

### The Java daemon as a backend for the repository's other tests

The reference's own daemon test, against this port's command line (78 daemon
starts; about 30 s on the development machine, against 8 s for the reference):

```
cd ../../tests
SMARTDELEGATE_TEST_CLI='["'$PWD'/../ports/java/bin/smartdelegate-java"]' python3 -m unittest test_conformance.DaemonConformance
```

The scenario harness (`harness/README.md`), against a Java daemon you start:

```
# smartdelegate.json: {"bundle_dir": "<repo>/examples/company", "state_dir": "<somewhere>/state",
#   "issuer": "smartdelegate://harness", "mode": "enforce", "allow_test_clock": true, "max_depth": 3}
export SMARTDELEGATE_ADMIN_KEY=... SMARTDELEGATE_PEP_KEY=...        # 16+ characters each
bin/smartdelegate-java serve --config smartdelegate.json --listen 127.0.0.1:0 2> stderr.txt &
cd ../.. && PYTHONPATH=src python3 -m harness run --backend url:http://127.0.0.1:<port from stderr.txt>
kill <pid of the daemon>
```

Both passed when this was written (`verdict: PASS`, 0 violations).
`ports/conformance/matrix.py` still drives this port through its
`ports/conformance/java/Shim.java`; the command line here accepts the same
`call <op> --config FILE --input -` and adds `audit verify` and
`bundle sign`, so the shim is no longer needed.

## Not included / not tested

- No HTTP proxy (`http-proxy`), no MCP proxy (`mcp-proxy`), no SQL guard, no
  bridges, no `init`, `bench` or demo, no `.cedar` compiler. Use the Python
  package for those and the Rust port for `bundle compile`. This port loads
  `policies.json` only.
- **Windows**: `bin\smartdelegate-java.cmd` and `build.cmd` were written
  without a Windows machine and have never been run. Nothing in this port
  has been run on Windows or macOS.
- **Maven**: `pom.xml` was validated (`mvn -o validate`) but `mvn package`
  has not been run (see "Maven").
- The daemon's 500 answer for an exception inside a handler is not exercised
  by a test: nothing in the tests makes the engine throw.
- The daemon is tested with HTTP/1.1 clients on loopback (the Java client,
  Python's `http.client`, raw sockets). No TLS, no HTTP/2.
- The JWKS is inline or a file. There is no OIDC discovery and no key
  fetching: after the provider rotates its keys, write the new JWKS to
  `idp.jwks_file` and call `reload`.
- ID-token verification is exercised with RS256 fixtures only. The ES256,
  ES384, RS384, RS512 and EdDSA code paths exist and are not tested.
- Do not share a state directory between this port and another port while
  both are running: the JVM file lock is a different lock from the `flock`
  the Python and Rust ports use (`../../spec/PORTING.md`). Used one after the
  other, the formats are the same (the tests do that). Concurrent Java
  processes on one state directory are serialised by the lock file (the
  launcher test runs the command line next to a running daemon), and engines
  in one JVM by a lock per directory.
- Rate limits from policy annotations are counted in the memory of one
  engine, as in the reference: each run of the command line starts at zero;
  a daemon counts across its requests.
- `chain.role` / `chain.groups` with `trust_caller_chain` are implemented as in
  the reference but no shared vector covers them.
- Kotlin can use these classes; no Kotlin code has been compiled or run.
- Not benchmarked. As an indication only, a simulation run measured
  about 90 to 240 decisions per second against the Java daemon on the
  development machine (2 cores, shared), with a decision p50 of 20 to 35 ms
  under 8 to 32 concurrent agents; one client alone sees about 2.5 ms per
  `authorize` over REST once the JVM is warm, 9 ms for the first 200 calls.
