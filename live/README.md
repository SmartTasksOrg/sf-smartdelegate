# Live tests

Until now SmartDelegate's enforcement points were tested against stand-in
upstreams (`examples/fake_crm.py`, `examples/fake_mcp_server.py`), never
against a real system, a real network boundary or load. These tests add the
three that were missing. They are **not** part of the offline suite in
`tests/` and nothing here changes the engine, the proxies, the harness or the
spec; they only drive what is already built.

```
live/
  upstream/   A. a real system behind the enforcement points (PostgreSQL + a REST API + an MCP server)
  boundary/   B. is the proxy really the only way out? (a kernel-enforced network namespace)
  load/       C. load and soak
  idp/        a real Keycloak (written separately); not driven by run.sh — see its own README
  run.sh      runs what it can; PASS / FAIL / SKIP per part
  runner.py   unittest runner behind run.sh (exit status, "FIXED?" lines)
  FINDINGS.md defects and differences these tests found in the product (read this)
```

## How to run

```
live/run.sh all            # upstream + boundary (root only) + load
live/run.sh all --quick    # the whole thing under ~3 minutes
live/run.sh upstream       # just part A
live/run.sh boundary       # part B (needs root; SKIPs otherwise)
live/run.sh load           # part C, with the CI thresholds

# or directly:
cd <repo>
PYTHONPATH=src python3 -m unittest live.upstream.test_live_upstream
sudo  PYTHONPATH=src python3 -m unittest live.boundary.test_boundary
PYTHONPATH=src python3 -m live.load --help
```

`run.sh` exits **0** when at least one part ran and nothing failed, **1** when a part failed, **3** when
nothing ran (every part skipped; the reasons are printed). A part in which no test ran prints SKIP, never
PASS. Its last act is a self-check: the test code records the pid of every process it starts, and if one of
them is still alive when the run ends it is listed, stopped, and the run exits 1. It stops everything it started — the test processes and, through them, daemons, proxies, `company-api`
and MCP servers, and the private PostgreSQL cluster unless it attached with `SD_PG_DSN` or found one already
running — on success, on failure and on Ctrl-C, by PID. Children are also started with `PR_SET_PDEATHSIG`,
so a test process that is killed outright does not leave them behind.

A test tied to an open finding is an expected failure. When one starts to pass, the run prints
`FIXED? finding L-n no longer reproduces: <test>` and the part still PASSes if every other test passed; that
line is the cue to remove the `@finding` mark and update `FINDINGS.md`. (Plain `python3 -m unittest` reports
the same thing as "unexpected success" and fails; `python3 -m live.runner <module>` is what `run.sh` uses.)

Requirements: Python 3 with `psycopg2` and `cryptography`; PyYAML only for the syntax check of the two
deployment files in `boundary/` (that one test skips without it); PostgreSQL 16
binaries on the host (or `SD_PG_DSN`); Node, Go, PHP and the built Rust binary
only for the ports they test (missing ones SKIP, never fail); **root and
working network namespaces for part B**. Everything started is stopped by its
PID, the private PostgreSQL cluster is dropped, namespaces and temp dirs are
removed, and nothing — no key, state, report or data dump — is written into the
repository. The generated data comes from a seeded generator
(`live/upstream/seed.py`), not from a committed dump.

## Attaching to services someone else started (docker-compose, CI)

Each piece is started here unless the matching variables point at one already
running:

| Variables | Used instead of |
|---|---|
| `SD_PG_DSN` | the private PostgreSQL cluster (`live/upstream/pg.sh`) |
| `SD_UPSTREAM_URL`, `SD_UPSTREAM_KEY` | the `company-api` process |
| `SD_DAEMON_URL`, `SD_ADMIN_KEY`, `SD_PEP_KEY` (+ `SD_PROXY_URL`) | the decision daemon and HTTP proxy |

`company_api.py` listens on `COMPANY_API_HOST`:`COMPANY_API_PORT` (default `127.0.0.1`, any free port; also
`[host:]port` on the command line) and reads its key and DSN from `COMPANY_API_KEY` / `COMPANY_API_DSN` or the
files named by `COMPANY_API_KEY_FILE` / `COMPANY_API_DSN_FILE`. `upstream/routes.json` names no address: every
upstream has `"base_url": "env:COMPANY_API_URL"`, so the same file serves a laptop, a container and CI (set
`COMPANY_API_URL` and `COMPANY_API_KEY` for the proxy).

When attached, the harness cannot read that server's state directory or its
PostgreSQL statement log, so the few checks that read them (the exact ledger,
the logged SQL) skip with a note; everything observable over the wire still
runs.

## A — `live/upstream`: a real system behind the enforcement points

`pg.sh` brings up a private PostgreSQL 16 cluster in a cache dir outside the
repo (scram auth, loopback only, `log_statement=all`); `seed.py` builds the
Kestrel Works company of `examples/company/` as a relational schema —
customers, tickets, refunds, invoices, payments, employees, salaries, vendors
with bank details, opportunities, contracts — a few thousand rows across two
tenants and three regions, generated deterministically from a seed.
`company_api.py` is a REST service **in a process of its own** with an API key
the agent never holds, doing real SQL, with list endpoints, nested JSON,
non-JSON endpoints (CSV, a binary PDF), a redirect, a slow endpoint, a >32 MB
endpoint and error statuses. `mcp_server.py` exposes the same database as MCP
tools over stdio. In front of them: `sf-smartdelegate http-proxy` with
`routes.json`, `sf-smartdelegate mcp-proxy` with `mcp_tools.json`, and `SqlGuard`
straight on PostgreSQL.

`test_live_upstream.py` then checks, on **real rows** and against an
engine-independent oracle (`oracle.py`, built from the catalog labels, the role
deny lists and the business rules — it imports nothing from the engine): only
permitted fields arrive; row filters by region hold (rows counted in SQL vs
what arrived); writes with forbidden fields are refused and the database row is
unchanged (verified by SQL); spend and budget are enforced and the ledger
equals the rows written; approval-required writes do not reach the database
until approved; a revoked user's token stops at the proxy; non-JSON, the >32 MB
response, the redirect and the slow endpoint behave as documented; the upstream
key never appears in anything the agent side receives (headers, bodies, errors,
proxy stderr, the audit log); SQL-injection attempts through ids and query
values do not change the query shape (checked against PostgreSQL's statement
log); and many agents at once never see each other's data. The HTTP-proxy and
MCP-proxy cases run against **both** the Python reference and the Rust port, and
the differences are printed side by side. The three PostgreSQL tests in
`tests/test_guard_sql.py` that skip without `SMARTDELEGATE_PG_DSN` are run here
and reported.

`routes.json` and `mcp_tools.json` are in the form `spec/API.md` describes, and both proxies (Python, Rust) are
given the same files. For one record, the region comes from the upstream's own record (`lookup`,
`attrs_from_record`); on list routes it is declared as what it is, a claim (`attrs_from_request`), and the
policy's row filter is the control. The tenant is never a claim and never a row filter: every route has
`"attrs": {"tenant": "{tenant}"}` (the path segment the upstream is asked about) and every tool mapping a fixed
tenant, so the engine's tenant check runs on every call (`test_06c` asserts this of the files). One route and
one tool are kept in the claim form on purpose (`company_claims`, `update_customer_as_claimed`) to show the
documented risk.

**Proves:** the enforcement points mask fields, filter rows, bound spend, hold
approvals and withhold the upstream credential correctly against a real
database and a real separate upstream, concurrently, and that the Python and
Rust proxies agree except where `FINDINGS.md` records they do not.
**Does not prove:** anything about an upstream we did not write — this is a
real database and a real separate process, but one of our own making; HTTPS
upstreams (every upstream here is plain HTTP on loopback); or correctness of
policies other than this company's.

## B — `live/boundary`: is the proxy really the only way out?

A stand-in agent runs inside a fresh network namespace (`unshare -n`). Because
this host has no `ip` command, the namespace's loopback is brought up with an
`ioctl` (`SIOCSIFFLAGS`) from Python, and the proxy is carried in over a
**Unix-domain socket**: a path-based Unix socket belongs to the filesystem, not
to a network namespace, so a small byte relay (`relay.py`) on each side is a
door the kernel lets through while every interface, route and TCP port of the
host stays outside. `cell.py` runs as root inside the namespace, refuses to
continue unless the only interface is `lo` (so a caller's mistake cannot run
the agent on the host network), starts the relay in its own root process, and
drops to an unprivileged uid with a private temp dir to run the agent. The
agent uid holds no capability, cannot open the root-only Unix socket directly,
cannot join another namespace (`setns` needs `CAP_SYS_ADMIN`) and cannot read
the root-owned proxy's `/proc/<pid>/environ`. This is a boundary the **kernel**
enforces, not one the agent cooperates with.

`test_boundary.py` proves, from inside: a permitted call through the proxy
returns masked data and no secret; direct TCP to the upstream, to PostgreSQL,
to the daemon admin port and to an internet address all fail at connect; the
agent's environment, readable files and other processes' `/proc` hold no
upstream credential; and a battery of egress attempts an injected agent could
make — direct connect, env/argv/proc scraping, unmapped routes, path traversal,
overriding Authorization/Host/X-Forwarded-*, request smuggling with conflicting
Content-Length/Transfer-Encoding, CONNECT, absolute-URI to another host,
over-long headers, a partial request — each obtains nothing outside the role.
Every attempt and its outcome is printed. A **contrast run** performs the same
attempts with no namespace, where the backend ports *are* reachable, and a
third case shows that an in-process integration (the credential in the agent's
own environment) exposes exactly what the boundary hides — the documented
limitation of in-process checks, made honest.

`deploy-compose.yml` (a Docker `internal: true` network) and
`deploy-networkpolicy.yaml` (a Kubernetes default-deny egress plus one
allowance to the proxy) express the same topology as deployment artifacts.
They are **UNTESTED** here — the test only checks they are syntactically valid
and marked so.

**Proves:** on this one Linux host, when the agent's only reachable service is
the proxy, the proxy is the only way out, and none of the listed bypasses
works. **Does not prove:** anything about a real cloud network — a network
namespace on one host is not a VPC; the Docker and Kubernetes artifacts have
not been run anywhere; nothing here constrains the host itself (the threat
model trusts the host). The test SKIPs with a reason when not root or when
namespaces are unavailable.

## C — `live/load`: load and soak

`python3 -m live.load` is a multi-**process** load generator (so the client's
own GIL is not the bottleneck) with open-loop (target rate) and closed-loop (N
busy clients) modes, warm-up, and a mix of company operations (issue, exchange,
authorize, filter with a realistic nested record, spend, revoke). It drives any
daemon — `python`, `rust`, `node`, `go`, `php`, `java` (started with the
command lines of `live/launchers.py`) or `--url` — and the HTTP proxy with the real
upstream of part A. It measures throughput, the latency distribution per
operation (p50/p90/p99/p99.9/max), error rate by type, daemon RSS and CPU over
time (from `/proc`), audit-log growth (bytes per decision) and `audit_verify`
time against log size, `state.json` growth and whether any operation's latency
grows with state size (a soak), behaviour at overload, and correctness under
load (budget totals exact from the audit log, audit chain valid, no lost
decisions, and the invariant that a deny-expected request is never allowed). It
writes `report.json`, `report.md` and a self-contained `report.html` with
latency-over-time and throughput charts drawn in inline SVG (light/dark, each
chart with axis labels, units and a text summary). `--check thresholds.json`
exits non-zero for CI when the error rate, the wrong-allow count or p99 exceed
conservative limits. `RESULTS.md` holds the real numbers from this machine.

The load client sets `TCP_NODELAY` so it measures the server, not its own Nagle
stall (the Rust daemon's own Nagle setting was finding L-9, since fixed).

**Proves:** the daemons sustain their throughput with a bounded error rate,
never wrongly allow a deny-expected request (including under overload), keep the
budget exact and the audit chain valid under concurrency, and shows where cost
grows with state and log size. **Does not prove:** absolute performance — client
and server share one small machine, so the numbers are indicative, not a
datasheet.

## What is untested anywhere here

The Docker Compose and Kubernetes artifacts (not run); HTTPS anywhere (every
upstream and daemon is plain HTTP on loopback); any OS but this Linux host; real
cloud networking (a namespace is not a VPC); and any upstream, database or MCP
server other than the ones in this directory, which we wrote.
