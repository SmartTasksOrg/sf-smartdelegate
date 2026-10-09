# Load and soak results — 2026-10-05

Measured on this machine: **2 cores, 8 GB; client and server on the same machine: indicative only**.

These are indicative numbers from one small shared host, not a datasheet. Run `live/run.sh load` to reproduce; `python3 -m live.load --help` for options.

## python daemon

- Steady state (closed, 6 workers): **341 req/s**, error rate 0.00%, wrong-allow 0.
  - authorize_allow: p50 17.9 ms, p99 30.7 ms, p99.9 35.5 ms, max 36.903 ms (1295 calls)
  - authorize_deny: p50 15.7 ms, p99 29.0 ms, p99.9 32.663 ms, max 32.663 ms (252 calls)
  - exchange: p50 16.6 ms, p99 31.6 ms, p99.9 33.372 ms, max 33.372 ms (146 calls)
  - filter_allow: p50 18.0 ms, p99 31.9 ms, p99.9 41.472 ms, max 41.472 ms (745 calls)
  - issue: p50 16.2 ms, p99 29.1 ms, p99.9 32.268 ms, max 32.268 ms (223 calls)
  - revoke: p50 16.0 ms, p99 27.97 ms, p99.9 27.97 ms, max 27.97 ms (66 calls)
- Daemon RSS 33→34 MiB; peak CPU 98% of one core.
- Overload (target 1364 req/s): 317 req/s sustained, error rate 0.0%, p99 170 ms, wrong-allow 0.
- Soak 2000 decisions: audit 761 bytes/decision; state.json 43040→225040 bytes.
  - authorize p50 went 3.661→5.656 ms as state.json grew to 219 KiB (grows with state size — every call re-reads state.json (LIMITATIONS §13))
  - audit_verify went 143.0→188.5 ms as the log grew to 6 MiB (recompute is linear in log size; keep the head hash and rotate the log)
- Correctness: engine allowed 200 spends, expected exactly 200 (over-allow 0); ledger 20000 of 20000 budget (from the audit log); audit chain valid; no lost decisions: True (Δ150 for 150 calls).

## rust daemon

- Steady state (closed, 6 workers): **371 req/s**, error rate 0.00%, wrong-allow 0.
  - authorize_allow: p50 16.3 ms, p99 28.3 ms, p99.9 35.0 ms, max 39.462 ms (1420 calls)
  - authorize_deny: p50 14.7 ms, p99 27.8 ms, p99.9 34.156 ms, max 34.156 ms (278 calls)
  - exchange: p50 14.9 ms, p99 30.3 ms, p99.9 51.657 ms, max 51.657 ms (155 calls)
  - filter_allow: p50 16.4 ms, p99 32.4 ms, p99.9 40.1 ms, max 40.1 ms (799 calls)
  - issue: p50 14.8 ms, p99 29.3 ms, p99.9 32.677 ms, max 32.677 ms (243 calls)
  - revoke: p50 14.5 ms, p99 34.895 ms, p99.9 34.895 ms, max 34.895 ms (74 calls)
- Daemon RSS 16→16 MiB; peak CPU 96% of one core.
- Overload (target 1484 req/s): 374 req/s sustained, error rate 0.0%, p99 127 ms, wrong-allow 0.
- Soak 2000 decisions: audit 771 bytes/decision; state.json 47144→229144 bytes.
  - authorize p50 went 3.326→3.299 ms as state.json grew to 223 KiB (did not grow materially with state size)
  - audit_verify went 101.1→137.3 ms as the log grew to 7 MiB (recompute is linear in log size; keep the head hash and rotate the log)
- Correctness: engine allowed 200 spends, expected exactly 200 (over-allow 0); ledger 20000 of 20000 budget (from the audit log); audit chain valid; no lost decisions: True (Δ150 for 150 calls).

## node daemon

- Steady state (closed, 6 workers): **727 req/s**, error rate 0.00%, wrong-allow 0.
  - authorize_allow: p50 6.9 ms, p99 17.7 ms, p99.9 21.0 ms, max 26.196 ms (2811 calls)
  - authorize_deny: p50 6.5 ms, p99 16.9 ms, p99.9 25.106 ms, max 25.106 ms (587 calls)
  - exchange: p50 7.5 ms, p99 18.9 ms, p99.9 22.455 ms, max 22.455 ms (289 calls)
  - filter_allow: p50 7.1 ms, p99 17.5 ms, p99.9 22.2 ms, max 22.383 ms (1524 calls)
  - issue: p50 7.2 ms, p99 18.6 ms, p99.9 28.599 ms, max 28.599 ms (480 calls)
  - revoke: p50 6.8 ms, p99 15.1 ms, p99.9 16.548 ms, max 16.548 ms (128 calls)
- Daemon RSS 89→103 MiB; peak CPU 112% of one core.
- Overload (target 2910 req/s): 704 req/s sustained, error rate 0.0%, p99 69 ms, wrong-allow 0.
- Soak 2000 decisions: audit 836 bytes/decision; state.json 84596→266596 bytes.
  - authorize p50 went 1.849→2.066 ms as state.json grew to 260 KiB (did not grow materially with state size)
  - audit_verify went 316.7→431.1 ms as the log grew to 12 MiB (recompute is linear in log size; keep the head hash and rotate the log)
- Correctness: engine allowed 200 spends, expected exactly 200 (over-allow 0); ledger 20000 of 20000 budget (from the audit log); audit chain valid; no lost decisions: True (Δ150 for 150 calls).

## go daemon

- Steady state (closed, 6 workers): **953 req/s**, error rate 0.00%, wrong-allow 0.
  - authorize_allow: p50 6.1 ms, p99 12.0 ms, p99.9 14.7 ms, max 15.712 ms (3735 calls)
  - authorize_deny: p50 5.6 ms, p99 10.7 ms, p99.9 15.311 ms, max 15.311 ms (802 calls)
  - exchange: p50 6.9 ms, p99 12.6 ms, p99.9 14.136 ms, max 14.136 ms (360 calls)
  - filter_allow: p50 6.1 ms, p99 11.7 ms, p99.9 16.7 ms, max 18.012 ms (1973 calls)
  - issue: p50 6.8 ms, p99 13.3 ms, p99.9 16.663 ms, max 16.663 ms (600 calls)
  - revoke: p50 6.6 ms, p99 14.0 ms, p99.9 15.556 ms, max 15.556 ms (157 calls)
- Daemon RSS 15→17 MiB; peak CPU 118% of one core.
- Overload (target 3814 req/s): 773 req/s sustained, error rate 0.0%, p99 86 ms, wrong-allow 0.
- Soak 2000 decisions: audit 860 bytes/decision; state.json 107268→289268 bytes.
  - authorize p50 went 1.128→1.359 ms as state.json grew to 282 KiB (did not grow materially with state size)
  - audit_verify went 257.5→370.8 ms as the log grew to 15 MiB (recompute is linear in log size; keep the head hash and rotate the log)
- Correctness: engine allowed 200 spends, expected exactly 200 (over-allow 0); ledger 20000 of 20000 budget (from the audit log); audit chain valid; no lost decisions: True (Δ150 for 150 calls).

## php daemon

- Steady state (closed, 6 workers): **456 req/s**, error rate 0.00%, wrong-allow 0.
  - authorize_allow: p50 13.3 ms, p99 22.1 ms, p99.9 30.0 ms, max 30.908 ms (1729 calls)
  - authorize_deny: p50 11.5 ms, p99 22.8 ms, p99.9 28.028 ms, max 28.028 ms (344 calls)
  - exchange: p50 12.6 ms, p99 19.1 ms, p99.9 23.273 ms, max 23.273 ms (215 calls)
  - filter_allow: p50 13.6 ms, p99 21.8 ms, p99.9 25.473 ms, max 25.473 ms (959 calls)
  - issue: p50 12.7 ms, p99 21.4 ms, p99.9 23.158 ms, max 23.158 ms (321 calls)
  - revoke: p50 12.1 ms, p99 25.501 ms, p99.9 25.501 ms, max 25.501 ms (80 calls)
- Daemon RSS 39→39 MiB; peak CPU 100% of one core.
- Overload (target 1824 req/s): 412 req/s sustained, error rate 0.0%, p99 85 ms, wrong-allow 0.
- Soak 2000 decisions: audit 789 bytes/decision; state.json 56950→238950 bytes.
  - authorize p50 went 3.225→2.908 ms as state.json grew to 233 KiB (did not grow materially with state size)
  - audit_verify went 411.7→504.9 ms as the log grew to 8 MiB (recompute is linear in log size; keep the head hash and rotate the log)
- Correctness: engine allowed 200 spends, expected exactly 200 (over-allow 0); ledger 20000 of 20000 budget (from the audit log); audit chain valid; no lost decisions: True (Δ150 for 150 calls).

## java daemon

- Steady state (closed, 6 workers): **505 req/s**, error rate 0.00%, wrong-allow 0.
  - authorize_allow: p50 11.6 ms, p99 25.1 ms, p99.9 29.5 ms, max 30.819 ms (1926 calls)
  - authorize_deny: p50 10.4 ms, p99 19.9 ms, p99.9 28.784 ms, max 28.784 ms (383 calls)
  - exchange: p50 12.4 ms, p99 24.3 ms, p99.9 25.238 ms, max 25.238 ms (229 calls)
  - filter_allow: p50 11.8 ms, p99 27.8 ms, p99.9 32.0 ms, max 32.224 ms (1059 calls)
  - issue: p50 10.6 ms, p99 26.4 ms, p99.9 28.0 ms, max 28.0 ms (356 calls)
  - revoke: p50 9.1 ms, p99 23.793 ms, p99.9 23.793 ms, max 23.793 ms (87 calls)
- Daemon RSS 200→297 MiB; peak CPU 178% of one core.
- Overload (target 2020 req/s): 526 req/s sustained, error rate 0.0%, p99 87 ms, wrong-allow 0.
- Soak 2000 decisions: audit 797 bytes/decision; state.json 60299→242299 bytes.
  - authorize p50 went 2.466→3.069 ms as state.json grew to 236 KiB (did not grow materially with state size)
  - audit_verify went 145.7→143.3 ms as the log grew to 8 MiB (recompute is linear in log size; keep the head hash and rotate the log)
- Correctness: engine allowed 200 spends, expected exactly 200 (over-allow 0); ledger 20000 of 20000 budget (from the audit log); audit chain valid; no lost decisions: True (Δ150 for 150 calls).

## python http-proxy + upstream

- Steady state (closed, 6 workers, through the python proxy to PostgreSQL): **117 req/s**, error rate 0.00%, wrong-allow 0.
  - GET /customers (list): p50 53.0 ms, p99 111.6 ms, p99.9 117.163 ms, max 117.163 ms (453 calls)
  - GET /customers/{id}: p50 46.1 ms, p99 90.2 ms, p99.9 93.028 ms, max 93.028 ms (485 calls)
- Proxy RSS at the end 36 MiB.

## rust http-proxy + upstream

- Steady state (closed, 6 workers, through the rust proxy to PostgreSQL): **141 req/s**, error rate 0.00%, wrong-allow 0.
  - GET /customers (list): p50 43.7 ms, p99 94.9 ms, p99.9 113.897 ms, max 113.897 ms (542 calls)
  - GET /customers/{id}: p50 39.2 ms, p99 78.2 ms, p99.9 93.865 ms, max 93.865 ms (589 calls)
- Proxy RSS at the end 19 MiB.

## Large soak (authorize-driven, single client)

Each decision appends one audit record; `state.json` is grown with a budgeted issue + revoke every 20
decisions. 50,000 decisions on the reference (python), 200,000 on the daemon with the highest steady
throughput in the run above (go).

| daemon | decisions | dec/s | authorize p50 first→last (×) | state.json end | audit_verify first→last | log size | audit records | bytes/record |
|---|--:|--:|--|--:|--|--:|--:|--:|
| python | 50000 | 224 | 4.692→3.64 ms (×0.78) | 222 KiB | 1.3→1297.9 ms | 51.8 MiB | 55183 | 985 |
| go | 200000 | 318 | 1.189→1.446 ms (×1.22) | 889 KiB | 0.6→3839.9 ms | 207.0 MiB | 220183 | 986 |

`audit_verify` along the way: python 733 ms at 28 MiB, 1298 ms at 51.8 MiB; go 2170 ms at 112 MiB, 3840 ms at 207.0 MiB.

## What changed since the first run of this file (earlier the same day)

- **Rust.** The Rust daemon's HTTP server was replaced and Nagle is off (finding L-9). In the first run its
  `issue`, `exchange` and `filter` sat at 44–48 ms p50 and the mixed load made 226 req/s; now every operation
  is at 15–16 ms p50 under the same 6-way contention and the mix makes 371 req/s.
- **Java** has a daemon now and is measured (it had none).
- **The proxy path** is measured on both implementations, with the routes in their current form (a single
  record is one upstream call, answered from the lookup). The first run had 11% connection errors on this
  path; this one had none on either proxy.
- **Run-to-run variation on this machine is large.** The Python daemon, whose code did not change, made
  159 req/s in the first run and 341 req/s in this one (other work was running on the box then). Differences
  between daemons smaller than about a factor of two should not be read as real.

## Operational conclusions

Only where the numbers above support them.

- **Rotate the audit log; this is the scaling limit that showed.** `audit_verify` recomputes the whole chain
  and grew in step with the log: 1.3 s at 51.8 MiB (python,
  55183 records) and 3.8 s at 207.0 MiB (go,
  220183 records), about 25 and 19 ms per MiB. A decision record is about 1 KiB
  (985–986 bytes), so a daemon at 100 decisions/s writes roughly 8 GiB a day. A file rotated at
  50 MiB verified in about 1–1.3 s here and one of 100 MiB in about 2–2.5 s; keep the head hash of each
  closed file somewhere the writer cannot change (LIMITATIONS §12).
- **Per-request cost did not grow with `state.json` at these sizes.** authorize p50 went ×0.78 (python, to
  222 KiB) and ×1.22 (go, to 889 KiB) over the large soaks, although every decision
  re-reads the file (LIMITATIONS §13). Nothing here measures tens of MiB. The ledger and the user-revocation
  list are never pruned, so the file only grows: watch its size.
- **One daemon does not use more than about one core of engine work.** Peak CPU was 96–118% of one core for
  python, rust, node, go and php (178% for java, with its runtime threads), on two cores shared with six
  client processes. Steady throughput in this run: go 953, node 727, java 505, php 456, rust 371,
  python 341 req/s. More throughput needs more daemons on one state directory (the flock ports) or a split
  by tenant, not a bigger machine.
- **Memory.** 15–40 MiB resident for go, rust, python and php, about 100 MiB for node, 200–300 MiB for java,
  flat over the run except node (+14 MiB) and java (+97 MiB, a JVM still warming up in a 10 s run).
- **Overload is queueing, not failure, and never a wrong allow.** With 24 clients sending at four times the
  measured rate, every daemon kept its steady throughput (go fell from 953 to 773 req/s), answered every
  request, and p99 rose to 69–170 ms. In no phase, on no daemon or proxy, was a deny-expected request allowed;
  the budget test allowed exactly 200 of 320 concurrent spends on every daemon and the audit chain verified.
  The run did not push far enough to find where requests start to time out.
- **Through a proxy the upstream dominates.** A read through the proxy, the REST service and PostgreSQL took
  39–53 ms p50 (117 req/s through the Python proxy, 141 through the Rust one), against 6–18 ms for a bare
  decision.
