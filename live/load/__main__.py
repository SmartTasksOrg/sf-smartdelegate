"""SmartDelegate load and soak.

    python3 -m live.load [options]

Targets (what to drive):
  --targets python,rust,node,go,php,java   decision daemons this harness starts (default: python,rust)
  --url URL                           a daemon someone else runs (SD_ADMIN_KEY / SD_PEP_KEY)
  --proxy python[,rust]               also drive the HTTP proxy with the real upstream of part A

Load shape:
  --mode open|closed      open-loop at --rate, or closed-loop with --procs busy clients (default closed)
  --rate N                target requests/second for open-loop and overload
  --procs N               worker processes (default: number of CPUs; the client is multi-process)
  --duration S            steady-state seconds (default 20)
  --warmup S              warm-up seconds, not measured (default 3)
  --soak N                decisions to drive in the soak (default 50000; 0 to skip)
  --quick                 a short run: duration 4, warmup 1, soak 3000, overload off by default

Output:
  --out DIR               where report.json/report.md/report.html go (default: a temp dir, path printed)
  --results-md PATH       also write a dated RESULTS.md with these numbers
  --check thresholds.json exit non-zero when error rate / wrong-allow / p99 exceed the thresholds (CI)

Everything this starts is stopped by PID; temporary state directories are removed.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import statistics
import sys
import tempfile
import threading
import time
from datetime import date
from pathlib import Path

from . import report as report_mod
from .daemons import Daemon
from .histogram import Hist
from .worker import run_worker
from .workload import COMPANY, DEFAULT_MIX, TENANT

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "live"))
from upstream.stack import DaemonApi, Stack, Unavailable, http_request  # noqa: E402

MACHINE = "2 cores, 8 GB; client and server on the same machine: indicative only"


def merge(results: list, duration: float) -> dict:
    ops = sorted({o for r in results for o in r["hists"]})
    per_op = {}
    for o in ops:
        h = Hist()
        for r in results:
            if o in r["hists"]:
                h.merge(Hist.from_tuple(r["hists"][o]))
        per_op[o] = h.summary()
    errors: dict = {}
    for r in results:
        for k, v in r["errors"].items():
            errors[k] = errors.get(k, 0) + v
    done = sum(r["done"] for r in results)
    wrong = sum(r["wrong_allow"] for r in results)
    secs = {}
    for r in results:
        for sec, (c, lsum, lmax) in r["series"].items():
            a = secs.setdefault(int(sec), [0, 0.0, 0.0])
            a[0] += c
            a[1] += lsum
            a[2] = max(a[2], lmax)
    tput = [(s, secs[s][0]) for s in sorted(secs) if s >= 0]
    lat = [(s, secs[s][1] / secs[s][0]) for s in sorted(secs) if s >= 0 and secs[s][0]]
    latmax = [(s, secs[s][2]) for s in sorted(secs) if s >= 0]
    return {"per_op": per_op, "errors_by_type": errors, "errors_total": sum(errors.values()), "wrong_allow": wrong,
            "throughput_rps": done / duration if duration else 0, "count": done,
            "throughput_series": tput, "latency_series": lat, "latency_max_series": latmax}


def run_phase(daemon_url: str, admin_key: str, pep_key: str, *, mode: str, rate: float, procs: int, duration: float,
              warmup: float, mix: dict, sampler=None, timeout: float = 30.0) -> dict:
    ctx = mp.get_context("spawn")
    t0 = time.monotonic() + 0.5
    cfgs = [{"url": daemon_url, "admin_key": admin_key, "pep_key": pep_key, "duration": duration, "warmup": warmup,
             "mode": mode, "rate": rate / procs, "concurrency": 1, "mix": mix, "timeout": timeout, "t0": t0, "seed": 1000 + i}
            for i in range(procs)]
    with ctx.Pool(procs) as pool:
        async_res = pool.starmap_async(run_worker, [(c,) for c in cfgs])
        if sampler:
            sampler.start(t0 + warmup)
        results = async_res.get()
        if sampler:
            sampler.stop()
    return merge(results, duration)


class ResourceSampler:
    def __init__(self, daemon: Daemon, every: float = 0.5):
        self.daemon, self.every = daemon, every
        self.samples, self._stop, self._thread, self._from = [], threading.Event(), None, None

    def start(self, from_time: float):
        self._from = from_time
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        prev = None
        while not self._stop.is_set():
            s = self.daemon.sample()
            now = time.monotonic()
            if s:
                rec = {"t": round(now - self._from, 2), "rss_kib": s["rss_kib"]}
                if prev:
                    dt = now - prev[0]
                    if dt > 0:
                        rec["cpu_pct"] = round((s["cpu_s"] - prev[1]) / dt * 100, 1)
                prev = (now, s["cpu_s"])
                if rec["t"] >= -0.5:
                    self.samples.append(rec)
            self._stop.wait(self.every)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def result(self) -> dict:
        return {"series": self.samples, "peak_cpu_pct": max((x.get("cpu_pct", 0) for x in self.samples), default=0),
                "peak_rss_kib": max((x["rss_kib"] for x in self.samples), default=0)}


def correctness(api: DaemonApi) -> dict:
    """Budget is enforced exactly under concurrency; the ledger equals what was
    allowed; the audit chain stays valid; no decision is lost. A dedicated
    token (budget 20000 EUR) is hit by many threads sending 100-unit spends;
    exactly budget/amount must be allowed and never one more, whatever the
    interleaving. Each thread stops on the first budget_exceeded, so no answer
    is dropped to a connection storm."""
    import queue
    g = api.call("issue_token", {"user": "anna", "agent": "support-orchestrator", "role": "support-agent", "task": "ticket-correct", "tenant": TENANT})
    token, budget, amount = g["token"], 20000, 100
    expected = budget // amount
    counts = {"allow": 0, "budget_exceeded": 0, "transport": 0, "other": 0}
    over = [0]
    lock = threading.Lock()
    work = queue.Queue()
    for i in range(expected + 120):     # more attempts than the budget can satisfy
        work.put(i)

    def spender():
        while True:
            try:
                i = work.get_nowait()
            except queue.Empty:
                return
            r = api.call("authorize", {"token": token, "action": "create", "resource": {"path": "billing.refund", "id": f"r-{i}", "attrs": {"tenant": TENANT, "region": "EU"}},
                                       "context": {"spend": {"currency": "EUR", "amount": amount}}})
            with lock:
                if r.get("effect") == "allow":
                    counts["allow"] += 1
                elif r.get("reason") == "budget_exceeded":
                    counts["budget_exceeded"] += 1
                elif (r.get("error") or {}).get("code") == "transport":
                    counts["transport"] += 1
                else:
                    counts["other"] += 1
    threads = [threading.Thread(target=spender) for _ in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    # Ground truth is the engine's own audit log, not the client's view: a spend
    # whose HTTP answer was lost in transit was still charged, and the log shows
    # it. Sum every allowed billing.refund decision charged to this token.
    tid = g["token_id"]
    tail = api.call("audit_tail", {"n": (expected + 300) * 2}).get("records", [])
    charged = [r for r in tail if r.get("event") == "decision" and r.get("token_id") == tid and r.get("effect") == "allow" and (r.get("spend") or {}).get("currency") == "EUR"]
    engine_allowed = len(charged)
    engine_charged = sum(r["spend"]["amount"] for r in charged)
    over_allow = max(0, engine_charged - budget)
    # no lost decisions: K sequential authorizes grow the audit log by exactly K
    before = api.call("audit_verify").get("records", 0)
    k = 150
    for i in range(k):
        api.call("authorize", {"token": token, "action": "read", "resource": {"path": "crm.customer", "id": f"c-{i}", "attrs": {"tenant": TENANT, "region": "EU"}}})
    after = api.call("audit_verify")
    return {"attempts": expected + 120, "allowed": counts["allow"], "client_counts": counts,
            "engine_allowed": engine_allowed, "expected_allowed": expected, "over_allow": over_allow,
            "ledger": engine_charged, "expected_ledger": budget,
            "budget_exact": engine_allowed == expected and engine_charged == budget and over_allow == 0,
            "audit_valid": bool(after.get("ok")),
            "records_delta": after.get("records", 0) - before, "lost_check_k": k,
            "no_lost_decisions": after.get("records", 0) - before == k}


def soak(daemon: Daemon, api: DaemonApi, decisions: int) -> dict:
    """Drive `decisions` state-changing operations; watch audit growth, state.json
    growth and whether a fixed authorize gets slower as state grows."""
    g = api.call("issue_token", {"user": "anna", "agent": "support-orchestrator", "role": "support-agent", "task": "ticket-soak", "tenant": TENANT})
    probe = {"token": g["token"], "action": "read", "resource": {"path": "crm.customer", "id": "c-soak", "attrs": {"tenant": TENANT, "region": "EU"}}}
    state_start = daemon.state_bytes()
    checkpoints = max(6, decisions // 2000)
    step = max(1, decisions // checkpoints)
    lat_vs_state, verify_vs_size = [], []
    t_start = time.monotonic()
    for i in range(decisions):
        # a budgeted token (adds to `limits`) and a revoke (adds to `revoked`): state grows, never pruned within the day
        issued = api.call("issue_token", {"user": "anna", "agent": "support-orchestrator", "role": "support-agent", "task": "ticket-soak", "tenant": TENANT})
        api.call("revoke", {"token_id": issued.get("token_id", f"x-{i}")})
        if i % step == 0 or i == decisions - 1:
            samples = sorted((api_time(api, probe) for _ in range(5)))
            v0 = time.monotonic()
            v = api.call("audit_verify")
            vt = (time.monotonic() - v0) * 1000
            lat_vs_state.append((daemon.state_bytes() / 1024, round(statistics.median(samples), 3)))
            verify_vs_size.append((daemon.audit_bytes() / (1024 * 1024), round(vt, 1)))
    elapsed = time.monotonic() - t_start
    v = api.call("audit_verify")
    records = v.get("records", 0)
    first_lat = lat_vs_state[0][1] if lat_vs_state else 0
    last_lat = lat_vs_state[-1][1] if lat_vs_state else 0
    growth = (last_lat / first_lat) if first_lat else 1
    verdict = (f"authorize p50 went {first_lat:.3f}→{last_lat:.3f} ms as state.json grew to {daemon.state_bytes()//1024} KiB "
               f"({'grows with state size — every call re-reads state.json (LIMITATIONS §13)' if growth > 1.5 else 'did not grow materially with state size'})")
    vfirst = verify_vs_size[0][1] if verify_vs_size else 0
    vlast = verify_vs_size[-1][1] if verify_vs_size else 0
    return {"decisions": decisions, "rate_per_s": round(decisions * 2 / elapsed, 0), "records": records,
            "audit_bytes": daemon.audit_bytes(), "audit_bytes_per_decision": daemon.audit_bytes() / records if records else 0,
            "state_start_bytes": state_start, "state_end_bytes": daemon.state_bytes(),
            "latency_vs_state": lat_vs_state, "verify_vs_size": verify_vs_size,
            "state_growth_verdict": verdict, "growth_ratio": round(growth, 2),
            "verify_verdict": f"audit_verify went {vfirst:.1f}→{vlast:.1f} ms as the log grew to {daemon.audit_bytes()//(1024*1024)} MiB "
                              f"(recompute is linear in log size; keep the head hash and rotate the log)"}


def api_time(api: DaemonApi, payload: dict) -> float:
    s = time.monotonic()
    api.call("authorize", payload)
    return (time.monotonic() - s) * 1000


def big_soak(daemon, api: DaemonApi, n: int) -> dict:
    """A large soak: drive `n` authorize decisions (each appends one audit
    record), growing state.json every so often with a budgeted issue + a
    revoke, and checkpoint authorize p50, audit_verify time and the file
    sizes. This answers two documented concerns at scale: whether a request's
    cost grows as state.json grows (LIMITATIONS §13) and how audit_verify time
    grows with the log (LIMITATIONS §12)."""
    g = api.call("issue_token", {"user": "anna", "agent": "support-orchestrator", "role": "support-agent", "task": "ticket-big", "tenant": TENANT})
    probe = {"token": g["token"], "action": "read", "resource": {"path": "crm.customer", "id": "c-big", "attrs": {"tenant": TENANT, "region": "EU"}}}
    grow_every = 20
    checkpoints = 24
    step = max(1, n // checkpoints)
    lat_vs_state, verify_vs_size = [], []
    t_start = time.monotonic()
    for i in range(n):
        api.call("authorize", probe)
        if i % grow_every == 0:
            issued = api.call("issue_token", {"user": "anna", "agent": "support-orchestrator", "role": "support-agent", "task": "ticket-big", "tenant": TENANT})
            api.call("revoke", {"token_id": issued.get("token_id", f"x-{i}")})
        if i % step == 0 or i == n - 1:
            samples = sorted(api_time(api, probe) for _ in range(7))
            v0 = time.monotonic(); v = api.call("audit_verify"); vt = (time.monotonic() - v0) * 1000
            lat_vs_state.append((round(daemon.state_bytes() / 1024, 1), round(statistics.median(samples), 3)))
            verify_vs_size.append((round(daemon.audit_bytes() / (1024 * 1024), 2), round(vt, 1)))
    elapsed = time.monotonic() - t_start
    v = api.call("audit_verify"); records = v.get("records", 0)
    first, last = lat_vs_state[0][1], lat_vs_state[-1][1]
    growth = last / first if first else 1
    return {"decisions": n, "elapsed_s": round(elapsed, 1), "decisions_per_s": round(n / elapsed, 0), "records": records,
            "audit_bytes": daemon.audit_bytes(), "audit_mib": round(daemon.audit_bytes() / (1024 * 1024), 1),
            "audit_bytes_per_decision": round(daemon.audit_bytes() / records, 1) if records else 0,
            "state_start_kib": lat_vs_state[0][0], "state_end_kib": lat_vs_state[-1][0],
            "authorize_p50_first_ms": first, "authorize_p50_last_ms": last, "growth_ratio": round(growth, 2),
            "audit_verify_first_ms": verify_vs_size[0][1], "audit_verify_last_ms": verify_vs_size[-1][1],
            "latency_vs_state": lat_vs_state, "verify_vs_size": verify_vs_size}


def drive_target(name: str, make_daemon, args) -> dict:
    daemon = make_daemon()
    try:
        api = DaemonApi(daemon.url, daemon.admin_key, daemon.pep_key)
        deadline = time.monotonic() + 30
        while not api.healthy():
            if time.monotonic() > deadline:
                raise RuntimeError(f"{name} does not answer /healthz")
            time.sleep(0.05)
        sampler = ResourceSampler(daemon) if hasattr(daemon, "sample") else None
        steady = run_phase(daemon.url, daemon.admin_key, daemon.pep_key, mode=args.mode, rate=args.rate, procs=args.procs,
                           duration=args.duration, warmup=args.warmup, mix=DEFAULT_MIX, sampler=sampler)
        out = {"mode": f"{args.mode}, {args.procs} workers" + (f", target {args.rate:.0f} rps" if args.mode == "open" else ""),
               "steady": steady}
        if sampler:
            out["resources"] = sampler.result()
        if args.overload:
            # oversubscribe: many more concurrent clients than the daemon has
            # worker threads, each with a short deadline, so a daemon that cannot
            # keep up must queue, time out or error rather than wrongly allow.
            o_procs = min(32, max(16, args.procs * 4))
            o_rate = args.overload_rate or steady["throughput_rps"] * 4 or 2000
            over = run_phase(daemon.url, daemon.admin_key, daemon.pep_key, mode="open", rate=o_rate, procs=o_procs,
                             duration=max(4, int(args.duration // 2)), warmup=1, mix=DEFAULT_MIX, timeout=3)
            out["overload"] = {"target_rps": o_rate, "clients": o_procs, "throughput_rps": over["throughput_rps"],
                               "error_rate": over["errors_total"] / max(1, over["count"] + over["errors_total"]),
                               "p99_ms": max((s["p99_ms"] for s in over["per_op"].values()), default=0), "wrong_allow": over["wrong_allow"],
                               "errors_by_type": over["errors_by_type"]}
        out["correctness"] = correctness(api)
        if args.soak:
            out["soak"] = soak(daemon, api, args.soak)
        return out
    finally:
        daemon.close()


def check_thresholds(report: dict, path: Path) -> int:
    th = json.loads(Path(path).read_text(encoding="utf-8"))
    problems = []
    for tname, t in report["targets"].items():
        if "skipped" in t:
            print(f"thresholds: {tname} skipped ({t['skipped']})", file=sys.stderr)
            continue
        st = t["steady"]
        rate = st["errors_total"] / max(1, st["count"] + st["errors_total"])
        if rate > th["max_error_rate"]:
            problems.append(f"{tname}: steady error rate {rate:.3f} > {th['max_error_rate']}")
        if st["wrong_allow"] > th["max_wrong_allow"]:
            problems.append(f"{tname}: wrong-allow {st['wrong_allow']} > {th['max_wrong_allow']}")
        hot = st["per_op"].get(th.get("p99_op", "authorize_allow"))
        if hot and hot["p99_ms"] > th["max_p99_ms"]:
            problems.append(f"{tname}: {th.get('p99_op')} p99 {hot['p99_ms']} ms > {th['max_p99_ms']} ms")
        if t.get("overload") and t["overload"]["wrong_allow"] > th["max_wrong_allow"]:
            problems.append(f"{tname}: wrong-allow under overload {t['overload']['wrong_allow']}")
        if t.get("correctness"):
            c = t["correctness"]
            if c.get("over_allow", 0) > 0 or not c["budget_exact"] or not c["audit_valid"] or not c["no_lost_decisions"]:
                problems.append(f"{tname}: correctness failed ({c})")
    for p in problems:
        print("THRESHOLD FAIL:", p, file=sys.stderr)
    print(("thresholds: all targets within limits" if not problems else f"thresholds: {len(problems)} breach(es)"), file=sys.stderr)
    return 1 if problems else 0


def main(argv=None) -> int:
    import signal
    # SIGTERM (run.sh on Ctrl-C, a CI timeout) unwinds like Ctrl-C: pools are terminated and daemons stopped by PID
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    ap = argparse.ArgumentParser(prog="python3 -m live.load", description=__doc__.split("\n")[0])
    ap.add_argument("--targets", default="python,rust")
    ap.add_argument("--url")
    ap.add_argument("--proxy", nargs="?", const="python", default=None)
    ap.add_argument("--mode", choices=["open", "closed"], default="closed")
    ap.add_argument("--rate", type=float, default=4000)
    ap.add_argument("--procs", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--warmup", type=float, default=3)
    ap.add_argument("--soak", type=int, default=50000)
    ap.add_argument("--overload", action="store_true")
    ap.add_argument("--overload-rate", type=float, default=0)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--results-md")
    ap.add_argument("--check")
    ap.add_argument("--big-soak", type=int, default=0, help="run only a large authorize-driven soak of N decisions per target and append to --results-md")
    a = ap.parse_args(argv)
    if a.quick:
        a.duration, a.warmup, a.soak = min(a.duration, 4), min(a.warmup, 1), min(a.soak, 3000) if a.soak else 0
    report = {"meta": {"dated": date.today().isoformat(), "machine": MACHINE,
                       "note": "The upstream is a real PostgreSQL database and a real separate process we wrote; client and server share one small machine, so treat throughput as indicative, not a datasheet.",
                       "config": {"mode": a.mode, "procs": a.procs, "rate": a.rate, "duration": a.duration, "warmup": a.warmup, "soak": a.soak, "overload": a.overload}},
              "targets": {}}
    targets = [t for t in a.targets.split(",") if t] if not a.url else []

    if a.big_soak:
        soaks = {}
        for port in targets:
            try:
                d = Daemon(port)
            except (Unavailable, RuntimeError) as e:
                soaks[port] = {"skipped": str(e)}; continue
            try:
                api = DaemonApi(d.url, d.admin_key, d.pep_key)
                deadline = time.monotonic() + 30
                while not api.healthy():
                    if time.monotonic() > deadline:
                        raise RuntimeError("no /healthz")
                    time.sleep(0.05)
                soaks[port] = big_soak(d, api, a.big_soak)
            finally:
                d.close()
            print(f"{port}: {soaks[port].get('decisions')} decisions in {soaks[port].get('elapsed_s')} s "
                  f"({soaks[port].get('decisions_per_s')}/s); authorize p50 {soaks[port].get('authorize_p50_first_ms')}->{soaks[port].get('authorize_p50_last_ms')} ms "
                  f"(x{soaks[port].get('growth_ratio')}) as state grew to {soaks[port].get('state_end_kib')} KiB; "
                  f"audit_verify {soaks[port].get('audit_verify_first_ms')}->{soaks[port].get('audit_verify_last_ms')} ms over {soaks[port].get('audit_mib')} MiB", file=sys.stderr)
        if a.results_md:
            append_big_soak(Path(a.results_md), soaks)
        print(json.dumps(soaks, indent=2, default=str))
        return 0

    stack = None
    try:
        for port in targets:
            try:
                report["targets"][f"{port} daemon"] = drive_target(port, lambda p=port: Daemon(p), a)
            except (Unavailable, RuntimeError) as e:
                report["targets"][f"{port} daemon"] = {"skipped": str(e), "steady": {"per_op": {}, "errors_by_type": {}, "errors_total": 0, "wrong_allow": 0, "throughput_rps": 0, "count": 0, "throughput_series": [], "latency_series": [], "latency_max_series": []}}
        if a.url:
            class Attached:
                url, admin_key, pep_key = a.url, os.environ.get("SD_ADMIN_KEY", ""), os.environ.get("SD_PEP_KEY", "")
                def sample(self): return None
                def state_bytes(self): return 0
                def audit_bytes(self): return 0
                def close(self): pass
            report["targets"][f"url {a.url}"] = drive_target("url", Attached, a)
        for impl in [x for x in (a.proxy or "").split(",") if x]:
            try:
                report["targets"][f"{impl} http-proxy + upstream"] = drive_proxy(a, impl)
            except Exception as e:  # one phase must never lose the daemon results
                report["targets"][f"{impl} http-proxy + upstream"] = {"skipped": f"{type(e).__name__}: {e}", "steady": {"per_op": {}, "errors_by_type": {}, "errors_total": 0, "wrong_allow": 0, "throughput_rps": 0, "count": 0, "throughput_series": [], "latency_series": [], "latency_max_series": []}}
    finally:
        pass

    out = Path(a.out) if a.out else Path(tempfile.mkdtemp(prefix="smartdelegate-load-report-"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    report_mod.write_markdown(report, out / "report.md")
    report_mod.write_html(report, out / "report.html")
    print(f"load report: {out}/report.json | report.md | report.html", file=sys.stderr)
    if a.results_md:
        write_results_md(report, Path(a.results_md))
    if report["targets"] and all("skipped" in t for t in report["targets"].values()):
        for name, t in report["targets"].items():
            print(f"SKIPPED: {name}: {t['skipped']}", file=sys.stderr)
        return 3
    rc = 0
    if a.check:
        rc = check_thresholds(report, Path(a.check))
    return rc


def drive_proxy(a, impl: str) -> dict:
    """Steady load through the HTTP proxy and the real upstream of part A."""
    from .histogram import Hist
    from .proxyload import proxy_worker
    try:
        stack = Stack(impl)
    except Unavailable as e:
        return {"skipped": str(e), "steady": {"per_op": {}, "errors_by_type": {}, "errors_total": 0, "wrong_allow": 0, "throughput_rps": 0, "count": 0, "throughput_series": [], "latency_series": [], "latency_max_series": []}}
    try:
        token = stack.issue("anna", "support-agent", "ticket-proxy")["token"]
        ctx = mp.get_context("spawn")
        duration = a.duration
        t0 = time.monotonic() + 0.5
        cfgs = [{"base": stack.proxy_url + "/company", "token": token, "duration": duration, "warmup": a.warmup, "t0": t0, "seed": i} for i in range(a.procs)]
        with ctx.Pool(a.procs) as pool:
            results = pool.map(proxy_worker, cfgs)
        h_read, h_list = Hist(), Hist()
        done = errs = 0
        secs = {}
        for r in results:
            h_read.merge(Hist.from_tuple(r["read"]))
            h_list.merge(Hist.from_tuple(r["list"]))
            done += r["done"]
            errs += r["errors"]
            for s, c in r["series"].items():
                secs[s] = secs.get(s, 0) + c
        steady = {"per_op": {"GET /customers/{id}": h_read.summary(), "GET /customers (list)": h_list.summary()},
                  "errors_by_type": {"transport_or_non_200": errs} if errs else {}, "errors_total": errs, "wrong_allow": 0,
                  "throughput_rps": done / duration, "count": done,
                  "throughput_series": [(s, secs[s]) for s in sorted(secs) if s >= 0], "latency_series": [], "latency_max_series": []}
        res = {}
        if stack.proxy_proc is not None:
            res = {"proxy_rss_kib_end": _rss_kib(stack.proxy_proc.pid)}
        return {"mode": f"closed, {a.procs} workers, through the {impl} proxy to PostgreSQL", "steady": steady, **res,
                "note": "each request is proxy decision + upstream HTTP + a real SQL read + field masking"}
    finally:
        stack.close()


def _rss_kib(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") // 1024
    except (OSError, ValueError, IndexError):
        return 0


def write_results_md(report: dict, path: Path) -> None:
    L = [f"# Load and soak results — {report['meta']['dated']}", "",
         f"Measured on this machine: **{report['meta']['machine']}**.", "",
         "These are indicative numbers from one small shared host, not a datasheet. "
         "Run `live/run.sh load` to reproduce; `python3 -m live.load --help` for options.", ""]
    for tname, t in report["targets"].items():
        if "skipped" in t:
            L += [f"## {tname}", "", f"skipped: {t['skipped']}", ""]
            continue
        st = t["steady"]
        if t.get("proxy_rss_kib_end"):
            t.setdefault("note_lines", []).append(f"- Proxy RSS at the end {t['proxy_rss_kib_end']//1024} MiB.")
        L += [f"## {tname}", "", f"- Steady state ({t.get('mode','')}): **{st['throughput_rps']:.0f} req/s**, "
              f"error rate {st['errors_total']/max(1,st['count']+st['errors_total'])*100:.2f}%, wrong-allow {st['wrong_allow']}."]
        for op, s in sorted(st["per_op"].items()):
            L.append(f"  - {op}: p50 {s['p50_ms']} ms, p99 {s['p99_ms']} ms, p99.9 {s['p99_9_ms']} ms, max {s['max_ms']} ms ({s['count']} calls)")
        r = t.get("resources", {})
        if r.get("series"):
            L.append(f"- Daemon RSS {r['series'][0]['rss_kib']//1024}→{r.get('peak_rss_kib',0)//1024} MiB; peak CPU {r.get('peak_cpu_pct',0):.0f}% of one core.")
        if t.get("overload"):
            o = t["overload"]
            L.append(f"- Overload (target {o['target_rps']:.0f} req/s): {o['throughput_rps']:.0f} req/s sustained, error rate {o['error_rate']*100:.1f}%, p99 {o['p99_ms']:.0f} ms, wrong-allow {o['wrong_allow']}.")
        if t.get("soak"):
            s = t["soak"]
            L.append(f"- Soak {s['decisions']} decisions: audit {s['audit_bytes_per_decision']:.0f} bytes/decision; state.json {s['state_start_bytes']}→{s['state_end_bytes']} bytes.")
            L.append(f"  - {s['state_growth_verdict']}")
            L.append(f"  - {s['verify_verdict']}")
        L += t.get("note_lines", [])
        if t.get("correctness"):
            c = t["correctness"]
            L.append(f"- Correctness: engine allowed {c['engine_allowed']} spends, expected exactly {c['expected_allowed']} (over-allow {c['over_allow']}); ledger {c['ledger']} of {c['expected_ledger']} budget (from the audit log); audit chain {'valid' if c['audit_valid'] else 'BROKEN'}; no lost decisions: {c['no_lost_decisions']} (Δ{c['records_delta']} for {c['lost_check_k']} calls).")
        L.append("")
    path.write_text("\n".join(L), encoding="utf-8")


def append_big_soak(path: Path, soaks: dict) -> None:
    lines = ["", "## Large soak (authorize-driven, single client)", "",
             "Each decision appends one audit record; state.json is grown with a budgeted issue+revoke every 20 decisions. "
             "Shows whether per-request cost tracks state size (LIMITATIONS §13) and how audit_verify scales with the log (§12).", "",
             "| daemon | decisions | dec/s | authorize p50 first→last (×) | state.json end | audit_verify first→last | log size |",
             "|---|--:|--:|--|--:|--|--:|"]
    for port, s in soaks.items():
        if "skipped" in s:
            lines.append(f"| {port} | skipped: {s['skipped'][:40]} | | | | | |"); continue
        lines.append(f"| {port} | {s['decisions']} | {s['decisions_per_s']:.0f} | {s['authorize_p50_first_ms']}→{s['authorize_p50_last_ms']} ms (×{s['growth_ratio']}) | "
                     f"{s['state_end_kib']:.0f} KiB | {s['audit_verify_first_ms']}→{s['audit_verify_last_ms']} ms | {s['audit_mib']} MiB |")
    lines.append("")
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
