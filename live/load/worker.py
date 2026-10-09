"""One load-generator process. It opens keep-alive HTTP connections to the
decision daemon (or to the HTTP proxy), repeats a weighted mix of operations
in open-loop (a target rate) or closed-loop (a fixed number of in-flight
calls) for a fixed time, and returns compact results: a latency histogram per
operation, error counts by type, the count of any deny-expected request that
was wrongly allowed, and per-second time series for throughput and latency.

The client is multi-process (run from __main__) so the generator's own GIL is
not the bottleneck. Nothing here retries: an answer that does not arrive is an
error to report, never something to send again.
"""
from __future__ import annotations

import http.client
import json
import random
import socket
import time
import urllib.parse

from .histogram import Hist
from .workload import build_setup, op_request

DAEMON_ROUTES = {
    "authorize": ("POST", "/v1/authorize", "pep"), "filter": ("POST", "/v1/filter", "pep"),
    "issue_token": ("POST", "/v1/token", "admin"), "exchange_token": ("POST", "/v1/token", None),
    "revoke": ("POST", "/v1/admin/revoke", "admin"), "approve": ("POST", "/v1/admin/approve", "admin"),
}


class Conn:
    """A keep-alive HTTP/1.1 connection that reconnects on a dropped socket."""

    def __init__(self, url: str, timeout: float):
        u = urllib.parse.urlsplit(url)
        self.host, self.port, self.base = u.hostname, u.port or 80, u.path.rstrip("/")
        self.timeout = timeout
        self.c = None

    def _connect(self):
        self.c = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        self.c.connect()
        # measure the server, not the client's Nagle stall: a request with a
        # body goes out in two writes, and without this the kernel holds the
        # second for the peer's delayed ACK (~40 ms). The daemon disables Nagle
        # on its side; the load client must too.
        self.c.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def request(self, method: str, path: str, headers: dict, body: bytes | None) -> tuple:
        """-> (status, raw) or raises OSError/HTTPException."""
        if self.c is None:
            self._connect()
        try:
            self.c.request(method, self.base + path, body=body, headers=headers)
            r = self.c.getresponse()
            return r.status, r.read()
        except (OSError, http.client.HTTPException):
            try:
                self.c.close()
            except OSError:
                pass
            self.c = None
            raise

    def close(self):
        if self.c is not None:
            try:
                self.c.close()
            except OSError:
                pass


def classify_error(status: int, raw: bytes) -> str:
    try:
        doc = json.loads(raw)
    except ValueError:
        return f"http_{status}_non_json"
    if isinstance(doc, dict) and isinstance(doc.get("error"), dict):
        return "err_" + str(doc["error"].get("code", "unknown"))
    return f"http_{status}"


def run_worker(cfg: dict) -> dict:
    """cfg: url, admin_key, pep_key, duration, warmup, mode, rate|concurrency,
    mix, timeout, t0 (shared start), seed."""
    rnd = random.Random(cfg["seed"])
    keys = {"admin": cfg["admin_key"], "pep": cfg["pep_key"] or cfg["admin_key"], None: None}
    conn = Conn(cfg["url"], cfg["timeout"])

    def call(op: str, payload: dict) -> dict:
        method, path, kind = DAEMON_ROUTES[op]
        headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
        if keys[kind]:
            headers["Authorization"] = f"Bearer {keys[kind]}"
        try:
            status, raw = conn.request(method, path, headers, json.dumps(payload).encode())
            return json.loads(raw)
        except (OSError, http.client.HTTPException, ValueError) as e:
            return {"ok": False, "error": {"code": "transport", "message": str(e)}}

    tokens = build_setup(call)
    ops = list(cfg["mix"])
    weights = [cfg["mix"][o] for o in ops]

    hists = {o: Hist() for o in ops}
    errors: dict = {}
    wrong_allow = 0
    series: dict = {}      # second -> [count, lat_sum, lat_max]
    done = 0

    t0 = cfg["t0"]
    warm_until = t0 + cfg["warmup"]
    end = t0 + cfg["warmup"] + cfg["duration"]
    mode, timeout = cfg["mode"], cfg["timeout"]
    interval = 1.0 / cfg["rate"] if mode == "open" else 0.0
    next_send = t0

    # closed-loop: one in-flight call per worker (processes give the parallelism)
    while True:
        now = time.monotonic()
        if now >= end:
            break
        if mode == "open":
            if now < next_send:
                time.sleep(min(next_send - now, 0.01))
                continue
            next_send += interval
            if next_send < now - 0.5:       # fell behind: do not try to catch up unboundedly
                next_send = now
        op = rnd.choices(ops, weights)[0]
        engine_op, payload, expect = op_request(op, tokens)
        s = time.monotonic()
        result = call(engine_op, payload)
        dur = (time.monotonic() - s) * 1000.0
        warm = s < warm_until
        ok = result.get("ok") is True
        allowed = ok and (result.get("effect") == "allow" if engine_op in ("authorize", "filter") else True)
        if expect == "deny" and allowed:
            wrong_allow += 1
        if not warm:
            hists[op].add(dur)
            done += 1
            sec = int(s - warm_until)
            slot = series.setdefault(sec, [0, 0.0, 0.0])
            slot[0] += 1
            slot[1] += dur
            slot[2] = max(slot[2], dur)
            if not ok:
                code = classify_error(0, json.dumps(result).encode())
                errors[code] = errors.get(code, 0) + 1
            elif engine_op in ("authorize", "filter") and result.get("effect") != "allow" and expect == "allow":
                errors["unexpected_deny_" + str(result.get("reason"))] = errors.get("unexpected_deny_" + str(result.get("reason")), 0) + 1
    conn.close()
    return {"hists": {o: h.to_tuple() for o, h in hists.items()}, "errors": errors, "wrong_allow": wrong_allow,
            "done": done, "series": series, "support_id": tokens["support_id"]}
