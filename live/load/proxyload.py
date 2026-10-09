"""The per-process worker for driving the HTTP proxy with the real upstream.
It lives in its own module (not in __main__) so the spawn start method can
import it into child processes."""
from __future__ import annotations

import random
import time

from .histogram import Hist
from .workload import TENANT
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from upstream.stack import http_request  # noqa: E402


def proxy_worker(cfg: dict) -> dict:
    h_read, h_list = Hist(), Hist()
    done = errs = 0
    series: dict = {}
    warm_until = cfg["t0"] + cfg["warmup"]
    end = warm_until + cfg["duration"]
    # records of the agent's own region: the route decides on the record's region, so the others are 403
    first = http_request("GET", f"{cfg['base']}/{TENANT}/customers?region=EU&limit=400", token=cfg["token"], timeout=60)
    ids = [c["id"] for c in ((first.json or {}).get("items") or [])] or ["c-00006"]
    rnd = random.Random(cfg["seed"])
    while time.monotonic() < end:
        s = time.monotonic()
        if rnd.random() < 0.5:
            r = http_request("GET", f"{cfg['base']}/{TENANT}/customers/{rnd.choice(ids)}", token=cfg["token"], timeout=30)
            h = h_read
        else:
            r = http_request("GET", f"{cfg['base']}/{TENANT}/customers?region=EU&limit=20", token=cfg["token"], timeout=30)
            h = h_list
        dur = (time.monotonic() - s) * 1000
        if s >= warm_until:
            if r.status == 200:
                h.add(dur)
                done += 1
                sec = int(s - warm_until)
                series[sec] = series.get(sec, 0) + 1
            else:
                errs += 1
    return {"read": h_read.to_tuple(), "list": h_list.to_tuple(), "done": done, "errors": errs, "series": series}
