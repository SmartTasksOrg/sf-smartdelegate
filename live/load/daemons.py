"""Start a decision daemon of any port for the load test, with the
command lines of live/launchers.py, and sample its resource use from
/proc. Everything started is stopped by PID; the temporary state directory is
removed. Nothing is written into the repository.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "live"))
from launchers import launcher, available_ports  # noqa: E402
from upstream.stack import die_with_parent, record_pid  # noqa: E402

COMPANY = ROOT / "examples" / "company"
CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")


class Daemon:
    def __init__(self, port: str, config: dict | None = None):
        self.port = port
        self.dir = Path(tempfile.mkdtemp(prefix=f"smartdelegate-load-{port}-"))
        self.state_dir = self.dir / "state"
        self.admin_key, self.pep_key = secrets.token_hex(20), secrets.token_hex(20)
        cfg = {"bundle_dir": str(COMPANY), "state_dir": str(self.state_dir), "issuer": "smartdelegate://load", "mode": "enforce",
               "max_depth": 3, "admin_key": self.admin_key, "pep_key": self.pep_key}
        cfg.update(config or {})
        self.cfg_path = self.dir / "smartdelegate.json"
        self.cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
        argv, env = launcher(port, self.dir)
        self.proc = subprocess.Popen([*argv, "serve", "--config", str(self.cfg_path), "--listen", "127.0.0.1:0"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env={**os.environ, **env}, cwd=str(self.dir), preexec_fn=die_with_parent)
        record_pid(self.proc.pid)
        try:
            self.url = self._wait_url()
        except BaseException:
            self.close()
            raise

    def _wait_url(self, timeout: float = 60.0) -> str:
        seen, deadline = [], time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self.proc.stderr.readline()
            if line:
                seen.append(line)
                m = re.search(r"http://(\S+)", line)
                if m:
                    threading.Thread(target=self._drain, daemon=True).start()
                    return "http://" + m.group(1)
            if self.proc.poll() is not None:
                break
        raise RuntimeError(f"{self.port} daemon did not start: {''.join(seen)[-800:]}")

    def _drain(self):
        try:
            for _ in self.proc.stderr:
                pass
        except (OSError, ValueError):
            pass

    def sample(self) -> dict | None:
        """RSS in KiB and total CPU seconds of the daemon process."""
        try:
            with open(f"/proc/{self.proc.pid}/stat", "rb") as f:
                parts = f.read().split(b") ", 1)[1].split()
            utime, stime = int(parts[11]), int(parts[12])
            with open(f"/proc/{self.proc.pid}/statm", "rb") as f:
                rss_pages = int(f.read().split()[1])
            return {"cpu_s": (utime + stime) / CLK_TCK, "rss_kib": rss_pages * PAGE // 1024}
        except (OSError, IndexError, ValueError):
            return None

    def audit_bytes(self) -> int:
        p = self.state_dir / "audit.jsonl"
        return p.stat().st_size if p.exists() else 0

    def state_bytes(self) -> int:
        p = self.state_dir / "state.json"
        return p.stat().st_size if p.exists() else 0

    def _descendants(self) -> list:
        """A launcher that is a script (java, php) leaves the real daemon as its child: stop those by PID too."""
        out, todo = [], [self.proc.pid]
        while todo:
            pid = todo.pop()
            try:
                with open(f"/proc/{pid}/task/{pid}/children") as f:
                    kids = [int(x) for x in f.read().split()]
            except (OSError, ValueError):
                kids = []
            out += kids
            todo += kids
        return out

    def close(self):
        kids = self._descendants()
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
        for pid in kids:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
        try:
            self.proc.stderr.close()
        except OSError:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)
