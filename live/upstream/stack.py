"""Start, attach to and stop the pieces the live tests need:

    PostgreSQL          pg.sh (private cluster)          or SD_PG_DSN
    company-api         live/upstream/company_api.py     or SD_UPSTREAM_URL + SD_UPSTREAM_KEY
    decision daemon     `smartdelegate serve`            or SD_DAEMON_URL + SD_ADMIN_KEY + SD_PEP_KEY
    HTTP proxy          `smartdelegate http-proxy`       or SD_PROXY_URL (only together with SD_DAEMON_URL)

`impl` is `python` (the reference) or `rust`. The daemon and the proxy of one
stack share one state directory, so a token the daemon issues is the proxy's
own, and an approval or revocation made through the daemon is seen by the
proxy on its next request (both ports take the same flock).

Everything started here is stopped by PID in `close()`. Keys, state, logs and
the routes file with the real upstream address live in one mode-0700
temporary directory that `close()` removes. Nothing is written into the
repository.
"""
from __future__ import annotations

import atexit
import ctypes
import http.client
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
COMPANY = ROOT / "examples" / "company"
ISSUER = "smartdelegate://live"
TENANT = "kestrel"
RUST = ROOT / "ports" / "rust" / "target" / "release" / "smartdelegate"
START_TIMEOUT = 60
REDACTED = "[REDACTED]"


_LIVE: set = set()      # every Stack that still has something to stop


def record_pid(pid: int) -> None:
    """Append "pid starttime" to the file live/run.sh names in SD_LIVE_PIDFILE, so that it can check at
    its end that nothing it started is still alive (the start time tells a reused pid from the same process)."""
    path = os.environ.get("SD_LIVE_PIDFILE")
    if not path:
        return
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            start = f.read().rsplit(b") ", 1)[1].split()[19].decode()
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{pid} {start}\n")
    except (OSError, IndexError):
        pass


def die_with_parent():
    """preexec_fn: the kernel sends SIGTERM to this child when the process that started it dies
    (PR_SET_PDEATHSIG), so nothing outlives a test run that was killed."""
    try:
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)
    except (OSError, AttributeError):  # not Linux
        pass


def _close_all(*_):
    for st in list(_LIVE):
        try:
            st.close()
        except Exception:
            pass


def _on_signal(signum, _frame):
    _close_all()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def install_cleanup() -> None:
    """Stop everything on exit and on SIGTERM/SIGHUP (Ctrl-C raises KeyboardInterrupt, which reaches atexit)."""
    if getattr(install_cleanup, "done", False):
        return
    install_cleanup.done = True
    atexit.register(_close_all)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            if signal.getsignal(sig) in (signal.SIG_DFL, None):
                signal.signal(sig, _on_signal)
        except (ValueError, OSError):  # not the main thread
            pass


class Unavailable(Exception):
    """A requirement is missing on this machine: the caller SKIPs, never passes."""


def cli_of(impl: str) -> tuple:
    """-> (argv, extra env) of the command line of an implementation that has proxies."""
    if impl == "python":
        return [sys.executable, "-m", "sf_smartdelegate"], {"PYTHONPATH": str(ROOT / "src") + (os.pathsep + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")}
    if impl == "rust":
        if not RUST.exists():
            raise Unavailable("ports/rust/target/release/smartdelegate does not exist (cargo build --release in ports/rust)")
        return [str(RUST)], {}
    raise ValueError(f"no proxy implementation named '{impl}' (python, rust)")


def stop_process(proc: subprocess.Popen | None, grace: float = 10.0) -> None:
    """By PID, never by name."""
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:  # pragma: no cover
                pass
    for f in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if f:
                f.close()
        except OSError:
            pass


def wait_for_url(proc: subprocess.Popen, log: Path, what: str, timeout: float = START_TIMEOUT) -> str:
    """The first http://host:port a process prints to its log."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        m = re.search(r"http://[0-9A-Za-z_.:\[\]-]+", text)
        if m:
            return m.group(0)
        if proc.poll() is not None:
            raise RuntimeError(f"{what} exited with status {proc.returncode}: {text[-800:].strip() or '(no output)'}")
        time.sleep(0.03)
    raise RuntimeError(f"{what} did not print its URL within {timeout} s")


class Response:
    __slots__ = ("status", "headers", "raw", "error")

    def __init__(self, status: int, headers: list, raw: bytes, error: str | None = None):
        self.status, self.headers, self.raw, self.error = status, headers, raw, error

    def header(self, name: str):
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)

    @property
    def json(self):
        try:
            return json.loads(self.raw) if self.raw else None
        except ValueError:
            return None

    @property
    def code(self):
        """The `error.code` of a proxy denial, or None."""
        j = self.json
        return j["error"].get("code") if isinstance(j, dict) and isinstance(j.get("error"), dict) else None

    def everything(self) -> bytes:
        """Status, headers and body: all an agent receives of this answer."""
        head = "".join(f"{k}: {v}\r\n" for k, v in self.headers)
        return f"{self.status}\r\n{head}\r\n".encode("utf-8", "replace") + self.raw + (self.error or "").encode("utf-8", "replace")


def http_request(method: str, url: str, *, token: str | None = None, body=None, headers: dict | None = None, timeout: float = 30.0,
                 raw_body: bytes | None = None) -> Response:
    """One request on one connection, no environment proxy, a timeout on everything.
    A transport failure is a Response with status 0 and `error` set, never an exception."""
    u = urllib.parse.urlsplit(url)
    h = {"Connection": "close"}
    data = raw_body
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        h["Content-Type"] = "application/json"
    if token:
        h["Authorization"] = f"Bearer {token}"
    h.update(headers or {})
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request(method, (u.path or "/") + (f"?{u.query}" if u.query else ""), body=data, headers=h)
        r = conn.getresponse()
        return Response(r.status, r.getheaders(), r.read())
    except (OSError, http.client.HTTPException) as e:
        return Response(0, [], b"", f"{type(e).__name__}: {e}")
    finally:
        conn.close()


class DaemonApi:
    """REST calls to a decision daemon, one connection per call."""

    ROUTES = {
        "authorize": ("POST", "/v1/authorize", "pep"), "filter": ("POST", "/v1/filter", "pep"), "explain": ("POST", "/v1/explain", "pep"),
        "apply_obligations": ("POST", "/v1/obligations/apply", "pep"), "inspect_token": ("POST", "/v1/token/inspect", "pep"),
        "info": ("GET", "/v1/info", "pep"), "exchange_token": ("POST", "/v1/token", None), "issue_token": ("POST", "/v1/token", "admin"),
        "revoke": ("POST", "/v1/admin/revoke", "admin"), "approve": ("POST", "/v1/admin/approve", "admin"),
        "approvals": ("GET", "/v1/admin/approvals", "admin"), "audit_verify": ("GET", "/v1/admin/audit/verify", "admin"),
        "audit_tail": ("GET", "/v1/admin/audit/tail", "admin"),
    }

    def __init__(self, url: str, admin_key: str, pep_key: str | None = None, timeout: float = 60.0):
        self.url, self.keys, self.timeout = url.rstrip("/"), {"admin": admin_key, "pep": pep_key or admin_key}, timeout

    def call(self, op: str, payload: dict | None = None) -> dict:
        method, path, kind = self.ROUTES[op]
        if op == "audit_tail":
            path += f"?n={int((payload or {}).get('n', 20))}"
        r = http_request(method, self.url + path, token=self.keys[kind] if kind else None, body=payload if method == "POST" else None, timeout=self.timeout)
        doc = r.json
        if not isinstance(doc, dict):
            return {"ok": False, "error": {"code": "transport", "message": r.error or f"HTTP {r.status}: {r.raw[:200]!r}"}}
        return doc

    def healthy(self) -> bool:
        return http_request("GET", self.url + "/healthz", timeout=5).status == 200


def ensure_pg() -> tuple:
    """-> (dsn, started_here)."""
    if os.environ.get("SD_PG_DSN"):
        return os.environ["SD_PG_DSN"], False
    pg = str(HERE / "pg.sh")
    try:
        if subprocess.run([pg, "status"], capture_output=True, timeout=60).returncode == 0:
            return subprocess.run([pg, "url"], capture_output=True, text=True, timeout=30, check=True).stdout.strip(), False
        p = subprocess.run([pg, "start"], capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as e:
        raise Unavailable(f"pg.sh: {e}") from None
    if p.returncode != 0:
        raise Unavailable(f"no PostgreSQL: {p.stderr.strip() or p.stdout.strip()} (set SD_PG_DSN to attach to a server)")
    return p.stdout.strip().splitlines()[-1], True


def pg_log_path() -> Path | None:
    """The statement log of the private cluster; None when attached to somebody else's server."""
    if os.environ.get("SD_PG_DSN"):
        return None
    p = subprocess.run([str(HERE / "pg.sh"), "log"], capture_output=True, text=True, timeout=30)
    path = Path(p.stdout.strip()) if p.returncode == 0 else None
    return path if path and path.exists() and os.access(path, os.R_OK) else None


class Stack:
    def __init__(self, impl: str = "python", *, proxy: bool = True, daemon: bool = True, api: bool = True, seed_scale: float = 1.0, reseed: bool = False,
                 config: dict | None = None, proxy_listen: str = "127.0.0.1:0"):
        self.impl = impl
        self.procs: list = []
        self.pg_started = False
        self.tmp = Path(tempfile.mkdtemp(prefix=f"smartdelegate-live-{impl}-"))
        os.chmod(self.tmp, stat.S_IRWXU)
        self.attached = {"pg": bool(os.environ.get("SD_PG_DSN")), "api": False, "daemon": False, "proxy": False}
        self.daemon_url = self.proxy_url = self.api_url = None
        self.daemon_proc = self.proxy_proc = self.api_proc = None
        self.state_dir = self.tmp / "state"
        self.logs = {}
        install_cleanup()
        _LIVE.add(self)
        try:
            try:
                import psycopg2  # noqa: F401
            except ImportError:
                raise Unavailable("the Python package psycopg2 is not installed") from None
            from . import seed
            self.dsn, self.pg_started = ensure_pg()
            self.rows = seed.load(self.dsn, scale=seed_scale, force=reseed)
            self.argv, self.cli_env = cli_of(impl)
            if api:
                self._start_api()
            self.admin_key, self.pep_key = secrets.token_hex(20), secrets.token_hex(20)
            cfg = {"bundle_dir": str(COMPANY), "state_dir": str(self.state_dir), "issuer": ISSUER, "mode": "enforce", "max_depth": 3,
                   "admin_key": self.admin_key, "pep_key": self.pep_key}
            cfg.update(config or {})
            self.config = self.tmp / "smartdelegate.json"
            self._write_private(self.config, json.dumps(cfg))
            if os.environ.get("SD_DAEMON_URL") and os.environ.get("SD_PROXY_URL"):
                self.daemon_url, self.proxy_url = os.environ["SD_DAEMON_URL"].rstrip("/"), os.environ["SD_PROXY_URL"].rstrip("/")
                self.admin_key, self.pep_key = os.environ.get("SD_ADMIN_KEY", ""), os.environ.get("SD_PEP_KEY", "")
                if not self.admin_key:
                    raise Unavailable("SD_DAEMON_URL is set without SD_ADMIN_KEY")
                self.attached["daemon"] = self.attached["proxy"] = True
                self.state_dir = None
            else:
                if daemon:
                    self.daemon_proc, self.daemon_url = self._start_sd("serve", [], "daemon")
                if proxy:
                    self.routes = HERE / "routes.json"      # as committed: the upstream's address comes from the environment
                    self.proxy_proc, self.proxy_url = self._start_sd("http-proxy", ["--routes", str(self.routes)], "proxy",
                                                                     env={"COMPANY_API_KEY": self.api_key, "COMPANY_API_URL": self.api_url}, listen=proxy_listen)
            self.daemon = DaemonApi(self.daemon_url, self.admin_key, self.pep_key) if self.daemon_url else None
            if self.daemon is not None:
                deadline = time.monotonic() + START_TIMEOUT
                while not self.daemon.healthy():
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"the daemon at {self.daemon_url} does not answer /healthz")
                    time.sleep(0.05)
        except BaseException:
            self.close()
            raise

    # ---- starting things
    @staticmethod
    def _write_private(path: Path, text: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)

    def _spawn(self, argv: list, env: dict, name: str, stdout_to_log: bool = False) -> tuple:
        log = self.tmp / f"{name}.log"
        self.logs[name] = log
        f = open(log, "wb")
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=f if stdout_to_log else subprocess.DEVNULL, stderr=f,
                                    env={**os.environ, **env}, cwd=str(self.tmp), preexec_fn=die_with_parent)
        finally:
            f.close()
        self.procs.append(proc)
        record_pid(proc.pid)
        return proc, log

    def _start_api(self) -> None:
        if os.environ.get("SD_UPSTREAM_URL"):
            self.api_url, self.api_key = os.environ["SD_UPSTREAM_URL"].rstrip("/"), os.environ.get("SD_UPSTREAM_KEY", "")
            if not self.api_key:
                raise Unavailable("SD_UPSTREAM_URL is set without SD_UPSTREAM_KEY")
            self.attached["api"] = True
            return
        self.api_key = "upk_" + secrets.token_hex(24)
        self.api_proc, log = self._spawn([sys.executable, str(HERE / "company_api.py")],
                                         {"COMPANY_API_KEY": self.api_key, "COMPANY_API_DSN": self.dsn, "COMPANY_API_HOST": "127.0.0.1", "COMPANY_API_PORT": "0"},
                                         "company-api", stdout_to_log=True)
        self.api_url = wait_for_url(self.api_proc, log, "company-api")
        deadline = time.monotonic() + START_TIMEOUT
        while http_request("GET", self.api_url + "/healthz", timeout=5).status != 200:
            if time.monotonic() > deadline:
                raise RuntimeError("company-api does not answer /healthz")
            time.sleep(0.05)

    def _start_sd(self, command: str, args: list, name: str, env: dict | None = None, listen: str = "127.0.0.1:0") -> tuple:
        proc, log = self._spawn([*self.argv, command, "--config", str(self.config), "--listen", listen, *args], {**self.cli_env, **(env or {})}, name)
        return proc, wait_for_url(proc, log, f"{self.impl} {command}")

    # ---- using them
    def admin(self, op: str, payload: dict | None = None) -> dict:
        return self.daemon.call(op, payload or {})

    def issue(self, user: str, role: str, task: str, agent: str | None = None, **extra) -> dict:
        """A role token the way a token service would ask for it. Raises on refusal."""
        roles = json.loads((COMPANY / "roles.json").read_text(encoding="utf-8"))["roles"]
        r = self.admin("issue_token", {"user": user, "agent": agent or roles[role]["agents"][0], "role": role, "task": task, "tenant": TENANT, **extra})
        if r.get("ok") is not True:
            raise RuntimeError(f"issue_token {user}/{role}/{task}: {r}")
        return r

    def sql(self, query: str, params: tuple = ()) -> list:
        """The test's own look at the database (not through any enforcement point)."""
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(self.dsn, connect_timeout=15, options="-c search_path=company")
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, params)
                rows = [dict(r) for r in cur.fetchall()] if cur.description else []
            conn.commit()
            return rows
        finally:
            conn.close()

    def log_text(self, name: str) -> str:
        p = self.logs.get(name)
        return p.read_text(encoding="utf-8", errors="replace") if p and p.exists() else ""

    def state(self) -> dict:
        """state.json of the stack's own state directory ({} when attached)."""
        if not self.state_dir or not (self.state_dir / "state.json").exists():
            return {}
        return json.loads((self.state_dir / "state.json").read_text(encoding="utf-8"))

    def close(self) -> None:
        _LIVE.discard(self)
        for proc in reversed(self.procs):
            stop_process(proc)
        self.procs = []
        if self.pg_started:
            subprocess.run([str(HERE / "pg.sh"), "stop"], capture_output=True, timeout=120)
            self.pg_started = False
        shutil.rmtree(self.tmp, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
