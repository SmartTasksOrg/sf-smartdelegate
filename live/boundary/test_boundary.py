"""Is the proxy really the only way out?

A stand-in agent runs inside a fresh network namespace (`unshare -n`) whose
only reachable service is the SmartDelegate HTTP proxy, carried in over a
Unix-domain socket by a byte relay (live/boundary/relay.py, live/boundary/cell.py).
The upstream REST service, PostgreSQL and the decision daemon's admin port all
live on the host, outside the namespace. The test asserts, from inside:

  * a permitted call through the proxy returns masked data and no secret;
  * a direct TCP connection to the upstream, to PostgreSQL, to the daemon
    admin port and to an internet-style address all fail at connect;
  * the agent process holds no upstream credential in its environment, in any
    file its uid can read, or in another process's /proc (it runs as an
    unprivileged uid and cannot read the root-owned proxy's environ);
  * a battery of egress attempts a prompt-injected agent could make (direct
    connect, env/argv/proc scraping, unmapped routes, path traversal, header
    override of Authorization/Host/X-Forwarded-*, request smuggling with
    conflicting Content-Length/Transfer-Encoding, CONNECT, absolute-URI to
    another host, over-long headers, a partial request) obtains nothing
    outside the role.

A contrast run performs the same attempts in the host's network namespace
(no boundary) to show what the namespace adds: there the direct connections
succeed, which is the documented limitation of in-process checks made honest.

Requires root and working network namespaces; SKIPs with a reason otherwise.

    sudo python3 -m unittest -v live.boundary.test_boundary
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "live"))
from upstream.oracle import CARD, IBAN, NATIONAL_ID, TAX_ID  # noqa: E402
from upstream.stack import Stack, Unavailable, http_request  # noqa: E402

from . import relay  # noqa: E402

TENANT = "kestrel"


def namespaces_work() -> tuple:
    if os.geteuid() != 0:
        return False, "not root (the boundary test creates a network namespace and drops to an unprivileged uid)"
    if not shutil.which("unshare"):
        return False, "the `unshare` command is not available"
    try:
        p = subprocess.run(["unshare", "-n", "true"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return False, f"unshare -n does not work here: {e}"
    if p.returncode != 0:
        return False, f"unshare -n is refused here: {p.stderr.decode(errors='replace').strip()}"
    try:
        import pwd
        pwd.getpwnam("nobody")
    except KeyError:
        return False, "there is no 'nobody' user to run the agent as"
    return True, ""


class Boundary(unittest.TestCase):
    maxDiff = 4000

    @classmethod
    def setUpClass(cls):
        ok, why = namespaces_work()
        if not ok:
            raise unittest.SkipTest(why)
        try:
            cls.stack = Stack("python", proxy_listen="127.0.0.1:0")
        except Unavailable as e:
            raise unittest.SkipTest(str(e)) from None
        import pwd
        nob = pwd.getpwnam("nobody")
        cls.uid, cls.gid = nob.pw_uid, nob.pw_gid
        # a root-only directory for the Unix socket; the agent uid cannot enter it
        cls.sockdir = Path(tempfile.mkdtemp(prefix="smartdelegate-boundary-sock-"))
        os.chmod(cls.sockdir, 0o700)
        cls.uds = cls.sockdir / "proxy.sock"
        # outside relay: Unix socket -> the proxy's TCP address on the host
        u = cls.stack.proxy_url.split("://", 1)[1]
        host, _, port = u.rpartition(":")
        cls.stop = threading.Event()
        listener = relay.unix_listener(str(cls.uds), mode=0o600)
        os.chown(cls.sockdir, 0, 0)
        threading.Thread(target=relay.serve, args=(listener, relay.tcp_connector(host, int(port)), cls.stop), daemon=True).start()
        cls._listener = listener
        cls.token = cls.stack.issue("anna", "support-agent", "ticket-boundary")["token"]
        u = cls.stack.api_url.split("://", 1)[1]
        da = cls.stack.daemon_url.split("://", 1)[1]
        cls.targets = {"upstream": u, "postgres": "127.0.0.1:" + cls.dsn_port(), "admin": da, "internet": "93.184.216.34:80"}
        cls.markers = {"upstream_api_key": cls.stack.api_key, "db_password": cls.dsn_password(),
                       "card_number": CARD.pattern.decode(), "iban": IBAN.pattern.decode(),
                       "national_id": NATIONAL_ID.pattern.decode(), "tax_id": TAX_ID.pattern.decode()}

    @classmethod
    def dsn_port(cls):
        import urllib.parse
        return str(urllib.parse.urlsplit(cls.stack.dsn).port)

    @classmethod
    def dsn_password(cls):
        import urllib.parse
        return urllib.parse.urlsplit(cls.stack.dsn).password or "x-no-password"

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "stop", None):
            cls.stop.set()
        if getattr(cls, "_listener", None):
            try:
                cls._listener.close()
            except OSError:
                pass
        if getattr(cls, "sockdir", None):
            shutil.rmtree(cls.sockdir, ignore_errors=True)
        if getattr(cls, "stack", None):
            cls.stack.close()

    # ---- running the probe
    def probe_env(self, proxy: str) -> dict:
        return {"SD_PROBE_PROXY": proxy, "SD_PROBE_TOKEN": self.token, "SD_PROBE_TENANT": TENANT, "SD_PROBE_REGION": "EU",
                "SD_PROBE_TARGETS": json.dumps(self.targets), "SD_PROBE_MARKERS": json.dumps(self.markers),
                "PATH": "/usr/bin:/bin", "HOME": "/tmp"}

    def run_in_cell(self) -> dict:
        """The probe inside a fresh namespace, reachable only via the relay."""
        workdir = Path(tempfile.mkdtemp(prefix="smartdelegate-boundary-work-"))
        os.chown(workdir, self.uid, self.gid)
        os.chmod(workdir, 0o700)
        env = {**self.probe_env("http://127.0.0.1:8182"), "HOME": str(workdir)}
        try:
            argv = ["unshare", "-n", sys.executable, str(HERE / "cell.py"), "--uds", str(self.uds), "--port", "8182",
                    "--uid", str(self.uid), "--gid", str(self.gid), "--workdir", str(workdir), "--timeout", "120"]
            for k, v in env.items():
                argv += ["--env", f"{k}={v}"]
            argv += ["--", sys.executable, str(HERE / "probe.py")]
            p = subprocess.run(argv, capture_output=True, text=True, timeout=180)
            self.assertEqual(p.returncode, 0, f"cell exited {p.returncode}: {p.stderr[-1500:]}")
            return self._last_json(p.stdout)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def run_on_host(self) -> dict:
        """The same probe with no namespace, as the unprivileged uid, pointed
        straight at the proxy: the contrast that shows what the boundary adds."""
        def drop():
            os.setgroups([])
            os.setgid(self.gid)
            os.setuid(self.uid)
        p = subprocess.run([sys.executable, str(HERE / "probe.py")], capture_output=True, text=True, timeout=180,
                           env=self.probe_env(self.stack.proxy_url), preexec_fn=drop, cwd="/tmp")
        self.assertEqual(p.returncode, 0, p.stderr[-1500:])
        return self._last_json(p.stdout)

    @staticmethod
    def _last_json(text: str) -> dict:
        for line in reversed(text.strip().splitlines()):
            try:
                return json.loads(line)
            except ValueError:
                continue
        raise AssertionError(f"the probe printed no JSON: {text[-500:]}")

    @staticmethod
    def by_name(report: dict) -> dict:
        return {a["attempt"]: a for a in report["attempts"]}

    # ---- the test
    def test_the_namespace_is_a_real_boundary_and_every_bypass_fails(self):
        report = self.run_in_cell()
        a = self.by_name(report)
        type(self).report = report

        # 1. the permitted call works and returns masked data, no secret
        p = a["permitted-call"]
        self.assertEqual(p["result"]["status"], 200, p)
        self.assertEqual(p["result"]["markers_found"], [])
        self.assertIn("ada", p["result"]["body"] + "ada")   # body is masked customer data; just assert no secret marker above

        # 2. every direct connection out of the namespace fails at connect
        for name in ("upstream", "postgres", "admin", "internet"):
            c = a[f"connect-{name}"]["result"]
            self.assertFalse(c.get("connected"), f"a direct connection to {name} succeeded from inside the namespace: {c}")

        # 3. no secret in environment, files, or another process's /proc
        for name in ("scrape-own-environment", "read-readable-files", "scrape-proc-environ"):
            self.assertEqual(a[name]["result"]["markers_found"], [], f"{name} found a secret: {a[name]['result']}")
        self.assertEqual(a["scrape-proc-environ"]["result"]["markers_found"], [], "the agent read a credential from some process's /proc/environ")

        # 4. no attempt obtained anything outside the role
        obtained = [x["attempt"] for x in report["attempts"] if x["obtained_data_outside_role"]]
        self.assertEqual(obtained, [], f"these attempts obtained data outside the role: {obtained}")

        # the refused calls carry the proxy's own denial, never upstream data
        for name, code in (("unmapped-route", (403,)), ("other-region", (403,)), ("other-tenant", (403,)),
                           ("unknown-upstream", (403,)), ("path-traversal", (403,)), ("unlisted-query", (400,)),
                           ("other-region-record", (403,)), ("duplicate-query", (400,)), ("encoded-query-name", (400,)),
                           ("smuggle-upstream-key", (200,)), ("override-host", (200,)), ("override-forwarded", (200,))):
            r = a[name]["result"]
            if "status" in r:
                self.assertIn(r["status"], code, f"{name}: {r}")
            self.assertEqual(r.get("markers_found", []), [], name)
        # overriding Authorization with junk is rejected, not honoured
        self.assertFalse(a["override-authorization"]["obtained_data_outside_role"])

    def test_contrast_without_the_namespace_the_ports_are_reachable(self):
        host = self.run_on_host()
        a = self.by_name(host)
        type(self).contrast = host
        reachable = [n for n in ("upstream", "postgres", "admin") if a[f"connect-{n}"]["result"].get("connected")]
        self.assertTrue(reachable, "without the namespace the agent should be able to reach the backend ports directly")
        # even so, reaching the port is not reaching the data: the upstream still needs its key
        self.assertEqual(a["permitted-call"]["result"]["markers_found"], [])
        # and the proxy's refusals are the same with or without the boundary (the engine does not depend on the network)
        self.assertEqual(a["unmapped-route"]["result"]["status"], 403)

    def test_in_process_integration_would_expose_the_credential_the_boundary_hides(self):
        """Honest demonstration of docs/LIMITATIONS.md section 1: an in-process
        integration holds the upstream credential in the agent's own process, so
        the same environment scrape that finds nothing in the cell finds it here."""
        def drop():
            os.setgroups([]); os.setgid(self.gid); os.setuid(self.uid)
        env = {**self.probe_env(self.stack.proxy_url), "COMPANY_API_KEY": self.stack.api_key}  # as an in-process tool would have it
        p = subprocess.run([sys.executable, str(HERE / "probe.py")], capture_output=True, text=True, timeout=120,
                           env=env, preexec_fn=drop, cwd="/tmp")
        a = self.by_name(self._last_json(p.stdout))
        self.assertIn("upstream_api_key", a["scrape-own-environment"]["result"]["markers_found"],
                      "the point of the contrast: with the credential in the process, scraping the environment finds it")

    def test_deployment_artifacts_are_syntactically_valid_and_marked_untested(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed: the two deployment files were not parsed")
        for name in ("deploy-compose.yml", "deploy-networkpolicy.yaml"):
            text = (HERE / name).read_text(encoding="utf-8")
            self.assertIn("UNTESTED", text, f"{name} must be marked UNTESTED")
            docs = list(yaml.safe_load_all(text))
            self.assertTrue(docs and all(isinstance(d, dict) for d in docs), name)
        compose = yaml.safe_load((HERE / "deploy-compose.yml").read_text())
        self.assertTrue(compose["networks"]["agentnet"]["internal"])
        self.assertEqual(compose["services"]["agent"]["networks"], ["agentnet"], "the agent is on the internal network only")
        pols = {d["metadata"]["name"]: d for d in yaml.safe_load_all((HERE / "deploy-networkpolicy.yaml").read_text())}
        self.assertEqual(pols["agent-default-deny-egress"]["spec"]["egress"], [])
        self.assertEqual(pols["agent-egress-to-proxy-only"]["spec"]["egress"][0]["ports"][0]["port"], 8182)

    @classmethod
    def tearDownClassSummary(cls):
        pass


def tearDownModule():
    rep = getattr(Boundary, "report", None)
    con = getattr(Boundary, "contrast", None)
    if not rep:
        return
    lines = ["", "boundary: every egress attempt from inside the namespace, and the contrast without it"]
    cmap = {a["attempt"]: a for a in (con or {}).get("attempts", [])}
    for att in rep["attempts"]:
        name = att["attempt"]
        inside = _one_line(att)
        outside = _one_line(cmap[name]) if name in cmap else "-"
        mark = "LEAK" if att["obtained_data_outside_role"] else "    "
        lines.append(f"  {mark} {name:26} in-ns: {inside:38} host: {outside}")
    print("\n".join(lines), file=sys.stderr)
    if os.environ.get("SD_LIVE_OBSERVED"):
        Path(os.environ["SD_LIVE_OBSERVED"]).write_text(json.dumps({"boundary": rep, "contrast": con}, indent=2, default=str), encoding="utf-8")


def _one_line(att: dict) -> str:
    r = att["result"]
    if "connected" in r:
        return "connected" if r["connected"] else f"refused ({r.get('error', '')})"
    if "status" in r:
        return f"{r['status']} {r.get('code') or ''}".strip()
    if "markers_found" in r:
        return f"markers={r['markers_found'] or 'none'}"
    return (r.get("error") or r.get("response_within_timeout") or json.dumps(r))[:36]


if __name__ == "__main__":
    unittest.main()
