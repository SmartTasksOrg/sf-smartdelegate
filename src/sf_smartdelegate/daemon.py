"""REST decision daemon (`smartdelegate serve`). See spec/openapi.yaml.

Two keys guard it:
  pep key    enforcement points: /v1/authorize, /v1/filter, /v1/explain,
             /v1/obligations/apply, /v1/token/inspect, /v1/info
  admin key  /v1/admin/* and issuing a root token without an OIDC ID token
/v1/token needs no key for token exchange (holding the parent token is the
authority) or for issuance backed by a verified OIDC ID token.
TLS is not terminated here: bind to loopback or put it behind a mesh.
"""
from __future__ import annotations

import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 8 * 1024 * 1024

ROUTES = {
    ("GET", "/v1/info"): ("info", "pep"),
    ("POST", "/v1/authorize"): ("authorize", "pep"),
    ("POST", "/v1/filter"): ("filter", "pep"),
    ("POST", "/v1/explain"): ("explain", "pep"),
    ("POST", "/v1/obligations/apply"): ("apply_obligations", "pep"),
    ("POST", "/v1/token/inspect"): ("inspect_token", "pep"),
    ("POST", "/v1/admin/revoke"): ("revoke", "admin"),
    ("POST", "/v1/admin/approve"): ("approve", "admin"),
    ("POST", "/v1/admin/reload"): ("reload", "admin"),
    ("GET", "/v1/admin/approvals"): ("approvals", "admin"),
    ("GET", "/v1/admin/audit/verify"): ("audit_verify", "admin"),
    ("GET", "/v1/admin/audit/tail"): ("audit_tail", "admin"),
}


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


class JsonHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "smartdelegate"
    # Headers and body go out as two writes. Without this, Nagle's algorithm
    # holds the second one for the peer's delayed ACK: 40 ms on every call.
    disable_nagle_algorithm = True

    def log_message(self, *a):  # quiet; decisions are in the audit log
        pass

    def bearer(self):
        h = self.headers.get("Authorization") or ""
        return h[7:].strip() if h.startswith("Bearer ") else None

    def send_json(self, status: int, body, extra: dict | None = None):
        raw = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def read_body(self):
        """-> (bytes, None) or (None, error message)"""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, "bad Content-Length"
        if n > MAX_BODY:
            self.close_connection = True
            return None, "request body is too large"
        return (self.rfile.read(n) if n > 0 else b""), None


class _Handler(JsonHandler):
    def _handle(self, method: str):
        srv = self.server
        path, _, query = self.path.partition("?")
        if path == "/healthz":
            return self.send_json(200, {"ok": True})
        body = {}
        if method == "POST":
            raw, err = self.read_body()
            if err is None and raw.strip():
                try:
                    body = json.loads(raw)
                except (ValueError, RecursionError):
                    err = "body is not JSON"
            if err:
                return self.send_json(400, {"ok": False, "error": {"code": "invalid_input", "message": err}})
        key = self.bearer() or ""
        is_admin = same(key, srv.admin_key)
        is_pep = is_admin or same(key, srv.pep_key)
        if (method, path) == ("POST", "/v1/token"):
            if isinstance(body, dict) and "subject_token" in body:
                op, allowed = "exchange_token", True
            elif isinstance(body, dict) and "id_token" in body:
                body = {k: v for k, v in body.items() if k != "user"}   # identity comes from the ID token alone
                op, allowed = "issue_token", True
            else:
                op, allowed = "issue_token", is_admin
        elif (method, path) in ROUTES:
            op, need = ROUTES[(method, path)]
            allowed = is_admin if need == "admin" else is_pep
            if op == "audit_tail":
                n = next((kv[2:] for kv in query.split("&") if kv.startswith("n=")), "20")
                body = {"n": int(n) if n.isdigit() else 20}
        else:
            return self.send_json(404, {"ok": False, "error": {"code": "not_found", "message": "no such endpoint"}})
        if not allowed:
            return self.send_json(401, {"ok": False, "error": {"code": "unauthorized", "message": "missing or wrong API key"}})
        result = srv.engine.call(op, body)
        self.send_json(200 if result.get("ok") else 400, result)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


def listen_address(text: str) -> tuple:
    host, _, port = text.rpartition(":")
    return (host or "127.0.0.1", int(port))


def serve(engine, listen: str, admin_key: str, pep_key: str) -> None:
    if len(admin_key or "") < 16 or len(pep_key or "") < 16:
        raise SystemExit("smartdelegate: serve needs admin_key and pep_key (16+ characters) in the config or SMARTDELEGATE_ADMIN_KEY / SMARTDELEGATE_PEP_KEY")
    server = ThreadingHTTPServer(listen_address(listen), _Handler)
    server.daemon_threads = True
    server.engine, server.admin_key, server.pep_key = engine, admin_key, pep_key
    host, port = server.server_address[:2]
    print(f"smartdelegate daemon listening on http://{host}:{port}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
