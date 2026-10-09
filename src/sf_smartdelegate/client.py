"""Thin REST client for `smartdelegate serve`. Standard library only."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .backend import SmartDelegateError, Backend

_ROUTES = {
    "authorize": ("POST", "/v1/authorize", "pep"),
    "filter": ("POST", "/v1/filter", "pep"),
    "explain": ("POST", "/v1/explain", "pep"),
    "apply_obligations": ("POST", "/v1/obligations/apply", "pep"),
    "inspect_token": ("POST", "/v1/token/inspect", "pep"),
    "info": ("GET", "/v1/info", "pep"),
    "exchange_token": ("POST", "/v1/token", None),
    "issue_token": ("POST", "/v1/token", "admin"),
    "revoke": ("POST", "/v1/admin/revoke", "admin"),
    "approve": ("POST", "/v1/admin/approve", "admin"),
    "reload": ("POST", "/v1/admin/reload", "admin"),
    "approvals": ("GET", "/v1/admin/approvals", "admin"),
    "audit_verify": ("GET", "/v1/admin/audit/verify", "admin"),
    "audit_tail": ("GET", "/v1/admin/audit/tail", "admin"),
}


class DaemonClient(Backend):
    def __init__(self, url: str, pep_key: str | None = None, admin_key: str | None = None, timeout: float = 10.0):
        self.url = url.rstrip("/")
        self.keys = {"pep": pep_key or admin_key, "admin": admin_key}
        self.timeout = timeout
        # never route decision traffic through an environment proxy
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, op: str, payload: dict) -> dict:
        if op not in _ROUTES:
            return {"ok": False, "error": {"code": "unknown_op", "message": f"no operation named '{op}'"}}
        method, path, key_kind = _ROUTES[op]
        if op == "audit_tail" and "n" in payload:
            path += f"?n={int(payload['n'])}"
        headers = {"Content-Type": "application/json"}
        key = self.keys.get(key_kind) if key_kind else None
        if op == "issue_token" and payload.get("id_token"):
            key = None  # the ID token is the credential
        if key:
            headers["Authorization"] = f"Bearer {key}"
        data = json.dumps(payload).encode("utf-8") if method == "POST" else None
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8"))
            except Exception:
                return {"ok": False, "error": {"code": "http_error", "message": f"HTTP {e.code}"}}
        except (urllib.error.URLError, OSError) as e:
            # an unreachable decision point is never an allow
            raise SmartDelegateError("daemon_unreachable", str(e)) from e
