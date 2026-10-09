"""Shared plumbing for the live Keycloak tests: where the server is, an
Admin REST client, and the few OIDC calls the tests need.

Standard library only. Every request has a timeout. Requests to a loopback
host never go through an environment proxy. Secrets (admin password, client
secrets, test users' passwords) are read from the environment or from the
cache directory and are never written into the repository.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TIMEOUT = 30
REALM = os.environ.get("SD_KEYCLOAK_REALM", "kestrel")
OTHER_REALM = REALM + "-other"


class Unavailable(Exception):
    """Keycloak cannot be reached or was not provisioned. Tests skip on this."""


def cache_dir() -> Path:
    return Path(os.environ.get("SD_KEYCLOAK_CACHE") or Path.home() / ".cache" / "smartdelegate" / "keycloak")


def _env_file(path: Path) -> dict:
    out = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            k, eq, v = line.partition("=")
            if eq and k.strip():
                out[k.strip()] = v.strip()
    return out


def locate() -> dict:
    """{"url", "admin", "password", "attached"}: the server to use.
    SD_KEYCLOAK_URL (+ SD_KEYCLOAK_ADMIN, SD_KEYCLOAK_ADMIN_PASSWORD) attaches
    to an existing server; otherwise the one `keycloak.sh start` recorded in
    the cache directory."""
    url = os.environ.get("SD_KEYCLOAK_URL")
    if url:
        admin, password = os.environ.get("SD_KEYCLOAK_ADMIN"), os.environ.get("SD_KEYCLOAK_ADMIN_PASSWORD")
        if not admin or not password:
            raise Unavailable("SD_KEYCLOAK_URL is set but SD_KEYCLOAK_ADMIN / SD_KEYCLOAK_ADMIN_PASSWORD are not")
        return {"url": url.rstrip("/"), "admin": admin, "password": password, "attached": True}
    cache = cache_dir()
    port, creds = cache / "keycloak.port", _env_file(cache / "admin.env")
    if not port.is_file() or "SD_KEYCLOAK_ADMIN_PASSWORD" not in creds:
        raise Unavailable(f"no Keycloak: run live/idp/keycloak.sh start (nothing recorded in {cache}), or set SD_KEYCLOAK_URL")
    return {"url": f"http://127.0.0.1:{port.read_text().strip()}", "admin": creds.get("SD_KEYCLOAK_ADMIN", "admin"),
            "password": creds["SD_KEYCLOAK_ADMIN_PASSWORD"], "attached": False}


def provision_file() -> Path:
    """Where provision.py records what it created (ids, client secrets, the
    test users' passwords). In the cache directory, mode 0600."""
    return cache_dir() / "provision.json"


def load_provision() -> dict:
    p = provision_file()
    if not p.is_file():
        raise Unavailable(f"the realm was not provisioned: run live/idp/provision.py ({p} is missing)")
    return json.loads(p.read_text(encoding="utf-8"))


_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_default = urllib.request.build_opener()


def http(method: str, url: str, *, headers: dict | None = None, body: bytes | None = None, timeout: float = TIMEOUT) -> tuple:
    """(status, headers, bytes). An HTTP error status is returned, not raised;
    a connection failure raises Unavailable."""
    host = urllib.parse.urlsplit(url).hostname or ""
    opener = _direct if host in _LOOPBACK else _default
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except (urllib.error.URLError, OSError) as e:
        raise Unavailable(f"{method} {url.split('?')[0]}: {getattr(e, 'reason', e)}") from None


def reachable(url: str) -> bool:
    try:
        return http("GET", url + "/realms/master", timeout=10)[0] == 200
    except Unavailable:
        return False


class KeycloakError(Exception):
    def __init__(self, status: int, method: str, path: str, body: bytes):
        super().__init__(f"{method} {path}: HTTP {status} {body[:300].decode('utf-8', 'replace')}")
        self.status = status


class Admin:
    """Admin REST client. Logs in with the admin user (password grant on the
    master realm's admin-cli client) and renews the token before it expires."""

    def __init__(self, url: str, user: str, password: str):
        self.url, self._user, self._password = url.rstrip("/"), user, password
        self._token, self._exp = None, 0.0

    @classmethod
    def connect(cls) -> "Admin":
        where = locate()
        if not reachable(where["url"]):
            raise Unavailable(f"Keycloak does not answer at {where['url']}")
        a = cls(where["url"], where["admin"], where["password"])
        a.token()
        return a

    def token(self) -> str:
        if self._token is None or time.time() > self._exp - 15:
            r = token_request(self.url, "master", {"grant_type": "password", "client_id": "admin-cli", "username": self._user,
                                                   "password": self._password})
            if "access_token" not in r:
                raise Unavailable(f"the Keycloak admin login was refused ({r.get('error', 'no token')})")
            self._token, self._exp = r["access_token"], time.time() + int(r.get("expires_in", 60))
        return self._token

    def call(self, method: str, path: str, body=None, *, ok: tuple = (200, 201, 204), query: dict | None = None):
        url = f"{self.url}/admin{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {"Authorization": f"Bearer {self.token()}", "Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        status, got, raw = http(method, url, headers=headers, body=data)
        if status not in ok:
            raise KeycloakError(status, method, path, raw)
        self.last_headers = {k.lower(): v for k, v in got.items()}
        return json.loads(raw) if raw.strip() else None

    def get(self, path: str, **query):
        return self.call("GET", path, query=query or None)

    def post(self, path: str, body=None, **kw):
        return self.call("POST", path, body, **kw)

    def put(self, path: str, body=None, **kw):
        return self.call("PUT", path, body, **kw)

    def delete(self, path: str, body=None, **kw):
        return self.call("DELETE", path, body, **kw)

    def created_id(self) -> str:
        """The id in the Location header of the POST that just returned 201."""
        return self.last_headers["location"].rstrip("/").rsplit("/", 1)[1]

    # -- lookups the tests and the provisioner share --------------------------------
    def realm_exists(self, realm: str) -> bool:
        try:
            self.get(f"/realms/{realm}")
            return True
        except KeycloakError as e:
            if e.status == 404:
                return False
            raise

    def user_id(self, realm: str, username: str) -> str | None:
        found = self.get(f"/realms/{realm}/users", username=username, exact="true")
        return found[0]["id"] if found else None

    def group_by_path(self, realm: str, path: str) -> dict | None:
        try:
            return self.get(f"/realms/{realm}/group-by-path/{urllib.parse.quote(path.strip('/'))}")
        except KeycloakError as e:
            if e.status == 404:
                return None
            raise

    def client(self, realm: str, client_id: str) -> dict | None:
        found = self.get(f"/realms/{realm}/clients", clientId=client_id)
        return found[0] if found else None

    def join(self, realm: str, username: str, path: str) -> None:
        self.put(f"/realms/{realm}/users/{self.user_id(realm, username)}/groups/{self.group_by_path(realm, path)['id']}")

    def leave(self, realm: str, username: str, path: str) -> None:
        self.delete(f"/realms/{realm}/users/{self.user_id(realm, username)}/groups/{self.group_by_path(realm, path)['id']}")

    def version(self) -> str:
        return self.get("/serverinfo")["systemInfo"]["version"]


def token_request(url: str, realm: str, form: dict) -> dict:
    """POST to the realm's token endpoint. Returns the JSON answer, error
    answers included ({"error": ..., "error_description": ...})."""
    status, _, raw = http("POST", f"{url}/realms/{realm}/protocol/openid-connect/token",
                          headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                          body=urllib.parse.urlencode(form).encode("ascii"))
    try:
        out = json.loads(raw)
    except ValueError:
        raise Unavailable(f"the token endpoint of realm {realm} answered HTTP {status} without JSON") from None
    if isinstance(out, dict):
        out["_status"] = status
    return out


def sign_in(url: str, realm: str, client_id: str, client_secret: str | None, username: str, password: str, scope: str = "openid") -> dict:
    """Direct access grant (resource owner password credentials): the test
    stand-in for a human signing in. Production uses the authorization-code
    flow in a browser; the tokens that come back have the same claims.
    Returns {"id_token", "access_token", "refresh_token", ...} or the error answer."""
    form = {"grant_type": "password", "client_id": client_id, "username": username, "password": password, "scope": scope}
    if client_secret:
        form["client_secret"] = client_secret
    return token_request(url, realm, form)


def client_credentials(url: str, realm: str, client_id: str, client_secret: str) -> dict:
    return token_request(url, realm, {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret})


def jwks(url: str, realm: str) -> dict:
    status, _, raw = http("GET", f"{url}/realms/{realm}/protocol/openid-connect/certs")
    if status != 200:
        raise Unavailable(f"JWKS of realm {realm}: HTTP {status}")
    return json.loads(raw)


def issuer(url: str, realm: str) -> str:
    return f"{url}/realms/{realm}"


def b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def claims_of(jwt: str) -> dict:
    """The payload of a JWT, NOT verified. For looking at what Keycloak sent."""
    return json.loads(b64u(jwt.split(".")[1]))


def header_of(jwt: str) -> dict:
    return json.loads(b64u(jwt.split(".")[0]))
