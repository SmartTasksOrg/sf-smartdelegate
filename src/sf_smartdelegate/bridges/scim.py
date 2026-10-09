"""SCIM 2.0 directory adapter (any provider that exposes a SCIM server: Ping,
OneLogin, JumpCloud, a home-grown HR system, ...).

Written from:
  RFC 7644 (protocol)  https://www.rfc-editor.org/info/rfc7644/   section 3.4.2.4: `startIndex`
      (1-based), `count`; response `totalResults`, `itemsPerPage`, `startIndex`, `Resources`;
      schema urn:ietf:params:scim:api:messages:2.0:ListResponse; media type application/scim+json
  RFC 7643 (schema)    https://rfc-editor.org/rfc/rfc7643   `userName`, `active`, group
      `members` with `value`, `$ref`, `type` ("User" | "Group"); the enterprise extension
      urn:ietf:params:scim:schemas:extension:enterprise:2.0:User
Tested only against the fake SCIM server in tests/. No real SCIM server was contacted.

# UNVERIFIED: a user without an `active` attribute is treated as active (the attribute is
# optional); a server that signals deactivation some other way keeps such users active here.
# UNVERIFIED: some SCIM servers leave `members` out of GET /Groups unless it is asked for
# (`attributes=members`), and some cap `count` silently. This adapter sends plain
# startIndex/count and trusts `totalResults`; a server that omits `members` gives every user
# no groups, which `directory.write_entities` then refuses (removal guard).
"""
from __future__ import annotations

from . import BridgeError
from .directory import Group, Snapshot, User
from .http import PageGuard, Transport, bearer, get_json, safe_url, secret_from_env, str_field, urllib_transport, with_query

LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


def _list(transport: Transport, url: str, headers: dict, page_size: int, max_pages: int) -> list:
    """Every resource of a SCIM listing. Raises unless the number of distinct
    resources collected equals the server's `totalResults`."""
    guard = PageGuard(url, max_pages)
    start, out, seen = 1, [], set()
    while True:
        guard.step(start)
        page, _ = get_json(transport, with_query(url, {"startIndex": start, "count": page_size}), headers)
        if not isinstance(page, dict) or LIST_RESPONSE not in (page.get("schemas") or []):
            raise BridgeError("malformed_response", f"GET {safe_url(url)}: not a SCIM ListResponse")
        total, resources = page.get("totalResults"), page.get("Resources", [])
        if not isinstance(total, int) or isinstance(total, bool) or total < 0 or not isinstance(resources, list):
            raise BridgeError("malformed_response", f"GET {safe_url(url)}: totalResults or Resources is malformed")
        before = len(out)
        for r in resources:
            rid = str_field(r, "id", f"GET {safe_url(url)}")
            if rid not in seen:
                seen.add(rid)
                out.append(r)
        if len(out) >= total:
            return out
        if not resources:
            raise BridgeError("truncated_pagination", f"GET {safe_url(url)}: the server reported {total} results but returned only {len(out)}")
        if len(out) == before:
            raise BridgeError("pagination_loop", f"GET {safe_url(url)}: the server returned a page it had already returned")
        start += len(resources)


def fetch(base_url: str, *, token_env: str, transport: Transport = urllib_transport, page_size: int = 100,
          max_pages: int = 10000, env=None) -> Snapshot:
    """Users, groups and memberships of a SCIM 2.0 server.

    `base_url` is the SCIM root (".../scim/v2"); the bearer token is read from
    the environment variable `token_env`. Guarantees: all pages are read and
    the count is checked against `totalResults`, or BridgeError; users with
    `active: false` are in the snapshot with `active=False`; a group member of
    type Group becomes nesting; a member that is neither a listed user nor a
    listed group is ignored (it grants nothing)."""
    headers = {**bearer(secret_from_env(token_env, env)), "Accept": "application/scim+json, application/json"}
    base = base_url.rstrip("/")
    snap = Snapshot(source=f"scim:{safe_url(base)}")
    for r in _list(transport, base + "/Users", headers, page_size, max_pages):
        active = r.get("active", True)
        if not isinstance(active, bool):
            raise BridgeError("malformed_response", "SCIM user: 'active' is not a boolean")
        attrs = {k: r[k] for k in ("userName", "displayName", "externalId", "userType", "title") if isinstance(r.get(k), str)}
        emails = [e for e in (r.get("emails") or []) if isinstance(e, dict) and isinstance(e.get("value"), str)]
        if emails:
            attrs["email"] = next((e["value"] for e in emails if e.get("primary") is True), emails[0]["value"])
        ext = r.get(ENTERPRISE)
        if isinstance(ext, dict):
            attrs[ENTERPRISE] = ext
            attrs.update({k: ext[k] for k in ("department", "organization", "division", "costCenter", "employeeNumber") if isinstance(ext.get(k), str)})
        snap.users[r["id"]] = User(r["id"], str_field(r, "userName", "SCIM user"), active, attrs)
    groups = _list(transport, base + "/Groups", headers, page_size, max_pages)
    for g in groups:
        snap.groups[g["id"]] = Group(g["id"], str_field(g, "displayName", "SCIM group"))
    for g in groups:
        members = g.get("members", [])
        if not isinstance(members, list):
            raise BridgeError("malformed_response", "SCIM group: 'members' is not a list")
        for m in members:
            value = str_field(m, "value", "SCIM group member")
            kind = (m.get("type") or "").lower() if isinstance(m.get("type"), str) else ""
            ref = m.get("$ref") if isinstance(m.get("$ref"), str) else ""
            if not kind:
                kind = "group" if "/Groups/" in ref else "user" if "/Users/" in ref else ""
            if kind == "group" or (not kind and value in snap.groups):
                if value in snap.groups and value != g["id"]:
                    snap.groups[value].parents.add(g["id"])
            elif value in snap.users:
                snap.add_member(value, g["id"])
    return snap
