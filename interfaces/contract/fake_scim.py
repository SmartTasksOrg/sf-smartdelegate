"""An in-process stand-in for a SCIM 2.0 server holding the kit directory
(directory_fixture.json). It is a `Transport` (sf_smartdelegate.bridges.http):
no socket is opened. `fault` makes it misbehave the way the DirectorySource
checks need: "unreachable" (HTTP 503 on every call) or "truncated" (it
reports more results than it ever returns)."""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

FIXTURE = json.loads((Path(__file__).parent / "directory_fixture.json").read_text(encoding="utf-8"))
LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
TOKEN_ENV = "KIT_SCIM_TOKEN"
ENV = {TOKEN_ENV: "kit-scim-token-not-a-secret"}
BASE = "http://127.0.0.1:9/scim/v2"       # never contacted: the transport below answers


def transport(fault: str | None = None, page: int = 4):
    users = [{"id": f"u-{u['name']}", "userName": u["name"], "active": u["active"]} for u in FIXTURE["users"]]
    groups = []
    for g in FIXTURE["groups"]:
        members = [{"value": f"u-{u}", "type": "User"} for u, gs in FIXTURE["memberships"].items() if g["name"] in gs]
        members += [{"value": f"g-{c['name']}", "type": "Group"} for c in FIXTURE["groups"] if g["name"] in c["parents"]]
        groups.append({"id": f"g-{g['name']}", "displayName": g["name"], "members": members})

    def call(method: str, url: str, headers: dict, body):
        if headers.get("Authorization") != f"Bearer {ENV[TOKEN_ENV]}":
            return 401, {}, b"{}"
        if fault == "unreachable":
            return 503, {}, b"{}"
        parts = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qs(parts.query)
        start, count = int(q.get("startIndex", ["1"])[0]), min(int(q.get("count", ["100"])[0]), page)
        items = users if parts.path.endswith("/Users") else groups
        chunk = items[start - 1:start - 1 + count]
        total = len(items)
        if fault == "truncated":
            total, chunk = len(items) + 3, (chunk if start == 1 else [])
        doc = {"schemas": [LIST], "totalResults": total, "startIndex": start, "itemsPerPage": len(chunk), "Resources": chunk}
        return 200, {"content-type": "application/scim+json"}, json.dumps(doc).encode("utf-8")

    return call
