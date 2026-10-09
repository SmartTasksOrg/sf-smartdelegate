"""Google Workspace / Cloud Identity directory adapter (Admin SDK Directory API).

Written from:
  https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/list
      GET https://admin.googleapis.com/admin/directory/v1/users  customer ("my_customer"), domain,
      pageToken -> `users`, `nextPageToken`; scope .../auth/admin.directory.user.readonly
  https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list
      GET .../groups  customer, domain, maxResults (max 200), pageToken -> `groups`, `nextPageToken`;
      scope .../auth/admin.directory.group.readonly
  https://developers.google.com/admin-sdk/directory/reference/rest/v1/members/list
      GET .../groups/{groupKey}/members  maxResults (max 200), pageToken -> `members`, `nextPageToken`
  https://developers.google.com/admin-sdk/directory/reference/rest/v1/members
      Member.type: CUSTOMER | EXTERNAL | GROUP | USER
Tested only against the fake Directory API in tests/. Google was not contacted.

Not implemented: obtaining the access token. A service account with domain-wide delegation
signs a JWT with RSA, which the standard library cannot do; get the token with google-auth (or
`gcloud`) and put it in the environment variable named by `token_env`.

# UNVERIFIED: a member of type CUSTOMER ("all users in a domain") is IGNORED: a group that
# contains the whole domain gives nobody membership here. That under-grants on purpose; the
# semantics were not read closely enough to add every user to a group on their strength.
# UNVERIFIED: the User fields `suspended` and `archived` (named on the users.list page, not
# read from the User resource page); a user with either set to true is inactive.
"""
from __future__ import annotations

import urllib.parse

from . import BridgeError
from .directory import Group, Snapshot, User
from .http import PageGuard, Transport, bearer, get_json, safe_url, secret_from_env, str_field, urllib_transport, with_query

API = "https://admin.googleapis.com/admin/directory/v1"


def _list(transport: Transport, url: str, params: dict, key: str, headers: dict, max_pages: int) -> list:
    """Every item under `key` of a pageToken listing. A repeated page token raises."""
    guard = PageGuard(url, max_pages)
    token, out = None, []
    while True:
        guard.step(token)
        page, _ = get_json(transport, with_query(url, {**params, "pageToken": token}), headers)
        if not isinstance(page, dict) or not isinstance(page.get(key, []), list):
            raise BridgeError("malformed_response", f"GET {safe_url(url)}: expected an object with a '{key}' list")
        out.extend(page.get(key, []))
        token = page.get("nextPageToken")
        if token is None or token == "":
            return out
        if not isinstance(token, str):
            raise BridgeError("malformed_response", f"GET {safe_url(url)}: nextPageToken is not a string")


def fetch(*, customer: str = "my_customer", domain: str | None = None, token_env: str, transport: Transport = urllib_transport,
          api: str = API, max_pages: int = 10000, env=None) -> Snapshot:
    """Users, groups and memberships of a Google Workspace / Cloud Identity account.

    The OAuth access token is read from the environment variable `token_env`;
    it needs the read-only scopes admin.directory.user.readonly and
    admin.directory.group.readonly (admin.directory.group.member.readonly for
    members). Guarantees: all pages are read; a suspended or archived user is
    inactive; a member of type GROUP becomes nesting; EXTERNAL and CUSTOMER
    members are ignored (they grant nothing); an unknown member type raises."""
    headers = {**bearer(secret_from_env(token_env, env)), "Accept": "application/json"}
    scope = {"domain": domain} if domain else {"customer": customer}
    snap = Snapshot(source=f"google:{domain or customer}")
    for u in _list(transport, api + "/users", scope, "users", headers, max_pages):
        uid, email = str_field(u, "id", "Google user"), str_field(u, "primaryEmail", "Google user")
        attrs = {"primaryEmail": email}
        if isinstance(u.get("orgUnitPath"), str):
            attrs["orgUnitPath"] = u["orgUnitPath"]
        if isinstance(u.get("name"), dict) and isinstance(u["name"].get("fullName"), str):
            attrs["fullName"] = u["name"]["fullName"]
        snap.users[uid] = User(uid, email, not (u.get("suspended") is True or u.get("archived") is True), attrs)
    for g in _list(transport, api + "/groups", {**scope, "maxResults": 200}, "groups", headers, max_pages):
        gid = str_field(g, "id", "Google group")
        snap.groups[gid] = Group(gid, str_field(g, "email", "Google group"))
    for gid in sorted(snap.groups):
        url = f"{api}/groups/{urllib.parse.quote(gid, safe='')}/members"
        for m in _list(transport, url, {"maxResults": 200}, "members", headers, max_pages):
            kind = m.get("type") if isinstance(m, dict) else None
            if kind == "USER":
                if m.get("id") in snap.users:
                    snap.add_member(m["id"], gid)
            elif kind == "GROUP":
                if m.get("id") in snap.groups and m["id"] != gid:
                    snap.groups[m["id"]].parents.add(gid)
            elif kind not in ("EXTERNAL", "CUSTOMER"):
                raise BridgeError("malformed_response", "Google group member: unknown member type")
    return snap
