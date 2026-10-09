"""Okta directory adapter (Okta Management API).

Written from:
  https://developer.okta.com/docs/reference/core-okta-api/   `Authorization: SSWS <token>`;
      pagination by the `Link` header, rel="next" ("follow these Link header values instead of
      constructing your own URLs"); the listing ends when there is no next link
  https://developer.okta.com/docs/reference/user-query/      GET /api/v1/users: default and
      maximum limit 200; DEPROVISIONED users are not returned by a plain list
  https://developer.okta.com/okta-sdk-java/apidocs/org/openapitools/client/api/GroupApi.html
      GET /api/v1/groups and GET /api/v1/groups/{groupId}/users with `limit` and `after`
Tested only against the fake Okta in tests/. No Okta org was contacted.

# UNVERIFIED: the full list of user `status` values. The pages read name STAGED, PROVISIONED,
# ACTIVE, LOCKED_OUT and DEPROVISIONED; RECOVERY, PASSWORD_EXPIRED and SUSPENDED are from memory.
# Any status not in `active_statuses` is treated as inactive, so an unknown value fails closed.
# UNVERIFIED: that Okta groups cannot contain groups (this adapter reads no nesting).
# UNVERIFIED: the object shapes (`id`, `status`, `profile.login`, `profile.name`): the OpenAPI
# reference pages did not render for the fetch tool.
"""
from __future__ import annotations

import urllib.parse

from . import BridgeError
from .directory import Group, Snapshot, User
from .http import Transport, pages_by_link_header, safe_url, secret_from_env, str_field, urllib_transport

#: statuses under which the account exists and has not been disabled by an administrator
ACTIVE_STATUSES = ("ACTIVE", "PASSWORD_EXPIRED", "RECOVERY", "LOCKED_OUT")


def _org(org: str) -> str:
    org = org.strip().rstrip("/")
    return org if "://" in org else "https://" + org


def fetch(org: str, *, token_env: str = "OKTA_API_TOKEN", transport: Transport = urllib_transport,
          active_statuses: tuple = ACTIVE_STATUSES, max_pages: int = 10000, env=None) -> Snapshot:
    """Users, groups and memberships of an Okta org (`org`: "example.okta.com" or its https URL).

    The API token is read from the environment variable `token_env` and sent
    as `Authorization: SSWS ...`. Guarantees: every listing follows the Link
    header to the end (next links to another host, or repeating, raise);
    a user whose `status` is not in `active_statuses` is `active=False`;
    members that the user listing did not return (deprovisioned) are ignored.
    A read-only administrator token is enough."""
    base = _org(org)
    headers = {"Authorization": "SSWS " + secret_from_env(token_env, env), "Accept": "application/json"}
    snap = Snapshot(source=f"okta:{safe_url(base)}")
    for page in pages_by_link_header(transport, base + "/api/v1/users?limit=200", headers, max_pages=max_pages):
        for u in page:
            uid, profile = str_field(u, "id", "Okta user"), u.get("profile")
            if not isinstance(profile, dict):
                raise BridgeError("malformed_response", "Okta user: 'profile' is missing")
            status = str_field(u, "status", "Okta user")
            attrs = {k: v for k, v in profile.items() if isinstance(v, (str, bool, int))}
            snap.users[uid] = User(uid, str_field(profile, "login", "Okta user profile"), status in active_statuses, {**attrs, "status": status})
    for page in pages_by_link_header(transport, base + "/api/v1/groups?limit=200", headers, max_pages=max_pages):
        for g in page:
            gid, profile = str_field(g, "id", "Okta group"), g.get("profile")
            if not isinstance(profile, dict):
                raise BridgeError("malformed_response", "Okta group: 'profile' is missing")
            snap.groups[gid] = Group(gid, str_field(profile, "name", "Okta group profile"))
    for gid in sorted(snap.groups):
        url = f"{base}/api/v1/groups/{urllib.parse.quote(gid, safe='')}/users?limit=200"
        for page in pages_by_link_header(transport, url, headers, max_pages=max_pages):
            for m in page:
                uid = str_field(m, "id", "Okta group member")
                if uid in snap.users:
                    snap.add_member(uid, gid)
    return snap
