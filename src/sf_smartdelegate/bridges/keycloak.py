"""Keycloak directory adapter (Admin REST API).

Written from:
  https://www.keycloak.org/docs-api/latest/rest-api/index.html
      GET /admin/realms/{realm}/users              first, max (default 100), briefRepresentation
      GET /admin/realms/{realm}/users/count
      GET /admin/realms/{realm}/groups             first, max; GroupRepresentation id, name, path,
                                                   subGroupCount, subGroups
      GET /admin/realms/{realm}/groups/{id}/children   first, max
      GET /admin/realms/{realm}/groups/{id}/members    first, max (default 100)
      UserRepresentation: id, username, enabled, email, firstName, lastName, attributes

Tested against a real Keycloak 26.0.7 (live/idp/, 2026-10-05), a second time against 26.8.0, and
against the fake Keycloak in tests/. What the real server does, each point covered by
live/idp/test_live_idp.py (the two versions differ in one answer, noted below):

  * GET /groups returns `"subGroups": []` together with `subGroupCount`; the children are only
    reachable through /groups/{id}/children (a `search=` listing does fill `subGroups`). Older
    servers that fill `subGroups` are handled too, but no such server was contacted.
  * /users and /groups/{id}/members return at most 100 items unless `max` says otherwise.
  * /users/count counts exactly what the unfiltered listing returns. Service-account users are
    in neither.
  * /groups/{id}/members lists DIRECT members only, disabled users included. A member of
    /support/eu is not listed under /support. Keycloak itself does treat the child group as
    inheriting the parent's role mappings (a realm role mapped on /support reaches a member of
    /support/eu), but its `groups` token claim lists direct memberships only. Default here: NO
    inheritance; `inherit=True` gives the child group the parent as `parents`.
  * Least privilege: the `realm-management` client role `view-users` alone is enough (it is a
    composite of `query-users` and `query-groups`). With `query-users` + `query-groups` but
    WITHOUT `view-users` the server answers 200 with EMPTY listings, not 403. /users/count then
    says 0 on 26.0.7 and the real number on 26.8.0. An empty user listing is therefore refused
    here (`empty_directory`, or `truncated_pagination` when the count disagrees) instead of
    being read as "the realm has no users".
  * A group name may contain "/", and Keycloak does not escape it in `path`: a top-level group
    named "support/eu" has the same path as the subgroup "eu" of "support". Two groups with
    the same path are refused here (`ambiguous_group_path`): by name they cannot be told apart.

# UNVERIFIED: Keycloak versions other than 26.0.7 and 26.8.0; a clustered Keycloak; realms with user
# federation (LDAP) or with fine-grained admin permissions enabled.
"""
from __future__ import annotations

import urllib.parse

from . import BridgeError
from .directory import Group, Snapshot, User
from .http import PageGuard, Transport, bearer, get_json, post_form, safe_url, secret_from_env, str_field, urllib_transport, with_query


def _paged(transport: Transport, url: str, headers: dict, page_size: int, max_pages: int, extra: dict | None = None) -> list:
    """Every item of a first/max listing: pages are requested until one comes
    back empty. A page that repeats items already seen (a server ignoring
    `first`) raises instead of looping."""
    guard = PageGuard(url, max_pages)
    first, out, seen = 0, [], set()
    while True:
        guard.step(first)
        page, _ = get_json(transport, with_query(url, {"first": first, "max": page_size, **(extra or {})}), headers)
        if not isinstance(page, list):
            raise BridgeError("malformed_response", f"GET {safe_url(url)}: expected a JSON list")
        if not page:
            return out
        for item in page:
            iid = str_field(item, "id", f"GET {safe_url(url)}")
            if iid in seen:
                raise BridgeError("pagination_loop", f"GET {safe_url(url)}: the server returned an item twice")
            seen.add(iid)
            out.append(item)
        first += len(page)


def acquire_token(base_url: str, realm: str, client_id: str, *, secret_env: str, transport: Transport = urllib_transport, env=None) -> str:
    """An admin access token for a service-account client (client-credentials
    grant at /realms/{realm}/protocol/openid-connect/token). The client secret
    is read from the environment variable `secret_env`. The client needs
    "Service accounts roles" enabled and the realm-management client role
    `view-users`. The token is returned, never stored; pass it on through an
    environment variable of your own (`fetch(..., token_env=...)`)."""
    url = f"{base_url.rstrip('/')}/realms/{urllib.parse.quote(realm, safe='')}/protocol/openid-connect/token"
    answer = post_form(transport, url, {"grant_type": "client_credentials", "client_id": client_id,
                                        "client_secret": secret_from_env(secret_env, env)})
    return str_field(answer, "access_token", "Keycloak token endpoint")


def fetch(base_url: str, realm: str, *, token_env: str, transport: Transport = urllib_transport, page_size: int = 100,
          inherit: bool = False, max_pages: int = 10000, env=None) -> Snapshot:
    """Users, groups (with subgroups) and memberships of a Keycloak realm.

    `base_url` is the server root (with "/auth" on old installations); the
    admin access token is read from the environment variable `token_env`
    (role needed on realm-management: view-users; see `acquire_token`).
    Guarantees: the user listing is checked against /users/count; an empty
    user listing raises (`empty_directory`); group names are full paths
    ("/support/eu") and two groups with the same path raise; subgroups are
    listed as groups of their own and, only with `inherit=True`, nested under
    their parent; a user with `enabled` other than true is inactive; any
    malformed page or HTTP error raises.

    The access token of a service account lives 5 minutes by default
    (the realm's access token lifespan). A sync that takes longer fails with
    HTTP 401 and writes nothing; raise the lifespan for that client."""
    root = f"{base_url.rstrip('/')}/admin/realms/{urllib.parse.quote(realm, safe='')}"
    headers = {**bearer(secret_from_env(token_env, env)), "Accept": "application/json"}
    snap = Snapshot(source=f"keycloak:{safe_url(root)}")
    for u in _paged(transport, root + "/users", headers, page_size, max_pages, {"briefRepresentation": "false"}):
        attrs = {k: u[k] for k in ("username", "email", "firstName", "lastName") if isinstance(u.get(k), str)}
        for k, v in (u.get("attributes") or {}).items() if isinstance(u.get("attributes"), dict) else []:
            if isinstance(v, list) and all(isinstance(x, str) for x in v):
                attrs.setdefault(k, v[0] if len(v) == 1 else v)
        snap.users[u["id"]] = User(u["id"], str_field(u, "username", "Keycloak user"), u.get("enabled") is True, attrs)
    count, _ = get_json(transport, root + "/users/count", headers)
    if not isinstance(count, int) or isinstance(count, bool):
        raise BridgeError("malformed_response", "Keycloak /users/count: not a number")
    if len(snap.users) < count:
        raise BridgeError("truncated_pagination", f"Keycloak reports {count} users but the listing returned {len(snap.users)}")
    if not snap.users:
        # A credential with query-users but without view-users gets 200 and an empty list, never 403.
        raise BridgeError("empty_directory", "Keycloak returned no users at all. A credential without the realm-management role "
                                             "'view-users' is answered with an empty listing instead of an error; nothing is read from it")

    paths: set = set()

    def walk(g: dict, parent: str | None, depth: int) -> None:
        if depth > 64:
            raise BridgeError("malformed_response", "Keycloak groups are nested deeper than 64 levels")
        gid = str_field(g, "id", "Keycloak group")
        if gid in snap.groups:
            raise BridgeError("malformed_response", "Keycloak returned the same group twice")
        path = g.get("path") if isinstance(g.get("path"), str) and g.get("path") else None
        name = path or ((snap.groups[parent].name if parent else "") + "/" + str_field(g, "name", "Keycloak group"))
        if name in paths:
            # "/" is legal in a group name and is not escaped in `path`: these are two different groups
            raise BridgeError("ambiguous_group_path", f"two Keycloak groups have the path {name!r} (a group name containing '/' "
                                                      "imitates a subgroup); they cannot be told apart by name. Rename one of them")
        paths.add(name)
        snap.groups[gid] = Group(gid, name, {parent} if parent and inherit else set())
        subs = g.get("subGroups") or []
        if not isinstance(subs, list):
            raise BridgeError("malformed_response", "Keycloak group: 'subGroups' is not a list")
        expected = g.get("subGroupCount")
        if isinstance(expected, int) and not isinstance(expected, bool) and expected > len(subs):
            subs = _paged(transport, f"{root}/groups/{urllib.parse.quote(gid, safe='')}/children", headers, page_size, max_pages)
        for s in subs:
            walk(s, gid, depth + 1)

    for g in _paged(transport, root + "/groups", headers, page_size, max_pages):
        walk(g, None, 0)
    for gid in sorted(snap.groups):
        for m in _paged(transport, f"{root}/groups/{urllib.parse.quote(gid, safe='')}/members", headers, page_size, max_pages):
            if m["id"] in snap.users:
                snap.add_member(m["id"], gid)
    return snap
