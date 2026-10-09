"""Microsoft Entra ID directory adapter (Microsoft Graph v1.0).

Written from:
  https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0   GET /users; page size
      100 by default, 999 at most; `accountEnabled` only with $select; `@odata.nextLink`;
      least-privileged application permission User.Read.All
  https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0  GET /groups, same paging
  https://learn.microsoft.com/en-us/graph/api/group-list-transitivemembers?view=graph-rest-1.0
      GET /groups/{id}/transitiveMembers; `@odata.type` "#microsoft.graph.user" / "...group";
      application permission GroupMember.Read.All (or GroupMember.ReadBasic.All)
  https://learn.microsoft.com/en-us/graph/api/directoryobject-getmembergroups?view=graph-rest-1.0
      POST /users/{id}/getMemberGroups {"securityEnabledOnly": bool}; transitive; `value` is a list
      of group ids; at most 11,000, else HTTP 400
  https://learn.microsoft.com/en-us/graph/auth-v2-service   client-credentials token request
Tested only against the fake Graph in tests/. No tenant was contacted.

# UNVERIFIED: GET /groups/{id}/members (used with nested="direct") was not read in detail; it is
# assumed to have the same shape and paging as transitiveMembers.
# UNVERIFIED: whether getMemberGroups can answer with `@odata.nextLink`. The page read does not
# mention paging; `member_groups` raises if a next link appears rather than return a partial list.
# UNVERIFIED: whether `@odata.type` is still present on members when `$select=id` is used. A member
# without it is classified by looking its id up among the listed users and groups.
"""
from __future__ import annotations

import re
import urllib.parse

from . import BridgeError
from .directory import Group, Snapshot, User
from .http import Transport, bearer, pages_by_next_link, post_form, post_json, secret_from_env, str_field, urllib_transport

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
_TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")
_USER_SELECT = "id,userPrincipalName,displayName,accountEnabled,mail,department,jobTitle,companyName,country,userType"


def token_url(tenant: str) -> str:
    """The v2.0 token endpoint of a tenant (GUID or domain)."""
    if not isinstance(tenant, str) or not _TENANT.fullmatch(tenant):
        raise BridgeError("invalid_input", "tenant must be a tenant id or domain name")
    return f"{LOGIN}/{tenant}/oauth2/v2.0/token"


def token_request(tenant: str, client_id: str, *, scope: str = "https://graph.microsoft.com/.default") -> dict:
    """The client-credentials (app-only) token request, WITHOUT the secret:
    {"method", "url", "headers", "form"}. The caller adds `client_secret` (or
    `client_assertion` + `client_assertion_type` for a certificate) to
    `form` and posts it, or uses `acquire_token`."""
    return {"method": "POST", "url": token_url(tenant), "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "form": {"client_id": client_id, "scope": scope, "grant_type": "client_credentials"}}


def acquire_token(tenant: str, client_id: str, *, secret_env: str, transport: Transport = urllib_transport, env=None) -> str:
    """Perform the client-credentials request and return the access token.
    The client secret is read from the environment variable `secret_env`,
    sent only to login.microsoftonline.com, and appears in no error."""
    req = token_request(tenant, client_id)
    answer = post_form(transport, req["url"], {**req["form"], "client_secret": secret_from_env(secret_env, env)})
    token = answer.get("access_token") if isinstance(answer, dict) else None
    if not isinstance(token, str) or not token:
        raise BridgeError("malformed_response", "the token endpoint returned no access_token")
    return token


def _token(token, token_env, env) -> str:
    if token:
        return token
    if token_env:
        return secret_from_env(token_env, env)
    raise BridgeError("no_credential", "pass token= (from acquire_token) or token_env=")


def fetch(*, token: str | None = None, token_env: str | None = None, transport: Transport = urllib_transport,
          nested: str = "transitive", graph: str = GRAPH, max_pages: int = 10000, env=None) -> Snapshot:
    """Users, groups and memberships of an Entra tenant.

    `token` is a Graph access token (see `acquire_token`), or `token_env`
    names the environment variable that holds one. Application permissions:
    User.Read.All and GroupMember.Read.All (read-only).

    nested="transitive" (default): each group's /transitiveMembers is read, so
    a user is recorded as a member of every group they reach through nesting.
    nested="direct": /members is read and nested groups become `parents`.

    Guarantees: all pages are read (`@odata.nextLink` to another host, or
    repeating, raises); a user is active only when `accountEnabled` is true;
    members that are neither listed users nor listed groups (devices, service
    principals, contacts) are ignored."""
    if nested not in ("transitive", "direct"):
        raise BridgeError("invalid_input", "nested must be 'transitive' or 'direct'")
    headers = {**bearer(_token(token, token_env, env)), "Accept": "application/json"}
    snap = Snapshot(source="entra:graph")
    for page in pages_by_next_link(transport, f"{graph}/users?$select={_USER_SELECT}&$top=999", headers, max_pages=max_pages):
        for u in page:
            uid = str_field(u, "id", "Graph user")
            attrs = {k: v for k, v in u.items() if isinstance(v, (str, bool)) and not k.startswith("@")}
            snap.users[uid] = User(uid, str_field(u, "userPrincipalName", "Graph user"), u.get("accountEnabled") is True, attrs)
    for page in pages_by_next_link(transport, f"{graph}/groups?$select=id,displayName,securityEnabled&$top=999", headers, max_pages=max_pages):
        for g in page:
            gid = str_field(g, "id", "Graph group")
            snap.groups[gid] = Group(gid, str_field(g, "displayName", "Graph group"))
    rel = "transitiveMembers" if nested == "transitive" else "members"
    for gid in sorted(snap.groups):
        url = f"{graph}/groups/{urllib.parse.quote(gid, safe='')}/{rel}?$select=id&$top=999"
        for page in pages_by_next_link(transport, url, headers, max_pages=max_pages):
            for m in page:
                mid = str_field(m, "id", "Graph group member")
                kind = m.get("@odata.type") or ""
                if kind == "#microsoft.graph.user" or (not kind and mid in snap.users):
                    if mid in snap.users:
                        snap.add_member(mid, gid)
                elif kind == "#microsoft.graph.group" or (not kind and mid in snap.groups):
                    if nested == "direct" and mid in snap.groups and mid != gid:
                        snap.groups[mid].parents.add(gid)
    return snap


def member_groups(user_id: str, *, token: str | None = None, token_env: str | None = None, transport: Transport = urllib_transport,
                  security_enabled_only: bool = False, graph: str = GRAPH, env=None) -> list:
    """The object ids of every group the user is in, transitively
    (POST /users/{id}/getMemberGroups). This is how a groups OVERAGE is
    resolved: when a token has `_claim_names`/`hasgroups` instead of `groups`,
    call this with the token's `oid` and pass the result (through a
    `claims`-style map) as `groups`.

    Guarantees: a sorted list of strings, or BridgeError. More than 11,000
    groups is an HTTP 400 at Graph and therefore an error here, never a
    shortened list."""
    if not isinstance(user_id, str) or not user_id:
        raise BridgeError("invalid_input", "user_id is required (the token's oid claim)")
    url = f"{graph}/users/{urllib.parse.quote(user_id, safe='@')}/getMemberGroups"
    answer, _ = post_json(transport, url, {"securityEnabledOnly": bool(security_enabled_only)},
                          {**bearer(_token(token, token_env, env)), "Accept": "application/json"})
    value = answer.get("value") if isinstance(answer, dict) else None
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise BridgeError("malformed_response", "getMemberGroups: 'value' is not a list of ids")
    if answer.get("@odata.nextLink"):
        raise BridgeError("truncated_pagination", "getMemberGroups answered with a next link; refusing a partial group list")
    return sorted(set(value))
