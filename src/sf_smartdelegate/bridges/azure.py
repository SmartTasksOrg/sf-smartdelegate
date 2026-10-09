"""Azure / Microsoft Entra: On-Behalf-Of scopes for a SmartDelegate capability,
and a ceiling from Azure RBAC permissions.

Plainly: Azure RBAC has no per-token session policy. There is nothing like an
AWS session policy or a Google access boundary for Azure Resource Manager; a
down-scoped ARM credential is not possible. For Azure the bound is therefore
  (a) the OAuth scopes requested in the On-Behalf-Of flow (coarse: per API permission),
  (b) the role ceiling computed from the human's own permissions (`ceiling_from_permissions`),
  (c) the SmartDelegate proxy in front of the API, which enforces the fine-grained capability.

Nothing here imports msal or azure-identity. Written from:
  https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow
      POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token with grant_type
      urn:ietf:params:oauth:grant-type:jwt-bearer, client_id, assertion, scope (space separated),
      requested_token_use=on_behalf_of, and client_secret or client_assertion(+_type)
  https://learn.microsoft.com/en-us/rest/api/authorization/permissions/list-for-resource-group?view=rest-authorization-2022-04-01
      GET https://management.azure.com/subscriptions/{id}/resourcegroups/{name}/providers/
      Microsoft.Authorization/permissions?api-version=2022-04-01 -> {"value": [{"actions",
      "notActions", "dataActions", "notDataActions"}], "nextLink"}
  https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions
      effective permissions = Actions - NotActions (DataActions - NotDataActions); `*` wildcards;
      NotActions is not a deny: another role assignment can still grant the action
Tested only on generated requests and hand-written permission lists. Azure was not contacted.

# UNVERIFIED: that one token request must name scopes of a single resource. That is the
# long-standing behaviour of the v2.0 endpoint but the page read does not say it; `obo_request`
# enforces it anyway (fewer scopes per token is the safe side).
# UNVERIFIED: `permissions_request` for a scope that is not a resource group (subscription or
# single resource): the URL is built by the same pattern, which was only read for resource groups.
# UNVERIFIED: wildcard matching details: `*` is matched anywhere in the string and
# case-insensitively. The page read shows `*` only as a whole segment or suffix.
# UNVERIFIED: whether the permissions API already accounts for deny assignments.
"""
from __future__ import annotations

import re

from . import BridgeError
from .cloudmap import allowed_pairs, not_enforced, pairs_to_cap, rules, select
from .entra import token_url

ARM = "https://management.azure.com"
API_VERSION = "2022-04-01"


def _resource_of(scope: str) -> str:
    """The resource (audience) a scope belongs to: everything before the last "/"."""
    if not isinstance(scope, str) or "://" not in scope or scope.endswith("/") or scope.count("/") < 3:
        raise BridgeError("map_invalid", f"azure scope '{scope}' must be a full URI such as https://graph.microsoft.com/Mail.Read")
    return scope.rsplit("/", 1)[0]


def scopes(cap, cloud_map: dict) -> dict:
    """The OAuth scopes a capability maps to, grouped by resource:
    {"by_resource": {resource: [scopes]}, "skipped": [...], "not_enforced": {...}}.

    Guarantee: a scope is listed only when the capability covers the rule's
    action AND its whole resource pattern. A scope cannot be narrowed to
    "this one mailbox item", so a capability narrower than the rule gets
    nothing from it (reported as "cannot_narrow"); the proxy enforces that
    part. Rules without `scopes` (RBAC-only rules) are not used here."""
    grants, skipped = select(cap, [r for r in rules(cloud_map, "azure")])
    by: dict = {}
    for g in grants:
        if "scopes" not in g.rule:
            continue
        if not g.whole:
            skipped.append({"action": g.rule["action"], "resource": g.resource, "reason": "cannot_narrow"})
            continue
        for s in g.rule["scopes"]:
            by.setdefault(_resource_of(s), set()).add(s)
    return {"by_resource": {r: sorted(v) for r, v in sorted(by.items())}, "skipped": skipped, "not_enforced": not_enforced(cap)}


def obo_request(cap, cloud_map: dict, *, tenant: str, client_id: str, user_assertion: str, resource: str | None = None) -> dict:
    """The On-Behalf-Of token request for a capability, WITHOUT the client
    credential: {"method", "url", "headers", "form"}. The caller adds
    `client_secret` (or `client_assertion` and `client_assertion_type`) to
    `form` and posts it, or passes the same values to msal's
    `acquire_token_on_behalf_of`.

    `user_assertion` is the access token the human's client sent to this
    service (audience: this service). It is passed through, not stored.

    Guarantees: `scope` holds only scopes the capability maps to (see
    `scopes`), all of ONE resource. When the capability maps to scopes of
    several resources, BridgeError("multiple_resources") is raised with the
    grouping in `.detail`; call again once per resource with `resource=`.
    BridgeError("no_scopes") when nothing maps: request no token."""
    got = scopes(cap, cloud_map)["by_resource"]
    if not got:
        raise BridgeError("no_scopes", "the capability maps to no OAuth scope; request no token")
    if resource is None:
        if len(got) > 1:
            raise BridgeError("multiple_resources", "the capability maps to scopes of several resources ("
                              + ", ".join(got) + "); one On-Behalf-Of request per resource, pass resource=", got)
        resource = next(iter(got))
    if resource not in got:
        raise BridgeError("no_scopes", f"the capability maps to no scope of {resource}")
    if not isinstance(user_assertion, str) or not user_assertion:
        raise BridgeError("no_credential", "user_assertion (the incoming access token) is missing")
    return {"method": "POST", "url": token_url(tenant), "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "form": {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "client_id": client_id,
                     "assertion": user_assertion, "scope": " ".join(got[resource]), "requested_token_use": "on_behalf_of"}}


# ---- ceiling -------------------------------------------------------------------

def permissions_request(scope: str) -> dict:
    """The ARM request that lists the CALLER's effective permissions at a
    scope: {"method": "GET", "url"}. Send it with the human's ARM access
    token, follow `nextLink`, and give the collected `value` entries to
    `ceiling_from_permissions`."""
    if not isinstance(scope, str) or not scope.startswith("/subscriptions/") or "?" in scope or "#" in scope:
        raise BridgeError("invalid_input", "scope must be an ARM scope starting with /subscriptions/")
    return {"method": "GET", "url": f"{ARM}{scope.rstrip('/')}/providers/Microsoft.Authorization/permissions?api-version={API_VERSION}"}


def _match(pattern: str, action: str) -> bool:
    return re.fullmatch(".*".join(re.escape(p) for p in pattern.split("*")), action, re.IGNORECASE | re.DOTALL) is not None


def rbac_allows(permissions: list, action: str, *, data: bool = False) -> bool:
    """Azure RBAC matching for one concrete action: allowed when SOME entry
    of `permissions` lists it in actions (dataActions when `data`) and does
    not list it in notActions (notDataActions). Each entry is one role
    assignment's permissions; NotActions of one entry does not cancel a grant
    by another. `*` in a permission matches any run of characters."""
    yes, no = ("dataActions", "notDataActions") if data else ("actions", "notActions")
    for p in permissions:
        if any(_match(x, action) for x in p.get(yes) or []) and not any(_match(x, action) for x in p.get(no) or []):
            return True
    return False


def _entries(permissions, scope: str) -> list:
    if isinstance(permissions, dict) and "value" not in permissions:
        permissions = permissions.get(scope, [])
    if isinstance(permissions, dict):
        if permissions.get("nextLink"):
            raise BridgeError("truncated_pagination", "the permissions list has a nextLink; fetch every page first")
        permissions = permissions.get("value")
    if not isinstance(permissions, list):
        raise BridgeError("malformed_response", "permissions must be a list of {actions, notActions, dataActions, notDataActions}")
    for p in permissions:
        if not isinstance(p, dict) or any(not isinstance(p.get(k, []), list) or not all(isinstance(x, str) for x in p.get(k, []))
                                           for k in ("actions", "notActions", "dataActions", "notDataActions")):
            raise BridgeError("malformed_response", "a permissions entry is malformed")
    return permissions


def ceiling_detail(permissions, cloud_map: dict) -> dict:
    """`cloudmap.pairs_to_cap` of the pairs Azure RBAC shows fully allowed."""
    rule_list = rules(cloud_map, "azure")
    ok = []
    for r in rule_list:
        wanted = [(a, False) for a in r.get("actions", [])] + [(a, True) for a in r.get("data_actions", [])]
        if not wanted or any("*" in a for a, _ in wanted):
            ok.append(False)  # scopes-only rules and wildcard rules cannot be shown fully allowed
            continue
        entries = _entries(permissions, r["scope"])
        ok.append(all(rbac_allows(entries, a, data=d) for a, d in wanted))
    return pairs_to_cap(allowed_pairs(rule_list, ok))


def ceiling_from_permissions(permissions, cloud_map: dict) -> dict:
    """What the human may do in Azure, as a capability {"actions",
    "resources"} to cap a role with.

    `permissions` is the `value` list of the permissions API for the rules'
    scope (or the response object, or {scope: list} when the map's rules use
    several scopes). Guarantee: a pair is in the result only if every
    `actions` / `data_actions` entry of every `azure` rule overlapping it is
    allowed by Azure RBAC matching (`rbac_allows`). Rules that only have
    OAuth `scopes`, or that name a wildcard, are never in the ceiling. Pairs
    that do not fit one capability are dropped (`ceiling_detail`)."""
    return ceiling_detail(permissions, cloud_map)["cap"]
