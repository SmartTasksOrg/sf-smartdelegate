"""Google Cloud: a Credential Access Boundary for a SmartDelegate capability,
the STS request that applies it, and a ceiling from testIamPermissions.

CLOUD STORAGE ONLY. Google's documentation says: "Credential Access Boundaries
are only available for Cloud Storage. Other Google Cloud services don't
support this feature." For any other Google API there is no way to down-scope
an existing credential per request. What remains is: impersonate a service
account that has exactly the role the task needs
(iamcredentials generateAccessToken with a short `lifetime`), restrict that
account with IAM Conditions where the service supports them, and keep the
SmartDelegate proxy as the enforcement point for the fine-grained bound. This
module does not implement impersonation.

Nothing here imports google-auth. Written from:
  https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials
      {"accessBoundary": {"accessBoundaryRules": [{"availableResource":
      "//storage.googleapis.com/projects/_/buckets/NAME", "availablePermissions":
      ["inRole:roles/..."], "availabilityCondition": {"expression": "..."}}]}}; at most 10 rules;
      condition `resource.name.startsWith('projects/_/buckets/NAME/objects/PREFIX')`; for listing
      objects, `api.getAttribute('storage.googleapis.com/objectListPrefix', '')`
  https://docs.cloud.google.com/iam/docs/create-downscoped-short-lived-credentials
      POST https://sts.googleapis.com/v1/token, form fields grant_type, subject_token_type,
      requested_token_type, subject_token, options (the boundary as JSON, percent-encoded)
  https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/testIamPermissions
      GET https://storage.googleapis.com/storage/v1/b/BUCKET/iam/testPermissions?permissions=...
      -> {"kind": "storage#testIamPermissionsResponse", "permissions": [...]}
Tested only on generated JSON and hand-written responses. Google was not contacted.

# UNVERIFIED: whether one boundary may hold two rules for the same bucket (this module emits one
# rule per bucket and condition; rules with the same bucket and condition are merged).
# UNVERIFIED: `==` on resource.name for a single object, and the exact CEL string-escaping rules;
# object names containing a quote or backslash are not granted (reported "unsafe_id").
# UNVERIFIED: that `permissions` may be repeated in the testPermissions query.
# UNVERIFIED: whether STS accepts a boundary with no rules; `access_boundary` refuses to build one.
"""
from __future__ import annotations

import json
import re
import urllib.parse

from . import BridgeError
from .cloudmap import allowed_pairs, not_enforced, pairs_to_cap, rules, select
from .http import Transport, post_form, urllib_transport, with_query

MAX_RULES = 10
STS_URL = "https://sts.googleapis.com/v1/token"
_BUCKET = re.compile(r"[a-z0-9][a-z0-9._-]{1,220}")


def _rules(cap, cloud_map: dict) -> tuple:
    grants, skipped = select(cap, rules(cloud_map, "gcp"))
    merged: dict = {}
    for g in grants:
        rule, bucket = g.rule, g.rule["bucket"]
        skip = lambda reason: skipped.append({"action": rule["action"], "resource": g.resource, "reason": reason})
        if not _BUCKET.fullmatch(bucket):
            raise BridgeError("map_invalid", f"gcp rule {g.index}: '{bucket}' is not a bucket name")
        prefix = rule.get("prefix")
        if prefix is None or "{id}" not in prefix:
            if not g.whole:  # a fixed bucket or prefix cannot be narrowed to the cap
                skip("cannot_narrow")
                continue
            name, wild = prefix or "", True
        else:
            if "'" in g.id or "\\" in g.id or "*" in g.id[:-1] or any(ord(c) < 32 for c in g.id):
                skip("unsafe_id")
                continue
            wild = g.id.endswith("*")
            name = prefix.replace("{id}", g.id[:-1] if wild else g.id)
        full = f"projects/_/buckets/{bucket}/objects/{name}"
        if wild and not name:
            expr = None  # the whole bucket, as the rule says
        elif wild:
            expr = f"resource.name.startsWith('{full}')"
            if rule.get("list_prefix"):
                expr += f" || api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('{name}')"
        else:
            expr = f"resource.name == '{full}'"
        merged.setdefault((bucket, expr), set()).add("inRole:" + rule["role"])
    out = []
    for (bucket, expr), perms in sorted(merged.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        r = {"availableResource": f"//storage.googleapis.com/projects/_/buckets/{bucket}", "availablePermissions": sorted(perms)}
        if expr:
            r["availabilityCondition"] = {"expression": expr}
        out.append(r)
    return out, skipped


def access_boundary(cap, cloud_map: dict) -> dict:
    """The Credential Access Boundary for a capability (Cloud Storage only).

    Guarantees: one rule per bucket and condition, only for (action, resource)
    pairs of the capability that the map's `gcp` rules cover; the condition
    restricts object names to the capability's id pattern (a prefix for
    `name*`, equality for an exact id); unmapped entries are absent;
    deterministic. Raises BridgeError("boundary_too_large") over 10 rules
    (the documented maximum) and BridgeError("empty_boundary") when nothing
    maps - the caller must then give the agent no Google credential at all,
    not the unscoped one.

    A boundary can only reduce what the source credential may do. It does
    not carry deny_labels, deny_fields or budget (see `access_boundary_report`)."""
    out, _ = _rules(cap, cloud_map)
    if not out:
        raise BridgeError("empty_boundary", "the capability maps to no Cloud Storage permission; issue no Google credential")
    if len(out) > MAX_RULES:
        raise BridgeError("boundary_too_large", f"{len(out)} access boundary rules; Google allows {MAX_RULES}", {"rules": len(out)})
    return {"accessBoundary": {"accessBoundaryRules": out}}


def access_boundary_report(cap, cloud_map: dict) -> dict:
    """{"boundary", "skipped", "not_enforced"}."""
    return {"boundary": access_boundary(cap, cloud_map), "skipped": _rules(cap, cloud_map)[1], "not_enforced": not_enforced(cap)}


def sts_exchange_request(boundary: dict, source_access_token: str) -> dict:
    """The token-exchange request that turns `source_access_token` into a
    down-scoped token: {"method", "url", "headers", "form"}. POST `form`
    url-encoded (that is the "percent encoding" of `options` the docs ask
    for). The source token is passed through into the form and stored
    nowhere; treat the returned dict as a secret."""
    rules_ = (boundary.get("accessBoundary") or {}).get("accessBoundaryRules") if isinstance(boundary, dict) else None
    if not isinstance(rules_, list) or not rules_ or len(rules_) > MAX_RULES:
        raise BridgeError("invalid_input", "boundary must be a Credential Access Boundary with 1 to 10 rules")
    if not isinstance(source_access_token, str) or not source_access_token:
        raise BridgeError("no_credential", "the source access token is missing")
    return {"method": "POST", "url": STS_URL, "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "form": {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                     "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                     "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                     "subject_token": source_access_token,
                     "options": json.dumps(boundary, separators=(",", ":"), sort_keys=True)}}


def exchange(request: dict, transport: Transport = urllib_transport) -> dict:
    """Perform a `sts_exchange_request` and return the answer ({"access_token",
    "token_type", "expires_in"?, ...}). Raises BridgeError on any HTTP error
    or when no access_token comes back; the error never contains a token."""
    answer = post_form(transport, request["url"], request["form"])
    if not isinstance(answer, dict) or not isinstance(answer.get("access_token"), str) or not answer["access_token"]:
        raise BridgeError("malformed_response", "the STS answer has no access_token")
    return answer


# ---- ceiling -------------------------------------------------------------------

def test_permissions_requests(cloud_map: dict) -> list:
    """One request per bucket that asks which of the permissions named by the
    map's `gcp` rules (`permissions`) the caller holds on it:
    [{"method": "GET", "url", "bucket", "permissions"}]. Send each with the
    HUMAN's access token and pass the answers, in the same order, to
    `ceiling_from_test_permissions`. Rules without `permissions` cannot be
    tested and never enter the ceiling. The test is per bucket: it does not
    see IAM Conditions or per-object ACLs."""
    per_bucket: dict = {}
    for r in rules(cloud_map, "gcp"):
        if r.get("permissions"):
            per_bucket.setdefault(r["bucket"], set()).update(r["permissions"])
    out = []
    for bucket in sorted(per_bucket):
        perms = sorted(per_bucket[bucket])
        url = with_query(f"https://storage.googleapis.com/storage/v1/b/{urllib.parse.quote(bucket, safe='')}/iam/testPermissions", {"permissions": perms})
        out.append({"method": "GET", "url": url, "bucket": bucket, "permissions": perms})
    return out


def ceiling_detail(responses: list, cloud_map: dict) -> dict:
    """`cloudmap.pairs_to_cap` of the pairs testIamPermissions shows fully held."""
    requests = test_permissions_requests(cloud_map)
    if not isinstance(responses, list) or len(responses) != len(requests):
        raise BridgeError("invalid_input", f"expected {len(requests)} testIamPermissions responses, one per request and in the same order")
    held: dict = {}
    for req, resp in zip(requests, responses):
        perms = resp.get("permissions", []) if isinstance(resp, dict) else None
        if not isinstance(perms, list) or not all(isinstance(p, str) for p in perms):
            raise BridgeError("malformed_response", "a testIamPermissions response has no 'permissions' list")
        held[req["bucket"]] = set(perms)
    rule_list = rules(cloud_map, "gcp")
    ok = [bool(r.get("permissions")) and set(r["permissions"]) <= held.get(r["bucket"], set()) for r in rule_list]
    return pairs_to_cap(allowed_pairs(rule_list, ok))


def ceiling_from_test_permissions(responses: list, cloud_map: dict) -> dict:
    """What the tested human may do in Cloud Storage, as a capability
    {"actions", "resources"} to cap a role with. Guarantee: a pair is in the
    result only if every permission of every `gcp` rule overlapping it was
    returned as held for the rule's bucket. Pairs that do not fit one
    capability are dropped, never rounded up (`ceiling_detail` lists them)."""
    return ceiling_detail(responses, cloud_map)["cap"]
