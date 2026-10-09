"""The mapping between SmartDelegate (action, resource pattern) and cloud permissions.

One JSON file, one section per cloud:

    {"aws":   {"rules": [{"action": "read", "resource": "s3.object/*",
                          "allow": {"Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::crm-exports/{id}"]}}]},
     "gcp":   {"rules": [{"action": "read", "resource": "gcs.object/*", "bucket": "crm-exports",
                          "role": "roles/storage.objectViewer", "prefix": "{id}",
                          "permissions": ["storage.objects.get"]}]},
     "azure": {"rules": [{"action": "read", "resource": "graph.mail/*", "scopes": ["https://graph.microsoft.com/Mail.Read"]},
                         {"action": "read", "resource": "blob.object/*", "scope": "/subscriptions/.../containers/crm",
                          "data_actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]}]}}

Patterns are those of `tokens.Cap`: a name with at most one trailing `*`.

How a capability selects rules (`select`):

  * the cap's action pattern must COVER the rule's action (a rule for "re*"
    is not granted to a cap that only has "read");
  * the cap's resource pattern must OVERLAP the rule's resource; what is
    generated is for the NARROWER of the two;
  * `{id}` in a template is the id part of that narrower pattern
    ("s3.object/reports/*" -> "reports/*"). A template without `{id}` cannot
    be narrowed, so it is used only when the cap covers the whole rule;
  * cap entries that select nothing produce nothing and are reported in
    `skipped`. Default deny.

This file is part of the trust base: it decides which cloud permission a
SmartDelegate permission stands for. Keep it with the bundle and review it
like policy. `deny_labels`, `deny_fields` and `budget` of a cap have no cloud
equivalent and are never enforced by a cloud credential.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..errors import EngineError
from ..tokens import Cap, _covers
from . import BridgeError

_KEYS = {
    "aws": ({"action", "resource", "allow"}, set()),
    "gcp": ({"action", "resource", "bucket", "role"}, {"prefix", "permissions", "list_prefix"}),
    "azure": ({"action", "resource"}, {"scopes", "scope", "actions", "data_actions"}),
}


def _bad(msg: str) -> BridgeError:
    return BridgeError("map_invalid", msg)


def _pattern(p, what: str) -> str:
    if not isinstance(p, str) or not p or "*" in p[:-1]:
        raise _bad(f"{what}: '{p}' is not a name with at most one trailing *")
    return p


def _strs(v, what: str) -> list:
    if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
        raise _bad(f"{what} must be a non-empty list of strings")
    return v


def validate(cloud_map: dict) -> dict:
    """Checks the whole map and returns it. An unknown section or key, a
    wrong type, or a resource pattern without "<path>/<id>" raises
    BridgeError("map_invalid"): a misspelt key must not change what is granted."""
    if not isinstance(cloud_map, dict):
        raise _bad("the cloud map must be an object")
    for cloud, section in cloud_map.items():
        if cloud not in _KEYS:
            raise _bad(f"unknown section '{cloud}' (expected aws, gcp, azure)")
        if not isinstance(section, dict) or set(section) != {"rules"} or not isinstance(section["rules"], list):
            raise _bad(f"{cloud}: expected {{\"rules\": [...]}}")
        required, optional = _KEYS[cloud]
        for i, r in enumerate(section["rules"]):
            where = f"{cloud}.rules[{i}]"
            if not isinstance(r, dict):
                raise _bad(f"{where} must be an object")
            if set(r) - required - optional or required - set(r):
                raise _bad(f"{where}: keys must include {sorted(required)} and may include {sorted(optional)}")
            _pattern(r["action"], where + ".action")
            if "/" not in _pattern(r["resource"], where + ".resource"):
                raise _bad(f"{where}.resource must be '<path>/<id pattern>'")
            if cloud == "aws":
                a = r["allow"]
                if not isinstance(a, dict) or set(a) - {"Action", "Resource", "Condition"} or not {"Action", "Resource"} <= set(a):
                    raise _bad(f"{where}.allow must have Action and Resource (and optionally Condition)")
                _strs(a["Action"], where + ".allow.Action")
                _strs(a["Resource"], where + ".allow.Resource")
                if "Condition" in a and not isinstance(a["Condition"], dict):
                    raise _bad(f"{where}.allow.Condition must be an object")
            elif cloud == "gcp":
                for k in ("bucket", "role"):
                    if not isinstance(r[k], str) or not r[k] or "'" in r[k] or "\\" in r[k]:
                        raise _bad(f"{where}.{k} must be a plain string")
                pre = r.get("prefix", "")
                if not isinstance(pre, str) or "'" in pre or "\\" in pre or "*" in pre or ("{id}" in pre and not (pre.endswith("{id}") and pre.count("{id}") == 1)):
                    raise _bad(f"{where}.prefix must be a plain string that ends with {{id}} or does not contain it")
                if "permissions" in r:
                    _strs(r["permissions"], where + ".permissions")
                if "list_prefix" in r and not isinstance(r["list_prefix"], bool):
                    raise _bad(f"{where}.list_prefix must be true or false")
            else:
                if not any(k in r for k in ("scopes", "actions", "data_actions")):
                    raise _bad(f"{where} needs scopes, actions or data_actions")
                for k in ("scopes", "actions", "data_actions"):
                    if k in r:
                        _strs(r[k], f"{where}.{k}")
                if ("actions" in r or "data_actions" in r) and not (isinstance(r.get("scope"), str) and r["scope"].startswith("/")):
                    raise _bad(f"{where}.scope (an ARM scope starting with /) is required with actions or data_actions")
    return cloud_map


def load(path) -> dict:
    """Read and validate a cloud map file."""
    try:
        return validate(json.loads(Path(path).read_text(encoding="utf-8-sig")))
    except (OSError, ValueError) as e:
        raise _bad(f"{path}: {e}") from None


def rules(cloud_map: dict, cloud: str) -> list:
    """The validated rules of one section (an absent section is no rules)."""
    return validate(cloud_map).get(cloud, {}).get("rules", [])


def as_cap(cap) -> Cap:
    """A validated `tokens.Cap` from a dict, a `models.Capability` or a Cap."""
    try:
        c = cap if isinstance(cap, Cap) else Cap.from_json(cap.to_json() if hasattr(cap, "to_json") else cap)
        c.validate()
        return c
    except EngineError as e:
        raise BridgeError("invalid_cap", e.message) from None


def narrower(a: str, b: str) -> str | None:
    """The pattern matching exactly the strings both `a` and `b` match, or
    None when they share none. With one trailing `*` at most, that is always
    one of the two."""
    if _covers(a, b):
        return b
    if _covers(b, a):
        return a
    return None


def overlaps(a: str, b: str) -> bool:
    return narrower(a, b) is not None


@dataclass(frozen=True)
class Grant:
    """One rule selected by a capability."""
    index: int          # position of the rule in its section
    rule: dict
    resource: str       # the narrower of the cap's and the rule's resource pattern
    id: str             # the id part of `resource`, e.g. "reports/*"
    whole: bool         # True when the cap covers the rule's whole resource pattern


def select(cap, rule_list: list) -> tuple:
    """(grants, skipped) for a capability and the rules of one cloud.

    Guarantee: every grant's (rule action, `resource`) is covered by the
    capability, i.e. the cap allows every concrete (action, resource) the
    grant stands for. `skipped` lists the cap's (action, resource) pattern
    pairs that selected no rule: {"action", "resource", "reason": "unmapped"}."""
    cap = as_cap(cap)
    grants, seen, skipped = [], set(), []
    for a in cap.actions:
        for r in cap.resources:
            hit = False
            for i, rule in enumerate(rule_list):
                if not _covers(a, rule["action"]):
                    continue
                n = narrower(r, rule["resource"])
                if n is None:
                    continue
                hit = True
                if (i, n) not in seen:
                    seen.add((i, n))
                    grants.append(Grant(i, rule, n, n.split("/", 1)[1] if "/" in n else "*", n == rule["resource"]))
            if not hit:
                skipped.append({"action": a, "resource": r, "reason": "unmapped"})
    # a grant whose resource is covered by another grant of the same rule adds nothing
    grants = [g for g in grants if not any(o.index == g.index and o.resource != g.resource and _covers(o.resource, g.resource) for o in grants)]
    grants.sort(key=lambda g: (g.index, g.resource))
    return grants, skipped


def not_enforced(cap) -> dict:
    """The parts of a capability no cloud credential can carry."""
    c = as_cap(cap)
    return {k: v for k, v in (("deny_labels", c.deny_labels), ("deny_fields", c.deny_fields), ("budget", c.budget)) if v}


# ---- ceilings ----------------------------------------------------------------

def allowed_pairs(rule_list: list, rule_allowed: list) -> list:
    """The (action, resource) pattern pairs a human demonstrably holds, given
    which rules were found fully allowed (`rule_allowed[i]` for rule i).

    A pair is included only when EVERY rule that overlaps it (same or
    overlapping action and resource patterns) is allowed: two rules for the
    same pair must both hold, and a wide rule ("*") is not counted while a
    narrower rule inside it is denied."""
    out = set()
    for i, r in enumerate(rule_list):
        if all(rule_allowed[j] for j, o in enumerate(rule_list)
               if overlaps(r["action"], o["action"]) and overlaps(r["resource"], o["resource"])):
            out.add((r["action"], r["resource"]))
    return sorted(out)


def pairs_to_cap(pairs: list) -> dict:
    """A capability no wider than a set of allowed (action, resource) pairs.

    A capability is a product: every action applies to every resource. A set
    of pairs that is not a product (read on A, update on B, but not update on
    A) cannot be written as one capability, so this returns the largest
    product found inside the set and reports the rest:

        {"cap": {"actions": [...], "resources": [...]}, "pairs": [...], "dropped": [...]}

    Guarantee: every (action, resource) of `cap` is in `pairs`. `dropped` are
    allowed pairs that did not fit; give them their own role if they matter."""
    s = {(a, r) for a, r in pairs}
    actions, resources = sorted({a for a, _ in s}), sorted({r for _, r in s})
    candidates = [(0, (), ())]
    for a in actions:
        rs = tuple(r for r in resources if (a, r) in s)
        acts = tuple(b for b in actions if all((b, r) in s for r in rs))
        candidates.append((len(acts) * len(rs), acts, rs))
    for r in resources:
        acts = tuple(a for a in actions if (a, r) in s)
        rs = tuple(q for q in resources if all((a, q) in s for a in acts))
        candidates.append((len(acts) * len(rs), acts, rs))
    # the largest product; ties broken by the listing order, so the result is deterministic
    best = min(candidates, key=lambda c: (-c[0], c[1], c[2]))
    _, acts, rs = best
    kept = {(a, r) for a in acts for r in rs}
    return {"cap": {"actions": list(acts), "resources": list(rs)}, "pairs": [list(p) for p in sorted(s)],
            "dropped": [list(p) for p in sorted(s - kept)]}
