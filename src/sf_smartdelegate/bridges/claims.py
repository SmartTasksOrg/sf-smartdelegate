"""Claims of a verified ID or access token -> the `groups` list for issue_token.

The caller verifies the token first (signature, issuer, audience, expiry);
this module only reads claims. It never treats a missing claim as "everything":
a missing claim is the empty list.

Documentation the presets were written from:
  entra     https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
            https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
            (groups = object-id GUIDs; roles; wids; overage: `_claim_names` / `_claim_sources`
            over 200 groups in a JWT, `hasgroups` in the implicit flow)
  cognito   https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
            ("The access and ID tokens both include a cognito:groups claim")
  auth0     https://auth0.com/docs/get-started/apis/scopes/sample-use-cases-scopes-and-claims
            (custom claims are namespaced with a URL, e.g. https://myapp.example.com/roles)
  google    https://developers.google.cn/identity/openid-connect/reference (the mirror that was read; `hd`, no groups claim)
  okta      # UNVERIFIED: the `groups` claim is whatever the administrator configures on the
            authorization server or app; "groups" is the conventional name, not a fixed one.
  keycloak  Checked against a real Keycloak 26.0.7 (live/idp/, 2026-10-05):
            - `groups` exists only when the client has a "Group Membership" mapper. It lists the
              user's DIRECT groups: full paths ("/support/eu") with "Full group path" on, bare
              names ("eu") with it off. A parent group is never listed for a member of a child
              group. A user in no group has NO `groups` claim (not an empty list).
            - a group name may contain "/", unescaped: the path "/support/eu" is also the path of a
              top-level group named "support/eu". Paths and names are not unique identifiers.
            - `realm_access.roles` and `resource_access.<client>.roles` are in the ACCESS token.
              The ID token has neither unless a mapper adds them; a "User Realm Role" mapper can
              write a flat claim (for example `roles`), read here with "roles_claim".
              Realm roles include roles inherited from parent groups and the realm's defaults
              (`default-roles-<realm>`, `offline_access`, `uma_authorization`): every user has
              those, never map them to a group.
  The presets other than keycloak: none was run against the real provider.
"""
from __future__ import annotations

from . import BridgeError

PROVIDERS = ("entra", "okta", "keycloak", "cognito", "auth0", "google", "generic")
_RULE_KEYS = {"provider", "claim", "map", "unmapped", "client", "sources", "group_paths", "roles_claim"}
_SOURCES = {"entra": ("groups", "roles", "wids"), "keycloak": ("groups", "realm_roles", "client_roles")}
_PATH_MODES = ("full", "strip", "leaf", "expand")


def _strings(v, what: str) -> list:
    """A claim value as a list of strings: absent -> [], a string -> [it]."""
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return list(v)
    raise BridgeError("claims_invalid", f"claim '{what}' is not a string or a list of strings")


def _dotted(claims: dict, path: str):
    """claims[path] when that exact key exists (URL-shaped claim names contain
    dots), else a walk along the dots. Missing -> None."""
    if path in claims:
        return claims[path]
    cur = claims
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _keycloak_paths(paths: list, mode: str) -> list:
    """Keycloak group paths in the form the rule asks for. Any mode other than
    "full" takes a path apart, so it needs real paths: a value without the
    leading "/" is what the mapper sends with "Full group path" off, and
    raises instead of being guessed at ("eu/west" may be one group's name)."""
    out = []
    for p in paths:
        parts = [x for x in p.split("/") if x]
        if not parts:
            continue
        if mode == "full":
            out.append(p)
            continue
        if not p.startswith("/"):
            raise BridgeError("claims_invalid", f"group_paths '{mode}' needs full group paths, but the token lists a bare group name: "
                                                "the client's group mapper has 'Full group path' off. Turn it on, or use group_paths 'full'")
        if mode == "strip":
            out.append("/".join(parts))
        elif mode == "leaf":
            out.append(parts[-1])
        else:  # expand: a member of /support/eu is also listed under /support
            out.extend("/" + "/".join(parts[:i]) for i in range(1, len(parts) + 1))
    return out


def has_overage(claims: dict) -> bool:
    """True when an Entra token says "this user has groups, but they are not
    in the token": `_claim_names` / `_claim_sources` naming `groups`, or `hasgroups`."""
    names, sources = claims.get("_claim_names"), claims.get("_claim_sources")
    if isinstance(names, dict) and "groups" in names:
        return True
    if isinstance(names, str) and "groups" in names:  # some libraries leave the JSON as text
        return True
    if isinstance(sources, dict) and "groups" in sources:
        return True
    return claims.get("hasgroups") in (True, "true", "True")


def groups_from_claims(claims: dict, rule: dict) -> list:
    """The SmartDelegate group ids a set of verified token claims stands for.

    rule = {"provider": one of PROVIDERS,
            "claim":    claim name (required for auth0 and generic; overrides the preset's
                        groups claim otherwise),
            "map":      {value at the provider -> SmartDelegate group id},
            "unmapped": "drop" (default) | "keep"  - what to do with values not in `map`,
            "client":   keycloak: the client whose roles to read,
            "sources":  entra: subset of ["groups", "roles", "wids"]; keycloak: subset of
                        ["groups", "realm_roles", "client_roles"]. Default ["groups"]. Values
                        from a source other than "groups" are prefixed "<source>:" (for example
                        "roles:Refund.Approver") so a role can never be mistaken for a group,
            "group_paths": keycloak: "full" (default: the values as sent, "/support/eu", or "eu"
                        when the mapper's full path is off), "strip" ("support/eu"), "leaf" ("eu")
                        or "expand" ("/support" and "/support/eu": Keycloak lists direct groups
                        only, this adds the parents). The last three need full paths and raise on
                        a bare name. "leaf" maps /sales/eu and /support/eu to the same "eu",
            "roles_claim": keycloak: the claim (name or dotted path) holding realm roles when a
                        mapper writes them somewhere else than `realm_access.roles`, e.g. "roles"}

    Guarantees: the result is sorted and free of duplicates; a missing claim
    gives []; with a `map`, values not in it are dropped unless "unmapped" is
    "keep"; without a `map`, values pass through unchanged (the engine then
    drops names entities.json does not define). An unknown rule key, a claim
    of the wrong type, or an Entra groups overage raises BridgeError - an
    overage must be resolved with `entra.member_groups`, never read as "no
    groups" or "all groups".

    google: Google ID tokens carry no groups, only `hd` (the Workspace domain).
    The preset yields the single value "hd:<domain>" and requires a `map`; for
    real group membership use the directory sync (`bridges.google.fetch`)."""
    if not isinstance(claims, dict):
        raise BridgeError("claims_invalid", "claims must be an object")
    if not isinstance(rule, dict):
        raise BridgeError("rule_invalid", "rule must be an object")
    unknown = set(rule) - _RULE_KEYS
    if unknown:
        raise BridgeError("rule_invalid", f"unknown rule key(s): {', '.join(sorted(unknown))}")
    provider = rule.get("provider")
    if provider not in PROVIDERS:
        raise BridgeError("rule_invalid", f"provider must be one of: {', '.join(PROVIDERS)}")
    mapping = rule.get("map")
    if mapping is not None and not (isinstance(mapping, dict) and all(isinstance(k, str) and isinstance(v, str) and v for k, v in mapping.items())):
        raise BridgeError("rule_invalid", "map must map a provider value to a SmartDelegate group id")
    unmapped = rule.get("unmapped", "drop")
    if unmapped not in ("drop", "keep"):
        raise BridgeError("rule_invalid", "unmapped must be 'drop' or 'keep'")
    claim = rule.get("claim")
    if claim is not None and not (isinstance(claim, str) and claim):
        raise BridgeError("rule_invalid", "claim must be a claim name")
    sources = rule.get("sources", ["groups"])
    if provider in _SOURCES:
        if not isinstance(sources, list) or not sources or any(s not in _SOURCES[provider] for s in sources):
            raise BridgeError("rule_invalid", f"sources must be a non-empty subset of {list(_SOURCES[provider])}")
    elif "sources" in rule:
        raise BridgeError("rule_invalid", f"'sources' does not apply to provider {provider}")
    roles_claim = rule.get("roles_claim")
    if "roles_claim" in rule and not (provider == "keycloak" and isinstance(roles_claim, str) and roles_claim):
        raise BridgeError("rule_invalid", "roles_claim applies to keycloak only and must be a claim name")
    mode = rule.get("group_paths", "full")
    if mode not in _PATH_MODES or ("group_paths" in rule and provider != "keycloak"):
        raise BridgeError("rule_invalid", f"group_paths applies to keycloak only and must be one of: {', '.join(_PATH_MODES)}")

    values: list = []
    if provider == "entra":
        if "groups" in sources:
            if has_overage(claims):
                raise BridgeError("claims_overage", "the token has a groups overage (too many groups to fit): resolve the user's groups with "
                                                   "bridges.entra.member_groups(<oid claim>) and pass that list instead")
            values += _strings(claims.get(claim or "groups"), claim or "groups")
        if "roles" in sources:
            values += ["roles:" + v for v in _strings(claims.get("roles"), "roles")]
        if "wids" in sources:
            values += ["wids:" + v for v in _strings(claims.get("wids"), "wids")]
    elif provider == "keycloak":
        if "groups" in sources:
            values += _keycloak_paths(_strings(claims.get(claim or "groups"), claim or "groups"), mode)
        if "realm_roles" in sources:
            where = roles_claim or "realm_access.roles"
            values += ["realm_roles:" + v for v in _strings(_dotted(claims, where), where)]
        if "client_roles" in sources:
            client = rule.get("client")
            if not isinstance(client, str) or not client:
                raise BridgeError("rule_invalid", "client_roles needs 'client'")
            ra = claims.get("resource_access")
            roles = ra.get(client, {}).get("roles") if isinstance(ra, dict) and isinstance(ra.get(client, {}), dict) else None
            values += ["client_roles:" + v for v in _strings(roles, f"resource_access.{client}.roles")]
    elif provider == "okta":
        values = _strings(claims.get(claim or "groups"), claim or "groups")
    elif provider == "cognito":
        values = _strings(claims.get(claim or "cognito:groups"), claim or "cognito:groups")
    elif provider == "auth0":
        if not claim:
            raise BridgeError("rule_invalid", "auth0 needs 'claim': the namespaced custom claim, e.g. https://example.com/groups")
        values = _strings(claims.get(claim), claim)
    elif provider == "google":
        if not mapping:
            raise BridgeError("claims_no_groups", "Google ID tokens carry no groups, only 'hd' (the Workspace domain). Give a map such as "
                                                  "{\"hd:example.com\": \"employees\"}, or sync groups with bridges.google.fetch")
        hd = claims.get("hd")
        if hd is not None and not isinstance(hd, str):
            raise BridgeError("claims_invalid", "claim 'hd' is not a string")
        values, unmapped = ([f"hd:{hd}"] if hd else []), "drop"
    else:  # generic
        if not claim:
            raise BridgeError("rule_invalid", "generic needs 'claim': a claim name or dotted path")
        values = _strings(_dotted(claims, claim), claim)

    if mapping is None:
        out = set(values)
    else:
        out = {mapping[v] for v in values if v in mapping}
        if unmapped == "keep":
            out |= {v for v in values if v not in mapping}
    return sorted(v for v in out if v)
