#!/usr/bin/env python3
"""Create the example company (Kestrel Works) as a Keycloak realm.

    python3 live/idp/provision.py            create or repair the realm (idempotent)
    python3 live/idp/provision.py --reset    delete the realm(s) and the provisioning record
    python3 live/idp/provision.py --extra N  number of filler users (default 120: more than one
                                             Admin REST page of 100)

What it creates, through the Admin REST API only:

  realm `kestrel` (SD_KEYCLOAK_REALM)
    users     the 35 humans of examples/company/entities.json: username = entity id, attributes
              region and unit (admin-editable only), a generated password each (direct-grant sign-in)
              + `ex-employee` (disabled, still listed in /employees/support)
              + N filler users in /pagination-fill (to force pagination)
    groups    the company's groups as a TREE (Keycloak groups have one parent):
                /employees/{managers,support,finance,hr,sales,procurement,it-ops,compliance}
                /employees/support/support-supervisors, /employees/finance/finance-approvers/finance-managers, ...
              The company's graph gives some groups two parents (support-supervisors is inside
              support AND managers). The second parent cannot be nested in Keycloak, so those
              humans are direct members of both groups. The effective membership is checked to be
              exactly the company's.
    roles     one realm role per company group, mapped on the group (for the realm-role variant)
    clients   sd-engine        the engine's audience; group-membership mapper `groups`, full path ON
              sd-engine-leaf   the same with full path OFF
              sd-engine-roles  no group mapper; realm-role mappers writing a flat `roles` claim and the
                               nested `realm_access.roles` into the ID token; one client role
                               (`refund-approver`)
              sd-attr-mapper   DELIBERATELY WRONG: `groups` filled from a user-editable attribute
              sd-other         another application in the same realm (audience tests)
              sd-sync          service account for `bridge sync-keycloak`, with exactly the
                               realm-management roles in SYNC_ROLES
  realm `kestrel-other`: one user and a client also called sd-engine (cross-realm token tests)

The record of what was created (client secrets, the users' passwords) is
written to the cache directory, never to the repository.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from live.idp import kc  # noqa: E402

COMPANY = ROOT / "examples" / "company"
#: the least privilege `bridge sync-keycloak` needs, found by removing one role at a time
#: (test_live_idp.LeastPrivilege); all are client roles of `realm-management`
SYNC_ROLES = ["view-users"]
FILL_GROUP = "/pagination-fill"
EMAIL_DOMAIN = "kestrel.example"


def company() -> dict:
    """Users, groups and the tree Keycloak can hold, from the example company."""
    entities = json.loads((COMPANY / "entities.json").read_text(encoding="utf-8"))
    groups = {e["uid"]["id"]: [p["id"] for p in e["parents"]] for e in entities if e["uid"]["type"] == "Group"}
    users = {e["uid"]["id"]: {"attrs": e["attrs"], "parents": [p["id"] for p in e["parents"]]} for e in entities if e["uid"]["type"] == "User"}

    def depth(g, seen=()):
        return 0 if not groups[g] else 1 + max(depth(p, seen + (g,)) for p in groups[g] if p not in seen)

    def above(start, parents_of):
        out, todo = set(), list(start)
        while todo:
            g = todo.pop()
            if g not in out:
                out.add(g)
                todo += parents_of(g)
        return out

    # one parent per group: the deepest one; `managers` (a cross-unit group) only when nothing else
    tree = {g: (sorted(ps, key=lambda p: (-depth(p), p == "managers", p))[0] if ps else None) for g, ps in groups.items()}

    def path(g):
        return (path(tree[g]) if tree[g] else "") + "/" + g

    paths = {g: path(g) for g in groups}
    direct = {}
    for u, rec in users.items():
        needed = above(rec["parents"], lambda g: groups[g])
        mine = set(rec["parents"])
        while True:
            missing = needed - above(mine, lambda g: [tree[g]] if tree[g] else [])
            if not missing:
                break
            mine.add(max(sorted(missing), key=depth))
        direct[u] = sorted(mine)
        assert above(mine, lambda g: [tree[g]] if tree[g] else []) == needed, u
    effective = {u: sorted(above(rec["parents"], lambda g: groups[g])) for u, rec in users.items()}
    return {"groups": groups, "users": users, "tree": tree, "paths": paths, "direct": direct, "effective": effective}


def ensure_realm(a: kc.Admin, realm: str, log) -> None:
    rep = {"realm": realm, "enabled": True, "accessTokenLifespan": 300, "ssoSessionIdleTimeout": 1800,
           "registrationAllowed": False, "editUsernameAllowed": False, "bruteForceProtected": False}
    if a.realm_exists(realm):
        a.put(f"/realms/{realm}", rep)
        log(f"realm {realm}: exists, settings restored")
    else:
        a.post("/realms", rep)
        log(f"realm {realm}: created")


def ensure_profile(a: kc.Admin, realm: str) -> None:
    """Declare the custom attributes (Keycloak 24+ drops attributes the user
    profile does not know). region/unit: only an admin may write them.
    nickname/groups: the user may edit them (used by the abuse tests)."""
    prof = a.get(f"/realms/{realm}/users/profile")
    have = {x["name"]: x for x in prof.get("attributes", [])}
    for name, edit in (("region", ["admin"]), ("unit", ["admin"]), ("nickname", ["admin", "user"]), ("groups", ["admin", "user"])):
        have[name] = {"name": name, "displayName": name, "permissions": {"view": ["admin", "user"], "edit": edit},
                      "multivalued": name == "groups", "validations": {}}
    prof["attributes"] = list(have.values())
    a.put(f"/realms/{realm}/users/profile", prof)


def ensure_group(a: kc.Admin, realm: str, path: str) -> str:
    g = a.group_by_path(realm, path)
    if g:
        return g["id"]
    parent, _, name = path.rpartition("/")
    if parent:
        a.post(f"/realms/{realm}/groups/{ensure_group(a, realm, parent)}/children", {"name": name})
    else:
        a.post(f"/realms/{realm}/groups", {"name": name})
    return a.created_id()


def ensure_role(a: kc.Admin, realm: str, name: str) -> dict:
    try:
        return a.get(f"/realms/{realm}/roles/{name}")
    except kc.KeycloakError as e:
        if e.status != 404:
            raise
    a.post(f"/realms/{realm}/roles", {"name": name, "description": "SmartDelegate live test: mirrors the group of the same name"})
    return a.get(f"/realms/{realm}/roles/{name}")


def ensure_user(a: kc.Admin, realm: str, username: str, rep: dict, password: str | None, update: bool = True) -> str:
    uid = a.user_id(realm, username)
    body = {"username": username, "enabled": True, "emailVerified": True, "requiredActions": [], **rep}
    if uid is None:
        a.post(f"/realms/{realm}/users", body)
        uid = a.created_id()
    elif update:
        a.put(f"/realms/{realm}/users/{uid}", body)
    else:
        return uid
    if password:
        a.put(f"/realms/{realm}/users/{uid}/reset-password", {"type": "password", "value": password, "temporary": False})
    return uid


def set_groups(a: kc.Admin, realm: str, uid: str, want_ids: set) -> None:
    have = {g["id"] for g in a.get(f"/realms/{realm}/users/{uid}/groups", max=1000)}
    for g in want_ids - have:
        a.put(f"/realms/{realm}/users/{uid}/groups/{g}")
    for g in have - want_ids:
        a.delete(f"/realms/{realm}/users/{uid}/groups/{g}")


def mapper(name: str, kind: str, **config) -> dict:
    return {"name": name, "protocol": "openid-connect", "protocolMapper": kind,
            "config": {"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true",
                       **{k.replace("_", "."): v for k, v in config.items()}}}


def ensure_client(a: kc.Admin, realm: str, client_id: str, *, mappers: list, service_account: bool = False, direct_grant: bool = True) -> tuple:
    rep = {"clientId": client_id, "enabled": True, "protocol": "openid-connect", "publicClient": False,
           "standardFlowEnabled": not service_account, "directAccessGrantsEnabled": direct_grant and not service_account,
           "serviceAccountsEnabled": service_account, "redirectUris": [] if service_account else ["http://127.0.0.1/*"],
           "fullScopeAllowed": True}
    c = a.client(realm, client_id)
    if c is None:
        a.post(f"/realms/{realm}/clients", rep)
        cid = a.created_id()
    else:
        cid = c["id"]
        # "" clears a per-client token lifespan a test may have left (leaving the key out keeps it)
        a.put(f"/realms/{realm}/clients/{cid}", {**c, **rep, "attributes": {**(c.get("attributes") or {}), "access.token.lifespan": ""}})
    for m in a.get(f"/realms/{realm}/clients/{cid}/protocol-mappers/models"):
        if m["name"].startswith("sd-"):
            a.delete(f"/realms/{realm}/clients/{cid}/protocol-mappers/models/{m['id']}")
    for m in mappers:
        a.post(f"/realms/{realm}/clients/{cid}/protocol-mappers/models", m)
    return cid, a.get(f"/realms/{realm}/clients/{cid}/client-secret")["value"]


def set_service_account_roles(a: kc.Admin, realm: str, client_uuid: str, roles: list) -> None:
    """Make the service account's realm-management client roles exactly `roles`."""
    sa = a.get(f"/realms/{realm}/clients/{client_uuid}/service-account-user")["id"]
    rm = a.client(realm, "realm-management")["id"]
    base = f"/realms/{realm}/users/{sa}/role-mappings/clients/{rm}"
    have = {r["name"]: r for r in a.get(base)}
    extra = [r for n, r in have.items() if n not in roles]
    if extra:
        a.delete(base, extra)
    add = [a.get(f"/realms/{realm}/clients/{rm}/roles/{n}") for n in roles if n not in have]
    if add:
        a.post(base, add)


def cleanup_leftovers(a: kc.Admin, realm: str, log) -> None:
    """Remove what an interrupted test run may have left: extra signing keys
    (`sd-live-*`) and groups whose NAME contains a slash."""
    for c in a.get(f"/realms/{realm}/components", type="org.keycloak.keys.KeyProvider"):
        if c["name"].startswith("sd-live-"):
            a.delete(f"/realms/{realm}/components/{c['id']}")
            log(f"leftover key provider {c['name']}: deleted")
    top = a.get(f"/realms/{realm}/groups", max=1000)
    emp = [g for g in top if g["name"] == "employees"]
    for g in top + (a.get(f"/realms/{realm}/groups/{emp[0]['id']}/children", max=1000) if emp else []):
        if "/" in g["name"]:
            a.delete(f"/realms/{realm}/groups/{g['id']}")
            log(f"leftover group named {g['name']!r}: deleted")


def provision(extra: int = 120, log=print) -> dict:
    a = kc.Admin.connect()
    realm, other = kc.REALM, kc.OTHER_REALM
    co = company()
    old = json.loads(kc.provision_file().read_text()) if kc.provision_file().is_file() else {}
    log(f"Keycloak {a.version()} at {a.url}")
    ensure_realm(a, realm, log)
    ensure_profile(a, realm)

    cleanup_leftovers(a, realm, log)
    gids = {g: ensure_group(a, realm, p) for g, p in sorted(co["paths"].items(), key=lambda kv: kv[1])}
    fill_gid = ensure_group(a, realm, FILL_GROUP)
    log(f"groups: {len(gids)} company groups as a tree + {FILL_GROUP}")

    for g, gid in gids.items():   # realm-role variant: role <group> mapped on group <group>
        role = ensure_role(a, realm, g)
        if g not in {r["name"] for r in a.get(f"/realms/{realm}/groups/{gid}/role-mappings/realm")}:
            a.post(f"/realms/{realm}/groups/{gid}/role-mappings/realm", [role])

    passwords = {}
    for u, rec in co["users"].items():
        first, _, last = rec["attrs"]["name"].partition(" ")
        passwords[u] = secrets.token_urlsafe(18)
        uid = ensure_user(a, realm, u, {"firstName": first, "lastName": last or first, "email": f"{u}@{EMAIL_DOMAIN}",
                                        "attributes": {"region": [rec["attrs"]["region"]], "unit": [rec["attrs"]["unit"]]}}, passwords[u])
        set_groups(a, realm, uid, {gids[g] for g in co["direct"][u]})
    log(f"users: {len(passwords)} humans, passwords regenerated, memberships set to the company's")

    passwords["ex-employee"] = secrets.token_urlsafe(18)
    uid = ensure_user(a, realm, "ex-employee", {"firstName": "Former", "lastName": "Employee", "email": f"ex-employee@{EMAIL_DOMAIN}",
                                                "enabled": False, "attributes": {"region": ["EU"], "unit": ["support"]}}, passwords["ex-employee"])
    set_groups(a, realm, uid, {gids["support"]})

    made = 0
    for n in range(1, extra + 1):
        name = f"filler-{n:03d}"
        if a.user_id(realm, name) is None:
            uid = ensure_user(a, realm, name, {"firstName": "Filler", "lastName": f"{n:03d}", "email": f"{name}@{EMAIL_DOMAIN}"}, None)
            a.put(f"/realms/{realm}/users/{uid}/groups/{fill_gid}")
            made += 1
    log(f"filler users: {extra} wanted, {made} created now (in {FILL_GROUP})")

    clients = {}
    group_mapper = lambda full: mapper("sd-groups", "oidc-group-membership-mapper", claim_name="groups", full_path="true" if full else "false")
    _, clients["sd-engine"] = ensure_client(a, realm, "sd-engine", mappers=[group_mapper(True)])
    _, clients["sd-engine-leaf"] = ensure_client(a, realm, "sd-engine-leaf", mappers=[group_mapper(False)])
    roles_uuid, clients["sd-engine-roles"] = ensure_client(a, realm, "sd-engine-roles", mappers=[
        mapper("sd-flat-realm-roles", "oidc-usermodel-realm-role-mapper", claim_name="roles", jsonType_label="String", multivalued="true"),
        # the built-in shape (nested under realm_access), which Keycloak by default puts in the access token only
        mapper("sd-nested-realm-roles", "oidc-usermodel-realm-role-mapper", claim_name="realm_access.roles", jsonType_label="String", multivalued="true")])
    _, clients["sd-attr-mapper"] = ensure_client(a, realm, "sd-attr-mapper", mappers=[
        mapper("sd-groups-from-attribute", "oidc-usermodel-attribute-mapper", claim_name="groups", user_attribute="groups",
               jsonType_label="String", multivalued="true")])
    _, clients["sd-other"] = ensure_client(a, realm, "sd-other", mappers=[])
    sync_uuid, clients["sd-sync"] = ensure_client(a, realm, "sd-sync", mappers=[], service_account=True)
    set_service_account_roles(a, realm, sync_uuid, SYNC_ROLES)
    # one client role on sd-engine-roles, held by elena (resource_access.<client>.roles)
    if "refund-approver" not in {r["name"] for r in a.get(f"/realms/{realm}/clients/{roles_uuid}/roles")}:
        a.post(f"/realms/{realm}/clients/{roles_uuid}/roles", {"name": "refund-approver"})
    cr = a.get(f"/realms/{realm}/clients/{roles_uuid}/roles/refund-approver")
    a.post(f"/realms/{realm}/users/{a.user_id(realm, 'elena')}/role-mappings/clients/{roles_uuid}", [cr])
    log(f"clients: {', '.join(sorted(clients))}; sd-sync holds realm-management roles {SYNC_ROLES}")

    ensure_realm(a, other, log)
    other_password = secrets.token_urlsafe(18)
    ensure_user(a, other, "anna", {"firstName": "Anna", "lastName": "Elsewhere", "email": f"anna@other.{EMAIL_DOMAIN}"}, other_password)
    og = ensure_group(a, other, "/employees/support")
    a.put(f"/realms/{other}/users/{a.user_id(other, 'anna')}/groups/{og}")
    _, other_secret = ensure_client(a, other, "sd-engine", mappers=[group_mapper(True)])

    record = {"keycloak_version": a.version(), "url": a.url, "realm": realm, "other_realm": other,
              "clients": clients, "passwords": passwords, "other": {"client_secret": other_secret, "password": other_password},
              "group_paths": co["paths"], "group_map": {p: g for g, p in co["paths"].items()},
              "direct": co["direct"], "effective": co["effective"], "sync_roles": SYNC_ROLES, "fill_group": FILL_GROUP, "filler_users": extra,
              "created": old.get("created") or __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    path = kc.provision_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path) + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1)
    os.replace(str(path) + ".tmp", path)
    log(f"record (secrets, mode 0600): {path}")
    return record


def reset(log=print) -> None:
    a = kc.Admin.connect()
    for realm in (kc.REALM, kc.OTHER_REALM):
        if a.realm_exists(realm):
            a.delete(f"/realms/{realm}")
            log(f"realm {realm}: deleted")
    try:
        kc.provision_file().unlink()
    except FileNotFoundError:
        pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Create the example company as a Keycloak realm.")
    ap.add_argument("--reset", action="store_true", help="delete the realm(s) and the provisioning record, then stop")
    ap.add_argument("--extra", type=int, default=120, help="filler users to create (default 120)")
    args = ap.parse_args(argv)
    try:
        if args.reset:
            reset()
        else:
            provision(args.extra)
    except kc.Unavailable as e:
        print(f"provision.py: Keycloak is not available: {e}", file=sys.stderr)
        return 3
    except kc.KeycloakError as e:
        print(f"provision.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
