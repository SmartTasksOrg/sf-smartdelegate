"""`smartdelegate bridge <subcommand>`: the bridges from the command line.

    sync-scim --url U --token-env VAR                      (--out BUNDLE_DIR | --entities FILE)
    sync-okta --org ORG --token-env VAR
    sync-entra (--tenant T --client-id ID --secret-env VAR | --token-env VAR) [--nested direct]
    sync-keycloak --url U --realm R --token-env VAR [--nested inherit]
    sync-google [--customer C | --domain D] --token-env VAR
    sync-aws-identity-center --identity-store-id ID --region R     (AWS_* environment variables)
        common: --group-map FILE --attr-map FILE --user-id name|id|PATH --group-id name|id
                --dry-run (print the diff, write nothing) --force --max-removal-fraction F
                --revoke   after the write, end the live tokens of every user the sync removed or
                           who lost a group. Needs an engine (--config / --bundle / --state, with a
                           state directory) or a daemon (--daemon-url URL --admin-key-env VAR)
                --daemon-url URL --admin-key-env VAR   also POST /v1/admin/reload after the write
        After a sync a running engine must reload (or restart) to see the new entities.json, and a
        signed bundle must be re-signed: entities.json is part of the bundle version.
    map-claims --claims JSON|@file (--rule JSON|@file | [--provider P] [--map FILE] [--claim C])
    aws-session-policy (--token T | --cap JSON) --map FILE [--role-arn ARN]
    gcp-boundary       (--token T | --cap JSON) --map FILE
    azure-scopes       (--token T | --cap JSON) --map FILE
    ceiling --provider aws|gcp|azure --results @file --map FILE [--role R --roles FILE [--write]]

Switches (no value): --dry-run, --force, --revoke, --write, --unverified.

`--token` is a SmartDelegate capability token. It is verified with an engine
built from --config / --bundle / --state exactly like the main CLI; with
`--unverified` its payload is only decoded (use that for inspection, never to
mint a cloud credential). Output is JSON on stdout. A BridgeError exits 1 with
"code: message" on stderr. Secrets are only ever named by environment variable.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .. import cli as main_cli
from ..errors import EngineError
from . import BridgeError, aws, aws_identity_center, azure, ceiling, claims, cloudmap, directory, entra, gcp, google, keycloak, okta, scim
from .http import check_url, secret_from_env, urllib_transport

SWITCHES = ("force", "write", "unverified", "revoke")
SYNC = ("sync-scim", "sync-okta", "sync-entra", "sync-keycloak", "sync-google", "sync-aws-identity-center")


def _json(s: str, what: str):
    """Inline JSON or @file."""
    text = s
    if s.startswith("@"):
        try:
            text = Path(s[1:]).read_text(encoding="utf-8-sig")
        except OSError as e:
            raise BridgeError("invalid_input", f"--{what}: {s[1:]}: {e.strerror or e}") from None
    try:
        return json.loads(text)
    except ValueError as e:
        raise BridgeError("invalid_input", f"--{what} is not valid JSON: {e}") from None


def _need(args, name: str) -> str:
    v = args.flag(name)
    if not v:
        raise BridgeError("invalid_input", f"--{name} is required")
    return v


def _file(args, name: str):
    return _json("@" + args.flag(name), name) if args.flag(name) else None


def _snapshot(cmd: str, args, transport):
    if cmd == "sync-scim":
        return scim.fetch(_need(args, "url"), token_env=_need(args, "token-env"), transport=transport)
    if cmd == "sync-okta":
        return okta.fetch(_need(args, "org"), token_env=_need(args, "token-env"), transport=transport)
    if cmd == "sync-entra":
        nested = args.flag("nested") or "transitive"
        if args.flag("token-env"):
            return entra.fetch(token_env=args.flag("token-env"), transport=transport, nested=nested)
        token = entra.acquire_token(_need(args, "tenant"), _need(args, "client-id"), secret_env=_need(args, "secret-env"), transport=transport)
        return entra.fetch(token=token, transport=transport, nested=nested)
    if cmd == "sync-keycloak":
        return keycloak.fetch(_need(args, "url"), _need(args, "realm"), token_env=_need(args, "token-env"), transport=transport,
                              inherit=args.flag("nested") == "inherit")
    if cmd == "sync-google":
        return google.fetch(customer=args.flag("customer") or "my_customer", domain=args.flag("domain"),
                            token_env=_need(args, "token-env"), transport=transport)
    return aws_identity_center.fetch(_need(args, "identity-store-id"), _need(args, "region"), transport=transport)


def _sync(cmd: str, args, switches: set, transport) -> dict:
    if args.flag("entities"):
        path = Path(args.flag("entities"))
    elif args.flag("out"):
        path = Path(args.flag("out")) / "entities.json"
    else:
        raise BridgeError("invalid_input", "--out BUNDLE_DIR or --entities FILE is required")
    if not path.parent.is_dir():
        raise BridgeError("invalid_input", f"{path.parent} is not a directory")
    try:
        fraction = float(args.flag("max-removal-fraction") or 0.3)
    except ValueError:
        raise BridgeError("invalid_input", "--max-removal-fraction must be a number") from None
    mapping = {"user_id": args.flag("user-id") or "name", "group_id": args.flag("group-id") or "name",
               "group_map": _file(args, "group-map"), "attr_map": _file(args, "attr-map")}
    dry, revoke = args.has("dry-run"), "revoke" in switches
    # everything that can fail for configuration reasons fails here, before anything is fetched or written
    daemon = engine = None
    if args.flag("daemon-url"):
        from ..client import DaemonClient
        check_url(args.flag("daemon-url"))
        daemon = DaemonClient(args.flag("daemon-url"), admin_key=secret_from_env(_need(args, "admin-key-env")))
    elif revoke and not dry:
        engine, _ = main_cli.engine_from(args)
        if engine.state_dir is None:
            engine.close()
            raise BridgeError("invalid_input", "--revoke needs an engine with a state directory (--config or --state), or --daemon-url")
    try:
        snap = _snapshot(cmd, args, transport)
        out = directory.sync(snap, path, force="force" in switches, max_removal_fraction=fraction, dry_run=dry, **mapping)
        out["would_revoke"] = directory.users_to_revoke(out["diff"])
        if dry:
            return out
        problems = []
        out["reminders"] = ["a signed bundle must be re-signed now: entities.json is part of the bundle version (smartdelegate bundle sign)"]
        if daemon is not None:   # reload first, so that no new token is issued from the old membership
            try:
                r = daemon.call("reload", {})
            except Exception as e:
                r = {"ok": False, "error": {"code": getattr(e, "code", "daemon_unreachable"), "message": type(e).__name__}}
            if r.get("ok") is True:
                out["reload"] = {"ok": True, "policy_version": r.get("policy_version")}
            else:
                err = r.get("error") or {}
                out["reload"] = {"ok": False, "code": err.get("code", "error"), "message": err.get("message", "")}
                problems.append(("reload_failed", f"the daemon did not reload ({out['reload']['code']}); it still serves the old entities.json"))
        else:
            out["reminders"].insert(0, "a running engine must reload (POST /v1/admin/reload, or restart) to see the new entities.json")
        if revoke:
            try:
                out["revoked"] = directory.revoke_changed(daemon if daemon is not None else engine, out["diff"], by=f"sync:{snap.source}")["revoked"]
            except BridgeError as e:
                out["revoked"], out["not_revoked"] = e.detail["revoked"], e.detail["not_revoked"]
                problems.append((e.code, e.message))
        if problems:
            raise BridgeError(problems[-1][0], "entities.json WAS written, but: " + "; ".join(m for _, m in problems), {"result": out})
        return out
    finally:
        if engine is not None:
            engine.close()


def _cap(args, switches: set) -> tuple:
    """(cap, claims or None) from --cap or --token."""
    if args.flag("cap"):
        return _json(args.flag("cap"), "cap"), None
    token = _need(args, "token")
    if "unverified" in switches:
        from ..tokens import b64u_dec
        try:
            c = json.loads(b64u_dec(token.split(".")[1]))
            assert isinstance(c, dict) and isinstance(c.get("cap"), dict)
        except Exception:
            raise BridgeError("token_invalid", "the token's payload cannot be decoded") from None
        print("smartdelegate bridge: --unverified: the token's signature, expiry and revocation were NOT checked", file=sys.stderr)
        return c["cap"], c
    engine, _ = main_cli.engine_from(args)
    try:
        r = engine.call("inspect_token", {"token": token})
    finally:
        engine.close()
    if not r.get("ok") or not r.get("valid"):
        why = r.get("reason") or (r.get("error") or {}).get("code") or "invalid"
        raise BridgeError("token_invalid", f"the capability token was refused: {why}")
    return r["claims"]["cap"], r["claims"]


def _switches(argv: list) -> tuple:
    """Split off the boolean switches (--force, --write, --unverified), given
    bare or as --name=true|false, and return (set of those on, other arguments)."""
    on, rest = set(), []
    for a in argv:
        name, eq, value = (a[2:].partition("=") if a.startswith("--") else ("", "", ""))
        if name not in SWITCHES:
            rest.append(a)
        elif not eq or value.lower() in ("true", "1", "yes"):
            on.add(name)
        elif value.lower() not in ("false", "0", "no"):
            raise BridgeError("invalid_input", f"--{name} takes no value (or =true / =false)")
    return on, rest


def run(argv: list, transport=None) -> dict:
    """Execute one subcommand and return its JSON result. Raises BridgeError."""
    switches, rest = _switches(argv)
    args = main_cli.Args(rest)
    cmd = args.pos[0] if args.pos else "help"
    if cmd in SYNC:
        return _sync(cmd, args, switches, transport or urllib_transport)
    if cmd == "map-claims":
        if args.flag("rule"):
            rule = _json(args.flag("rule"), "rule")
        else:
            # shorthand: --map FILE alone reads the "groups" claim through the map
            rule = {"provider": args.flag("provider") or "generic"}
            if args.flag("map"):
                rule["map"] = _file(args, "map")
            if args.flag("claim") or rule["provider"] == "generic":
                rule["claim"] = args.flag("claim") or "groups"
        return {"groups": claims.groups_from_claims(_json(_need(args, "claims"), "claims"), rule)}
    if cmd in ("aws-session-policy", "gcp-boundary", "azure-scopes"):
        cloud_map = cloudmap.load(_need(args, "map"))
        cap, token_claims = _cap(args, switches)
        if cmd == "gcp-boundary":
            return gcp.access_boundary_report(cap, cloud_map)
        if cmd == "azure-scopes":
            return azure.scopes(cap, cloud_map)
        out = aws.session_policy_report(cap, cloud_map)
        if args.flag("role-arn"):
            if token_claims is None:
                raise BridgeError("invalid_input", "--role-arn needs --token: the session is named and tagged from the token")
            if "unverified" in switches:
                raise BridgeError("invalid_input", "refusing to build an AssumeRole request from an unverified token")
            out["assume_role"] = aws.assume_role_request(token_claims, None, cloud_map, args.flag("role-arn"))
        return out
    if cmd == "ceiling":
        provider, cloud_map = _need(args, "provider"), cloudmap.load(_need(args, "map"))
        results = _json(_need(args, "results"), "results")
        detail = {"aws": aws.ceiling_detail, "gcp": gcp.ceiling_detail, "azure": azure.ceiling_detail}.get(provider)
        if detail is None:
            raise BridgeError("invalid_input", "--provider must be aws, gcp or azure")
        out = detail(results, cloud_map)
        if args.flag("role"):
            out["role"] = ceiling.cap_role(_need(args, "roles"), args.flag("role"), out["cap"], write="write" in switches)
        return out
    raise BridgeError("usage", "unknown subcommand; see `smartdelegate bridge help`")


def main(argv: list | None = None, transport=None) -> int:
    """Entry point for `smartdelegate bridge ...`. `transport` replaces the
    default urllib transport (tests). Returns the exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or "--help" in argv or argv[0] in ("help", "-h"):
        print(__doc__)
        return 0
    try:
        print(json.dumps(run(argv, transport), indent=2, ensure_ascii=False))
        return 0
    except BridgeError as e:
        if isinstance(e.detail, dict) and "result" in e.detail:   # failed after a write: say what did happen
            print(json.dumps(e.detail["result"], indent=2, ensure_ascii=False))
        print(f"smartdelegate bridge: {e.code}: {e.message}", file=sys.stderr)
    except EngineError as e:
        print(f"smartdelegate bridge: {e.code}: {e.message}", file=sys.stderr)
    except SystemExit as e:  # the main CLI's die()
        return e.code if isinstance(e.code, int) else 1
    return 1
