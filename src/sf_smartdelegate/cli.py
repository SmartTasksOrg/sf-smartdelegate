"""`smartdelegate` command line: `python -m sf_smartdelegate <command>` (or the `smartdelegate`
script once the package is installed)."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

from . import __version__, bundle, conformance
from .engine import Engine
from .errors import EngineError

HELP = """smartdelegate - identity and access management for LLM agents

USAGE
  sf-smartdelegate <command> [options]          JSON options accept @file, e.g. --cap @cap.json

START HERE
  --demo                                a scripted walk through the example bundle
  --version

SETUP
  init <dir>                            create a working directory with an example bundle
  info                                  version, policy version, mode, key id
  policy check                          load the bundle and report problems
  policy test                           run the bundle's tests/*.json
  bundle keygen <prefix>                write <prefix>.key and <prefix>.pub (Ed25519)
  bundle sign --key <file>              sign the bundle (writes bundle.sig.json)
  bundle compile                        policies/*.cedar -> policies.json. Needs the Cedar
                                        toolchain: use the Rust port (ports/rust)

TOKENS
  token issue --user U --agent A (--cap JSON | --role R [--cap JSON]) [--groups g1,g2]
              [--ttl S] [--tenant T] [--task X] [--id-token JWT] [--raw]
                                        --role: lend the agent a role the user holds; the
                                        token can never carry more than the role allows
  token exchange --token T --actor A [--cap JSON] [--ttl S] [--raw]
  token inspect --token T
  token revoke --id TOKEN_ID | --token T | --user U     --user ends every token already
                                        issued for that human (offboarding)

DECISIONS
  authorize --token T --action A --resource path/id [--attrs JSON] [--context JSON]
            [--data JSON] [--strict] [--dry-run]      exit code 0 allow, 2 deny, 1 error
  explain   (same options)              show every check and every field decision
  approvals                             list held requests
  approve <approval_id> --by USER

AUDIT
  audit verify                          recompute the hash chain
  audit tail [-n N]

SERVERS
  serve [--listen 127.0.0.1:8181]       REST decision daemon
  http-proxy --routes FILE [--listen 127.0.0.1:8182]
  mcp-proxy --tools FILE [--token-file F] -- <mcp server command...>

BRIDGES (identity providers and clouds; see docs/BRIDGES.md)
  bridge sync-scim --url U --token-env VAR --out DIR     users and groups -> entities.json
  bridge sync-okta|sync-entra|sync-keycloak|sync-google|sync-aws-identity-center ...
  bridge map-claims --claims JSON --map FILE              ID-token claims -> groups
  bridge aws-session-policy --token T --map FILE          down-scoped STS session policy
  bridge gcp-boundary --token T --map FILE                Credential Access Boundary
  bridge azure-scopes --token T --map FILE                scopes for the On-Behalf-Of flow
  bridge ceiling --provider aws|gcp|azure ...             a role ceiling from what the human can do

OTHER
  call <op> [--input JSON|@file|-]      any operation of spec/API.md, JSON in, JSON out
  conformance <vectors dir> <bundle dir>
  bench [-n N]

CONFIG
  --config FILE (or SMARTDELEGATE_CONFIG, or ./smartdelegate.json); --bundle DIR and --state DIR override it.
  --shadow logs would-be denials without enforcing them.
"""

SWITCHES = {"raw", "strict", "dry-run", "shadow", "help", "force", "write", "unverified"}


def die(msg: str):
    print(f"smartdelegate: {msg}", file=sys.stderr)
    raise SystemExit(1)


class Args:
    def __init__(self, argv: list):
        self.pos, self.flags, self.rest = [], {}, []
        i = 0
        while i < len(argv):
            x = argv[i]
            if x == "--":
                self.rest = argv[i + 1:]
                break
            name = x[2:] if x.startswith("--") else (x[1:] if x.startswith("-") and len(x) == 2 else None)
            if name is None:
                self.pos.append(x)
            elif name in SWITCHES:
                self.flags[name] = "true"
            elif "=" in name:
                k, v = name.split("=", 1)
                self.flags[k] = v
            else:
                i += 1
                if i >= len(argv):
                    die(f"--{name} needs a value")
                self.flags[name] = argv[i]
            i += 1
        if "help" in self.flags:
            self.pos = ["help"]

    def flag(self, k):
        return self.flags.get(k)

    def has(self, k) -> bool:
        return k in self.flags

    def req(self, k) -> str:
        if k not in self.flags:
            die(f"--{k} is required")
        return self.flags[k]

    def at(self, n, usage: str) -> str:
        if len(self.pos) <= n:
            die(usage)
        return self.pos[n]


def json_arg(s: str):
    """A JSON value given inline or as @file (friendlier in PowerShell and cmd)."""
    text = s
    if s.startswith("@"):
        try:
            text = Path(s[1:]).read_text(encoding="utf-8-sig")
        except OSError as e:
            die(f"{s[1:]}: {e.strerror or e}")
    try:
        return json.loads(text)
    except ValueError as e:
        die(f"not valid JSON ({e}): {s}")


def load_config(args: Args) -> dict:
    """Config file + command-line overrides. Relative paths in the file are
    relative to the file."""
    path = args.flag("config") or os.environ.get("SMARTDELEGATE_CONFIG") or ("smartdelegate.json" if Path("smartdelegate.json").exists() else None)
    cfg: dict = {}
    if path:
        try:
            cfg = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as e:
            die(f"{path}: {e}")
        base = Path(path).resolve().parent
        fix = lambda p: p if Path(p).is_absolute() else str(base / p)
        for k in ("bundle_dir", "state_dir"):
            if isinstance(cfg.get(k), str):
                cfg[k] = fix(cfg[k])
        if isinstance(cfg.get("idp"), dict) and isinstance(cfg["idp"].get("jwks_file"), str):
            cfg["idp"]["jwks_file"] = fix(cfg["idp"]["jwks_file"])
    if args.flag("bundle"):
        cfg["bundle_dir"] = args.flag("bundle")
    if args.flag("state"):
        cfg["state_dir"] = args.flag("state")
    if args.has("shadow"):
        cfg["mode"] = "shadow"
    for k, env in (("admin_key", "SMARTDELEGATE_ADMIN_KEY"), ("pep_key", "SMARTDELEGATE_PEP_KEY")):
        if os.environ.get(env):
            cfg[k] = os.environ[env]
    if not cfg.get("bundle_dir"):
        die("no bundle: run `smartdelegate init <dir>`, or pass --config FILE or --bundle DIR")
    return cfg


def engine_from(args: Args):
    cfg = load_config(args)
    try:
        return Engine(cfg), cfg
    except EngineError as e:
        die(str(e))


def finish(v: dict) -> int:
    print(json.dumps(v, indent=2, ensure_ascii=False))
    return 1 if v.get("ok") is not True else (2 if v.get("effect") == "deny" else 0)


def decision_input(args: Args):
    res = args.req("resource")
    path, _, rid = res.partition("/")
    i = {"action": args.req("action"), "resource": {"path": path, "id": rid or "any"}}
    if args.flag("token"):
        i["token"] = args.flag("token")
    if args.flag("attrs"):
        i["resource"]["attrs"] = json_arg(args.flag("attrs"))
    if args.flag("context"):
        i["context"] = json_arg(args.flag("context"))
    if args.has("strict"):
        i["strict"] = True
    if args.has("dry-run"):
        i["dry_run"] = True
    if args.flag("data"):
        i["data"] = json_arg(args.flag("data"))
        return i, "filter"
    return i, "authorize"


def ttl_of(args: Args, i: dict) -> None:
    if args.flag("ttl"):
        try:
            i["ttl"] = int(args.flag("ttl"))
        except ValueError:
            die("--ttl must be a number of seconds")


def token_out(v: dict, args: Args) -> int:
    if args.has("raw") and v.get("ok"):
        print(v["token"])
        return 0
    return finish(v)


def init(target: Path) -> int:
    cfg_path = target / "smartdelegate.json"
    if cfg_path.exists():
        die(f"{cfg_path} already exists; not overwriting")
    shutil.copytree(Path(__file__).parent / "example_bundle", target / "bundle", dirs_exist_ok=True)
    cfg = {"bundle_dir": "bundle", "state_dir": "state", "issuer": "smartdelegate://local", "mode": "enforce",
           "listen": "127.0.0.1:8181", "admin_key": secrets.token_hex(20), "pep_key": secrets.token_hex(20)}
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    (target / "cap.json").write_text(json.dumps({"actions": ["read", "create", "update"], "resources": ["crm.customer/*", "billing.refund/*"],
                                                 "budget": {"EUR": 20000}}, indent=2), encoding="utf-8")
    print(f"Created {cfg_path}\n  bundle/   example policies, entities and field catalog\n  state/    signing key, audit log (created on first use)\n\n"
          f"Next:\n  cd {target}\n  smartdelegate policy test\n  smartdelegate token issue --user alice --agent support-bot --cap @cap.json --raw")
    return 0


def report(results: dict, label: str) -> int:
    for r in results["results"]:
        if not r["passed"]:
            print(f"FAIL {json.dumps(r['name'])}\n{json.dumps(r['failures'], indent=2)}")
    print(f"{label}: {results['total']} cases, {results['failed']} failed")
    return 0 if results["failed"] == 0 else 1


def bench(args: Args) -> int:
    n = int(args.flag("n") or 2000)
    cfg = load_config(args)
    state = tempfile.mkdtemp(prefix="smartdelegate-bench-")
    cfg["state_dir"] = state
    try:
        with Engine(cfg) as e:
            t = e.call("issue_token", {"user": "alice", "agent": "support-bot", "cap": {"actions": ["read"], "resources": ["crm.customer/*"]}})
            if not t.get("ok"):
                die("bench needs the example bundle (user alice, agent support-bot)")
            req = {"token": t["token"], "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}}
            times = []
            for _ in range(n):
                t0 = time.perf_counter()
                r = e.call("authorize", req)
                times.append((time.perf_counter() - t0) * 1000)
                if r.get("effect") != "allow":
                    die("unexpected deny during bench")
    finally:
        shutil.rmtree(state, ignore_errors=True)
    times.sort()
    print(json.dumps({"what": "python, in-process, example bundle, audit log on, 12 field decisions per call", "calls": n,
                      "p50_ms": round(statistics.median(times), 3), "p99_ms": round(times[int((n - 1) * 0.99)], 3),
                      "max_ms": round(times[-1], 3)}, indent=2))
    return 0


def core_demo() -> str:
    """The scripted demo (`smartdelegate --demo`) as text."""
    from . import core
    return core.demo()


def main(argv: list | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] in ("--version", "-V"):
        print(f"smartdelegate {__version__} (python)")
        return 0
    if raw and raw[0] in ("--help", "-h"):
        print(HELP, end="")
        return 0
    if raw and raw[0] in ("--demo", "demo"):
        print(core_demo())
        return 0
    if raw and raw[0] == "bridge":
        # the bridges have their own options; hand the rest over untouched
        from .bridges import cli as bridge_cli
        return bridge_cli.main(raw[1:])
    args = Args(raw)
    cmd = args.pos[0] if args.pos else "help"
    sub = args.pos[1] if len(args.pos) > 1 else ""
    if cmd in ("help", "-h"):
        print(HELP, end="")
        return 0
    if cmd == "version":
        print(f"smartdelegate {__version__} (python)")
        return 0
    if cmd == "init" and sub:
        return init(Path(sub))
    if cmd == "info":
        return finish(engine_from(args)[0].call("info", {}))
    if (cmd, sub) == ("policy", "check"):
        info = engine_from(args)[0].call("info", {})
        print(f"bundle loads: {info['policies']} policies, version {info['policy_version']}")
        return 0
    if (cmd, sub) == ("policy", "test"):
        try:
            r = conformance.run_bundle_tests(load_config(args)["bundle_dir"])
        except EngineError as e:
            die(str(e))
        for c in r["results"]:
            print(("ok  " if c["passed"] else "FAIL"), c["name"])
            if not c["passed"]:
                print(json.dumps(c["failures"], indent=2))
        print(f"{r['total']} tests, {r['failed']} failed")
        return 0 if r["failed"] == 0 else 1
    if (cmd, sub) == ("bundle", "keygen"):
        prefix = args.at(2, "usage: smartdelegate bundle keygen <prefix>")
        sk, pk = bundle.keygen()
        fd = os.open(prefix + ".key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(sk)
        Path(prefix + ".pub").write_text(pk, encoding="utf-8")
        print(f'wrote {prefix}.key (keep secret) and {prefix}.pub\nset "bundle_public_key": "{pk}" in smartdelegate.json to require signed bundles')
        return 0
    if (cmd, sub) == ("bundle", "sign"):
        try:
            v = bundle.sign(Path(load_config(args)["bundle_dir"]), Path(args.req("key")).read_text(encoding="utf-8"))
        except (EngineError, OSError) as e:
            die(str(e))
        print(f"signed bundle version {v['version']} with key {v['key_id']}")
        return 0
    if (cmd, sub) == ("bundle", "compile"):
        die("compiling .cedar to policies.json needs the Cedar toolchain: run `smartdelegate bundle compile` from the Rust port (ports/rust)")
    if (cmd, sub) == ("token", "issue"):
        i = {"agent": args.req("agent")}
        if args.flag("cap"):
            i["cap"] = json_arg(args.flag("cap"))
        elif not args.flag("role"):
            die("--cap JSON or --role NAME is required")
        for k, f in (("user", "user"), ("tenant", "tenant"), ("task", "task"), ("id_token", "id-token"), ("role", "role")):
            if args.flag(f):
                i[k] = args.flag(f)
        if args.flag("groups") is not None and args.has("groups"):
            i["groups"] = [g for g in args.flag("groups").split(",") if g]
        ttl_of(args, i)
        return token_out(engine_from(args)[0].call("issue_token", i), args)
    if (cmd, sub) == ("token", "exchange"):
        i = {"subject_token": args.req("token"), "actor": args.req("actor")}
        if args.flag("cap"):
            i["cap"] = json_arg(args.flag("cap"))
        ttl_of(args, i)
        return token_out(engine_from(args)[0].call("exchange_token", i), args)
    if (cmd, sub) == ("token", "inspect"):
        return finish(engine_from(args)[0].call("inspect_token", {"token": args.req("token")}))
    if (cmd, sub) == ("token", "revoke"):
        if args.flag("user"):
            i = {"user": args.flag("user"), "by": "cli"}
        else:
            i = {"token_id": args.flag("id"), "by": "cli"} if args.flag("id") else {"token": args.req("token"), "by": "cli"}
        return finish(engine_from(args)[0].call("revoke", i))
    if cmd == "call" and sub:
        # any operation, input as JSON: the form other ports and scripts use
        raw = args.flag("input") or "{}"
        return finish(engine_from(args)[0].call(sub, json.loads(sys.stdin.read()) if raw == "-" else json_arg(raw)))
    if cmd == "authorize":
        i, op = decision_input(args)
        return finish(engine_from(args)[0].call(op, i))
    if cmd == "explain":
        return finish(engine_from(args)[0].call("explain", decision_input(args)[0]))
    if cmd == "approvals":
        return finish(engine_from(args)[0].call("approvals", {}))
    if cmd == "approve" and sub:
        return finish(engine_from(args)[0].call("approve", {"approval_id": sub, "by": args.req("by")}))
    if (cmd, sub) == ("audit", "verify"):
        return finish(engine_from(args)[0].call("audit_verify", {}))
    if (cmd, sub) == ("audit", "tail"):
        r = engine_from(args)[0].call("audit_tail", {"n": int(args.flag("n") or 20)})
        for rec in r.get("records") or []:
            print(json.dumps(rec, separators=(",", ":"), ensure_ascii=False))
        return 0
    if cmd == "serve":
        from . import daemon
        engine, cfg = engine_from(args)
        daemon.serve(engine, args.flag("listen") or cfg.get("listen") or "127.0.0.1:8181", cfg.get("admin_key") or "", cfg.get("pep_key") or "")
        return 0
    if cmd == "http-proxy":
        from . import httpproxy
        engine, _ = engine_from(args)
        routes = json_arg("@" + args.req("routes"))
        httpproxy.serve(engine, routes, args.flag("listen") or routes.get("listen") or "127.0.0.1:8182")
        return 0
    if cmd == "mcp-proxy":
        from . import mcpproxy
        if not args.rest:
            die("usage: smartdelegate mcp-proxy --tools FILE [--token-file F] -- <mcp server command...>")
        engine, _ = engine_from(args)
        return mcpproxy.run(engine, json_arg("@" + args.req("tools")), args.rest, args.flag("token-file"))
    if cmd == "conformance" and sub:
        try:
            return report(conformance.run_vectors(sub, args.pos[2] if len(args.pos) > 2 else "spec/conformance/bundle"), "conformance")
        except EngineError as e:
            die(str(e))
    if cmd == "bench":
        return bench(args)
    print(HELP, end="", file=sys.stderr)
    return 1
