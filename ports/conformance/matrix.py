#!/usr/bin/env python3
"""Cross-port interoperability matrix for the SmartDelegate engine ports.

For every ordered pair (issuer port A, verifier port B), A != B, each port is
driven through its command line in separate processes with separate state
directories:

  a  role token with live groups: A issues, B (verify_only, trusted_keys = A's
     public key) inspects, authorizes and filters; B's filter result is
     compared with A's own
  b  A exchanges to a sub-agent with a narrower cap; B accepts the child and
     denies what is outside the child's cap with A's reason and rule
  c  a tampered token (one payload character changed; token + "!!!!") is
     token_invalid on B
  d  A signs a copy of the conformance bundle; B loads it with
     bundle_public_key and reports A's policy_version; after roles.json is
     edited B refuses to load it (bundle_signature)
  e  A writes an audit log (one task contains U+2028); B verifies a copy of
     A's state directory: same record count and head hash; after one byte is
     flipped B reports audit_broken

Then the ports that lock the state directory with flock (python, rust, go,
php) take turns on ONE state directory: spend against a budget, revocation,
an approval, a burst of concurrent spends, and one audit chain verified by each.

The Java port is built with its own ports/java/build.sh (into ports/java/build,
which git ignores) and driven through ports/java/bin/smartdelegate-java like
the others. It is left out of the shared-directory part, as Node.js is: both
use their own locks.

Python 3.10+, standard library only. Keys, state, bundle copies and the Go
binary go to a temporary directory that is removed at the end (--keep keeps
it, so that the printed commands can be re-run). The only things written
below the repository are the Java and Rust ports' own ignored build
directories (ports/java/build, ports/rust/target). Exit status: 0 no FAIL, 1 at least one FAIL, 2 usage or setup error.

  python3 ports/conformance/matrix.py [--report FILE] [--ports a,b] [--checks a,b,c,d,e,shared]
                                      [--jobs N] [--timeout S] [--keep] [--verbose]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUNDLE = ROOT / "spec" / "conformance" / "bundle"
ISSUER = "smartdelegate://matrix"
T0 = 1700000000
PORTS = ["python", "java", "node", "go", "php", "rust"]
FLOCK_PORTS = ["python", "rust", "go", "php"]  # the READMEs that document flock(2) on <state>/lock
CHECKS = {
    "a": "role token with live groups: inspect, authorize, filter (B's result = A's)",
    "b": "exchanged sub-agent token: accepted; out-of-cap action denied with A's reason and rule",
    "c": "tampered token is token_invalid",
    "d": "bundle signed by A loads in B with the same policy_version; edited roles.json is bundle_signature",
    "e": "audit log written by A verifies in B (same records, same head); flipped byte is audit_broken",
}
RECORD = {"id": "c-1", "name": "Ann", "email": "ann@example.com", "region": "US", "tier": "gold", "ssn": "123-45-6789",
          "notes": "called twice", "card": {"last4": "4242", "number": "4111111111111111"}}
CUSTOMER = {"path": "crm.customer", "id": "c-1"}
REFUND = {"path": "billing.refund", "id": "r-1"}
CHILD_CAP = {"actions": ["read"], "resources": ["crm.customer/*"], "deny_labels": ["secret"]}
SUPPORT = [{"type": "Group", "id": "support"}]


class Fail(Exception):
    """A check cannot continue."""


# ---------------------------------------------------------------- JSON values

def same(a, b) -> bool:
    """Equality of JSON values: object member order is ignored, true is not 1, 1 is not 1.0."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same(v, b[k]) for k, v in a.items())
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b


def short(v, limit: int = 300) -> str:
    text = json.dumps(v, ensure_ascii=True, sort_keys=True) if not isinstance(v, str) else v
    return text if len(text) <= limit else text[:limit] + "..."


# ---------------------------------------------------------------------- ports

class Port:
    def __init__(self, name: str, argv: list, env: dict | None = None):
        self.name, self.argv, self.env = name, [str(x) for x in argv], env or {}
        self.version = ""

    def shell(self, args: list, stdin: str | None) -> str:
        env = "".join(f"{k}={shlex.quote(v)} " for k, v in self.env.items())
        cmd = env + shlex.join(self.argv + [str(a) for a in args])
        return cmd if stdin is None else f"printf '%s' {shlex.quote(stdin)} | {cmd}"

    def run(self, log: list, args: list, stdin: str | None = None) -> dict:
        """Runs one command. Returns {"rc", "out", "err", "json", "code"}: `json` is stdout when it is a
        JSON object, `code` the error code (from the JSON error, or from "smartdelegate: <code>: ..." on stderr)."""
        log.append(self.shell(args, stdin))
        try:
            p = subprocess.run(self.argv + [str(a) for a in args], input=(stdin or "").encode("utf-8"), capture_output=True,
                               timeout=OPTIONS.timeout, env={**os.environ, **self.env}, cwd=str(OPTIONS.work))
        except subprocess.TimeoutExpired:
            log.append(f"#   -> no answer within {OPTIONS.timeout} s")
            return {"rc": None, "out": "", "err": f"timeout after {OPTIONS.timeout} s", "json": None, "code": "timeout"}
        except OSError as e:
            log.append(f"#   -> could not start: {e}")
            return {"rc": None, "out": "", "err": str(e), "json": None, "code": "not_started"}
        out, err = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
        err = "\n".join(line for line in err.splitlines() if not line.startswith("Picked up JAVA_TOOL_OPTIONS"))
        doc = None
        try:
            doc = json.loads(out)
        except ValueError:
            pass
        if not isinstance(doc, dict):
            doc = None
        code = None
        if doc is not None and doc.get("ok") is not True:
            error = doc.get("error")
            code = error.get("code") if isinstance(error, dict) else "malformed_result"
        elif doc is None:
            m = re.search(r"^smartdelegate[^:\n]*: ([a-z_]+): ", err, re.M)
            code = m.group(1) if m else "no_json_output"
        log.append(f"#   -> exit {p.returncode}: " + short(doc if doc is not None else (err.strip() or out.strip())).replace("\n", " | "))
        return {"rc": p.returncode, "out": out, "err": err, "json": doc, "code": code}

    def call(self, log: list, op: str, payload: dict, config: Path) -> dict:
        """An operation of spec/API.md. Always returns an object; a result that is not one becomes
        {"ok": false, "error": {"code": ...}}."""
        r = self.run(log, ["call", op, "--config", config, "--input", "-"], json.dumps(payload, ensure_ascii=False))
        return r["json"] if r["json"] is not None else {"ok": False, "error": {"code": r["code"], "message": (r["err"] or r["out"]).strip()[:500]}}

    def audit_verify(self, log: list, config: Path) -> dict:
        r = self.run(log, ["audit", "verify", "--config", config])
        return r["json"] if r["json"] is not None else {"ok": False, "error": {"code": r["code"], "message": (r["err"] or r["out"]).strip()[:500]}}


def tool(log: list, argv: list, cwd: Path, env: dict | None = None, timeout: int = 900) -> tuple:
    log.append(f"(cd {shlex.quote(str(cwd))} && {shlex.join(str(a) for a in argv)})")
    try:
        p = subprocess.run([str(a) for a in argv], cwd=str(cwd), capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})})
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 1, f"timeout after {timeout} s"
    except OSError as e:
        return 1, str(e)


def discover(work: Path, wanted: list) -> tuple:
    """-> ({name: Port}, {name: why it is skipped})"""
    ports, skipped, log = {}, {}, []
    bin_dir = work / "bin"
    bin_dir.mkdir()
    for name in wanted:
        if name == "python":
            env = {"PYTHONPATH": str(ROOT / "src") + (os.pathsep + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")}
            rc, out = tool(log, [sys.executable, "-c", "import cryptography"], ROOT)
            if rc != 0:
                skipped[name] = "the Python package `cryptography` is not installed"
                continue
            ports[name] = Port(name, [sys.executable, "-m", "sf_smartdelegate"], env)
        elif name == "node":
            if not shutil.which("node"):
                skipped[name] = "node is not installed"
                continue
            ports[name] = Port(name, ["node", ROOT / "ports/node/bin/cli.mjs"])
        elif name == "php":
            if not shutil.which("php"):
                skipped[name] = "php is not installed"
                continue
            rc, out = tool(log, ["php", "-r", "exit(extension_loaded('sodium') ? 0 : 1);"], ROOT)
            if rc != 0:
                skipped[name] = "php has no sodium extension"
                continue
            ports[name] = Port(name, ["php", ROOT / "ports/php/bin/smartdelegate-php"])
        elif name == "go":
            if not shutil.which("go"):
                skipped[name] = "go is not installed"
                continue
            exe = bin_dir / ("smartdelegate-go.exe" if os.name == "nt" else "smartdelegate-go")
            rc, out = tool(log, ["go", "build", "-o", exe, "./cmd/smartdelegate-go"], ROOT / "ports/go",
                           {"GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "local"), "GOFLAGS": os.environ.get("GOFLAGS", "-buildvcs=false")})
            if rc != 0:
                raise SystemExit(f"matrix: go build failed:\n{out}")
            ports[name] = Port(name, [exe])
        elif name == "rust":
            exe = ROOT / "ports/rust/target/release" / ("smartdelegate.exe" if os.name == "nt" else "smartdelegate")
            if shutil.which("cargo"):
                rc, out = tool(log, ["cargo", "build", "--release"], ROOT / "ports/rust", timeout=3600)
                if rc != 0:
                    raise SystemExit(f"matrix: cargo build --release failed:\n{out[-3000:]}")
            elif not exe.exists():
                skipped[name] = "cargo is not installed and ports/rust/target/release/smartdelegate does not exist"
                continue
            else:
                NOTES.append("rust: cargo is not installed; using the existing ports/rust/target/release/smartdelegate as it is")
            ports[name] = Port(name, [exe])
        elif name == "java":
            if not (shutil.which("javac") and shutil.which("java") and shutil.which("jar")):
                skipped[name] = "a JDK (javac, jar, java) is not installed"
                continue
            windows = os.name == "nt"
            rc, out = tool(log, ["cmd", "/c", "build.cmd"] if windows else ["sh", "build.sh"], ROOT / "ports/java")
            if rc != 0:
                raise SystemExit(f"matrix: building the Java port (ports/java/build.sh) failed:\n{out[-3000:]}")
            ports[name] = Port(name, [ROOT / "ports/java/bin" / ("smartdelegate-java.cmd" if windows else "smartdelegate-java")])
    return ports, skipped


# -------------------------------------------------------------------- results

class Cell:
    """One (check, issuer, verifier) result with the commands that produced it."""

    def __init__(self, check: str, issuer: str, verifier: str, setup: list | None = None):
        self.check, self.issuer, self.verifier = check, issuer, verifier
        self.log = list(setup or [])
        self.problems: list = []
        self.status = "PASS"
        self.note = ""

    def expect(self, ok: bool, message: str) -> bool:
        if not ok:
            self.problems.append(message)
            self.status = "FAIL"
        return ok

    def need(self, ok: bool, message: str) -> None:
        if not self.expect(ok, message):
            raise Fail(message)

    def to_json(self) -> dict:
        d = {"check": self.check, "issuer": self.issuer, "verifier": self.verifier, "status": self.status}
        if self.note:
            d["note"] = self.note
        if self.status == "FAIL":
            d["problems"], d["commands"] = self.problems, self.log
        return d


def write_config(path: Path, state: Path, bundle: Path = BUNDLE, **extra) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"bundle_dir": str(bundle), "state_dir": str(state), "issuer": ISSUER, "allow_test_clock": True, **extra}, indent=1), encoding="utf-8")
    return path


def pick(d, *keys):
    return {k: (d or {}).get(k) for k in keys}


def tamper_payload(token: str) -> str:
    head, payload, sig = token.split(".")
    i = len(payload) // 2
    return ".".join([head, payload[:i] + ("B" if payload[i] != "B" else "C") + payload[i + 1:], sig])


# ------------------------------------------------------ what the issuer makes

def prepare_tokens(a: Port, base: Path) -> dict:
    """A issues a role token with live groups and exchanges it; A's own answers are the reference for B."""
    c = Cell("setup", a.name, a.name)
    cfg = write_config(base / "issuer.json", base / "issuer-state")
    out = {"cell": c}
    try:
        info = a.call(c.log, "info", {}, cfg)
        c.need(info.get("ok") is True and isinstance(info.get("public_key"), str), f"{a.name} info: {short(info)}")
        out["public_key"] = info["public_key"]
        t = a.call(c.log, "issue_token", {"user": "dave", "agent": "support-bot", "role": "support-agent", "groups": ["support"], "task": "ticket-4711", "now": T0}, cfg)
        c.need(t.get("ok") is True and isinstance(t.get("token"), str), f"{a.name} issue_token (role, live groups): {short(t)}")
        c.expect(t.get("role") == "support-agent", f"{a.name} issue_token: role is {short(t.get('role'))}")
        out["token"] = t["token"]
        ins = a.call(c.log, "inspect_token", {"token": t["token"], "now": T0 + 1}, cfg)
        c.need(ins.get("valid") is True and isinstance(ins.get("claims"), dict), f"{a.name} inspect_token of its own token: {short(ins)}")
        c.expect(ins["claims"].get("role") == "support-agent" and same(ins["claims"].get("grp"), SUPPORT),
                 f"{a.name}: its own token has role {short(ins['claims'].get('role'))}, grp {short(ins['claims'].get('grp'))}")
        out["claims"] = ins["claims"]
        request = {"token": t["token"], "action": "read", "resource": CUSTOMER, "now": T0 + 2}
        out["authorize"] = a.call(c.log, "authorize", request, cfg)
        c.expect(out["authorize"].get("effect") == "allow", f"{a.name} authorize with its own token: {short(out['authorize'])}")
        out["filter"] = a.call(c.log, "filter", {**request, "data": RECORD}, cfg)
        c.need(out["filter"].get("effect") == "allow", f"{a.name} filter with its own token: {short(out['filter'])}")
        c.expect(isinstance(out["filter"].get("data"), dict) and "ssn" not in out["filter"]["data"] and "notes" not in out["filter"]["data"],
                 f"{a.name} filter left ssn / notes in the data: {short(out['filter'].get('data'))}")
        child = a.call(c.log, "exchange_token", {"subject_token": t["token"], "actor": "refund-helper", "cap": CHILD_CAP, "ttl": 300, "now": T0 + 3}, cfg)
        c.need(child.get("ok") is True and isinstance(child.get("token"), str), f"{a.name} exchange_token: {short(child)}")
        out["child"] = child["token"]
        out["child_read"] = a.call(c.log, "authorize", {"token": child["token"], "action": "read", "resource": CUSTOMER, "now": T0 + 4}, cfg)
        c.expect(out["child_read"].get("effect") == "allow", f"{a.name} authorize read with the child token: {short(out['child_read'])}")
        out["child_denied"] = {}
        for label, action, resource in (("action", "update", CUSTOMER), ("resource", "read", REFUND)):
            d = a.call(c.log, "authorize", {"token": child["token"], "action": action, "resource": resource, "now": T0 + 5}, cfg)
            c.expect(d.get("effect") == "deny" and isinstance(d.get("reason"), str),
                     f"{a.name} did not deny {action} on {resource['path']} for a child whose cap is {short(CHILD_CAP)}: {short(d)}")
            out["child_denied"][label] = (action, resource, d)
    except Fail:
        pass
    return out


def prepare_bundle(a: Port, base: Path) -> dict:
    c = Cell("setup", a.name, a.name)
    out = {"cell": c}
    try:
        keys = base / "bundle-key"
        r = a.run(c.log, ["bundle", "keygen", keys])
        c.need(r["rc"] == 0 and Path(str(keys) + ".pub").is_file() and Path(str(keys) + ".key").is_file(), f"{a.name} bundle keygen: exit {r['rc']}, {short(r['err'] or r['out'])}")
        out["public_key"] = Path(str(keys) + ".pub").read_text(encoding="utf-8").strip()
        out["bundle"] = base / "signed-bundle"
        shutil.copytree(BUNDLE, out["bundle"])
        c.log.append(f"cp -r {shlex.quote(str(BUNDLE))} {shlex.quote(str(out['bundle']))}")
        r = a.run(c.log, ["bundle", "sign", "--key", str(keys) + ".key", "--bundle", out["bundle"]])
        c.need(r["rc"] == 0 and (out["bundle"] / "bundle.sig.json").is_file(), f"{a.name} bundle sign: exit {r['rc']}, {short(r['err'] or r['out'])}")
        cfg = write_config(base / "issuer-bundle.json", base / "issuer-bundle-state", out["bundle"], bundle_public_key=out["public_key"])
        info = a.call(c.log, "info", {}, cfg)
        c.need(info.get("ok") is True and isinstance(info.get("policy_version"), str), f"{a.name} does not load the bundle it signed: {short(info)}")
        out["info"] = info
    except Fail:
        pass
    return out


def prepare_audit(a: Port, base: Path) -> dict:
    c = Cell("setup", a.name, a.name)
    out = {"cell": c, "state": base / "audit-state"}
    cfg = write_config(base / "issuer-audit.json", out["state"])
    try:
        t = a.call(c.log, "issue_token", {"user": "dave", "agent": "support-bot", "role": "support-agent", "groups": ["support"],
                                          "task": "ticket with a line separator  \u0085 é", "now": T0}, cfg)
        c.need(t.get("ok") is True and isinstance(t.get("token"), str), f"{a.name} issue_token with U+2028 in the task: {short(t)}")
        request = {"token": t["token"], "action": "read", "resource": CUSTOMER, "now": T0 + 1}
        c.expect(a.call(c.log, "filter", {**request, "data": RECORD}, cfg).get("effect") == "allow", f"{a.name} filter did not allow")
        c.expect(a.call(c.log, "authorize", {**request, "action": "delete"}, cfg).get("effect") == "deny", f"{a.name} authorize delete did not deny")
        child = a.call(c.log, "exchange_token", {"subject_token": t["token"], "actor": "summarizer", "cap": CHILD_CAP, "ttl": 120, "now": T0 + 2}, cfg)
        c.expect(child.get("ok") is True, f"{a.name} exchange_token: {short(child)}")
        c.expect(a.call(c.log, "revoke", {"token_id": t.get("token_id"), "by": "matrix", "now": T0 + 3}, cfg).get("ok") is True, f"{a.name} revoke failed")
        c.expect(a.call(c.log, "authorize", {**request, "now": T0 + 4}, cfg).get("reason") == "token_revoked", f"{a.name} authorize after revoke is not token_revoked")
        v = a.audit_verify(c.log, cfg)
        c.need(v.get("ok") is True and isinstance(v.get("records"), int) and isinstance(v.get("head"), str), f"{a.name} audit verify of its own log: {short(v)}")
        c.expect(v["records"] >= 5, f"{a.name} wrote {v['records']} audit records for 6 audited operations")
        out["verify"] = v
    except Fail:
        pass
    return out


# ------------------------------------------------------ what the verifier does

def check_a(c: Cell, b: Port, cfg: Path, made: dict) -> None:
    token = made["token"]
    ins = b.call(c.log, "inspect_token", {"token": token, "now": T0 + 1}, cfg)
    if c.expect(ins.get("valid") is True, f"{b.name} inspect_token: expected valid, got {short(pick(ins, 'valid', 'reason', 'detail', 'error'))}"):
        claims = ins.get("claims") if isinstance(ins.get("claims"), dict) else {}
        c.expect(claims.get("role") == "support-agent", f"{b.name} inspect_token: claims.role is {short(claims.get('role'))}")
        c.expect(same(claims.get("grp"), SUPPORT), f"{b.name} inspect_token: claims.grp is {short(claims.get('grp'))}")
        c.expect(same(claims, made["claims"]), f"{b.name} inspect_token: claims differ from {c.issuer}'s: {short(claims, 600)} vs {short(made['claims'], 600)}")
    request = {"token": token, "action": "read", "resource": CUSTOMER, "now": T0 + 2}
    d = b.call(c.log, "authorize", request, cfg)
    c.expect(d.get("effect") == "allow", f"{b.name} authorize read crm.customer: expected allow, got {short(pick(d, 'effect', 'reason', 'detail', 'error'))}")
    principal = d.get("principal") if isinstance(d.get("principal"), dict) else {}
    c.expect(principal.get("role") == "support-agent", f"{b.name} authorize: principal.role is {short(principal.get('role'))}")
    c.expect(same(d.get("principal"), made["authorize"].get("principal")),
             f"{b.name} authorize: principal {short(d.get('principal'))} differs from {c.issuer}'s {short(made['authorize'].get('principal'))}")
    f = b.call(c.log, "filter", {**request, "data": RECORD}, cfg)
    for key in ("effect", "reason", "rule", "policies", "data", "masked", "rows_dropped", "obligations"):
        c.expect(key in f and same(f.get(key), made["filter"].get(key)),
                 f"{b.name} filter: `{key}` is {short(f.get(key))}, {c.issuer} itself returns {short(made['filter'].get(key))}")


def check_b(c: Cell, b: Port, cfg: Path, made: dict) -> None:
    child = made["child"]
    ins = b.call(c.log, "inspect_token", {"token": child, "now": T0 + 4}, cfg)
    c.expect(ins.get("valid") is True and same(ins.get("chain"), ["support-bot", "refund-helper"]),
             f"{b.name} inspect_token of the child: {short(pick(ins, 'valid', 'chain', 'reason', 'detail', 'error'))}")
    d = b.call(c.log, "authorize", {"token": child, "action": "read", "resource": CUSTOMER, "now": T0 + 4}, cfg)
    c.expect(d.get("effect") == "allow", f"{b.name} authorize read with the child token: expected allow, got {short(pick(d, 'effect', 'reason', 'detail', 'error'))}")
    c.expect(same(d.get("principal"), made["child_read"].get("principal")),
             f"{b.name} authorize (child): principal {short(d.get('principal'))} differs from {c.issuer}'s {short(made['child_read'].get('principal'))}")
    for label, (action, resource, ref) in made["child_denied"].items():
        d = b.call(c.log, "authorize", {"token": child, "action": action, "resource": resource, "now": T0 + 5}, cfg)
        c.expect(d.get("effect") == "deny", f"{b.name} authorize {action} {resource['path']} (outside the child's cap): expected deny, got {short(pick(d, 'effect', 'reason', 'error'))}")
        c.expect(same(pick(d, "reason", "rule"), pick(ref, "reason", "rule")),
                 f"{b.name} denies {action} {resource['path']} with {short(pick(d, 'reason', 'rule'))}, {c.issuer} with {short(pick(ref, 'reason', 'rule'))}")


def check_c(c: Cell, b: Port, cfg: Path, made: dict) -> None:
    for what, bad in (("one payload character changed", tamper_payload(made["token"])), ('token + "!!!!"', made["token"] + "!!!!"),
                      ("child, one payload character changed", tamper_payload(made["child"]))):
        ins = b.call(c.log, "inspect_token", {"token": bad, "now": T0 + 1}, cfg)
        c.expect(ins.get("valid") is False and ins.get("reason") == "token_invalid",
                 f"{b.name} inspect_token ({what}): expected valid false / token_invalid, got {short(pick(ins, 'valid', 'reason', 'detail', 'error'))}")
        d = b.call(c.log, "authorize", {"token": bad, "action": "read", "resource": CUSTOMER, "now": T0 + 2}, cfg)
        c.expect(d.get("effect") == "deny" and d.get("reason") == "token_invalid" and d.get("rule") == "DELEGATE-TOKEN-INVALID",
                 f"{b.name} authorize ({what}): expected deny token_invalid, got {short(pick(d, 'effect', 'reason', 'rule', 'error'))}")


def check_d(c: Cell, b: Port, base: Path, made: dict) -> None:
    copy = base / "bundle"
    shutil.copytree(made["bundle"], copy)
    c.log.append(f"cp -r {shlex.quote(str(made['bundle']))} {shlex.quote(str(copy))}")
    cfg = write_config(base / "bundle.json", base / "bundle-state", copy, bundle_public_key=made["public_key"])
    info = b.call(c.log, "info", {}, cfg)
    if c.expect(info.get("ok") is True, f"{b.name} does not load the bundle signed by {c.issuer}: {short(info.get('error'))}"):
        for key in ("policy_version", "bundle_signed_by", "roles"):
            c.expect(same(info.get(key), made["info"].get(key)), f"{b.name} info: {key} is {short(info.get(key))}, {c.issuer} reports {short(made['info'].get(key))}")
    roles = copy / "roles.json"
    text = roles.read_text(encoding="utf-8")
    c.need('"max_ttl": 600' in text, "matrix: roles.json of the conformance bundle no longer has \"max_ttl\": 600; update check d")
    roles.write_text(text.replace('"max_ttl": 600', '"max_ttl": 86400', 1), encoding="utf-8")
    c.log.append(f"sed -i 's/\"max_ttl\": 600/\"max_ttl\": 86400/' {shlex.quote(str(roles))}")
    info = b.call(c.log, "info", {}, cfg)
    code = (info.get("error") or {}).get("code") if isinstance(info.get("error"), dict) else None
    c.expect(info.get("ok") is not True and code == "bundle_signature",
             f"{b.name} with roles.json edited after signing: expected refusal bundle_signature, got {short(info if info.get('ok') is not True else pick(info, 'ok', 'policy_version'))}")


def check_e(c: Cell, b: Port, base: Path, made: dict) -> None:
    copy = base / "audit-state"
    shutil.copytree(made["state"], copy)
    c.log.append(f"cp -r {shlex.quote(str(made['state']))} {shlex.quote(str(copy))}")
    cfg = write_config(base / "audit.json", copy)
    v = b.audit_verify(c.log, cfg)
    if c.expect(v.get("ok") is True, f"{b.name} audit verify of {c.issuer}'s log: {short(v)}"):
        c.expect(same(pick(v, "records", "head"), pick(made["verify"], "records", "head")),
                 f"{b.name} audit verify: {short(pick(v, 'records', 'head'))}, {c.issuer} itself: {short(pick(made['verify'], 'records', 'head'))}")
    log_file = copy / "audit.jsonl"
    raw = bytearray(log_file.read_bytes())
    at = raw.find(b'"user":"dave"', raw.find(b"\n") + 1)
    c.need(at > 0, f"matrix: no second audit record with \"user\":\"dave\" in {c.issuer}'s log")
    at += len(b'"user":"')
    raw[at] ^= 1
    log_file.write_bytes(bytes(raw))
    c.log.append(f"python3 -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,\"rb\").read()); b[{at}]^=1; open(p,\"wb\").write(b)' {shlex.quote(str(log_file))}")
    v = b.audit_verify(c.log, cfg)
    code = (v.get("error") or {}).get("code") if isinstance(v.get("error"), dict) else None
    c.expect(v.get("ok") is not True and code == "audit_broken", f"{b.name} audit verify after one byte was flipped: expected audit_broken, got {short(v)}")


def run_pair(a: Port, b: Port, made: dict, checks: list, work: Path) -> list:
    base = work / f"{a.name}-to-{b.name}"
    base.mkdir()
    cells = []
    tokens, bundle, audit = made.get("tokens"), made.get("bundle"), made.get("audit")
    for check in checks:
        source = tokens if check in "abc" else bundle if check == "d" else audit
        c = Cell(check, a.name, b.name, source["cell"].log)
        cells.append(c)
        if source.get("na"):
            c.status, c.note = "n/a", source["na"]
            continue
        try:
            needed = {"a": ("token", "claims", "filter", "authorize"), "b": ("child", "child_read", "child_denied"), "c": ("token", "child"),
                      "d": ("bundle", "info"), "e": ("verify",)}[check]
            if source["cell"].problems or not all(k in source for k in needed):
                c.need(False, f"issuer side ({a.name} alone) failed: " + "; ".join(source["cell"].problems))
            if check in "abc":
                cfg = write_config(base / "verifier.json", base / "verifier-state", verify_only=True, trusted_keys=[tokens["public_key"]])
                {"a": check_a, "b": check_b, "c": check_c}[check](c, b, cfg, tokens)
            elif check == "d":
                check_d(c, b, base, bundle)
            else:
                check_e(c, b, base, audit)
        except Fail:
            pass
        except Exception as e:  # a bug in this script must not look like a pass
            c.expect(False, f"matrix.py error: {type(e).__name__}: {e}")
    return cells


# ---------------------------------------------------------- shared state dir

def shared_state(ports: list, work: Path) -> list:
    """The flock ports take turns on one state directory with one signing key. -> [Cell]"""
    base = work / "shared"
    base.mkdir()
    cfg = write_config(base / "shared.json", base / "state")
    names = ",".join(p.name for p in ports)
    n, turn, clock = len(ports), [0], [T0]
    log: list = []
    cells: list = []

    def nxt() -> Port:
        turn[0] += 1
        return ports[(turn[0] - 1) % n]

    def now() -> int:
        clock[0] += 1
        return clock[0]

    def part(title: str) -> Cell:
        # one sequence on one directory: a part's reproduction is every command up to the end of that part
        if cells:
            cells[-1].log = list(log)
        c = Cell("shared: " + title, names, names)
        c.log = log
        return c

    cap = {"actions": ["read", "create"], "resources": ["crm.customer/*", "billing.refund/*"]}

    # spend against one budget: the first n-1 ports spend 3000 each, the n-th is refused, 1000 more fits, then nothing does
    c = part("cumulative spend is enforced across ports")
    cells.append(c)
    try:
        p = nxt()
        budget = 3000 * n - 2000
        t = p.call(log, "issue_token", {"user": "alice", "agent": "support-bot", "cap": {**cap, "budget": {"EUR": budget}}, "now": now()}, cfg)
        c.need(t.get("ok") is True, f"{p.name} issue_token: {short(t)}")
        plan = [(3000, "allow")] * (n - 1) + [(3000, "deny"), (1000, "allow"), (1, "deny")]
        spent = 0
        for amount, expected in plan:
            p = nxt()
            d = p.call(log, "authorize", {"token": t["token"], "action": "create", "resource": REFUND, "now": now(), "context": {"spend": {"currency": "EUR", "amount": amount}}}, cfg)
            ok = d.get("effect") == expected and (expected == "allow" or d.get("reason") == "budget_exceeded")
            c.expect(ok, f"{p.name}: spend {amount} with {spent} of {budget} already spent by the other ports: expected {expected}"
                         f"{' budget_exceeded' if expected == 'deny' else ''}, got {short(pick(d, 'effect', 'reason', 'detail', 'error'))}")
            spent += amount if expected == "allow" else 0
    except Fail:
        pass

    # revocation: one port issues, another exchanges, a third revokes, all see it
    for r, revoker in enumerate(ports):
        c = part(f"a token revoked by {revoker.name} is token_revoked on the others")
        cells.append(c)
        try:
            issuer, exchanger = ports[(r + 1) % n], ports[(r + 2) % n]
            t = issuer.call(log, "issue_token", {"user": "alice", "agent": "support-bot", "cap": cap, "now": now()}, cfg)
            c.need(t.get("ok") is True, f"{issuer.name} issue_token: {short(t)}")
            child = exchanger.call(log, "exchange_token", {"subject_token": t["token"], "actor": "refund-helper", "cap": CHILD_CAP, "ttl": 300, "now": now()}, cfg)
            c.need(child.get("ok") is True, f"{exchanger.name} exchange_token of a token issued by {issuer.name}: {short(child)}")
            for p in ports:
                d = p.call(log, "authorize", {"token": child["token"], "action": "read", "resource": CUSTOMER, "now": now()}, cfg)
                c.expect(d.get("effect") == "allow", f"{p.name} before the revocation: expected allow, got {short(pick(d, 'effect', 'reason', 'error'))}")
            rv = revoker.call(log, "revoke", {"token_id": t["token_id"], "by": "matrix", "now": now()}, cfg)
            c.expect(rv.get("ok") is True, f"{revoker.name} revoke: {short(rv)}")
            for p in ports:
                for what, token in (("the token", t["token"]), ("its child", child["token"])):
                    d = p.call(log, "authorize", {"token": token, "action": "read", "resource": CUSTOMER, "now": now()}, cfg)
                    c.expect(d.get("effect") == "deny" and d.get("reason") == "token_revoked",
                             f"{p.name}, {what} after {revoker.name} revoked it: expected deny token_revoked, got {short(pick(d, 'effect', 'reason', 'error'))}")
                ins = p.call(log, "inspect_token", {"token": t["token"], "now": now()}, cfg)
                c.expect(ins.get("valid") is False and ins.get("reason") == "token_revoked",
                         f"{p.name} inspect_token after {revoker.name} revoked it: {short(pick(ins, 'valid', 'reason', 'error'))}")
        except Fail:
            pass

    # approval: requested in one port, listed in the next, granted in the next, used in the next, used up for the next
    c = part("approval requested, listed, granted and consumed in different ports")
    cells.append(c)
    try:
        p = nxt()
        t = p.call(log, "issue_token", {"user": "alice", "agent": "support-bot", "cap": {**cap, "budget": {"EUR": 90000}}, "now": now()}, cfg)
        c.need(t.get("ok") is True, f"{p.name} issue_token: {short(t)}")
        request = {"token": t["token"], "action": "create", "resource": REFUND, "context": {"spend": {"currency": "EUR", "amount": 15000}}}
        p = nxt()
        d = p.call(log, "authorize", {**request, "now": now()}, cfg)
        approval = d.get("approval") if isinstance(d.get("approval"), dict) else {}
        c.need(d.get("reason") == "approval_required" and isinstance(approval.get("id"), str), f"{p.name}: expected deny approval_required with approval.id, got {short(pick(d, 'effect', 'reason', 'approval', 'error'))}")
        p = nxt()
        listed = p.call(log, "approvals", {}, cfg)
        c.expect(isinstance(listed.get("pending"), dict) and approval["id"] in listed["pending"], f"{p.name} approvals: the request held by another port is not pending: {short(listed)}")
        p = nxt()
        refused = p.call(log, "approve", {"approval_id": approval["id"], "by": "alice", "now": now()}, cfg)
        c.expect((refused.get("error") or {}).get("code") == "self_approval", f"{p.name} approve by the user herself: expected self_approval, got {short(refused)}")
        p = nxt()
        granted = p.call(log, "approve", {"approval_id": approval["id"], "by": "bob", "now": now()}, cfg)
        c.expect(granted.get("ok") is True, f"{p.name} approve by bob: {short(granted)}")
        p = nxt()
        d = p.call(log, "authorize", {**request, "now": now()}, cfg)
        by = ((d.get("obligations") or {}).get("approved") or {}).get("by") if isinstance(d.get("obligations"), dict) else None
        c.expect(d.get("effect") == "allow" and by == "bob", f"{p.name} after the approval given in another port: expected allow approved by bob, got {short(pick(d, 'effect', 'reason', 'obligations', 'error'))}")
        p = nxt()
        d = p.call(log, "authorize", {**request, "now": now()}, cfg)
        c.expect(d.get("reason") == "approval_required", f"{p.name}: the approval was used in another port, expected approval_required again, got {short(pick(d, 'effect', 'reason', 'error'))}")
    except Fail:
        pass

    def chain(c: Cell, least: int = 1) -> None:
        answers = {}
        for p in ports:
            v = p.audit_verify(log, cfg)
            if c.expect(v.get("ok") is True and isinstance(v.get("records"), int) and v["records"] >= least, f"{p.name} audit verify on the shared directory: {short(v)}"):
                answers[p.name] = (v["records"], v.get("head"))
        c.expect(len(set(answers.values())) <= 1, f"the ports disagree about the shared audit log: {short({k: list(v) for k, v in answers.items()})}")
        if answers and c.status == "PASS":
            c.note = f"{next(iter(answers.values()))[0]} records"

    c = part("one valid audit chain, verified by each port")
    cells.append(c)
    chain(c, 10)

    # all ports at once: 5 processes each, every one tries to spend 1000 of a budget that covers half of them
    c = part("concurrent spends from all ports stay within the budget")
    cells.append(c)
    try:
        p = nxt()
        attempts = 5 * n
        allowed_expected = attempts // 2
        t = p.call(log, "issue_token", {"user": "alice", "agent": "support-bot", "cap": {**cap, "budget": {"EUR": 1000 * allowed_expected}}, "now": now()}, cfg)
        c.need(t.get("ok") is True, f"{p.name} issue_token: {short(t)}")
        at = now()
        log.append(f"# the next {attempts} commands are started at the same time")
        logs = [[] for _ in range(attempts)]
        with concurrent.futures.ThreadPoolExecutor(attempts) as pool:
            futures = [pool.submit(ports[i % n].call, logs[i], "authorize",
                                   {"token": t["token"], "action": "create", "resource": {"path": "billing.refund", "id": f"r-{i}"}, "now": at,
                                    "context": {"spend": {"currency": "EUR", "amount": 1000}}}, cfg) for i in range(attempts)]
            results = [f.result() for f in futures]
        for one in logs:
            log.extend(one)
        log.append("# end of the concurrent commands")
        allows = sum(1 for d in results if d.get("effect") == "allow")
        denies = sum(1 for d in results if d.get("effect") == "deny" and d.get("reason") == "budget_exceeded")
        other = [f"{ports[i % n].name}: {short(pick(d, 'effect', 'reason', 'error'))}" for i, d in enumerate(results)
                 if not (d.get("effect") == "allow" or (d.get("effect") == "deny" and d.get("reason") == "budget_exceeded"))]
        c.expect(not other, f"unexpected answers under concurrency: {'; '.join(other)}")
        c.expect(allows == allowed_expected and denies == attempts - allowed_expected,
                 f"{attempts} concurrent spends of 1000 against a budget of {1000 * allowed_expected}: {allows} allowed, {denies} budget_exceeded (expected {allowed_expected} and {attempts - allowed_expected})")
        chain(c, 10 + attempts)
    except Fail:
        pass
    cells[-1].log = list(log)
    return cells


# --------------------------------------------------------------------- output

def table(check: str, names: list, cells: dict) -> str:
    width = max(len(x) for x in names + ["issuer \\ verifier"]) + 2
    col = max(max(len(x) for x in names), 4) + 2
    lines = ["issuer \\ verifier".ljust(width) + "".join(x.ljust(col) for x in names)]
    for a in names:
        row = a.ljust(width)
        for b in names:
            row += ("-" if a == b else cells[(check, a, b)].status).ljust(col)
        lines.append(row.rstrip())
    return "\n".join(lines)


def main() -> int:
    global OPTIONS
    ap = argparse.ArgumentParser(description="Cross-port interoperability matrix (see the module docstring).")
    ap.add_argument("--report", metavar="FILE", help="write the results as JSON to FILE (default: no report file)")
    ap.add_argument("--ports", default=",".join(PORTS), help=f"comma-separated subset of: {','.join(PORTS)}")
    ap.add_argument("--checks", default="a,b,c,d,e,shared", help="comma-separated subset of: a,b,c,d,e,shared")
    ap.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1), help="pairs run in parallel (default: CPU count, at most 4)")
    ap.add_argument("--timeout", type=int, default=120, help="seconds allowed for one command of a port (default 120)")
    ap.add_argument("--keep", action="store_true", help="keep the temporary directory, so that the printed commands can be re-run")
    ap.add_argument("--verbose", action="store_true", help="print each cell's result as soon as its pair is finished")
    OPTIONS = ap.parse_args()
    wanted = [x for x in OPTIONS.ports.split(",") if x]
    checks = [x for x in OPTIONS.checks.split(",") if x]
    if [x for x in wanted if x not in PORTS] or [x for x in checks if x not in list(CHECKS) + ["shared"]] or OPTIONS.jobs < 1 or OPTIONS.timeout < 1:
        ap.print_usage(sys.stderr)
        return 2
    wanted = [x for x in PORTS if x in wanted]
    started = time.time()
    work = Path(tempfile.mkdtemp(prefix="smartdelegate-matrix-"))
    OPTIONS.work = work
    try:
        return run(wanted, checks, work, started)
    finally:
        if OPTIONS.keep:
            print(f"\nkept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


def run(wanted: list, checks: list, work: Path, started: float) -> int:
    ports, skipped = discover(work, wanted)
    names = [n for n in wanted if n in ports]
    probe = write_config(work / "probe.json", work / "probe-state")
    for n in names:  # what each port says it is; a port that cannot answer `info` fails in the checks below
        info = ports[n].call([], "info", {}, probe)
        ports[n].version = f"{info.get('implementation')} {info.get('version')}" if info.get("ok") is True else "no answer to `info`"
    pair_checks = [c for c in checks if c in CHECKS]
    cells: dict = {}
    shared_cells: list = []
    shared_note = ""

    with concurrent.futures.ThreadPoolExecutor(OPTIONS.jobs) as pool:
        def prepare(name: str) -> dict:
            base = work / f"{name}-issuer"
            base.mkdir()
            made = {}
            if set(pair_checks) & set("abc"):
                made["tokens"] = prepare_tokens(ports[name], base)
            if "d" in pair_checks:
                made["bundle"] = prepare_bundle(ports[name], base)
            if "e" in pair_checks:
                made["audit"] = prepare_audit(ports[name], base)
            return made

        made = dict(zip(names, pool.map(prepare, names))) if pair_checks and len(names) > 1 else {}
        futures = [pool.submit(run_pair, ports[a], ports[b], made[a], pair_checks, work) for a in names for b in names if a != b] if made else []
        for f in futures:
            for c in f.result():
                cells[(c.check, c.issuer, c.verifier)] = c
                if OPTIONS.verbose:
                    print(f"{c.check} {c.issuer} -> {c.verifier}: {c.status}", flush=True)

    if "shared" in checks:
        group = [ports[n] for n in FLOCK_PORTS if n in ports]
        if os.name == "nt":
            shared_note = "skipped: on Windows the ports do not take a common lock"
        elif len(group) < 2:
            shared_note = f"skipped: needs at least two of {', '.join(FLOCK_PORTS)}; available: {', '.join(p.name for p in group) or 'none'}"
        else:
            shared_cells = shared_state(group, work)
            shared_note = "ports: " + ", ".join(p.name for p in group) + " (node and java use their own locks and are excluded)"

    # ---- report
    print("SmartDelegate cross-port matrix")
    print("ports: " + (", ".join(f"{n} ({ports[n].version})" if ports[n].version else n for n in names) or "none"))
    for n, why in skipped.items():
        print(f"SKIP {n}: {why}")
    for note in NOTES:
        print(f"note: {note}")
    if len(names) < 2:
        print("fewer than two ports are available: there are no pairs to check")
    for check in pair_checks if len(names) > 1 else []:
        print(f"\n[{check}] {CHECKS[check]}")
        print(table(check, names, cells))
        notes = sorted({f"{c.issuer}: n/a, {c.note}" for c in cells.values() if c.check == check and c.status == "n/a"})
        for note in notes:
            print(f"  {note}")
    if "shared" in checks:
        print("\n[shared] one state directory, one signing key, used in turn")
        print(f"  {shared_note}")
        for c in shared_cells:
            print(f"  {c.status:<5} {c.check[len('shared: '):]}{' (' + c.note + ')' if c.note else ''}")

    everything = list(cells.values()) + shared_cells
    failures = [c for c in everything if c.status == "FAIL"]
    counts = {s: sum(1 for c in everything if c.status == s) for s in ("PASS", "FAIL", "n/a")}
    if failures:
        print(f"\n{len(failures)} FAILED. Commands are in the order they were run; paths are in the temporary directory"
              f"{'' if OPTIONS.keep else ' (re-run with --keep to keep it)'}; '#   ->' lines are what came back.")
        groups: dict = {}  # an issuer-side failure fails a whole row with the same commands: print it once
        for c in failures:
            groups.setdefault((tuple(c.problems), tuple(c.log)), []).append(c)
        for i, group in enumerate(groups.values(), 1):
            c = group[0]
            where = c.check if c.check.startswith("shared") else "; ".join(f"[{x.check}] issuer {x.issuer}, verifier {x.verifier}" for x in group)
            print(f"\n--- failure {i}: {where}")
            for problem in c.problems:
                print(f"  * {problem}")
            if not c.check.startswith("shared"):
                print(f"  only this cell: python3 ports/conformance/matrix.py --ports {c.issuer},{c.verifier} --checks {c.check} --keep")
            print("  commands:")
            for line in c.log:
                print(f"    {line}")
    print(f"\nsummary: pass={counts['PASS']} fail={counts['FAIL']} n/a={counts['n/a']} skipped_ports={len(skipped)} ({time.time() - started:.0f} s)")

    if OPTIONS.report:
        report = {
            "root": str(ROOT), "seconds": round(time.time() - started, 1),
            "ports": {n: ({"status": "run", "implementation": ports[n].version, "command": ports[n].shell([], None)} if n in ports else {"status": "skipped", "reason": skipped[n]}) for n in wanted},
            "checks": {k: {"title": CHECKS[k], "cells": {a: {b: cells[(k, a, b)].status for b in names if b != a} for a in names}} for k in pair_checks if cells},
            "shared": {"note": shared_note, "parts": [c.to_json() for c in shared_cells]} if "shared" in checks else None,
            "failures": [c.to_json() for c in failures],
            "notes": NOTES + sorted({f"[{c.check}] {c.issuer}: {c.note}" for c in cells.values() if c.status == "n/a"}),
            "summary": {"pass": counts["PASS"], "fail": counts["FAIL"], "na": counts["n/a"], "skipped_ports": len(skipped)},
        }
        Path(OPTIONS.report).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"report: {OPTIONS.report}")
    return 1 if failures else 0


OPTIONS: argparse.Namespace
NOTES: list = []

if __name__ == "__main__":
    sys.exit(main())
