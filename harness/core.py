"""A small scenario harness for SmartDelegate.

It plays business scenarios (harness/scenarios/*.json) against an engine: a
human lends an agent a role for a task, agents hand narrower tokens to
sub-agents, call tools, wait for approvals, get offboarded. Every step states
the outcome the company's rules require, and the harness checks it, plus four
things that must hold whatever the scenario says:

  INV-J  every step got its expected outcome
  INV-B  no field the token's role or capability denies came back in data
  INV-C  the spend allowed on a token and on its ancestors stayed within budget
  INV-D  nothing was allowed for a revoked, offboarded or expired token
  INV-I  the audit log verifies and has a record for every decision

Standard library and the `smartdelegate` package only. One scenario instance
runs at a time, with scripted agents. This is deliberately the simple version:
it has no misbehaving agents, no independent model of the business rules and
no cross-port comparison.
"""
from __future__ import annotations

import http.client
import json
import os
import random
import shutil
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPANY = ROOT / "examples" / "company"
SCENARIOS = Path(__file__).resolve().parent / "scenarios"
DECISIONS = ("authorize", "filter")
REDACTED = "[REDACTED]"
#: used for `{name.currency}` unless the scenario file has its own "currency_by_region"
CURRENCY_BY_REGION = {"EU": "EUR", "US": "USD", "APAC": "USD"}
ROUTES = {"authorize": ("POST", "/v1/authorize", "pep"), "filter": ("POST", "/v1/filter", "pep"), "inspect_token": ("POST", "/v1/token/inspect", "pep"),
          "info": ("GET", "/v1/info", "pep"), "exchange_token": ("POST", "/v1/token", None), "issue_token": ("POST", "/v1/token", "admin"),
          "revoke": ("POST", "/v1/admin/revoke", "admin"), "approve": ("POST", "/v1/admin/approve", "admin"),
          "audit_verify": ("GET", "/v1/admin/audit/verify", "admin"), "audit_tail": ("GET", "/v1/admin/audit/tail", "admin")}


class HarnessError(Exception):
    """The harness could not do what was asked (exit status 2). Not a verdict about the engine."""


# ------------------------------------------------------------------ backends

class InProcess:
    """The Python reference engine in this process, on a temporary state directory."""
    name = "inprocess"

    def __init__(self, bundle_dir=COMPANY):
        from sf_smartdelegate.engine import Engine
        self._dir = tempfile.mkdtemp(prefix="smartdelegate-harness-")
        self.engine = Engine({"bundle_dir": str(bundle_dir), "state_dir": os.path.join(self._dir, "state"), "issuer": "smartdelegate://harness",
                              "allow_test_clock": True, "max_depth": 3})
        self.audit_start = 0

    def call(self, op: str, payload: dict) -> dict:
        return self.engine.call(op, payload)

    def close(self) -> None:
        self.engine.close()
        shutil.rmtree(self._dir, ignore_errors=True)


class Url:
    """A daemon that is already running: yours, or any port's `serve`."""

    def __init__(self, url: str, admin_key: str, pep_key: str | None = None):
        u = urllib.parse.urlsplit(url)
        if u.scheme != "http" or not u.hostname:
            raise HarnessError(f"'{url}' is not an http:// URL")
        if not admin_key:
            raise HarnessError("a url: backend needs the daemon's admin key (see --admin-key-env)")
        self.name, self.host, self.port, self.base = f"url:{url}", u.hostname, u.port or 80, u.path.rstrip("/")
        self.keys = {"admin": admin_key, "pep": pep_key or admin_key}
        v = self.call("audit_verify", {})
        if v.get("ok") is not True:
            raise HarnessError(f"{url} does not answer as a SmartDelegate daemon: {v.get('error')}")
        self.audit_start = v.get("records", 0)        # records of earlier runs are not this run's

    def call(self, op: str, payload: dict) -> dict:
        method, path, kind = ROUTES[op]
        if op == "audit_tail":
            path += f"?n={int(payload.get('n', 20))}"
        headers = {"Content-Type": "application/json", "Connection": "close"}
        if kind:
            headers["Authorization"] = f"Bearer {self.keys[kind]}"
        conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
        try:
            conn.request(method, self.base + path, body=json.dumps(payload).encode() if method == "POST" else None, headers=headers)
            doc = json.loads(conn.getresponse().read().decode("utf-8"))
            return doc if isinstance(doc, dict) else {"ok": False, "error": {"code": "harness_transport", "message": "not a JSON object"}}
        except (OSError, ValueError, http.client.HTTPException) as e:      # no answer is never an allow
            return {"ok": False, "error": {"code": "harness_transport", "message": f"{type(e).__name__}: {e}"}}
        finally:
            conn.close()

    def close(self) -> None:
        pass


def open_backend(spec: str, bundle_dir=COMPANY, admin_key_env: str | None = None, pep_key_env: str | None = None):
    if spec == "inprocess":
        return InProcess(bundle_dir)
    if spec.startswith("url:"):
        return Url(spec[4:], os.environ.get(admin_key_env or "SMARTDELEGATE_ADMIN_KEY", ""), os.environ.get(pep_key_env or "SMARTDELEGATE_PEP_KEY") or None)
    raise HarnessError(f"unknown backend '{spec}' (inprocess, or url:http://host:port for a daemon that is running)")


# ----------------------------------------------------------------- the bundle

class Company:
    """What the harness needs to know about a bundle: who is in which group, and what each role denies."""

    def __init__(self, bundle_dir=COMPANY):
        self.dir = Path(bundle_dir)
        read = lambda name: json.loads((self.dir / name).read_text(encoding="utf-8"))
        self.parents, self.attrs = {}, {}
        for e in read("entities.json"):
            key = (e["uid"]["type"], e["uid"]["id"])
            self.parents[key] = [(p["type"], p["id"]) for p in e.get("parents") or []]
            self.attrs[key] = e.get("attrs") or {}
        self.users = sorted(i for t, i in self.parents if t == "User")
        self.agents = sorted(i for t, i in self.parents if t == "Agent")
        self.roles = read("roles.json")["roles"]
        self.catalog = {path: {name: f.get("labels") or [] for name, f in r["fields"].items()} for path, r in read("catalog.json")["resources"].items()}
        self.regions = sorted({a["region"] for (t, _), a in self.attrs.items() if t == "User" and "region" in a})

    def groups_of(self, user: str) -> set:
        seen, todo = set(), list(self.parents.get(("User", user), []))
        while todo:
            p = todo.pop()
            if p not in seen:
                seen.add(p)
                todo.extend(self.parents.get(p, []))
        return {i for t, i in seen if t == "Group"}

    def unit(self, actor: str) -> str:
        return self.attrs.get(("User", actor), self.attrs.get(("Agent", actor), {})).get("unit", "")


def load_scenarios(directory=SCENARIOS) -> dict:
    out = {}
    for f in sorted(Path(directory).glob("*.json")):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except ValueError as e:
            raise HarnessError(f"{f.name}: not JSON: {e}") from None
        for key in ("name", "description", "units", "cast", "steps"):
            if key not in doc:
                raise HarnessError(f"{f.name}: '{key}' is missing")
        doc.setdefault("id", f.stem)
        out[doc["id"]] = doc
    return out


def needs_clock(doc: dict) -> bool:
    return "test_clock" in (doc.get("requires") or []) or any(s["op"] == "advance" and s.get("seconds", 0) > 3 for s in doc["steps"])


def outcome_of(op: str, resp: dict) -> str:
    """allow, deny:<reason>, ok, error:<code>"""
    if resp.get("ok") is not True:
        return "error:" + str((resp.get("error") or {}).get("code") or "malformed_result")
    if op in DECISIONS:
        return "allow" if resp.get("effect") == "allow" else "deny:" + str(resp.get("reason"))
    return "ok"


def rule_of(resp: dict) -> str:
    if resp.get("ok") is True:
        return resp.get("rule") or "DELEGATE-OK"
    err = resp.get("error") or {}
    return err.get("rule") or "DELEGATE-" + str(err.get("code", "error")).upper().replace("_", "-")


def visible_paths(data, prefix: str = "") -> set:
    """Every path present in returned data whose value is not the redaction marker (lists as `name[]`)."""
    out = set()
    if isinstance(data, dict):
        for k, v in data.items():
            if v != REDACTED:
                p = f"{prefix}.{k}" if prefix else k
                out.add(p)
                out |= visible_paths(v, p)
    elif isinstance(data, list):
        for el in data:
            out |= visible_paths(el, prefix + "[]" if prefix else "")
    return out


class Token:
    def __init__(self, name, token, token_id, user, role, cap, parent, expires):
        self.name, self.token, self.token_id, self.user, self.role = name, token, token_id, user, role
        self.cap, self.parent, self.expires, self.dead = cap, parent, expires, None
        self.spent: dict = {}

    def chain(self) -> list:
        return [self] + (self.parent.chain() if self.parent else [])


# ------------------------------------------------------------------- the run

class Run:
    def __init__(self, backend, company: Company, scenarios: dict, seed: int = 1):
        self.backend, self.company, self.scenarios, self.seed = backend, company, scenarios, seed
        self.trace: list = []
        self.violations: list = []
        self.instances: list = []
        self.skipped: dict = {}
        self.harness_errors: list = []
        self.audit: dict = {}
        self.test_clock = isinstance(backend, InProcess)
        self.info: dict = {}
        self.wall = 0.0
        self.floor = 0
        self._lock = threading.RLock()        # flag() is called with it held
        self.nonce = f"r{int(time.time()) % 100000:05d}-"      # keeps this run's record ids apart from earlier runs on a daemon that keeps state

    # ---- plumbing
    def flag(self, invariant: str, entry: dict, detail: str) -> None:
        with self._lock:
            self.violations.append({"invariant": invariant, "detail": detail, "instance": entry["instance"], "scenario": entry["scenario"], "step": entry["step"],
                                    "kind": "scripted", "actor": entry["actor"], "op": entry["op"], "request": entry["request"], "response": entry["response"], "entry": entry["i"]})
            entry.setdefault("violations", []).append(invariant)

    def record(self, inst, step, actor, actor_kind, op, request, response, outcome, rule, ms=0.0, **more) -> dict:
        entry = {"instance": inst["idx"], "scenario": inst["doc"]["id"], "step": step.get("id", "?"), "kind": "scripted", "actor": actor, "actor_kind": actor_kind,
                 "op": op, "request": request, "response": response, "outcome": outcome, "rule": rule, "ms": round(ms, 3),
                 "expect": step.get("expect"), "why": step.get("why"), **more}
        with self._lock:
            entry["i"] = len(self.trace)
            self.trace.append(entry)
        return entry

    def call(self, inst, step, actor, actor_kind, op, payload, **more) -> dict:
        if self.test_clock:
            payload = dict(payload, now=inst["base"] + inst["offset"])
        t0 = time.monotonic()
        resp = self.backend.call(op, payload)
        return self.record(inst, step, actor, actor_kind, op, payload, resp, outcome_of(op, resp), rule_of(resp), (time.monotonic() - t0) * 1000, **more)

    def preflight(self) -> None:
        self.info = self.backend.call("info", {})
        if self.info.get("ok") is not True:
            raise HarnessError(f"the backend does not answer `info`: {self.info.get('error')}")
        probe_user = next((u for u in self.company.users for r in self.company.roles.values()
                           if any(m["type"] == "Group" and m["id"] in self.company.groups_of(u) for m in r["members"])), None)
        role = next((n for n, r in self.company.roles.items() if probe_user and any(m["id"] in self.company.groups_of(probe_user) for m in r["members"])), None)
        if role is None:
            return
        r = self.company.roles[role]
        t = self.backend.call("issue_token", {"user": probe_user, "agent": (r.get("agents") or self.company.agents)[0], "role": role,
                                              "task": (r.get("tasks") or ["task-*"])[0].replace("*", "clock-probe-" + self.nonce)})
        if t.get("ok") is True:        # valid now; expired a million seconds on only if the engine honours `now`
            far = self.backend.call("inspect_token", {"token": t["token"], "now": int(time.time()) + 1_000_000})
            self.test_clock = far.get("valid") is False and far.get("reason") == "token_expired"

    def run(self, wanted: str = "all", instances: int | None = None) -> None:
        t0 = time.monotonic()
        self.preflight()
        ids = sorted(self.scenarios) if wanted in ("all", None) else [x.strip() for x in wanted.split(",") if x.strip()]
        docs = []
        for sid in ids:
            match = [k for k in self.scenarios if k == sid or k.startswith(sid + "_")]
            if len(match) != 1:
                raise HarnessError(f"no scenario '{sid}' (try `list`)")
            doc = self.scenarios[match[0]]
            if needs_clock(doc) and not self.test_clock:
                self.skipped[doc["id"]] = "needs the engine's test clock (`allow_test_clock: true`), which this backend does not honour"
            else:
                docs.append(doc)
        for idx in range(instances if instances is not None else len(docs)):
            if docs:
                self.instance(idx, docs[idx % len(docs)])
        self.check_audit()
        self.wall = time.monotonic() - t0

    # ---- one instance of one scenario
    def instance(self, idx: int, doc: dict) -> None:
        rng = random.Random(f"{self.seed}:{idx}")
        inst = {"idx": idx, "doc": doc, "cast": {}, "tokens": {}, "approvals": {}, "n": f"{self.nonce}{idx}", "base": max(int(time.time()), self.floor), "offset": 0, "failures": 0}
        try:
            c = self.company
            for name, spec in doc["cast"].items():
                pool = [spec["user"]] if "user" in spec else list(c.users)
                as_list = lambda v: [v] if isinstance(v, str) else list(v or [])
                pool = [u for u in pool if all(g in c.groups_of(u) for g in as_list(spec.get("group"))) and not any(g in c.groups_of(u) for g in as_list(spec.get("not_group")))]
                region = lambda u: c.attrs[("User", u)].get("region")
                if "region_of" in spec:
                    pool = [u for u in pool if region(u) == region(inst["cast"][spec["region_of"]])]
                if "not_region_of" in spec:
                    pool = [u for u in pool if region(u) != region(inst["cast"][spec["not_region_of"]])]
                if "region" in spec:
                    pool = [u for u in pool if region(u) == spec["region"]]
                pool = sorted(u for u in pool if u not in inst["cast"].values())
                if not pool:
                    raise HarnessError(f"{doc['id']}: nobody in the bundle fits the cast member '{name}' ({spec})")
                inst["cast"][name] = rng.choice(pool)
            for step in doc["steps"]:
                self.step(inst, step)
        except HarnessError as e:
            self.harness_errors.append(f"{doc['id']} instance {idx}: {e}")
        # Offboarding a human ends every token issued for them up to that second, in later instances too. So the
        # next instance starts its clock after everything this one did (with the real clock: after a short wait).
        self.floor = inst["base"] + inst["offset"] + 1
        if not self.test_clock and any(s["op"] == "revoke_user" for s in doc["steps"]):
            time.sleep(1.1)
        self.instances.append({"instance": idx, "scenario": doc["id"], "cast": inst["cast"], "failures": inst["failures"]})

    def subst(self, inst, v):
        """`{n}`, `{name}`, `{name.region}`, `{name.currency}`, `{name.other_region}`, `{name.<attribute>}` in strings, keys included."""
        if isinstance(v, dict):
            return {self.subst(inst, k): self.subst(inst, x) for k, x in v.items()}
        if isinstance(v, list):
            return [self.subst(inst, x) for x in v]
        if not isinstance(v, str) or "{" not in v:
            return v
        out, i = "", 0
        while i < len(v):
            if v[i] != "{":
                out, i = out + v[i], i + 1
                continue
            j = v.index("}", i)
            who, _, attr = v[i + 1:j].partition(".")
            i = j + 1
            if who == "n" and not attr:
                out += inst["n"]
                continue
            if who not in inst["cast"]:
                raise HarnessError(f"'{{{who}}}' names nobody in the cast")
            user = inst["cast"][who]
            region = self.company.attrs[("User", user)].get("region", "")
            if not attr:
                out += user
            elif attr == "currency":
                out += (inst["doc"].get("currency_by_region") or CURRENCY_BY_REGION).get(region, "EUR")
            elif attr == "other_region":
                out += next(r for r in self.company.regions if r != region)
            else:
                out += str(self.company.attrs[("User", user)][attr])
        return out

    def token(self, inst, step) -> Token:
        tok = inst["tokens"].get(step["token"])
        if tok is None:
            raise HarnessError(f"step {step['id']}: token '{step['token']}' does not exist (the step that should have produced it was refused)")
        return tok

    def step(self, inst, raw: dict) -> None:
        op = raw["op"]
        if op == "parallel":
            return self.parallel(inst, raw)
        s = self.subst(inst, raw)
        human = lambda name: inst["cast"].get(name, name)
        if op == "delegate":
            user, role = human(s["actor"]), self.company.roles.get(s.get("role"), {})
            payload = {"user": user, "agent": s["agent"], **{k: s[k] for k in ("role", "task", "cap", "ttl", "groups", "tenant") if s.get(k) is not None}}
            e = self.call(inst, s, user, "human", "issue_token", payload, to_agent=s["agent"], new_token_name=s.get("save"))
            if e["outcome"] == "ok" and s.get("save"):
                cap = dict(s.get("cap") or role.get("cap") or {})
                cap["deny_labels"] = sorted(set(cap.get("deny_labels") or []) | set((role.get("cap") or {}).get("deny_labels") or []))
                cap["deny_fields"] = sorted(set(cap.get("deny_fields") or []) | set((role.get("cap") or {}).get("deny_fields") or []))
                ttl = min(s.get("ttl") or 900, role.get("max_ttl") or 3600)
                inst["tokens"][s["save"]] = Token(s["save"], e["response"]["token"], e["response"].get("token_id"), user, s.get("role"), cap, None, inst["offset"] + ttl)
        elif op == "narrow":
            parent = self.token(inst, s)
            cap = s.get("cap")
            if isinstance(cap, dict) and not s.get("cap_exact"):       # a narrower capability must repeat what the parent denies: filled in here
                cap = dict(cap, deny_labels=sorted(set(cap.get("deny_labels") or []) | set(parent.cap.get("deny_labels") or [])),
                           deny_fields=sorted(set(cap.get("deny_fields") or []) | set(parent.cap.get("deny_fields") or [])))
            payload = {"subject_token": parent.token, "actor": s["to"], **({"cap": cap} if cap is not None else {}),
                       **{k: s[k] for k in ("ttl", "role", "task") if s.get(k) is not None}}
            e = self.call(inst, s, s["actor"], "agent", "exchange_token", payload, to_agent=s["to"], token_name=parent.name, new_token_name=s.get("save"))
            if e["outcome"] == "ok" and s.get("save"):
                inst["tokens"][s["save"]] = Token(s["save"], e["response"]["token"], e["response"].get("token_id"), parent.user, parent.role,
                                                  cap if cap is not None else parent.cap, parent, min(parent.expires, inst["offset"] + (s.get("ttl") or 900)))
        elif op == "call":
            e = self.tool_call(inst, s)
        elif op == "approve":
            aid = inst["approvals"].get(s["request"])
            if not aid:
                raise HarnessError(f"step {s['id']}: step '{s['request']}' produced no approval id")
            e = self.call(inst, s, human(s["actor"]), "human", "approve", {"approval_id": aid, "by": human(s["actor"])}, approval_of=s["request"])
        elif op == "revoke_user":
            user = inst["cast"][s["user"]]
            e = self.call(inst, s, human(s["actor"]), "human", "revoke", {"user": user, "by": human(s["actor"])})
            if e["outcome"] == "ok":
                for t in inst["tokens"].values():
                    if t.user == user:
                        t.dead = t.dead or "offboarded"
        elif op == "revoke_token":
            tok = self.token(inst, s)
            e = self.call(inst, s, human(s["actor"]), "human", "revoke", {"token_id": tok.token_id, "by": human(s["actor"])}, token_name=tok.name)
            if e["outcome"] == "ok":
                for t in inst["tokens"].values():
                    if tok in t.chain():
                        t.dead = t.dead or "revoked"
        elif op == "handoff":      # a work item goes to another agent; no request to the engine, no authority moves
            e = self.record(inst, s, s["actor"], "agent", "handoff", {"to": s["to"], "item": s.get("item"), "tokens": s.get("tokens") or []}, None, "-", "")
        elif op == "advance":
            if self.test_clock:
                inst["offset"] += int(s["seconds"])
                for t in inst["tokens"].values():
                    if inst["offset"] >= t.expires:
                        t.dead = t.dead or "expired"
            else:
                time.sleep(int(s["seconds"]))
            e = self.record(inst, s, "clock", "harness", "advance", {"seconds": s["seconds"]}, None, "-", "")
        else:
            raise HarnessError(f"step {s.get('id')}: unknown op '{op}'")
        if op not in ("handoff", "advance"):
            self.expect(inst, s, e)

    def tool_call(self, inst, s) -> dict:
        tok = self.token(inst, s)
        path, _, rid = s["resource"].partition("/")
        res = {"path": path, "id": rid or "any", **({"attrs": s["attrs"]} if s.get("attrs") else {})}
        token = tok.token if not s.get("tamper") else ("not-a-token" if s["tamper"] == "garbage" else tok.token[:-6] + ("AAAAAA" if not tok.token.endswith("AAAAAA") else "BBBBBB"))
        payload = {"token": token, "action": s["action"], "resource": res, **{k: s[k] for k in ("context", "data", "strict", "dry_run", "fields") if s.get(k) is not None}}
        e = self.call(inst, s, s["actor"], "agent", "filter" if "data" in payload else "authorize", payload, token_name=tok.name)
        resp = e["response"]
        if e["outcome"] == "deny:approval_required" and isinstance(resp.get("approval"), dict):
            inst["approvals"][s["id"]] = resp["approval"].get("id")
        if e["outcome"] != "allow" or s.get("tamper"):
            return e
        # INV-D: a dead token must not work
        dead = next((t.dead for t in tok.chain() if t.dead), None)
        if dead:
            self.flag("INV-D", e, f"token '{tok.name}' is {dead} and the call was allowed")
        # INV-C: the spend stays within the budget of the token and of every ancestor
        spend = (s.get("context") or {}).get("spend")
        if isinstance(spend, dict) and isinstance(spend.get("amount"), int):
            with self._lock:
                for t in tok.chain():
                    limit = (t.cap.get("budget") or {}).get(spend.get("currency"))
                    total = t.spent.get(spend.get("currency"), 0) + spend["amount"]
                    if limit is None or total > limit:
                        self.flag("INV-C", e, f"{total} {spend.get('currency')} allowed on token '{t.name}', whose budget is {limit}")
                    if not s.get("dry_run"):
                        t.spent[spend.get("currency")] = total
        # INV-B: no field with a label (or name) the chain denies is in the returned data
        if "data" in payload:
            deny_labels = {label for t in tok.chain() for label in t.cap.get("deny_labels") or []}
            deny_fields = {f for t in tok.chain() for f in t.cap.get("deny_fields") or []}
            for p in sorted(visible_paths(resp.get("data"))):
                labels = self.company.catalog.get(path, {}).get(p)
                if labels is not None and (deny_labels & set(labels) or f"{path}.{p}" in deny_fields):
                    self.flag("INV-B", e, f"'{p}' (labels {labels}) came back although the token's role or capability denies it")
        return e

    def parallel(self, inst, raw: dict) -> None:
        subs = [self.subst(inst, sub) for sub in raw["steps"]]
        results: list = [None] * len(subs)

        def one(k):
            results[k] = self.tool_call(inst, subs[k])
            results[k]["parallel"] = raw["id"]

        threads = [threading.Thread(target=one, args=(k,)) for k in range(len(subs))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        expect = raw.get("expect") or {}
        allowed = sum(1 for e in results if e and e["outcome"] == "allow")
        last = results[-1]
        if "allow" in expect and allowed != expect["allow"]:
            inst["failures"] += 1
            self.flag("INV-J", last, f"step {raw['id']}: expected exactly {expect['allow']} of {len(subs)} parallel calls to be allowed, {allowed} were. {raw.get('why', '')}")
        for e in results:
            if "rest" in expect and e["outcome"] not in ("allow", expect["rest"]):
                inst["failures"] += 1
                self.flag("INV-J", e, f"step {raw['id']}: expected the calls that were not allowed to be {expect['rest']}, got {e['outcome']}")

    def expect(self, inst, s, e) -> None:
        expect = s.get("expect")
        if expect is None:
            return
        want = expect if isinstance(expect, str) else expect.get("outcome", "allow")
        problems = []
        if e["outcome"] not in [x.strip() for x in want.split("|")]:
            problems.append(f"expected {want}, got {e['outcome']}")
        elif isinstance(expect, dict) and e["outcome"] == "allow":
            data = e["response"].get("data")
            seen = visible_paths(data)
            problems += [f"'{p}' should have been removed or redacted, and is visible" for p in expect.get("hidden", []) if p in seen]
            problems += [f"'{p}' should be visible, and is not" for p in expect.get("visible", []) if p not in seen]
            rows = len(data) if isinstance(data, list) else (0 if data is None else 1)
            if "rows" in expect and rows != expect["rows"]:
                problems.append(f"expected {expect['rows']} rows, got {rows}")
        for problem in problems:
            inst["failures"] += 1
            e["unexpected"] = problem
            self.flag("INV-J", e, f"step {s['id']}: {problem}. Why the scenario expects it: {s.get('why', '')}")

    # ---- INV-I
    def check_audit(self) -> None:
        anchor = {"instance": -1, "scenario": "(run)", "step": "audit", "actor": "harness", "op": "audit_verify", "request": None, "response": None, "i": -1}
        v = self.backend.call("audit_verify", {})
        if v.get("ok") is not True:
            anchor["response"] = v
            return self.flag("INV-I", anchor, f"the audit log does not verify: {(v.get('error') or {}).get('message')}")
        n = v.get("records", 0) - self.backend.audit_start
        tail = self.backend.call("audit_tail", {"n": n}) if n > 0 else {"ok": True, "records": []}
        records = {r.get("decision_id"): r for r in tail.get("records") or [] if r.get("event") == "decision"}
        matched = 0
        for e in self.trace:
            resp = e["response"] if isinstance(e["response"], dict) else {}
            if e["op"] not in DECISIONS or resp.get("ok") is not True or e["request"].get("dry_run"):
                continue
            rec = records.get(resp.get("decision_id"))
            if rec is None:
                self.flag("INV-I", e, f"no audit record for the decision {resp.get('decision_id')}")
            elif rec.get("effect") != resp.get("effect") or rec.get("reason") != resp.get("reason"):
                self.flag("INV-I", e, f"the audit record says {rec.get('effect')}/{rec.get('reason')}, the answer was {resp.get('effect')}/{resp.get('reason')}")
            else:
                matched += 1
        self.audit = {"logs": 1, "records": n, "decision_records": len(records), "decisions_matched": matched, "head": v.get("head")}
