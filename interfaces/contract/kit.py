"""The contract checks. One function per check; each builds what it needs in
a temporary directory on the conformance bundle (spec/conformance/bundle),
calls the implementation under test through its factory, and raises
`Violation` when the contract is broken.

    results = run("enforcement", my_factory)        # -> [Result]
    python -m interfaces.contract --enforcement mypkg.my_factory

What a factory receives is documented per interface in interfaces/README.md
and in `FACTORY_ARGUMENTS` below.
"""
from __future__ import annotations

import json
import shutil
import socket
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from sf_smartdelegate import DaemonClient, Engine
from sf_smartdelegate.bridges import BridgeError, directory as bridge_directory

from sf_smartdelegate.canon import canon, sha256_hex

from ..contracts import ContractError, Outcome, Revocation, SpawnRefused, ToolBinding
from ..reference.approval import pump
from ..reference.audit import apply_revocations, read_records, revocations_from_audit, ship

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "spec" / "conformance" / "bundle"
OIDC = ROOT / "spec" / "conformance" / "oidc"
DIRECTORY = json.loads((Path(__file__).parent / "directory_fixture.json").read_text(encoding="utf-8"))

FACTORY_ARGUMENTS = {
    "identity": "factory(issuer, audience, jwks, groups_claim, group_map) -> IdentitySource. The kit passes the test provider of "
                "spec/conformance/oidc and its ID tokens.",
    "directory": "factory(fault=None) -> DirectorySource over a directory holding interfaces/contract/directory_fixture.json. "
                 "fault is None, 'unreachable' or 'truncated': a source whose directory fails that way.",
    "roles": "factory(bundle_dir) -> RoleCatalog for the roles of that bundle directory (a copy of the conformance bundle).",
    "enforcement": "factory(backend, tools) -> EnforcementPoint. backend is an Engine or a DaemonClient; tools maps a name to "
                   "(ToolBinding, function).",
    "runtime": "factory(backend) -> AgentRuntime with no task and no tools.",
    "approval": "factory(human) -> ApprovalChannel. human(payload) stands for the person at the far end: it returns "
                "{'approve': bool, 'by': user id}, or None for no answer.",
    "audit": "factory(location) -> AuditSink. location is a directory; two sinks made with the same location share what they hold.",
    "revocation": "factory(location) -> RevocationFeed. Same rule for location.",
}

ADA = {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU", "tier": "gold",
       "notes": "threatened to churn", "card": {"last4": "4242", "number": "4242424242424242"}}
#: values of ADA the support role must never be shown
HIDDEN = ("123-45-6789", "threatened to churn", "4242424242424242")
FULL_CAP = {"actions": ["read", "create", "update"], "resources": ["crm.customer/*", "billing.refund/*"], "budget": {"EUR": 20000}}


class Violation(AssertionError):
    """The implementation under test broke the contract."""


def need(condition, message: str) -> None:
    if not condition:
        raise Violation(message)


@dataclass(frozen=True)
class Check:
    id: str
    interface: str
    title: str
    fn: Callable


@dataclass(frozen=True)
class Result:
    id: str
    interface: str
    title: str
    ok: bool
    detail: str = ""


CHECKS: list = []


def check(interface: str, id: str, title: str):
    def add(fn):
        CHECKS.append(Check(id, interface, title, fn))
        return fn
    return add


class Lab:
    """A temporary directory with engines on the conformance bundle."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="smartdelegate-contract-"))
        self._engines: list = []

    def path(self, name: str) -> Path:
        p = self.dir / name
        p.mkdir(parents=True, exist_ok=True)
        return p

    def engine(self, state: str = "state", bundle=BUNDLE, **config) -> Engine:
        e = Engine({"bundle_dir": str(bundle), "state_dir": str(self.dir / state), **config})
        self._engines.append(e)
        return e

    def bundle_copy(self) -> Path:
        target = self.dir / "bundle"
        if not target.exists():
            shutil.copytree(BUNDLE, target)
        return target

    def close(self) -> None:
        for e in self._engines:
            e.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def role_token(engine, user="alice", role="support-agent", task="ticket-7", agent="support-bot") -> dict:
    return engine.issue_token(agent, user=user, role=role, task=task)


class Tools:
    """Stand-in tools that return more than an agent should see and record
    every time they run."""

    def __init__(self):
        self.calls: list = []

    def get_customer(self, customer_id):
        self.calls.append("get_customer")
        return dict(ADA)

    def export_notes(self, customer_id):
        self.calls.append("export_notes")
        return "Ada Lovelace, ssn 123-45-6789, threatened to churn"

    def update_customer(self, customer_id, changes):
        self.calls.append("update_customer")
        return {**ADA, **changes}

    def refund(self, order_id, currency, amount):
        self.calls.append("refund")
        return {"order_id": order_id, "amount": amount, "currency": currency, "internal_note": "fraud score 0.2"}

    def read_salary(self, employee):
        self.calls.append("read_salary")
        return {"employee": employee, "amount": 100000}

    def bound(self) -> dict:
        return {"get_customer": (ToolBinding("read", "crm.customer", id="customer_id"), self.get_customer),
                "export_notes": (ToolBinding("read", "crm.customer", id="customer_id"), self.export_notes),
                "update_customer": (ToolBinding("update", "crm.customer", id="customer_id", input="changes"), self.update_customer),
                "refund": (ToolBinding("create", "billing.refund", id="order_id", spend=("currency", "amount")), self.refund),
                "read_salary": (ToolBinding("read", "hr.salary", id="employee"), self.read_salary)}


def refused(outcome, what: str, reason: str | None = None) -> None:
    """`outcome` must be a refusal in the contract's shape."""
    need(isinstance(outcome, Outcome), f"{what}: the answer is not an Outcome")
    need(outcome.allowed is False, f"{what}: the call was allowed")
    need(outcome.value is None, f"{what}: a refusal carries a value")
    r = outcome.refusal
    need(r is not None and isinstance(r.reason, str) and r.reason, f"{what}: the refusal has no reason")
    need(r.rule == "DELEGATE-" + r.reason.upper().replace("_", "-"), f"{what}: rule {r.rule!r} is not the DELEGATE-* id of {r.reason!r}")
    if reason is not None:
        need(r.reason == reason, f"{what}: reason {r.reason!r}, expected {reason!r}")


def unreachable_backend() -> DaemonClient:
    """A daemon address nothing listens on."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return DaemonClient(f"http://127.0.0.1:{port}", pep_key="k" * 16, admin_key="k" * 16, timeout=2.0)


# ---- IdentitySource -----------------------------------------------------------

def _idp(factory):
    tokens = json.loads((OIDC / "id_tokens.json").read_text(encoding="utf-8"))
    jwks = json.loads((OIDC / "jwks.json").read_text(encoding="utf-8"))
    source = factory("https://idp.example.test", "smartdelegate-demo", jwks, "groups",
                     {"sg-support": "support", "sg-supervisors": "supervisors", "sg-compliance": "compliance"})
    return source, tokens


def _must_refuse(source, token, what: str) -> None:
    try:
        got = source.identify(token)
    except ContractError:
        return
    except Exception as e:
        raise Violation(f"{what}: raised {type(e).__name__} instead of IdentityError") from None
    raise Violation(f"{what}: accepted, as user {getattr(got, 'user', None)!r}")


@check("identity", "identity-valid-token", "a valid ID token gives the user and the mapped groups")
def _(lab, factory):
    source, t = _idp(factory)
    who = source.identify(t["alice_support"])
    need(who.user == "alice", f"user is {who.user!r}, expected 'alice'")
    need(who.groups == ["support"], f"groups are {who.groups!r}, expected ['support']")


@check("identity", "identity-wrong-audience", "a token for another audience is refused")
def _(lab, factory):
    source, t = _idp(factory)
    _must_refuse(source, t["wrong_audience"], "a token whose aud is another client")


@check("identity", "identity-other-client", "a token issued to another client (azp) is refused, also when our client is among its audiences")
def _(lab, factory):
    source, t = _idp(factory)
    for name in ("alice_azp_other", "alice_azp_other_single", "alice_multi_aud_no_azp"):
        _must_refuse(source, t[name], f"token {name}")


@check("identity", "identity-wrong-issuer", "a token from another issuer is refused")
def _(lab, factory):
    source, t = _idp(factory)
    _must_refuse(source, t["wrong_issuer"], "a token from another issuer")


@check("identity", "identity-expired", "an expired token is refused")
def _(lab, factory):
    source, t = _idp(factory)
    _must_refuse(source, t["expired"], "an expired token")


@check("identity", "identity-forged", "a token whose signature does not verify, or that is not a JWT, is refused")
def _(lab, factory):
    source, t = _idp(factory)
    _must_refuse(source, t["forged"], "a token with a wrong signature")
    head, body, sig = t["alice_support"].split(".")
    _must_refuse(source, f"{head}.{t['bob_both'].split('.')[1]}.{sig}", "a token whose payload was swapped")
    for junk in ("", "not-a-token", "a.b.c"):
        _must_refuse(source, junk, f"the text {junk!r}")


@check("identity", "identity-no-groups-is-empty", "a user with no groups gets an empty list: not an error, not None")
def _(lab, factory):
    source, t = _idp(factory)
    for name in ("alice", "alice_removed"):          # no groups claim at all; an empty groups claim
        try:
            who = source.identify(t[name])
        except Exception as e:
            raise Violation(f"token {name} (a user in no group) raised {type(e).__name__}: {e}") from None
        need(isinstance(who.groups, list) and who.groups == [], f"token {name}: groups are {who.groups!r}, expected []")
        need(who.user == "alice", f"token {name}: user is {who.user!r}")


@check("identity", "identity-no-stale-groups", "groups come from this token only, never from an earlier one")
def _(lab, factory):
    source, t = _idp(factory)
    need(source.identify(t["alice_support"]).groups == ["support"], "the first token did not give ['support']")
    for name in ("alice_removed", "alice"):
        need(source.identify(t[name]).groups == [], f"after alice left the group, token {name} still gives groups: stale membership")


@check("identity", "identity-malformed-groups", "a groups claim of the wrong type is refused, not read as no groups")
def _(lab, factory):
    source, t = _idp(factory)
    _must_refuse(source, t["alice_malformed"], "a token whose groups claim is [1, 2]")


@check("identity", "identity-unmapped-dropped", "groups outside the map are dropped; the result is sorted, without duplicates")
def _(lab, factory):
    source, t = _idp(factory)
    need(source.identify(t["bob_both"]).groups == ["supervisors", "support"], "bob's groups are not exactly ['supervisors', 'support']")
    need(source.identify(t["carol_string"]).groups == ["compliance"], "a groups claim that is one string was not read as one group")


@check("identity", "identity-feeds-issuance", "the identity, given to issue_token, gets the role when held and role_not_held when not")
def _(lab, factory):
    source, t = _idp(factory)
    engine = lab.engine()
    who = source.identify(t["dave_support"])           # dave is in no group in entities.json; the provider says support
    r = engine.call("issue_token", {"user": who.user, "groups": who.groups, "agent": "support-bot", "role": "support-agent", "task": "t-1"})
    need(r.get("ok") is True and r.get("user") == "dave", f"issuance with live groups failed: {r.get('error')}")
    who = source.identify(t["alice_removed"])          # alice is in support in entities.json; the provider says no group
    r = engine.call("issue_token", {"user": who.user, "groups": who.groups, "agent": "support-bot", "role": "support-agent", "task": "t-2"})
    need((r.get("error") or {}).get("code") == "role_not_held", "a user the provider removed from the group still got the role")


# ---- DirectorySource ----------------------------------------------------------

def _by_name(snapshot):
    users = {u.name: u for u in snapshot.users.values()}
    groups = {g.name: g for g in snapshot.groups.values()}
    return users, groups


@check("directory", "directory-matches-fixture", "users, active flags, groups, nesting and memberships equal the kit directory")
def _(lab, factory):
    snap = factory().snapshot()
    users, groups = _by_name(snap)
    need(sorted(users) == sorted(u["name"] for u in DIRECTORY["users"]), f"users are {sorted(users)}")
    need(sorted(groups) == sorted(g["name"] for g in DIRECTORY["groups"]), f"groups are {sorted(groups)}")
    for u in DIRECTORY["users"]:
        need(users[u["name"]].active is u["active"], f"user {u['name']}: active is {users[u['name']].active!r}")
        got = sorted(snap.groups[g].name for g in snap.memberships.get(users[u["name"]].id, ()))
        need(got == sorted(DIRECTORY["memberships"][u["name"]]), f"user {u['name']}: direct groups are {got}")
    for g in DIRECTORY["groups"]:
        got = sorted(snap.groups[p].name for p in groups[g["name"]].parents)
        need(got == sorted(g["parents"]), f"group {g['name']}: parents are {got}")


@check("directory", "directory-consistent", "every membership and every parent names a listed user or group; ids are non-empty strings")
def _(lab, factory):
    snap = factory().snapshot()
    for kind, table in (("user", snap.users), ("group", snap.groups)):
        for key, obj in table.items():
            need(isinstance(key, str) and key and obj.id == key, f"{kind} id {key!r} is empty or differs from the object's id")
            need(isinstance(obj.name, str) and obj.name, f"{kind} {key!r} has no name")
    for user, gs in snap.memberships.items():
        need(user in snap.users, f"a membership names user {user!r}, which was not listed")
        need(all(g in snap.groups for g in gs), f"user {user!r} is a member of a group that was not listed")
    for g in snap.groups.values():
        need(all(p in snap.groups for p in g.parents), f"group {g.id!r} has a parent that was not listed")


@check("directory", "directory-deterministic", "two snapshots of an unchanged directory give the same entities")
def _(lab, factory):
    a = bridge_directory.to_entities(factory().snapshot(), [])
    b = bridge_directory.to_entities(factory().snapshot(), [])
    need(a == b, "two snapshots of the same directory differ")


@check("directory", "directory-entities-load", "the snapshot becomes an entities.json the engine loads; inactive users are absent; nesting is kept")
def _(lab, factory):
    bundle = lab.bundle_copy()
    result = bridge_directory.sync(factory().snapshot(), bundle / "entities.json", force=True)
    need(result["written"] is True, "entities.json was not written")
    engine = lab.engine(bundle=bundle)
    for user, ok in (("alice", True), ("frank", True), ("dave", False), ("erin", False)):
        r = engine.call("issue_token", {"user": user, "agent": "support-bot", "role": "support-agent", "task": "t"})
        why = {"alice": "a direct member of support", "frank": "a member of support-eu, nested in support",
               "dave": "in no group", "erin": "inactive in the directory"}[user]
        need((r.get("ok") is True) is ok, f"{user} ({why}) {'did not get' if ok else 'got'} the support-agent role")


def _must_fail(factory, fault: str) -> None:
    try:
        snap = factory(fault).snapshot()
    except (ContractError, BridgeError):
        return
    except Exception as e:
        raise Violation(f"a directory that is {fault} raised {type(e).__name__} instead of DirectoryError") from None
    raise Violation(f"a directory that is {fault} gave a snapshot with {len(snap.users)} users instead of an error")


@check("directory", "directory-unreachable-raises", "an unreachable directory raises; it never yields an empty snapshot")
def _(lab, factory):
    _must_fail(factory, "unreachable")


@check("directory", "directory-truncated-raises", "a truncated listing raises; it never yields a partial snapshot")
def _(lab, factory):
    _must_fail(factory, "truncated")


# ---- RoleCatalog --------------------------------------------------------------

def _catalog(lab, factory):
    bundle = lab.bundle_copy()
    return factory(str(bundle)), bundle, json.loads((bundle / "roles.json").read_text(encoding="utf-8"))


def _must_reject(catalog, document, what: str, before: dict) -> None:
    for op in (catalog.validate, catalog.write):
        try:
            op(document)
        except ContractError:
            pass
        except Exception as e:
            raise Violation(f"{what}: {op.__name__} raised {type(e).__name__} instead of CatalogError") from None
        else:
            raise Violation(f"{what}: {op.__name__} accepted it")
    need(catalog.load() == before, f"{what}: the stored document changed although the write was refused")


@check("roles", "roles-load", "load returns the stored role document")
def _(lab, factory):
    catalog, _, seeded = _catalog(lab, factory)
    need(catalog.load() == seeded, "load() does not return the roles.json of the bundle")
    catalog.validate(seeded)


@check("roles", "roles-unknown-key", "a role with an unknown (misspelt) key is rejected, never stored without it")
def _(lab, factory):
    catalog, _, seeded = _catalog(lab, factory)
    doc = json.loads(json.dumps(seeded))
    doc["roles"]["support-agent"]["max_tll"] = doc["roles"]["support-agent"].pop("max_ttl")
    _must_reject(catalog, doc, "a role with the key 'max_tll'", seeded)
    doc = json.loads(json.dumps(seeded))
    doc["roles"]["support-agent"]["cap"]["resource"] = ["*"]
    _must_reject(catalog, doc, "a ceiling with the key 'resource'", seeded)
    _must_reject(catalog, dict(seeded, rolez={}), "a second top-level key", seeded)


@check("roles", "roles-malformed", "a role without members, without a ceiling, or of the wrong shape is rejected")
def _(lab, factory):
    catalog, _, seeded = _catalog(lab, factory)
    base = seeded["roles"]["support-agent"]
    for what, role in (("no members", {k: v for k, v in base.items() if k != "members"}), ("an empty members list", dict(base, members=[])),
                       ("no cap", {k: v for k, v in base.items() if k != "cap"}), ("max_ttl 0", dict(base, max_ttl=0)),
                       ("a task pattern with * in the middle", dict(base, tasks=["tick*et"])), ("a role that is a list", [])):
        _must_reject(catalog, {"roles": {"support-agent": role}}, f"a role with {what}", seeded)
    _must_reject(catalog, {"roles": []}, "roles that are a list", seeded)
    _must_reject(catalog, [], "a document that is a list", seeded)


@check("roles", "roles-write-roundtrip", "a valid write is what load returns next, and what the engine loads")
def _(lab, factory):
    catalog, bundle, seeded = _catalog(lab, factory)
    doc = json.loads(json.dumps(seeded))
    doc["roles"]["night-shift"] = {"members": [{"type": "Group", "id": "support"}], "cap": {"actions": ["read"], "resources": ["crm.customer/*"], "deny_labels": ["secret"]},
                                   "max_ttl": 120}
    digest = catalog.write(doc)
    need(isinstance(digest, str) and len(digest) == 64, "write did not return a sha256")
    need(catalog.load() == doc, "load() after write does not return what was written")
    need(factory(str(bundle)).load() == doc, "a second catalog on the same bundle does not see the write")
    info = lab.engine(bundle=bundle).call("info", {})
    need("night-shift" in (info.get("roles") or []), "the engine does not load the written role")


@check("roles", "roles-ceiling-enforced", "a ceiling written through the catalog is the ceiling the engine enforces")
def _(lab, factory):
    catalog, bundle, seeded = _catalog(lab, factory)
    doc = json.loads(json.dumps(seeded))
    doc["roles"]["support-agent"]["cap"]["budget"] = {"EUR": 5000}
    catalog.write(doc)
    engine = lab.engine(bundle=bundle)
    ask = {"user": "alice", "agent": "support-bot", "role": "support-agent", "task": "t",
           "cap": {"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 10000}}}
    need((engine.call("issue_token", ask).get("error") or {}).get("code") == "role_exceeded", "a budget above the written ceiling was issued")
    r = engine.call("issue_token", {k: v for k, v in ask.items() if k != "cap"})
    need(r.get("ok") is True and r["cap"]["budget"] == {"EUR": 5000}, "the token does not carry the written ceiling")


# ---- EnforcementPoint ---------------------------------------------------------

def _pep(lab, factory, **config):
    engine, tools = lab.engine(**config), Tools()
    return factory(engine, tools.bound()), engine, tools


@check("enforcement", "pep-allow-masks", "an allowed read returns the record without any field the principal may not see")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    out = pep.invoke(role_token(engine)["token"], "get_customer", {"customer_id": "c-1"})
    need(isinstance(out, Outcome) and out.allowed is True and out.refusal is None, f"an allowed read was refused: {out!r}")
    text = json.dumps(out.value, ensure_ascii=False)
    need("Ada Lovelace" in text, "the permitted fields did not come back")
    for hidden in HIDDEN:
        need(hidden not in text, f"a denied field value reached the caller: {hidden!r}")
    need(tools.calls == ["get_customer"], f"the tool ran {len(tools.calls)} times, expected once")


@check("enforcement", "pep-deny-does-not-run", "on a denial the tool does not run and the refusal carries reason and rule id")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    out = pep.invoke(role_token(engine)["token"], "read_salary", {"employee": "e-1"})
    refused(out, "a read outside the token's capability", "capability_resource")
    need(tools.calls == [], "the tool ran although the call was denied")


@check("enforcement", "pep-strict-input", "record data the tool is about to write is checked strictly; a forbidden field denies the call")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    token = role_token(engine)["token"]
    out = pep.invoke(token, "update_customer", {"customer_id": "c-1", "changes": {"email": "new@example.com", "ssn": "000-00-0000"}})
    refused(out, "an update that writes ssn", "field_denied")
    need(tools.calls == [], "the tool ran with a field the principal may not write")
    out = pep.invoke(token, "update_customer", {"customer_id": "c-1", "changes": {"email": "new@example.com"}})
    need(out.allowed is True and tools.calls == ["update_customer"], "an update of a permitted field was refused")


@check("enforcement", "pep-approval-id", "a held call surfaces the approval id, does not run, and runs once after a human approved")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    token = engine.issue_token("support-bot", dict(FULL_CAP, budget={"EUR": 50000}), user="alice")["token"]
    args = {"order_id": "o-9", "currency": "EUR", "amount": 15000}
    out = pep.invoke(token, "refund", args)
    refused(out, "a refund that needs approval", "approval_required")
    need(isinstance(out.refusal.approval_id, str) and out.refusal.approval_id, "the refusal does not carry the approval id")
    need(out.refusal.approval_id in engine.call("approvals", {})["pending"], "the approval id is not the one the engine holds")
    need(tools.calls == [], "the tool ran before a human approved")
    engine.approve(out.refusal.approval_id, "bob")
    need(pep.invoke(token, "refund", args).allowed is True and tools.calls == ["refund"], "the approved call did not run exactly once")
    refused(pep.invoke(token, "refund", args), "the same call again (an approval is good for one call)", "approval_required")
    need(tools.calls == ["refund"], "the tool ran a second time on one approval")


@check("enforcement", "pep-budget", "spend is checked: a call beyond the budget is refused and does not run")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    token = role_token(engine)["token"]               # 100.00 EUR for the task
    need(pep.invoke(token, "refund", {"order_id": "o-1", "currency": "EUR", "amount": 6000}).allowed is True, "a refund within budget was refused")
    refused(pep.invoke(token, "refund", {"order_id": "o-2", "currency": "EUR", "amount": 6000}), "a second refund beyond the budget", "budget_exceeded")
    need(tools.calls == ["refund"], "the tool ran for a spend the budget does not cover")
    for amount in (60.5, "6000", -1, None):
        out = pep.invoke(token, "refund", {"order_id": "o-3", "currency": "EUR", "amount": amount})
        refused(out, f"a refund with amount {amount!r}")
    need(tools.calls == ["refund"], "the tool ran with an amount that is not a whole number of minor units")


@check("enforcement", "pep-engine-unreachable", "when the engine cannot be reached the call is refused and the tool does not run")
def _(lab, factory):
    tools = Tools()
    pep = factory(unreachable_backend(), tools.bound())
    out = pep.invoke("any-token", "get_customer", {"customer_id": "c-1"})
    refused(out, "a call while the engine is unreachable")
    need(tools.calls == [], "the tool ran although no decision could be obtained: fail open")


@check("enforcement", "pep-token-per-call", "no token, a garbage token and a revoked token are refused; the token is checked on every call")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    grant = role_token(engine)
    need(pep.invoke(grant["token"], "get_customer", {"customer_id": "c-1"}).allowed is True, "a valid token was refused")
    for bad in ("", "garbage", None):
        refused(pep.invoke(bad, "get_customer", {"customer_id": "c-1"}), f"a call with token {bad!r}", "token_invalid")
    engine.revoke(grant["token_id"])
    refused(pep.invoke(grant["token"], "get_customer", {"customer_id": "c-1"}), "a call with a revoked token", "token_revoked")
    need(tools.calls == ["get_customer"], "the tool ran without a valid token")


@check("enforcement", "pep-unknown-tool", "a tool that is not bound is refused")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    refused(pep.invoke(role_token(engine)["token"], "drop_database", {}), "a call of an unbound tool")
    need(tools.calls == [], "something ran for an unbound tool")


@check("enforcement", "pep-unmaskable-output", "output that cannot be field-checked (plain text) is withheld")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    out = pep.invoke(role_token(engine)["token"], "export_notes", {"customer_id": "c-1"})
    text = json.dumps(out.value, ensure_ascii=False) if out.allowed else ""
    for hidden in HIDDEN:
        need(hidden not in text, f"plain-text tool output reached the caller unchecked: {hidden!r}")


@check("enforcement", "pep-audited", "every call the enforcement point lets through or refuses on policy is a decision in the audit log")
def _(lab, factory):
    pep, engine, tools = _pep(lab, factory)
    token = role_token(engine)["token"]
    pep.invoke(token, "get_customer", {"customer_id": "c-1"})
    pep.invoke(token, "read_salary", {"employee": "e-1"})
    decisions = [(r["effect"], r["resource"]) for r in engine.call("audit_tail", {"n": 20})["records"] if r["event"] == "decision"]
    need(("allow", "crm.customer/c-1") in decisions, "the allowed call left no decision record: was it decided with dry_run?")
    need(("deny", "hr.salary/e-1") in decisions, "the denied call left no decision record")


# ---- AgentRuntime -------------------------------------------------------------

def _runtime(lab, factory):
    engine, tools = lab.engine(), Tools()
    rt = factory(engine)
    for name, (binding, fn) in tools.bound().items():
        rt.register(name, binding, fn)
    return rt, engine, tools


@check("runtime", "runtime-no-task", "without a task token every call is refused and nothing runs")
def _(lab, factory):
    rt, engine, tools = _runtime(lab, factory)
    need(rt.current_token() == "", "a new runtime already holds a token")
    refused(rt.call("get_customer", {"customer_id": "c-1"}), "a call before begin_task", "token_invalid")
    need(tools.calls == [], "a tool ran without a task")


@check("runtime", "runtime-task-token", "calls run under the token of begin_task and stop at end_task")
def _(lab, factory):
    rt, engine, tools = _runtime(lab, factory)
    grant = role_token(engine)
    rt.begin_task(grant["token"])
    need(rt.current_token() == grant["token"], "current_token is not the token of begin_task")
    out = rt.call("get_customer", {"customer_id": "c-1"})
    need(out.allowed is True and "123-45-6789" not in json.dumps(out.value), "the call under the task token was refused or unmasked")
    rt.end_task()
    need(rt.current_token() == "", "the token survived end_task")
    refused(rt.call("get_customer", {"customer_id": "c-1"}), "a call after end_task", "token_invalid")
    need(tools.calls == ["get_customer"], "a tool ran after end_task")


@check("runtime", "runtime-tasks-isolated", "a task in another thread does not see this task's token")
def _(lab, factory):
    rt, engine, tools = _runtime(lab, factory)
    alice = role_token(engine)["token"]
    started, seen = threading.Event(), {}

    def other():
        started.wait(5)
        seen["token"] = rt.current_token()
        seen["out"] = rt.call("get_customer", {"customer_id": "c-1"})

    worker = threading.Thread(target=other)
    worker.start()
    rt.begin_task(alice)
    started.set()
    worker.join(10)
    need(seen.get("token") == "", "a thread that never began a task sees another task's token")
    refused(seen["out"], "a call from a thread without a task", "token_invalid")
    need(rt.current_token() == alice, "the first task lost its token")


@check("runtime", "runtime-unregistered-tool", "a tool that was never registered is refused, not raised and not run")
def _(lab, factory):
    rt, engine, tools = _runtime(lab, factory)
    rt.begin_task(role_token(engine)["token"])
    refused(rt.call("drop_database", {}), "a call of an unregistered tool")


@check("runtime", "runtime-spawn-narrows", "a sub-agent runs under an exchanged token: same human and role, longer chain, narrower capability")
def _(lab, factory):
    rt, engine, tools = _runtime(lab, factory)
    parent = role_token(engine)
    rt.begin_task(parent["token"])
    child = rt.spawn("summarizer", {"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["secret"]}, 120)
    need(child.current_token() not in ("", parent["token"]), "the sub-agent holds no token of its own")
    info = engine.inspect_token(child.current_token())
    need(info["valid"] and info["user"] == "alice" and info["chain"] == ["support-bot", "summarizer"],
         f"the sub-agent's token is not alice via support-bot -> summarizer: {info.get('chain')}")
    need(info["claims"].get("role") == "support-agent", "the sub-agent's token lost the role")
    need(parent["token_id"] in info["claims"]["anc"], "the sub-agent's token is not derived from the parent's")
    need(child.call("get_customer", {"customer_id": "c-1"}).allowed is True, "the sub-agent cannot do what it was handed")
    refused(child.call("update_customer", {"customer_id": "c-1", "changes": {"email": "x@example.com"}}), "an update by the read-only sub-agent",
            "capability_action")
    need(rt.current_token() == parent["token"], "spawning changed the parent's token")
    need(rt.call("update_customer", {"customer_id": "c-1", "changes": {"email": "x@example.com"}}).allowed is True, "the parent lost its own capability")


@check("runtime", "runtime-spawn-cannot-widen", "asking for more than the parent holds raises SpawnRefused; no runtime comes back")
def _(lab, factory):
    rt, engine, tools = _runtime(lab, factory)
    rt.begin_task(role_token(engine)["token"])
    child = rt.spawn("summarizer", {"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["secret"]})
    for who, runtime, cap, reason in (("the parent", rt, {"actions": ["read"], "resources": ["hr.salary/*"], "deny_labels": ["secret"]}, "widening"),
                                      ("the sub-agent", child, {"actions": ["read", "update"], "resources": ["crm.customer/*"], "deny_labels": ["secret"]}, "widening"),
                                      ("an agent no policy lets it delegate to", rt, None, "delegation_denied")):
        actor = "rogue-bot" if reason == "delegation_denied" else "summarizer"
        try:
            got = runtime.spawn(actor, cap)
        except SpawnRefused as e:
            need(e.refusal.reason == reason and e.refusal.rule == "DELEGATE-" + reason.upper().replace("_", "-"),
                 f"{who}: refused with {e.refusal.reason!r}, expected {reason!r}")
            continue
        except Exception as e:
            raise Violation(f"{who}: raised {type(e).__name__} instead of SpawnRefused") from None
        raise Violation(f"{who} asked for {reason} and got a runtime back (token of the parent: {got.current_token() == runtime.current_token()})")
    try:
        factory(engine).spawn("summarizer")
    except SpawnRefused:
        pass
    else:
        raise Violation("spawn without a task returned a runtime")


@check("runtime", "runtime-child-dies-with-parent", "revoking the task's token stops its sub-agents")
def _(lab, factory):
    rt, engine, tools = _runtime(lab, factory)
    parent = role_token(engine)
    rt.begin_task(parent["token"])
    child = rt.spawn("summarizer", {"actions": ["read"], "resources": ["crm.customer/*"], "deny_labels": ["secret"]})
    need(child.call("get_customer", {"customer_id": "c-1"}).allowed is True, "the sub-agent could not act before the revocation")
    engine.revoke(parent["token_id"])
    refused(child.call("get_customer", {"customer_id": "c-1"}), "a sub-agent call after the parent token was revoked", "token_revoked")


# ---- ApprovalChannel ----------------------------------------------------------

def _held(lab):
    """An engine with one request held for approval. -> (engine, token, the request as authorize input, approval id)"""
    engine = lab.engine()
    token = engine.issue_token("support-bot", dict(FULL_CAP, budget={"EUR": 50000}), user="alice")["token"]
    request = {"token": token, "action": "create", "resource": {"path": "billing.refund", "id": "o-9"},
               "context": {"spend": {"currency": "EUR", "amount": 15000}}}
    d = engine.call("authorize", request)
    need(d.get("reason") == "approval_required", "the kit could not set up a held request")
    return engine, request, d["approval"]["id"]


def _round(engine, factory, human):
    seen: list = []

    def person(payload):
        seen.append(payload)
        return human(payload)

    channel = factory(person)
    return pump(engine, channel, set()), seen, channel


@check("approval", "approval-delivers", "the human is shown the approval id, the label, who asks, the agent, the action and the resource")
def _(lab, factory):
    engine, request, aid = _held(lab)
    result, seen, _ = _round(engine, factory, lambda payload: None)
    need(result["delivered"] == [aid] and len(seen) == 1, "the held request was not delivered exactly once")
    text = json.dumps(seen[0])
    for part in (aid, "refund-over-100-eur", "alice", "support-bot", "create", "billing.refund/o-9"):
        need(part in text, f"what the human is shown lacks {part!r}")
    need(request["token"] not in text, "what the human is shown contains the capability token")


@check("approval", "approval-silence", "no answer is no approval: the request stays held")
def _(lab, factory):
    engine, request, aid = _held(lab)
    for silence in (lambda p: None, lambda p: {}, lambda p: {"approve": "yes", "by": "bob"}, lambda p: {"approve": True}):
        result, _, channel = _round(engine, factory, silence)
        need(result["approved"] == [] and channel.verdicts() == [], "an unanswered or unclear reply became an approval")
    need(aid in engine.call("approvals", {})["pending"], "the request is no longer pending")
    need(engine.call("authorize", request)["effect"] == "deny", "the held call went through without an approval")


@check("approval", "approval-reject", "a rejection is not an approval")
def _(lab, factory):
    engine, request, aid = _held(lab)
    result, _, _ = _round(engine, factory, lambda p: {"approve": False, "by": "bob"})
    need(result["approved"] == [] and result["rejected"] == [aid], f"a rejection was handled as {result}")
    need(engine.call("authorize", request)["effect"] == "deny", "the rejected call went through")


@check("approval", "approval-names-approver", "an approval is recorded under the human who gave it, and lets the call through once")
def _(lab, factory):
    engine, request, aid = _held(lab)
    result, _, channel = _round(engine, factory, lambda p: {"approve": True, "by": "bob"})
    need(result["approved"] == [aid], f"bob's approval was not applied: {result}")
    granted = [r for r in engine.call("audit_tail", {"n": 10})["records"] if r["event"] == "approval_granted"]
    need(len(granted) == 1 and granted[0]["by"] == "bob", "the audit log does not name bob as the approver")
    need(channel.verdicts() == [], "the channel returned the same verdict twice")
    need(engine.call("authorize", request)["effect"] == "allow", "the approved call was still denied")


@check("approval", "approval-not-laundered", "the channel passes on who answered: the requesting user and a user without the right cannot approve")
def _(lab, factory):
    engine, request, aid = _held(lab)
    for who, code in (("alice", "self_approval"), ("carol", "approval_denied")):
        result, _, _ = _round(engine, factory, lambda p, who=who: {"approve": True, "by": who})
        need(result["approved"] == [], f"an approval answered by {who} was applied: the channel replaced the approver's identity")
        need([r["code"] for r in result["refused"]] == [code] and result["refused"][0]["by"] == who,
             f"the engine was not asked as {who}: {result['refused']}")
    need(engine.call("authorize", request)["effect"] == "deny", "the call went through although nobody entitled approved it")


@check("approval", "approval-own-requests-only", "a verdict is tied to the request it answers")
def _(lab, factory):
    engine, request, aid = _held(lab)
    other = dict(request, resource={"path": "billing.refund", "id": "o-10"})
    other_id = engine.call("authorize", other)["approval"]["id"]
    need(other_id != aid, "the kit could not set up two different held requests")
    result, _, _ = _round(engine, factory, lambda p: {"approve": True, "by": "bob"} if aid in json.dumps(p) else None)
    need(result["approved"] == [aid], f"approving one of two requests approved {result['approved']}")
    need(engine.call("authorize", other)["effect"] == "deny", "the request nobody answered went through")


# ---- AuditSink ----------------------------------------------------------------

def _log(lab, extra: int = 0):
    """An engine that has written some audit records. -> (engine, audit path, records)"""
    engine = lab.engine()
    token = role_token(engine)["token"]
    for i in range(3 + extra):
        engine.call("authorize", {"token": token, "action": "read", "resource": {"path": "crm.customer", "id": f"c-{i}"}})
    path = lab.dir / "state" / "audit.jsonl"
    return engine, path, read_records(path)


def _sink_refuses(sink, records, what: str) -> None:
    before = sink.head()
    try:
        sink.append(records)
    except ContractError:
        need(sink.head() == before, f"{what}: the sink refused, but its head moved")
        return
    except Exception as e:
        raise Violation(f"{what}: raised {type(e).__name__} instead of SinkError") from None
    raise Violation(f"{what}: the sink took it")


@check("audit", "audit-head", "an empty sink has no head; after shipping, its head is the log's newest record")
def _(lab, factory):
    engine, path, records = _log(lab)
    sink = factory(str(lab.path("sink")))
    need(sink.head() is None, "an empty sink reports a head")
    ship(path, sink)
    need(tuple(sink.head()) == (records[-1]["seq"], records[-1]["hash"]), "the sink's head is not the newest record of the log")
    need(tuple(sink.head())[1] == engine.call("audit_verify", {})["head"], "the sink's head is not the head `audit verify` reports")


@check("audit", "audit-replay", "records the sink already holds are skipped; shipping twice changes nothing")
def _(lab, factory):
    engine, path, records = _log(lab)
    sink = factory(str(lab.path("sink")))
    sink.append(records[:2])
    sink.append(records[:2])
    sink.append(records[1:])
    need(tuple(sink.head()) == (records[-1]["seq"], records[-1]["hash"]), "after a replay the head is wrong")
    need(ship(path, sink)["shipped"] == 0, "a second shipment sent records again")
    engine.call("authorize", {"token": "garbage", "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}})
    need(ship(path, sink)["shipped"] == 1 and tuple(sink.head())[0] == records[-1]["seq"] + 1, "a record written later was not shipped")


@check("audit", "audit-gap", "records with a sequence number missing are refused")
def _(lab, factory):
    _, _, records = _log(lab)
    sink = factory(str(lab.path("sink")))
    _sink_refuses(sink, [records[0], records[2]], "a batch that skips a record")
    sink.append(records[:1])
    _sink_refuses(sink, records[2:], "a batch that starts after a gap")
    _sink_refuses(factory(str(lab.path("sink2"))), records[1:], "a first batch that does not start at record 1")


@check("audit", "audit-chain", "a record that was edited, or does not chain onto the one before, is refused")
def _(lab, factory):
    _, _, records = _log(lab)
    sink = factory(str(lab.path("sink")))
    sink.append(records[:2])
    edited = dict(records[2], user="mallory")
    _sink_refuses(sink, [edited], "a record whose content was edited (hash left as it was)")
    foreign = {k: v for k, v in records[2].items() if k != "hash"}
    foreign["prev"] = "f" * 64
    foreign["hash"] = sha256_hex((foreign["prev"] + canon(foreign)).encode("utf-8"))
    _sink_refuses(sink, [foreign], "a well-formed record from another chain")


@check("audit", "audit-rewrite", "a log that was rewritten or cut back is refused, not followed")
def _(lab, factory):
    engine, path, records = _log(lab)
    sink = factory(str(lab.path("sink")))
    ship(path, sink)
    with Lab() as second:                               # the same host, with the log deleted and regrown
        _, other_path, other = _log(second, extra=2)
        _sink_refuses(sink, other[:len(records)], "different records under sequence numbers the sink already holds")
        try:
            ship(other_path, sink)
        except ContractError:
            pass
        else:
            raise Violation("shipping a re-forged log succeeded")
    path.write_text(canon(records[0]) + "\n", encoding="utf-8", newline="\n")
    try:
        ship(path, sink)
    except ContractError:
        pass
    else:
        raise Violation("shipping a log whose newest records were removed succeeded")
    need(tuple(sink.head()) == (records[-1]["seq"], records[-1]["hash"]), "the sink's head changed while refusing")


@check("audit", "audit-restart", "the head survives a restart of the sink")
def _(lab, factory):
    _, path, records = _log(lab)
    location = str(lab.path("sink"))
    ship(path, factory(location))
    again = factory(location)
    need(again.head() is not None and tuple(again.head()) == (records[-1]["seq"], records[-1]["hash"]), "a new sink on the same location lost the head")


# ---- RevocationFeed -----------------------------------------------------------

EVENTS = [Revocation(4, "token", "aaaa", 1700000100, "cli"), Revocation(7, "user", "alice", 1700000200, "sync"),
          Revocation(9, "token", "bbbb", 1700000300, None)]


@check("revocation", "feed-order", "poll returns every event after the cursor, in sequence order")
def _(lab, factory):
    feed = factory(str(lab.path("feed")))
    need(feed.poll() == [], "an empty feed returns events")
    feed.publish([EVENTS[2], EVENTS[0]])
    feed.publish([EVENTS[1]])
    seqs = lambda after=0: [e.seq for e in feed.poll(after)]
    need(seqs() == [4, 7, 9], f"poll() is {seqs()}, expected [4, 7, 9]")
    need(seqs(4) == [7, 9] and seqs(9) == [], "poll(after=...) does not return exactly the later events")


@check("revocation", "feed-replay", "publishing an event again does not duplicate it")
def _(lab, factory):
    feed = factory(str(lab.path("feed")))
    feed.publish(EVENTS)
    feed.publish(EVENTS[:2])
    feed.publish([EVENTS[1], EVENTS[1]])
    need([e.seq for e in feed.poll()] == [4, 7, 9], "a replayed event appears twice, or one was lost")


@check("revocation", "feed-restart", "published events survive a restart of the feed")
def _(lab, factory):
    location = str(lab.path("feed"))
    factory(location).publish(EVENTS)
    need([e.seq for e in factory(location).poll(after=4)] == [7, 9], "a new feed on the same location lost events")


@check("revocation", "feed-fidelity", "an event comes back as it was published: kind, subject, time and who")
def _(lab, factory):
    feed = factory(str(lab.path("feed")))
    feed.publish(EVENTS)
    got = feed.poll()
    for want, have in zip(EVENTS, got):
        need(isinstance(have, Revocation) and have.to_json() == want.to_json(), f"event {want.seq} came back as {getattr(have, 'to_json', lambda: have)()}")


@check("revocation", "feed-reaches-verifier", "a revocation by token and one by user, carried by the feed, stop the tokens at an engine with its own state")
def _(lab, factory):
    issuer = lab.engine("issuer")
    verifier = lab.engine("verifier", verify_only=True, trusted_keys=[issuer.info()["public_key"]])
    ask = lambda token: verifier.call("authorize", {"token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}})
    alice, bob, other = role_token(issuer), role_token(issuer, user="bob"), role_token(issuer, task="ticket-8")
    child = issuer.exchange_token(alice["token"], "summarizer", cap={"actions": ["read"], "resources": ["crm.customer/*"], "deny_labels": ["secret"]})
    need(all(ask(t["token"])["effect"] == "allow" for t in (alice, bob, other, child)), "the verifying engine does not accept the issuer's tokens")
    issuer.revoke(alice["token_id"])
    issuer.revoke_user("bob", by="hr")
    need(ask(alice["token"])["effect"] == "allow", "the kit expected the verifier not to know of the revocation yet")
    feed = factory(str(lab.path("feed")))
    feed.publish(revocations_from_audit(lab.dir / "issuer" / "audit.jsonl"))
    events = feed.poll()
    need([(e.kind, e.subject) for e in events] == [("token", alice["token_id"]), ("user", "bob")], f"the feed carries {[(e.kind, e.subject) for e in events]}")
    cursor = apply_revocations(verifier, events)
    for what, token in (("the revoked token", alice), ("a sub-agent token derived from it", child), ("a token of the revoked user", bob)):
        need(ask(token["token"]).get("reason") == "token_revoked", f"{what} is still accepted by the verifying engine")
    need(ask(other["token"])["effect"] == "allow", "a token nobody revoked stopped working")
    need(feed.poll(after=cursor) == [], "the cursor returned by apply_revocations does not mark the feed as read")
    need(apply_revocations(verifier, feed.poll()) == cursor, "replaying the feed failed")


# ---- running ------------------------------------------------------------------

def checks_for(interface: str) -> list:
    return [c for c in CHECKS if c.interface == interface]


def run(interface: str, factory: Callable, only: list | None = None) -> list:
    """Every check of `interface` against `factory`. A check that raises
    anything is failed; the kit itself never raises for an implementation's fault."""
    out = []
    for c in checks_for(interface):
        if only and c.id not in only:
            continue
        with Lab() as lab:
            try:
                c.fn(lab, factory)
                out.append(Result(c.id, interface, c.title, True))
            except Violation as e:
                out.append(Result(c.id, interface, c.title, False, str(e)))
            except Exception as e:
                out.append(Result(c.id, interface, c.title, False, f"the check stopped on {type(e).__name__}: {e}"))
    return out

