"""The short way in: three functions over the engine.

    from sf_smartdelegate import core

    iam = core.open_engine("bundle", "state")
    grant = core.delegate(iam, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
    d = core.check(iam, grant.token, "read", "crm.customer", "c-1", data=record)
    if d.allowed:
        use(d.data)            # already masked

`delegate` is where the bound is set: the human lends the agent one of the
roles they hold, for one task. The token can never carry more than that role
allows, and a sub-agent's token (`narrow`) can only carry less.
"""
from __future__ import annotations

from pathlib import Path

from .engine import Engine
from .errors import EngineError, rule_id
from .models import AuditRecord, Capability, Decision, Grant, Role

RULE_PREFIX = "DELEGATE"
EXAMPLE_BUNDLE = Path(__file__).parent / "example_bundle"


def open_engine(bundle_dir=None, state_dir=None, **config) -> Engine:
    """An engine on a bundle directory. Without `state_dir` it keeps nothing
    on disk (ephemeral signing key, no audit log): fine for tests and demos."""
    cfg = {"bundle_dir": str(bundle_dir or EXAMPLE_BUNDLE), **config}
    if state_dir:
        cfg["state_dir"] = str(state_dir)
    return Engine(cfg)


def _raise(result: dict) -> dict:
    if not result.get("ok"):
        err = result.get("error") or {}
        raise EngineError(err.get("code", "error"), err.get("message", "unknown error"))
    return result


def delegate(engine, *, user: str | None = None, agent: str, role: str | None = None, task: str | None = None,
             capability: Capability | dict | None = None, groups: list | None = None, id_token: str | None = None,
             ttl: int | None = None, tenant: str | None = None, now: int | None = None) -> Grant:
    """A human lends an agent authority for one task.

    With `role`, the human must hold the role and the token cannot exceed it.
    `groups` is the human's live membership when the caller has it from the
    identity provider (see sf_smartdelegate.bridges); `id_token` lets the engine
    read identity and groups from a verified OIDC ID token itself.
    Raises EngineError: role_not_held, role_exceeded, delegation_denied, ..."""
    cap = capability.to_json() if isinstance(capability, Capability) else capability
    body = {"user": user, "agent": agent, "role": role, "task": task, "cap": cap, "groups": groups, "id_token": id_token,
            "ttl": ttl, "tenant": tenant, "now": now}
    return Grant.from_json(_raise(engine.call("issue_token", {k: v for k, v in body.items() if v is not None})))


def narrow(engine, grant: Grant | str, *, actor: str, capability: Capability | dict | None = None, ttl: int | None = None,
           now: int | None = None) -> Grant:
    """An agent hands part of what it holds to a sub-agent. Never more."""
    cap = capability.to_json() if isinstance(capability, Capability) else capability
    body = {"subject_token": grant.token if isinstance(grant, Grant) else grant, "actor": actor, "cap": cap, "ttl": ttl, "now": now}
    return Grant.from_json(_raise(engine.call("exchange_token", {k: v for k, v in body.items() if v is not None})))


def check(engine, token: str, action: str, resource: str, id: str | None = None, *, data=None, attrs: dict | None = None,
          context: dict | None = None, strict: bool = False, now: int | None = None) -> Decision:
    """May this token do this? With `data`, the answer carries the data with
    every field the principal may not see removed or redacted."""
    res = {"path": resource, "id": id if id is not None else "any"}
    if attrs:
        res["attrs"] = attrs
    body = {"token": token, "action": action, "resource": res}
    if context:
        body["context"] = context
    if strict:
        body["strict"] = True
    if now is not None:
        body["now"] = now
    if data is not None:
        body["data"] = data
    return Decision.from_json(_raise(engine.call("filter" if data is not None else "authorize", body)))


def roles(engine) -> list[Role]:
    """The roles of the loaded bundle."""
    return [Role(r.name, [{"type": m[0], "id": m[1]} for m in r.members], Capability.from_json(r.cap.to_json()), r.max_ttl,
                 r.tasks, r.agents, dict(r.bindings)) for r in engine.bundle.roles.values()]


def audit(engine, n: int = 20) -> list[AuditRecord]:
    return [AuditRecord.from_json(r) for r in _raise(engine.call("audit_tail", {"n": n}))["records"]]


def demo() -> str:
    """A scripted walk through the example bundle. Returns the transcript."""
    import shutil
    import tempfile

    out = []
    say = out.append
    state = tempfile.mkdtemp(prefix="smartdelegate-demo-")
    try:
        with open_engine(state_dir=state) as iam:
            say("SmartDelegate demo: an agent never holds more than the human's role for the task")
            say("")
            say("Roles in the bundle:")
            for r in roles(iam):
                who = ", ".join(f"{m['type']}::{m['id']}" for m in r.members)
                say(f"  {r.name:<14} held by {who}; ceiling: {', '.join(r.ceiling.actions)} on {', '.join(r.ceiling.resources)}"
                    + (f"; budget {r.ceiling.budget}" if r.ceiling.budget else ""))
            say("")

            say("1. Alice (support) lends support-bot her support-agent role for ticket-7")
            g = delegate(iam, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
            say(f"   token for {g.user} via {' -> '.join(g.chain)}, role {g.role}, budget {g.capability.budget}, never sees {g.capability.deny_labels}")

            record = {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU",
                      "notes": "VIP, do not upsell", "card": {"last4": "4242", "number": "4000 0000 0000 4242"}}
            d = check(iam, g.token, "read", "crm.customer", "c-1", data=record)
            say(f"2. The bot reads customer c-1: {d.rule}")
            say(f"   the model receives: {d.data}")
            say(f"   removed before it reached the model: {d.masked}")

            d = check(iam, g.token, "create", "billing.refund", "r-1", context={"spend": {"currency": "EUR", "amount": 6000}})
            say(f"3. Refund 60.00 EUR: {d.rule}")
            d = check(iam, g.token, "create", "billing.refund", "r-2", context={"spend": {"currency": "EUR", "amount": 6000}})
            say(f"4. A second 60.00 EUR refund on the same task: {d.rule} ({d.detail})")

            say("5. Alice asks for more than her role allows (a 500 EUR budget)")
            try:
                delegate(iam, user="alice", agent="support-bot", role="support-agent", task="ticket-8",
                         capability={"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 50000}})
            except EngineError as e:
                say(f"   refused: {rule_id(e.code)} ({e.message})")

            say("6. The bot hands a read-only slice to a sub-agent")
            sub = narrow(iam, g, actor="summarizer", ttl=300, capability={"actions": ["read"], "resources": ["crm.customer/c-1"],
                                                                         "deny_labels": ["pii", "secret"]})
            d = check(iam, sub.token, "read", "crm.customer", "c-1", data=record)
            say(f"   {' -> '.join(sub.chain)} (role {sub.role}) receives: {d.data}")
            try:
                narrow(iam, sub, actor="summarizer", capability={"actions": ["read", "update"], "resources": ["crm.customer/*"]})
            except EngineError as e:
                say(f"   and cannot widen it again: {rule_id(e.code)}")

            say("7. Dave is not in support and tries the same role")
            try:
                delegate(iam, user="dave", agent="support-bot", role="support-agent", task="ticket-9")
            except EngineError as e:
                say(f"   refused: {rule_id(e.code)}")

            say("8. The identity provider says Alice left the support group five minutes ago")
            try:
                delegate(iam, user="alice", agent="support-bot", role="support-agent", task="ticket-10", groups=[])
            except EngineError as e:
                say(f"   refused: {rule_id(e.code)} (live membership replaces the stored one)")

            v = _raise(iam.call("audit_verify", {}))
            say(f"9. Audit log: {v['records']} records, hash chain verifies, head {v['head'][:16]}...")
    finally:
        shutil.rmtree(state, ignore_errors=True)
    return "\n".join(out)
