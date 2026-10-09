"""Data objects of SmartDelegate. The UML diagram in the README is these
classes. The engine itself speaks JSON (spec/API.md); these are typed views
of that JSON for Python callers."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Capability:
    """What a token may do at most. A ceiling, not a grant: policy still decides."""
    actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    deny_labels: list[str] = field(default_factory=list)
    deny_fields: list[str] = field(default_factory=list)
    budget: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_json(cls, v: dict | None) -> "Capability":
        v = v or {}
        return cls(list(v.get("actions") or []), list(v.get("resources") or []), list(v.get("deny_labels") or []),
                   list(v.get("deny_fields") or []), dict(v.get("budget") or {}))

    def to_json(self) -> dict:
        return {"actions": self.actions, "resources": self.resources, "deny_labels": self.deny_labels,
                "deny_fields": self.deny_fields, "budget": self.budget}


@dataclass
class Role:
    """A role a human holds and can lend to an agent for one task."""
    name: str
    members: list[dict]
    ceiling: Capability
    max_ttl: int | None = None
    tasks: list[str] | None = None
    agents: list[str] | None = None
    bindings: dict = field(default_factory=dict)


@dataclass
class Principal:
    """Who is acting: the human, and the chain of agents acting for them."""
    user: str
    agent: str
    chain: list[str]
    role: str | None = None
    task: str | None = None
    tenant: str | None = None
    token_id: str | None = None

    @classmethod
    def from_json(cls, v: dict | None) -> "Principal | None":
        if not v:
            return None
        return cls(v.get("user", ""), v.get("agent", ""), list(v.get("chain") or []), v.get("role"), v.get("task"),
                   v.get("tenant"), v.get("token_id"))


@dataclass
class Grant:
    """A capability token and what it carries."""
    token: str
    token_id: str
    user: str
    chain: list[str]
    role: str | None
    capability: Capability
    expires_at: int
    task: str | None = None

    @classmethod
    def from_json(cls, v: dict) -> "Grant":
        return cls(v["token"], v["token_id"], v["user"], list(v["chain"]), v.get("role"), Capability.from_json(v.get("cap")),
                   v["expires_at"], v.get("task"))


@dataclass
class Obligations:
    """What the caller must do with an allowed request."""
    fields_allow: list[str] = field(default_factory=list)
    fields_deny: list[str] = field(default_factory=list)
    fields_redact: list[str] = field(default_factory=list)
    row_filter: list[dict] = field(default_factory=list)
    rate_limit: dict | None = None

    @classmethod
    def from_json(cls, v: dict | None) -> "Obligations":
        v = v or {}
        f = v.get("fields") or {}
        return cls(list(f.get("allow") or []), list(f.get("deny") or []), list(f.get("redact") or []),
                   list(v.get("row_filter") or []), v.get("rate_limit"))


@dataclass
class Decision:
    """The answer to one request. `rule` is the family rule id, DELEGATE-*."""
    allowed: bool
    reason: str
    rule: str
    detail: str = ""
    policies: list[str] = field(default_factory=list)
    principal: Principal | None = None
    obligations: Obligations = field(default_factory=Obligations)
    approval: dict | None = None
    data: object = None
    masked: list[str] = field(default_factory=list)
    decision_id: str = ""
    policy_version: str = ""

    @classmethod
    def from_json(cls, v: dict) -> "Decision":
        return cls(v.get("effect") == "allow", v.get("reason", ""), v.get("rule", ""), v.get("detail", ""),
                   list(v.get("policies") or []), Principal.from_json(v.get("principal")),
                   Obligations.from_json(v.get("obligations")), v.get("approval"), v.get("data"),
                   list(v.get("masked") or []), v.get("decision_id", ""), v.get("policy_version", ""))


@dataclass
class AuditRecord:
    """One line of the hash-chained log."""
    seq: int
    ts: int
    event: str
    prev: str
    hash: str
    body: dict = field(default_factory=dict)

    @classmethod
    def from_json(cls, v: dict) -> "AuditRecord":
        known = ("seq", "ts", "event", "prev", "hash")
        return cls(v.get("seq", 0), v.get("ts", 0), v.get("event", ""), v.get("prev", ""), v.get("hash", ""),
                   {k: x for k, x in v.items() if k not in known})
