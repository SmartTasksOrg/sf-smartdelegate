"""The interfaces an adopter implements to plug SmartDelegate into the IAM and
agent systems they already run. Typed contracts only: standard library,
no import of the engine.

    IdentitySource    a verified ID token -> who the human is and what they belong to now
    DirectorySource   users, groups and memberships, as one snapshot, for the scheduled sync
    RoleCatalog       roles and their ceilings (roles.json): load, validate, write
    EnforcementPoint  a task token and a tool call: authorize, run, filter
    AgentRuntime      how a framework holds the current task token and narrows it for sub-agents
    ApprovalChannel   deliver a held request to a human and bring the verdict back
    AuditSink         receive the audit records somewhere the engine's host cannot rewrite
    RevocationFeed    carry revocations to engines that do not share the issuer's state

One page per interface is in interfaces/docs/. Reference implementations are
in interfaces/reference/. `python -m interfaces.contract` runs the contract
checks against an implementation.

Every implementation follows one rule: when it cannot give a true answer it
raises (or returns a refusal). It never returns a partial answer, an empty
answer standing for "unknown", or an allow.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Protocol, runtime_checkable

if TYPE_CHECKING:       # the snapshot type lives with the bridges; contracts stay import-free
    from sf_smartdelegate.bridges.directory import Snapshot

__all__ = ["ContractError", "IdentityError", "DirectoryError", "CatalogError", "SinkError", "FeedError", "SpawnRefused",
           "Identity", "ToolBinding", "Refusal", "Outcome", "ApprovalRequest", "Verdict", "Revocation",
           "IdentitySource", "DirectorySource", "RoleCatalog", "EnforcementPoint", "AgentRuntime", "ApprovalChannel",
           "AuditSink", "RevocationFeed", "INTERFACES"]


class ContractError(Exception):
    """An implementation could not give a true answer. `code` is short and
    stable; `message` never holds a credential, a token or record data."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code, self.message = code, message


class IdentityError(ContractError):
    """The ID token is not acceptable. Nothing about the human is returned."""


class DirectoryError(ContractError):
    """The directory could not be read completely. No snapshot is returned."""


class CatalogError(ContractError):
    """The role document is not valid, or could not be stored. The stored one is unchanged."""


class SinkError(ContractError):
    """The sink did not take the records. Its head is unchanged."""


class FeedError(ContractError):
    """The feed could not publish or could not be read. The reader knows nothing new."""


# ---- identity ----------------------------------------------------------------

@dataclass(frozen=True)
class Identity:
    """Who signed in, and what they are a member of right now.

    `groups` are SmartDelegate group ids (after the adopter's mapping),
    sorted, without duplicates. An empty list is a true answer: this human is
    in no group. It is passed to `issue_token` as `groups`, where it replaces
    the stored membership of that user for the token."""
    user: str
    groups: list
    issuer: str = ""
    expires_at: int = 0


@runtime_checkable
class IdentitySource(Protocol):
    def identify(self, id_token: str) -> Identity:
        """Verify an OIDC ID token and read the human from it.

        Raises IdentityError unless the signature verifies against the
        provider's keys, the issuer is the configured one, the audience is
        this client (and `azp`, when present, too), and the token has not
        expired. Raises IdentityError when the groups claim is malformed or
        incomplete (an overage). Never returns groups remembered from an
        earlier token."""
        ...


# ---- directory ---------------------------------------------------------------

@runtime_checkable
class DirectorySource(Protocol):
    def snapshot(self) -> "Snapshot":
        """Every user, every group and every membership, read at one time.

        Raises DirectoryError (or sf_smartdelegate.bridges.BridgeError) when the
        directory is unreachable, answers with an error, or the listing is
        truncated. A partial snapshot is never returned: written to
        entities.json it would remove people's access, or keep it."""
        ...


# ---- roles -------------------------------------------------------------------

@runtime_checkable
class RoleCatalog(Protocol):
    def load(self) -> dict:
        """The role document as stored: {"roles": {name: {...}}} (spec/ROLES.md)."""
        ...

    def validate(self, document: dict) -> None:
        """Raises CatalogError unless `document` is a role document the engine
        would load. An unknown key is an error, never ignored: a misspelt key
        must not loosen a role."""
        ...

    def write(self, document: dict) -> str:
        """Validate, then replace the stored document as a whole. Returns the
        sha256 of what was stored. On any failure raises CatalogError and the
        stored document is the old one, complete."""
        ...


# ---- enforcement -------------------------------------------------------------

@dataclass(frozen=True)
class ToolBinding:
    """How one tool maps onto an engine request (the fields of
    integrations/adapter.ToolSpec, without the function).

    action, resource   what policies see: "read" on "crm.customer"
    id                 name of the argument holding the resource id (None: "any")
    input              name of the argument holding record data the tool writes; checked in strict mode
    spend              (currency argument, amount argument); the amount is an integer in minor units
    attrs              name of the argument holding resource attributes
    output             "filter" (default) or "raw" for tools that return no record data"""
    action: str
    resource: str
    id: str | None = None
    input: str | None = None
    spend: tuple | None = None
    attrs: str | None = None
    output: str = "filter"


@dataclass(frozen=True)
class Refusal:
    """Why a call did not happen. `rule` is the DELEGATE-* id of `reason`."""
    reason: str
    rule: str
    detail: str = ""
    approval_id: str | None = None
    decision_id: str | None = None


@dataclass(frozen=True)
class Outcome:
    """What an enforcement point answers. `allowed` False always comes with a
    refusal and with `value` None."""
    allowed: bool
    value: Any = None
    refusal: Refusal | None = None


@runtime_checkable
class EnforcementPoint(Protocol):
    def invoke(self, token: str, tool: str, arguments: dict) -> Outcome:
        """Authorize, run, filter.

        The tool runs only after the engine allowed this exact call. What the
        tool returned passes through the decision's obligations before it is
        returned; output that cannot be field-checked is withheld. A denial,
        an engine error, an unreachable engine, an unknown tool or arguments
        that cannot be read are all an Outcome with allowed False; the tool
        did not run. An exception raised by the tool itself may propagate."""
        ...


class SpawnRefused(ContractError):
    """A sub-agent token was refused (DELEGATE-WIDENING, -DEPTH-EXCEEDED,
    -DELEGATION-DENIED, a dead parent token ...). No runtime is returned."""

    def __init__(self, refusal: Refusal):
        super().__init__(refusal.reason, refusal.detail)
        self.refusal = refusal


@runtime_checkable
class AgentRuntime(Protocol):
    def begin_task(self, token: str) -> None:
        """This thread of work now acts under `token`. Other concurrent tasks
        in the process are unaffected."""
        ...

    def end_task(self) -> None:
        """Forget the token. Later calls are refused until the next begin_task."""
        ...

    def current_token(self) -> str:
        """The token of the task in hand, or "" when there is none."""
        ...

    def register(self, name: str, binding: ToolBinding, fn: Callable[..., Any]) -> None:
        """Make a tool callable. A tool without a binding cannot be called."""
        ...

    def call(self, name: str, arguments: dict) -> Outcome:
        """One tool call through the enforcement point, under the current token."""
        ...

    def spawn(self, actor: str, capability: dict | None = None, ttl: int | None = None) -> "AgentRuntime":
        """A runtime for a sub-agent, holding a token exchanged from the
        current one: same human, same role, a longer chain, and a capability
        that is the same or narrower. Raises SpawnRefused when the engine
        refuses; it never falls back to the parent's token."""
        ...


# ---- approvals ---------------------------------------------------------------

@dataclass(frozen=True)
class ApprovalRequest:
    """A held request, as the engine lists it (`approvals`). It holds no
    token and no record values."""
    id: str
    label: str
    user: str
    agent: str
    action: str
    resource: str
    requested_at: int = 0


@dataclass(frozen=True)
class Verdict:
    """What a human decided. `by` is that human's user id in entities.json."""
    approval_id: str
    approve: bool
    by: str


@runtime_checkable
class ApprovalChannel(Protocol):
    def deliver(self, request: ApprovalRequest) -> None:
        """Put the request in front of a human. Raises when it could not be delivered."""
        ...

    def verdicts(self) -> list:
        """The verdicts received since the last call, each returned once. No
        answer is no verdict: silence, a timeout or an unreadable reply never
        becomes an approval. `by` is the human who answered, never a fixed
        service identity."""
        ...


# ---- audit and revocation -----------------------------------------------------

@runtime_checkable
class AuditSink(Protocol):
    def append(self, records: list) -> None:
        """Take audit records (spec/PORTING.md, "Audit record") in sequence
        order. Records already held are skipped. Raises SinkError, holding
        nothing new, when a sequence number is missing, when a record's `prev`
        is not the hash of the record before it, or when a record differs
        from the one already held under that sequence number."""
        ...

    def head(self) -> tuple | None:
        """(seq, hash) of the newest record held, or None when empty. Kept
        where the engine's host cannot change it, it is the anchor that shows
        a truncated or re-forged log."""
        ...


@dataclass(frozen=True)
class Revocation:
    """One revocation, taken from an audit record.

    seq      the audit record's sequence number; orders the feed
    kind     "token" (subject is a token id; everything derived from it dies too)
             or "user" (subject is a user id; every token issued up to `ts` dies)
    ts       when it was decided (for "user": the cut-off, `issued_up_to`)"""
    seq: int
    kind: str
    subject: str
    ts: int
    by: str | None = None

    def to_json(self) -> dict:
        return {"seq": self.seq, "kind": self.kind, "subject": self.subject, "ts": self.ts, "by": self.by}

    @classmethod
    def from_json(cls, v: dict) -> "Revocation":
        return cls(int(v["seq"]), str(v["kind"]), str(v["subject"]), int(v["ts"]), v.get("by"))


@runtime_checkable
class RevocationFeed(Protocol):
    def publish(self, events: list) -> None:
        """Add revocations. An event already published (same seq) is skipped. Raises FeedError on failure."""
        ...

    def poll(self, after: int = 0) -> list:
        """Every published event with seq > after, in seq order. Raises
        FeedError when the feed cannot be read: an empty list means "nothing
        was revoked", and must only ever mean that."""
        ...


#: name used on the command line -> the Protocol
INTERFACES = {"identity": IdentitySource, "directory": DirectorySource, "roles": RoleCatalog, "enforcement": EnforcementPoint,
              "runtime": AgentRuntime, "approval": ApprovalChannel, "audit": AuditSink, "revocation": RevocationFeed}
