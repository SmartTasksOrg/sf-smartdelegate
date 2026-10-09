"""Reference ApprovalChannels, and the pump that moves requests and verdicts
between the engine and a channel.

    ConsoleApprovalChannel   asks on a terminal (or any pair of functions)
    WebhookApprovalChannel   webhook-shaped stub: builds the JSON body an
                             outgoing webhook would carry and hands it to a
                             function you supply; the reply comes back through
                             `receive`. It opens no connection itself.

`approve` needs the admin key (or an in-process engine). The engine decides
who may approve: never the user the agent acts for (DELEGATE-SELF-APPROVAL),
and only someone a policy permits (DELEGATE-APPROVAL-DENIED). The identity in
`by` is the channel's statement: the engine does not authenticate the approver
(docs/THREAT_MODEL.md, threat 17). Authenticate the human in the channel.
"""
from __future__ import annotations

from ..contracts import ApprovalChannel, ApprovalRequest, Verdict


def payload_of(request: ApprovalRequest) -> dict:
    """What a human is shown. No token and no record values exist in it."""
    return {"type": "smartdelegate.approval_request", "approval_id": request.id, "label": request.label, "user": request.user,
            "agent": request.agent, "action": request.action, "resource": request.resource, "requested_at": request.requested_at}


def _verdict(approval_id: str, reply) -> Verdict | None:
    """A reply counts only when it says, in so many words, who approves or
    rejects. Anything else (None, a timeout, free text) is no verdict."""
    if not isinstance(reply, dict) or not isinstance(reply.get("approve"), bool) or not isinstance(reply.get("by"), str) or not reply["by"]:
        return None
    return Verdict(approval_id, reply["approve"], reply["by"])


class ConsoleApprovalChannel:
    def __init__(self, ask=None):
        """`ask(payload) -> {"approve": bool, "by": user} | None`. Default: prompt on the terminal."""
        self._ask, self._ready = ask or self._prompt, []

    @staticmethod
    def _prompt(payload: dict):
        print(f"Approval {payload['approval_id']} ({payload['label']}): agent {payload['agent']}, acting for {payload['user']}, "
              f"asks to {payload['action']} {payload['resource']}")
        by = input("Your user id (empty to skip): ").strip()
        answer = input("Approve? [y/N]: ").strip().lower() if by else ""
        return {"approve": answer == "y", "by": by} if by and answer in ("y", "n") else None

    def deliver(self, request: ApprovalRequest) -> None:
        v = _verdict(request.id, self._ask(payload_of(request)))
        if v is not None:
            self._ready.append(v)

    def verdicts(self) -> list:
        out, self._ready = self._ready, []
        return out


class WebhookApprovalChannel:
    def __init__(self, post):
        """`post(body: dict) -> None` sends the request wherever approvals
        are handled (chat, ticketing). Raise from it when delivery fails."""
        self._post, self._open, self._ready = post, set(), []

    def deliver(self, request: ApprovalRequest) -> None:
        self._post(payload_of(request))
        self._open.add(request.id)

    def receive(self, body) -> bool:
        """Call this from your webhook handler with the reply body
        {"approval_id", "approve", "by"}. Returns False, and records nothing,
        for a reply to a request this channel did not deliver or one that is
        not a clear verdict."""
        aid = body.get("approval_id") if isinstance(body, dict) else None
        v = _verdict(aid, body) if aid in self._open else None
        if v is None:
            return False
        self._open.discard(aid)
        self._ready.append(v)
        return True

    def verdicts(self) -> list:
        out, self._ready = self._ready, []
        return out


def pump(backend, channel: ApprovalChannel, delivered: set) -> dict:
    """One round: deliver held requests the channel has not seen (ids are
    remembered in `delivered`, which the caller keeps), then apply the
    verdicts that came back.

    Returns {"delivered", "approved", "rejected", "refused", "undelivered"}.
    `refused` lists verdicts the engine did not accept, with its error code
    (self_approval, approval_denied, unknown_approval); `undelivered` lists
    requests the channel raised on, which stay pending and are tried again in
    the next round. A verdict for a request that is not pending is ignored. A
    rejection is not sent to the engine: the request stays held until it
    expires with the token."""
    out = {"delivered": [], "approved": [], "rejected": [], "refused": [], "undelivered": []}
    listing = backend.call("approvals", {})
    if not listing.get("ok"):
        raise RuntimeError(f"approvals: {(listing.get('error') or {}).get('code')}")
    pending = listing["pending"]
    for aid, p in sorted(pending.items()):
        if aid in delivered:
            continue
        try:
            channel.deliver(ApprovalRequest(aid, p["label"], p["user"], p["agent"], p["action"], p["resource"], p.get("requested_at", 0)))
        except Exception:
            out["undelivered"].append(aid)
            continue
        delivered.add(aid)
        out["delivered"].append(aid)
    for v in channel.verdicts():
        if not isinstance(v, Verdict) or v.approval_id not in pending:
            continue
        if v.approve is not True:
            out["rejected"].append(v.approval_id)
            continue
        r = backend.call("approve", {"approval_id": v.approval_id, "by": v.by})
        if r.get("ok"):
            out["approved"].append(v.approval_id)
        else:
            out["refused"].append({"approval_id": v.approval_id, "by": v.by, "code": (r.get("error") or {}).get("code")})
    return out
