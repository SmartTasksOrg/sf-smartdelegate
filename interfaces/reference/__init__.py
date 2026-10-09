"""Reference implementations of interfaces.contracts, each a thin wrapper
around what the package already has, and the factories the contract kit calls.

A factory is what you pass to `python -m interfaces.contract`: the kit calls
it with the arguments listed in interfaces/README.md and checks what comes back.
"""
from __future__ import annotations

from pathlib import Path

from .approval import ConsoleApprovalChannel, WebhookApprovalChannel, pump
from .audit import FileRevocationFeed, JsonlAuditSink, apply_revocations, revocations_from_audit, ship
from .directory import ScimDirectorySource, sync_directory
from .enforcement import AdapterEnforcementPoint
from .identity import JwksIdentitySource
from .roles import FileRoleCatalog
from .runtime import SimpleRuntime

__all__ = ["JwksIdentitySource", "ScimDirectorySource", "sync_directory", "FileRoleCatalog", "AdapterEnforcementPoint", "SimpleRuntime",
           "ConsoleApprovalChannel", "WebhookApprovalChannel", "pump", "JsonlAuditSink", "FileRevocationFeed", "ship",
           "revocations_from_audit", "apply_revocations", "FACTORIES"]


def identity(issuer: str, audience: str, jwks: dict, groups_claim: str, group_map: dict):
    return JwksIdentitySource(issuer, audience, jwks, groups_claim=groups_claim, group_map=group_map)


def directory(fault: str | None = None):
    from ..contract import fake_scim
    return ScimDirectorySource(fake_scim.BASE, fake_scim.TOKEN_ENV, transport=fake_scim.transport(fault), env=fake_scim.ENV)


def roles(bundle_dir: str):
    return FileRoleCatalog(bundle_dir)


def enforcement(backend, tools: dict):
    return AdapterEnforcementPoint(backend, tools)


def runtime(backend):
    return SimpleRuntime(backend)


def approval(human):
    return ConsoleApprovalChannel(ask=human)


def approval_webhook(human):
    """The webhook-shaped channel with the human wired straight to it: what
    is posted is shown to `human`, whose reply comes back through `receive`."""
    channel = WebhookApprovalChannel(lambda body: replies.append((body, human(body))))
    replies: list = []
    deliver = channel.deliver

    def deliver_and_receive(request):
        deliver(request)
        body, reply = replies.pop()
        channel.receive(dict(reply, approval_id=body["approval_id"]) if isinstance(reply, dict) else reply)

    channel.deliver = deliver_and_receive
    return channel


def audit(location: str):
    return JsonlAuditSink(Path(location) / "audit-copy.jsonl")


def revocation(location: str):
    return FileRevocationFeed(Path(location) / "revocations.jsonl")


#: interface name -> factory of the reference implementation
FACTORIES = {"identity": identity, "directory": directory, "roles": roles, "enforcement": enforcement, "runtime": runtime,
             "approval": approval, "audit": audit, "revocation": revocation}
