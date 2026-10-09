"""Operations shared by every backend. Each returns the engine's JSON result
as a dict; a result with ok == False raises SmartDelegateError."""
from __future__ import annotations

from typing import Any

from .errors import EngineError


# One error type for the engine and the clients. A deny is not an error: it
# is a normal result with effect == "deny".
SmartDelegateError = EngineError


class Backend:
    def call(self, op: str, payload: dict) -> dict:  # pragma: no cover - overridden
        raise NotImplementedError

    def _ok(self, op: str, payload: dict) -> dict:
        result = self.call(op, payload)
        if not result.get("ok"):
            err = result.get("error") or {}
            raise SmartDelegateError(err.get("code", "error"), err.get("message", "unknown error"))
        return result

    @staticmethod
    def _request(token, action, resource, id, attrs, context, extra) -> dict:
        res: dict[str, Any] = {"path": resource, "id": id if id is not None else "any"}
        if attrs:
            res["attrs"] = attrs
        body: dict[str, Any] = {"token": token, "action": action, "resource": res}
        if context:
            body["context"] = context
        body.update({k: v for k, v in extra.items() if v is not None})
        return body

    def authorize(self, token: str, action: str, resource: str, id: str | None = None, *, attrs: dict | None = None,
                  context: dict | None = None, fields: list[str] | None = None, dry_run: bool | None = None) -> dict:
        return self._ok("authorize", self._request(token, action, resource, id, attrs, context, {"fields": fields, "dry_run": dry_run}))

    def filter(self, token: str, action: str, resource: str, data: Any, id: str | None = None, *, attrs: dict | None = None,
               context: dict | None = None, strict: bool = False) -> dict:
        body = self._request(token, action, resource, id, attrs, context, {"strict": strict or None})
        body["data"] = data
        return self._ok("filter", body)

    def explain(self, token: str, action: str, resource: str, id: str | None = None, *, attrs: dict | None = None, context: dict | None = None) -> dict:
        return self._ok("explain", self._request(token, action, resource, id, attrs, context, {}))

    def apply_obligations(self, decision: dict, data: Any) -> dict:
        """Mask data that arrived after the decision (a tool result)."""
        return self._ok("apply_obligations", {"obligations": decision["obligations"], "data": data, "decision_id": decision.get("decision_id")})

    def issue_token(self, agent: str, cap: dict | None = None, *, user: str | None = None, id_token: str | None = None,
                    ttl: int | None = None, tenant: str | None = None, task: str | None = None, role: str | None = None,
                    groups: list | None = None) -> dict:
        """`role`: lend the agent a role the user holds; the token can never
        carry more than the role allows, and `cap` may then be omitted.
        `groups`: the user's live group membership, when the caller has it
        from the identity provider."""
        body = {"agent": agent, "cap": cap, "user": user, "id_token": id_token, "ttl": ttl, "tenant": tenant, "task": task,
                "role": role, "groups": groups}
        return self._ok("issue_token", {k: v for k, v in body.items() if v is not None})

    def exchange_token(self, subject_token: str, actor: str, *, cap: dict | None = None, ttl: int | None = None) -> dict:
        body = {"subject_token": subject_token, "actor": actor, "cap": cap, "ttl": ttl}
        return self._ok("exchange_token", {k: v for k, v in body.items() if v is not None})

    def inspect_token(self, token: str) -> dict:
        return self._ok("inspect_token", {"token": token})

    def revoke(self, token_id: str) -> dict:
        return self._ok("revoke", {"token_id": token_id})

    def revoke_user(self, user: str, by: str | None = None) -> dict:
        """End every token already issued for this human (and their agents'
        sub-agent tokens). Use it when a person is offboarded or loses a role."""
        return self._ok("revoke", {k: v for k, v in {"user": user, "by": by}.items() if v is not None})

    def approve(self, approval_id: str, by: str) -> dict:
        return self._ok("approve", {"approval_id": approval_id, "by": by})

    def info(self) -> dict:
        return self._ok("info", {})
