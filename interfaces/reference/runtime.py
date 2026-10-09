"""Reference AgentRuntime: framework-free, about sixty lines.

The task token lives in a contextvars.ContextVar, so concurrent tasks in one
process (threads, asyncio tasks) each see their own. A framework adapter does
three things with it: `begin_task` when a task starts, `call` for every tool
call, `spawn` when it starts a sub-agent.
"""
from __future__ import annotations

import contextvars

from sf_smartdelegate.backend import SmartDelegateError
from sf_smartdelegate.errors import rule_id

from ..contracts import Outcome, Refusal, SpawnRefused, ToolBinding
from .enforcement import AdapterEnforcementPoint


class SimpleRuntime:
    def __init__(self, backend, enforcement=None):
        self.backend = backend
        self.enforcement = enforcement or AdapterEnforcementPoint(backend)
        self._token: contextvars.ContextVar = contextvars.ContextVar("smartdelegate_task_token", default="")

    def begin_task(self, token: str) -> None:
        if not isinstance(token, str) or not token:
            raise ValueError("begin_task needs the task's capability token")
        self._token.set(token)

    def end_task(self) -> None:
        self._token.set("")

    def current_token(self) -> str:
        return self._token.get()

    def register(self, name: str, binding: ToolBinding, fn) -> None:
        self.enforcement.register(name, binding, fn)

    def call(self, name: str, arguments: dict) -> Outcome:
        return self.enforcement.invoke(self.current_token(), name, arguments)

    def spawn(self, actor: str, capability: dict | None = None, ttl: int | None = None) -> "SimpleRuntime":
        parent = self.current_token()
        if not parent:
            raise SpawnRefused(Refusal("token_invalid", rule_id("token_invalid"), "there is no task token to narrow"))
        try:
            grant = self.backend.exchange_token(parent, actor, cap=capability, ttl=ttl)
        except SmartDelegateError as e:      # widening, depth_exceeded, delegation_denied, token_revoked, daemon_unreachable ...
            raise SpawnRefused(Refusal(e.code, rule_id(e.code), e.message)) from None
        child = SimpleRuntime(self.backend, self.enforcement)      # same tools, its own token
        child.begin_task(grant["token"])
        return child
