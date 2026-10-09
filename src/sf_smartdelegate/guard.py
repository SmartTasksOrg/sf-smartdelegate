"""Middleware that puts a decision in front of an agent tool and masks what
the tool returns before it can reach the model."""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from .backend import Backend


class Denied(PermissionError):
    def __init__(self, decision: dict):
        super().__init__(f"denied by SmartDelegate ({decision.get('reason')}): {decision.get('detail', '')}")
        self.decision = decision
        self.reason = decision.get("reason")


class ApprovalRequired(Denied):
    """A human must approve; retry the same call once they have."""

    def __init__(self, decision: dict):
        super().__init__(decision)
        self.approval_id = (decision.get("approval") or {}).get("id")


def _pick(spec, args: dict):
    if spec is None:
        return None
    if callable(spec):
        return spec(args)
    return args.get(spec)


class Guard:
    def __init__(self, backend: Backend, token: Callable[[], str] | str):
        self.backend = backend
        self._token = token if callable(token) else (lambda: token)

    def check(self, action: str, resource: str, id: str | None = None, *, input: Any = None, attrs: dict | None = None, context: dict | None = None) -> dict:
        """Decide; raise Denied/ApprovalRequired on deny. `input` is record
        data the tool is about to write: it is checked strictly."""
        token = self._token()
        if input is not None:
            d = self.backend.filter(token, action, resource, input, id, attrs=attrs, context=context, strict=True)
        else:
            d = self.backend.authorize(token, action, resource, id, attrs=attrs, context=context)
        if d.get("effect") != "allow":
            raise ApprovalRequired(d) if d.get("reason") == "approval_required" else Denied(d)
        return d

    def tool(self, action: str, resource: str, id=None, *, input=None, spend=None, attrs=None, output: str = "filter"):
        """Decorator. `id`, `input`, `attrs` are an argument name or a function
        of the call's arguments. `spend` is a function returning
        (currency, amount_in_minor_units). `output="raw"` skips masking of the
        return value; use it only for tools that return no record data."""

        def wrap(fn):
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def inner(*a, **kw):
                bound = sig.bind(*a, **kw)
                bound.apply_defaults()
                args = dict(bound.arguments)
                context = None
                if spend is not None:
                    currency, amount = spend(args)
                    context = {"spend": {"currency": currency, "amount": int(amount)}}
                d = self.check(action, resource, _pick(id, args), input=_pick(input, args), attrs=_pick(attrs, args), context=context)
                result = fn(*a, **kw)
                if output == "raw" or result is None:
                    return result
                return self.backend.apply_obligations(d, result)["data"]

            inner.__smartdelegate__ = {"action": action, "resource": resource}
            return inner

        return wrap
