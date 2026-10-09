#!/usr/bin/env python3
"""SmartDelegate integration adapter: the one framework-free piece every
wrapper in this folder uses.

    from adapter import Adapter, ToolSpec, delegate_for_task

    grant = delegate_for_task(engine, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
    adapter = Adapter(engine, token=lambda: grant.token)
    spec = ToolSpec(action="read", resource="crm.customer", id="customer_id")
    record = adapter.call(spec, get_customer, {"customer_id": "c-1"})   # masked

One call does four things, in this order:

  1. authorize   the request is decided by the engine (or the daemon). When the
                 spec names an `input` argument, that argument is record data
                 and is checked in strict mode: a field the principal may not
                 use denies the call instead of being dropped silently.
  2. run         the tool runs only after an allow.
  3. filter      what the tool returned is passed through the decision's
                 obligations before the caller (the model) sees it.
  4. deny        a refusal is raised as sf_smartdelegate.guard.Denied (or
                 ApprovalRequired); `Denial.of(exc)` gives the structured form:
                 reason, rule id (DELEGATE-*), detail, approval id.

`backend` is a smartdelegate.Engine (in-process) or a smartdelegate.DaemonClient.
In-process checks bind an agent that cooperates. The boundary an agent cannot
skip is a proxy (`smartdelegate http-proxy`, `smartdelegate mcp-proxy`).

Quick check, no framework needed:  python integrations/adapter.py --demo
"""
from __future__ import annotations

import functools
import inspect
import json
from dataclasses import dataclass
from typing import Any, Callable

from sf_smartdelegate import core
from sf_smartdelegate.backend import Backend, SmartDelegateError
from sf_smartdelegate.errors import rule_id
from sf_smartdelegate.guard import ApprovalRequired, Denied, Guard
from sf_smartdelegate.mcpproxy import WITHHELD
from sf_smartdelegate.models import Capability, Grant
from sf_smartdelegate.tokens import Cap, matches

__all__ = ["Adapter", "ToolSpec", "Denial", "Result", "TaskToken", "Denied", "ApprovalRequired", "WITHHELD",
           "delegate_for_task", "spend_from", "could_use", "bind_arguments"]

#: Codes this layer produces itself. Everything else comes from the engine.
INVALID_ARGUMENTS = "invalid_arguments"   # the call's arguments cannot be turned into a request
UNKNOWN_TOOL = "unknown_tool"             # a dispatcher was asked for a tool with no spec (default deny)
TOOL_FAILED = "tool_failed"               # the tool raised; its message is withheld (it can echo record data)


# ---- what a tool is, to the engine -------------------------------------------

@dataclass(frozen=True)
class ToolSpec:
    """How one tool maps onto an engine request.

    action    the action name policies use ("read", "create", ...)
    resource  the catalog path ("crm.customer")
    id        the name of the argument that holds the resource id, or a
              function of the arguments. None: the id is "any".
    input     the name of the argument (or a function of the arguments) that
              holds record data the tool is about to write. It is checked in
              strict mode.
    spend     a function of the arguments returning (currency, amount in
              minor units); see `spend_from`. Triggers the budget check.
    attrs     resource attributes for policy: an argument name or a function.
    output    "filter" (default) masks the return value. "raw" skips masking;
              use it only for tools that return no record data.
    """
    action: str
    resource: str
    id: str | Callable[[dict], Any] | None = None
    input: str | Callable[[dict], Any] | None = None
    spend: Callable[[dict], tuple] | None = None
    attrs: str | Callable[[dict], Any] | None = None
    output: str = "filter"

    def __post_init__(self):
        if not isinstance(self.action, str) or not self.action or not isinstance(self.resource, str) or not self.resource:
            raise ValueError("ToolSpec needs an action and a resource path")
        if self.output not in ("filter", "raw"):
            raise ValueError("ToolSpec.output must be 'filter' or 'raw'")

    @classmethod
    def of(cls, v: "ToolSpec | dict") -> "ToolSpec":
        if isinstance(v, cls):
            return v
        if isinstance(v, dict):
            return cls(**v)
        raise TypeError("a tool spec is a ToolSpec or a dict with the same keys")


def spend_from(currency: str, amount: str, *, literal_currency: bool = False) -> Callable[[dict], tuple]:
    """A spend extractor reading two arguments by name:
    `spend_from("currency", "amount")`. With `literal_currency=True` the first
    value is the currency itself: `spend_from("EUR", "amount", literal_currency=True)`."""
    def extract(args: dict) -> tuple:
        return (currency if literal_currency else args.get(currency)), args.get(amount)
    return extract


def _pick(spec, args: dict):
    if spec is None:
        return None
    if callable(spec):
        return spec(args)
    return args.get(spec)


# ---- the structured denial ---------------------------------------------------

@dataclass(frozen=True)
class Denial:
    """A refusal in a form a caller can branch on and a model can read."""
    reason: str
    rule: str
    detail: str = ""
    approval_id: str | None = None
    decision_id: str | None = None

    @classmethod
    def from_decision(cls, d: dict) -> "Denial":
        reason = str(d.get("reason") or "deny")
        return cls(reason, str(d.get("rule") or rule_id(reason)), str(d.get("detail") or ""),
                   (d.get("approval") or {}).get("id"), d.get("decision_id"))

    @classmethod
    def of(cls, exc: BaseException) -> "Denial":
        """From guard.Denied / ApprovalRequired, or from an engine error."""
        if isinstance(exc, Denied):
            return cls.from_decision(exc.decision)
        if isinstance(exc, SmartDelegateError):
            return cls(exc.code, rule_id(exc.code), exc.message)
        raise TypeError(f"not a SmartDelegate refusal: {type(exc).__name__}")

    def to_json(self) -> dict:
        """The same shape the HTTP proxy answers a denied call with."""
        err: dict = {"code": self.reason, "rule": self.rule, "message": self.detail, "by": "smartdelegate"}
        if self.decision_id:
            err["decision_id"] = self.decision_id
        if self.approval_id:
            err["approval"] = {"id": self.approval_id}
        return {"error": err}

    def text(self) -> str:
        """One line for a model, worded like the MCP proxy's denials."""
        out = f"Denied by SmartDelegate ({self.reason}, {self.rule}): {self.detail or 'not permitted'}."
        if self.approval_id:
            out += f" A human can approve it with id {self.approval_id}; then retry the same call."
        return out


def _refusal(code: str, message: str) -> Denied:
    """A request the engine could not process is never an allow: it is
    raised as a denial too, with the error code as the reason."""
    return Denied({"effect": "deny", "reason": code, "rule": rule_id(code), "detail": message})


@dataclass(frozen=True)
class Result:
    """What `Adapter.try_call` returns instead of raising."""
    ok: bool
    value: Any = None
    denial: Denial | None = None


# ---- the current task token --------------------------------------------------

class TaskToken:
    """A holder for the token of the task in hand. Set it when a task starts;
    the adapter reads it on every call.

        current = TaskToken()
        adapter = Adapter(engine, current)
        current.set(delegate_for_task(engine, ...))

    One holder is one task at a time. A process that runs several tasks
    concurrently passes its own function (for example one that reads a
    contextvars.ContextVar) instead."""

    def __init__(self, token=None):
        self._token = ""
        self.set(token)

    def set(self, token) -> None:
        self._token = _token_text(token)

    def clear(self) -> None:
        self._token = ""

    def __call__(self) -> str:
        return self._token


def _token_text(token) -> str:
    if token is None:
        return ""
    if isinstance(token, str):
        return token
    if isinstance(token, Grant):
        return token.token
    if isinstance(token, dict) and isinstance(token.get("token"), str):
        return token["token"]       # the JSON result of issue_token / exchange_token
    raise TypeError("a token is a string, a Grant, or the result of issue_token")


def delegate_for_task(backend, *, agent: str, role: str, task: str | None = None, user: str | None = None,
                      capability: Capability | dict | None = None, groups: list | None = None, id_token: str | None = None,
                      ttl: int | None = None, tenant: str | None = None) -> Grant:
    """A human lends `agent` one role they hold, for one task. A thin wrapper
    over sf_smartdelegate.core.delegate that insists on a role, so the token can
    never carry more than the role allows.

    Raises EngineError: unknown_role, role_not_held, role_exceeded,
    delegation_denied, ... Over a DaemonClient this needs the admin key (or an
    `id_token`)."""
    if not role:
        raise ValueError("delegate_for_task needs a role; use sf_smartdelegate.core.delegate for a bare capability")
    return core.delegate(backend, user=user, agent=agent, role=role, task=task, capability=capability, groups=groups,
                         id_token=id_token, ttl=ttl, tenant=tenant)


# ---- could this capability ever use that tool? -------------------------------

def could_use(cap: Cap, spec: ToolSpec | dict) -> bool:
    """False when no call of this tool can pass the capability check,
    whatever its arguments. True does not mean a call will be allowed: policy,
    budget and approval are decided per call."""
    spec = ToolSpec.of(spec)
    if not cap.allows_action(spec.action):
        return False
    if spec.id is None:
        return cap.allows_resource(spec.resource, "any")
    base = spec.resource + "/"
    for p in cap.resources:
        if p.endswith("*"):
            prefix = p[:-1]
            if prefix.startswith(base) or base.startswith(prefix):
                return True
        elif p.startswith(base) and len(p) > len(base):
            return True
    return False


def _check_on_deny(on_deny: str) -> None:
    if on_deny not in ("raise", "return"):
        raise ValueError("on_deny must be 'raise' or 'return'")


def bind_arguments(fn: Callable[..., Any], args: tuple, kwargs: dict) -> dict:
    """The call's arguments by parameter name, defaults included, so a spec
    can say id="customer_id" however the framework passed the value. A
    function whose signature cannot be read gets its keyword arguments only."""
    try:
        sig = inspect.signature(fn)
        bound = sig.bind(*args, **kwargs)
    except (TypeError, ValueError):
        return dict(kwargs)
    bound.apply_defaults()
    out: dict = {}
    for name, value in bound.arguments.items():
        if sig.parameters[name].kind is inspect.Parameter.VAR_KEYWORD:
            out.update(value)
        else:
            out[name] = value
    return out


# ---- the adapter -------------------------------------------------------------

class Adapter:
    def __init__(self, backend: Backend, token: Callable[[], Any] | Any = None):
        """`token`: the current task token: a string, a Grant, or a function
        returning either (called on every use, so it can change per task)."""
        if not isinstance(backend, Backend):
            raise TypeError("backend must be a smartdelegate.Engine or a smartdelegate.DaemonClient")
        self.backend = backend
        self._token = token if callable(token) else (lambda: token)
        self.guard = Guard(backend, self.token)

    def token(self) -> str:
        return _token_text(self._token())

    # -- the four steps --------------------------------------------------------
    def authorize(self, spec: ToolSpec | dict, arguments: dict | None = None) -> dict:
        """Step 1. Returns the allow decision; raises Denied / ApprovalRequired."""
        spec = ToolSpec.of(spec)
        args = dict(arguments or {})
        try:
            rid = _pick(spec.id, args)
            if rid is not None and not isinstance(rid, str):
                rid = str(rid) if isinstance(rid, int) and not isinstance(rid, bool) else self._bad("the resource id must be a string")
            data = _pick(spec.input, args)
            if spec.input is not None and not isinstance(data, (dict, list)):
                self._bad("the record data this tool writes must be an object or a list of objects")
            attrs = _pick(spec.attrs, args)
            if attrs is not None and not isinstance(attrs, dict):
                self._bad("resource attributes must be an object")
            context = None
            if spec.spend is not None:
                pair = spec.spend(args)
                currency, amount = pair if isinstance(pair, (tuple, list)) and len(pair) == 2 else (None, None)
                if not isinstance(currency, str) or not currency or not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
                    self._bad("this tool spends money: it needs a currency and a non-negative integer amount in minor units")
                context = {"spend": {"currency": currency, "amount": amount}}
        except Denied:
            raise
        except Exception as e:      # an extractor that fails must not become an allow
            raise _refusal(INVALID_ARGUMENTS, f"the call's arguments could not be read ({type(e).__name__})") from None
        try:
            return self.guard.check(spec.action, spec.resource, rid, input=data, attrs=attrs, context=context)
        except SmartDelegateError as e:
            raise _refusal(e.code, e.message) from None

    @staticmethod
    def _bad(message: str):
        raise _refusal(INVALID_ARGUMENTS, message)

    def filter_output(self, spec: ToolSpec | dict, decision: dict, result: Any) -> Any:
        """Step 3. A dict or a list of dicts is masked. A string that holds
        JSON is parsed, masked and written back as JSON. Anything else has no
        field identity, so it is replaced by a notice (fail closed) unless the
        spec says output="raw"."""
        spec = ToolSpec.of(spec)
        if spec.output == "raw" or result is None:
            return result
        as_text = isinstance(result, str)
        data = result
        if as_text:
            try:
                data = json.loads(result)
            except (ValueError, RecursionError):
                return WITHHELD
        if isinstance(data, tuple):
            data = list(data)
        if not isinstance(data, (dict, list)):
            return WITHHELD
        try:
            masked = self.backend.apply_obligations(decision, data)["data"]
        except SmartDelegateError as e:
            raise _refusal(e.code, e.message) from None
        return json.dumps(masked, ensure_ascii=False) if as_text else masked

    def call(self, spec: ToolSpec | dict, fn: Callable[..., Any], arguments: dict | None = None) -> Any:
        """Authorize, run `fn(**arguments)`, return its masked result."""
        decision = self.authorize(spec, arguments)
        return self.filter_output(spec, decision, fn(**(arguments or {})))

    async def acall(self, spec: ToolSpec | dict, fn: Callable[..., Any], arguments: dict | None = None) -> Any:
        """`call` for an async tool. The decision itself is synchronous: with
        a DaemonClient it blocks for one HTTP round trip."""
        decision = self.authorize(spec, arguments)
        return self.filter_output(spec, decision, await fn(**(arguments or {})))

    def try_call(self, spec: ToolSpec | dict, fn: Callable[..., Any], arguments: dict | None = None) -> Result:
        """`call` that returns the denial instead of raising it. An exception
        raised by the tool itself still propagates."""
        try:
            return Result(True, self.call(spec, fn, arguments))
        except Denied as e:
            return Result(False, None, Denial.of(e))

    def wrap(self, spec: ToolSpec | dict, fn: Callable[..., Any], on_deny: str = "raise") -> Callable[..., Any]:
        """`fn` with the four steps around it. The wrapper takes the same
        positional and keyword arguments as `fn`; they are bound to parameter
        names so the spec can refer to them. on_deny="return" gives the
        model-readable denial text back instead of raising."""
        spec = ToolSpec.of(spec)
        _check_on_deny(on_deny)

        @functools.wraps(fn)
        def inner(*args, **kwargs):
            try:
                decision = self.authorize(spec, bind_arguments(fn, args, kwargs))
                return self.filter_output(spec, decision, fn(*args, **kwargs))
            except Denied as e:
                if on_deny == "raise":
                    raise
                return Denial.of(e).text()

        inner.__smartdelegate__ = {"action": spec.action, "resource": spec.resource}
        return inner

    def awrap(self, spec: ToolSpec | dict, fn: Callable[..., Any], on_deny: str = "raise") -> Callable[..., Any]:
        """`wrap` for an async function."""
        spec = ToolSpec.of(spec)
        _check_on_deny(on_deny)

        @functools.wraps(fn)
        async def inner(*args, **kwargs):
            try:
                decision = self.authorize(spec, bind_arguments(fn, args, kwargs))
                return self.filter_output(spec, decision, await fn(*args, **kwargs))
            except Denied as e:
                if on_deny == "raise":
                    raise
                return Denial.of(e).text()

        inner.__smartdelegate__ = {"action": spec.action, "resource": spec.resource}
        return inner

    def tool(self, spec: ToolSpec | dict, on_deny: str = "raise") -> Callable:
        """Decorator form of `wrap`: `@adapter.tool(ToolSpec(...))`."""
        return lambda fn: self.wrap(spec, fn, on_deny)

    # -- what the current token is ----------------------------------------------
    def whoami(self) -> dict:
        """inspect_token for the current token: {"valid", "user", "chain", "claims", ...}."""
        token = self.token()
        if not token:
            return {"ok": True, "valid": False, "reason": "token_invalid", "detail": "no capability token was presented"}
        return self.backend.inspect_token(token)

    def capability(self) -> Cap | None:
        """The current token's capability, or None when the token is not valid."""
        info = self.whoami()
        return Cap.from_json(info["claims"]["cap"]) if info.get("valid") else None

    def visible(self, specs: dict) -> list:
        """Names of the tools the current token's capability could ever use.
        A tool whose action or resource the capability does not cover is left
        out; with no valid token the list is empty."""
        cap = self.capability()
        if cap is None:
            return []
        return [name for name, spec in specs.items() if could_use(cap, spec)]


# keep the pattern rule importable from here for wrappers that want it
pattern_matches = matches


def _demo() -> int:
    engine = core.open_engine()
    crm = {"c-1": {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU",
                   "notes": "threatened to churn"}}
    grant = delegate_for_task(engine, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
    adapter = Adapter(engine, grant)
    read = ToolSpec("read", "crm.customer", id="customer_id")
    refund = ToolSpec("create", "billing.refund", id="order_id", spend=spend_from("currency", "amount"))
    out = {
        "token": {"user": grant.user, "chain": grant.chain, "role": grant.role},
        "read_customer": adapter.call(read, lambda customer_id: crm[customer_id], {"customer_id": "c-1"}),
        "refund_150_eur": adapter.try_call(refund, lambda **kw: {"order_id": kw["order_id"]},
                                           {"order_id": "o-1", "currency": "EUR", "amount": 15000}).denial.to_json(),
        "visible_tools": adapter.visible({"read_customer": read, "refund": refund, "read_salary": ToolSpec("read", "hr.salary", id="employee")}),
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--demo"]:
        raise SystemExit(_demo())
    print(__doc__)
    raise SystemExit(0 if sys.argv[1:] in ([], ["--help"], ["-h"]) else 1)
