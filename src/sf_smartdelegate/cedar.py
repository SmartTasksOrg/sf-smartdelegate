"""Evaluator for Cedar's JSON policy form (the portable subset).

Policies are written in Cedar and compiled to JSON by the Cedar toolchain
(`smartdelegate bundle compile` in the Rust port). This module evaluates that JSON
directly. What it must do is fixed by spec/conformance/eval/cases.json, whose
expected answers come from the real Cedar engine. spec/POLICY_SUBSET.md lists
what is in the subset; anything outside it is refused when the bundle loads.

Semantics that are easy to get wrong, all covered by the eval cases:
  * a policy whose condition errors is skipped and reported, permit or forbid
  * `&&` / `||` short-circuit, but the side that is evaluated must be boolean
  * `==` across types is false; `<` across types is an error
  * arithmetic is 64-bit and overflow is an error
  * sets ignore order and duplicates
  * an entity missing from the store has no attributes (`.` errors, `has` is
    false) and is `in` only itself
"""
from __future__ import annotations

import re
from typing import Any

I64_MIN, I64_MAX = -(2**63), 2**63 - 1
_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$")

BINARY = {"==", "!=", "<", "<=", ">", ">=", "&&", "||", "+", "-", "*", "in", "contains", "containsAll", "containsAny"}
UNARY = {"!", "neg", "isEmpty"}


class EvalError(Exception):
    """A policy condition could not be evaluated. The policy is skipped."""


class Unsupported(Exception):
    """The policy uses Cedar that is outside the portable subset."""


class Entity(tuple):
    """An entity reference: (type, id)."""

    __slots__ = ()

    def __new__(cls, type_: str, id_: str):
        return super().__new__(cls, (type_, id_))

    def __str__(self) -> str:
        return f'{self[0]}::"{self[1]}"'


class CedarSet:
    """A Cedar set: unordered, no duplicates, any element types."""

    __slots__ = ("items",)

    def __init__(self, values):
        self.items = {key(v): v for v in values}


def key(v: Any):
    """A hashable identity for a value; equal values have equal keys."""
    if isinstance(v, bool):
        return ("b", v)
    if isinstance(v, int):
        return ("l", v)
    if isinstance(v, str):
        return ("s", v)
    if isinstance(v, Entity):
        return ("e", v[0], v[1])
    if isinstance(v, CedarSet):
        return ("set", frozenset(v.items))
    if isinstance(v, dict):
        return ("rec", tuple(sorted((k, key(x)) for k, x in v.items())))
    raise EvalError(f"not a Cedar value: {v!r}")


def valid_type(name: str) -> bool:
    return isinstance(name, str) and bool(_TYPE.fullmatch(name))


def from_json(v: Any) -> Any:
    """JSON -> Cedar value, for entity attributes, context and literals.
    Lists are sets; {"__entity": {type, id}} is an entity reference."""
    if isinstance(v, bool) or isinstance(v, str):
        return v
    if isinstance(v, int):
        if not I64_MIN <= v <= I64_MAX:
            raise ValueError("integer does not fit in 64 bits")
        return v
    if isinstance(v, float):
        raise ValueError("floating-point numbers are not Cedar values")
    if v is None:
        raise ValueError("null is not a Cedar value")
    if isinstance(v, list):
        return CedarSet(from_json(x) for x in v)
    if isinstance(v, dict):
        if "__entity" in v:
            e = v["__entity"]
            if len(v) != 1 or not isinstance(e, dict) or not valid_type(e.get("type")) or not isinstance(e.get("id"), str):
                raise ValueError("malformed __entity reference")
            return Entity(e["type"], e["id"])
        if "__extn" in v:
            raise ValueError("extension values (decimal, ip, datetime) are outside the portable subset")
        return {k: from_json(x) for k, x in v.items()}
    raise ValueError(f"not a JSON value: {type(v).__name__}")


class Store:
    """Entities: attributes and transitive ancestors."""

    def __init__(self, entities_json: list | None = None):
        self.attrs: dict[Entity, dict] = {}
        self.parents: dict[Entity, list[Entity]] = {}
        self._ancestors: dict[Entity, frozenset] = {}
        for e in entities_json or []:
            self.add(e)

    @staticmethod
    def _uid(u) -> Entity:
        if isinstance(u, dict) and "__entity" in u:
            u = u["__entity"]
        if not isinstance(u, dict) or not valid_type(u.get("type")) or not isinstance(u.get("id"), str):
            raise ValueError(f"malformed entity uid: {u!r}")
        return Entity(u["type"], u["id"])

    def add(self, e: dict) -> Entity:
        uid = self._uid(e.get("uid"))
        if uid in self.attrs:
            raise ValueError(f"duplicate entity {uid}")
        attrs = e.get("attrs") or {}
        if not isinstance(attrs, dict):
            raise ValueError(f"{uid}: attrs must be an object")
        self.attrs[uid] = {k: from_json(v) for k, v in attrs.items()}
        self.parents[uid] = [self._uid(p) for p in e.get("parents") or []]
        self._ancestors.clear()
        return uid

    def overlay(self, extra: list) -> "Store":
        """A store with request-scoped entities added. The base is not changed."""
        s = Store()
        s.attrs = dict(self.attrs)
        s.parents = dict(self.parents)
        for e in extra:
            s.add(e)
        return s

    def with_parents(self, uid: Entity, parents: list) -> "Store":
        """A store in which `uid` has exactly these parents (and its stored
        attributes, if any). Used for live group membership carried by a token."""
        s = Store()
        s.attrs = dict(self.attrs)
        s.parents = dict(self.parents)
        s.attrs.setdefault(uid, {})
        s.parents[uid] = list(parents)
        return s

    def __contains__(self, uid: Entity) -> bool:
        return uid in self.attrs

    def ancestors(self, uid: Entity) -> frozenset:
        got = self._ancestors.get(uid)
        if got is None:
            seen: set = set()
            stack = list(self.parents.get(uid, ()))
            while stack:
                p = stack.pop()
                if p not in seen:
                    seen.add(p)
                    stack.extend(self.parents.get(p, ()))
            got = self._ancestors[uid] = frozenset(seen)
        return got

    def is_in(self, child: Entity, ancestor: Entity) -> bool:
        return child == ancestor or ancestor in self.ancestors(child)


# ---- loading: reject anything outside the subset ---------------------------

def _entity_lit(e) -> Entity:
    if isinstance(e, dict) and "__entity" in e:
        e = e["__entity"]
    if not isinstance(e, dict) or not valid_type(e.get("type")) or not isinstance(e.get("id"), str):
        raise Unsupported(f"malformed entity in policy scope: {e!r}")
    return Entity(e["type"], e["id"])


def _check_expr(e) -> None:
    if not isinstance(e, dict) or len(e) != 1:
        raise Unsupported(f"malformed expression: {str(e)[:80]}")
    (op, arg), = e.items()
    if op == "Value":
        try:
            from_json(arg)
        except ValueError as err:
            raise Unsupported(str(err)) from None
    elif op == "Var":
        if arg not in ("principal", "action", "resource", "context"):
            raise Unsupported(f"unknown variable {arg!r}")
    elif op in BINARY:
        _check_expr(arg["left"])
        _check_expr(arg["right"])
    elif op in UNARY:
        _check_expr(arg["arg"])
    elif op in (".", "has"):
        _check_expr(arg["left"])
        if not isinstance(arg.get("attr"), str):
            raise Unsupported("attribute name must be a string")
    elif op == "is":
        _check_expr(arg["left"])
        if not valid_type(arg.get("entity_type")):
            raise Unsupported("malformed entity type in `is`")
        if "in" in arg:
            _check_expr(arg["in"])
    elif op == "like":
        _check_expr(arg["left"])
        if not isinstance(arg["pattern"], list):
            raise Unsupported("malformed like pattern")
        for part in arg["pattern"]:
            if part != "Wildcard" and not (isinstance(part, dict) and isinstance(part.get("Literal"), str)):
                raise Unsupported("malformed like pattern")
    elif op == "if-then-else":
        for k in ("if", "then", "else"):
            _check_expr(arg[k])
    elif op == "Set":
        if not isinstance(arg, list):
            raise Unsupported("a Set literal must be a list")
        for x in arg:
            _check_expr(x)
    elif op == "Record":
        if not isinstance(arg, dict):
            raise Unsupported("a Record literal must be an object")
        for x in arg.values():
            _check_expr(x)
    else:
        raise Unsupported(f"`{op}` is outside the portable Cedar subset")


def _check_scope(scope, what: str) -> None:
    op = scope.get("op") if isinstance(scope, dict) else None
    if "slot" in (scope or {}):
        raise Unsupported("policy templates are not supported")
    if op == "All":
        return
    if op == "==":
        _entity_lit(scope.get("entity"))
    elif op == "in":
        if "entities" in scope:
            if what != "action":
                raise Unsupported(f"{what} scope cannot use a list")
            if not isinstance(scope["entities"], list):
                raise Unsupported("scope entities must be a list")
            for x in scope["entities"]:
                _entity_lit(x)
        else:
            _entity_lit(scope.get("entity"))
    elif op == "is" and what != "action":
        if not valid_type(scope.get("entity_type")):
            raise Unsupported("malformed entity type in scope")
        if "in" in scope:
            _entity_lit(scope["in"].get("entity"))
    else:
        raise Unsupported(f"unsupported {what} scope: {scope!r}")


class Policy:
    __slots__ = ("id", "permit", "principal", "action", "resource", "conditions", "annotations")

    def __init__(self, pid: str, est: dict):
        try:
            if est.get("effect") not in ("permit", "forbid"):
                raise Unsupported("effect must be permit or forbid")
            for what in ("principal", "action", "resource"):
                _check_scope(est.get(what), what)
            if not isinstance(est, dict) or not isinstance(est.get("conditions", []), list):
                raise Unsupported("malformed policy JSON")
            if not isinstance(est.get("annotations") or {}, dict):
                raise Unsupported("annotations must be an object")
            for c in est.get("conditions", []):
                if c.get("kind") not in ("when", "unless"):
                    raise Unsupported("condition must be when or unless")
                _check_expr(c.get("body"))
        except (KeyError, TypeError, AttributeError) as err:
            raise Unsupported(f"malformed policy JSON ({err})") from None
        self.id = pid
        self.permit = est["effect"] == "permit"
        self.principal, self.action, self.resource = est["principal"], est["action"], est["resource"]
        self.conditions = est.get("conditions", [])
        self.annotations = dict(est.get("annotations") or {})
        for k, v in self.annotations.items():
            if v is None:
                self.annotations[k] = ""


# ---- evaluation ------------------------------------------------------------

class Env:
    __slots__ = ("principal", "action", "resource", "context", "store")

    def __init__(self, principal: Entity, action: Entity, resource: Entity, context: dict, store: Store):
        self.principal, self.action, self.resource, self.context, self.store = principal, action, resource, context, store


def _bool(v, what: str) -> bool:
    if not isinstance(v, bool):
        raise EvalError(f"{what} must be a boolean")
    return v


def _long(v, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise EvalError(f"{what} must be a long")
    return v


def _checked(n: int) -> int:
    if not I64_MIN <= n <= I64_MAX:
        raise EvalError("integer overflow")
    return n


def _set(v, what: str) -> CedarSet:
    if not isinstance(v, CedarSet):
        raise EvalError(f"{what} must be a set")
    return v


def _like(s: str, pattern: list) -> bool:
    # classic wildcard match with backtracking to the last star
    i = j = 0
    star = mark = -1
    while i < len(s):
        if j < len(pattern) and pattern[j] != "Wildcard" and pattern[j]["Literal"] == s[i]:
            i += 1
            j += 1
        elif j < len(pattern) and pattern[j] == "Wildcard":
            star, mark = j, i
            j += 1
        elif star != -1:
            j = star + 1
            mark += 1
            i = mark
        else:
            return False
    while j < len(pattern) and pattern[j] == "Wildcard":
        j += 1
    return j == len(pattern)


def evaluate(e: dict, env: Env) -> Any:
    (op, a), = e.items()
    if op == "Value":
        return from_json(a)
    if op == "Var":
        return getattr(env, a)
    if op == "&&":
        if not _bool(evaluate(a["left"], env), "left of &&"):
            return False
        return _bool(evaluate(a["right"], env), "right of &&")
    if op == "||":
        if _bool(evaluate(a["left"], env), "left of ||"):
            return True
        return _bool(evaluate(a["right"], env), "right of ||")
    if op == "if-then-else":
        return evaluate(a["then"] if _bool(evaluate(a["if"], env), "if condition") else a["else"], env)
    if op == "!":
        return not _bool(evaluate(a["arg"], env), "operand of !")
    if op == "neg":
        return _checked(-_long(evaluate(a["arg"], env), "operand of -"))
    if op == "isEmpty":
        return not _set(evaluate(a["arg"], env), "isEmpty receiver").items
    if op == ".":
        left = evaluate(a["left"], env)
        attr = a["attr"]
        if isinstance(left, Entity):
            if left not in env.store:
                raise EvalError(f"entity {left} does not exist")
            rec = env.store.attrs[left]
        elif isinstance(left, dict):
            rec = left
        else:
            raise EvalError("attribute access needs an entity or a record")
        if attr not in rec:
            raise EvalError(f"no attribute `{attr}`")
        return rec[attr]
    if op == "has":
        left = evaluate(a["left"], env)
        if isinstance(left, Entity):
            return a["attr"] in env.store.attrs.get(left, {})
        if isinstance(left, dict):
            return a["attr"] in left
        raise EvalError("`has` needs an entity or a record")
    if op == "is":
        left = evaluate(a["left"], env)
        if not isinstance(left, Entity):
            raise EvalError("`is` needs an entity")
        if left[0] != a["entity_type"]:
            return False
        if "in" in a:
            return _in(left, evaluate(a["in"], env), env)
        return True
    if op == "like":
        left = evaluate(a["left"], env)
        if not isinstance(left, str):
            raise EvalError("`like` needs a string")
        return _like(left, a["pattern"])
    if op == "Set":
        return CedarSet(evaluate(x, env) for x in a)
    if op == "Record":
        return {k: evaluate(x, env) for k, x in a.items()}

    left = evaluate(a["left"], env)
    right = evaluate(a["right"], env)
    if op == "==":
        return key(left) == key(right)
    if op == "!=":
        return key(left) != key(right)
    if op in ("<", "<=", ">", ">="):
        x, y = _long(left, f"left of {op}"), _long(right, f"right of {op}")
        return x < y if op == "<" else x <= y if op == "<=" else x > y if op == ">" else x >= y
    if op in ("+", "-", "*"):
        x, y = _long(left, f"left of {op}"), _long(right, f"right of {op}")
        return _checked(x + y if op == "+" else x - y if op == "-" else x * y)
    if op == "in":
        if not isinstance(left, Entity):
            raise EvalError("left of `in` must be an entity")
        return _in(left, right, env)
    if op == "contains":
        return key(right) in _set(left, "contains receiver").items
    if op == "containsAll":
        have, want = _set(left, "containsAll receiver").items, _set(right, "containsAll argument").items
        return all(k in have for k in want)
    if op == "containsAny":
        have, want = _set(left, "containsAny receiver").items, _set(right, "containsAny argument").items
        return any(k in have for k in want)
    raise EvalError(f"unsupported operator {op}")


def _in(left: Entity, right, env: Env) -> bool:
    if isinstance(right, Entity):
        return env.store.is_in(left, right)
    if isinstance(right, CedarSet):
        for x in right.items.values():
            if not isinstance(x, Entity):
                raise EvalError("right of `in` must be an entity or a set of entities")
        return any(env.store.is_in(left, x) for x in right.items.values())
    raise EvalError("right of `in` must be an entity or a set of entities")


def _scope(scope: dict, who: Entity, store: Store) -> bool:
    op = scope["op"]
    if op == "All":
        return True
    if op == "==":
        return who == _entity_lit(scope["entity"])
    if op == "in":
        if "entities" in scope:
            return any(store.is_in(who, _entity_lit(x)) for x in scope["entities"])
        return store.is_in(who, _entity_lit(scope["entity"]))
    if who[0] != scope["entity_type"]:  # op == "is"
        return False
    return "in" not in scope or store.is_in(who, _entity_lit(scope["in"]["entity"]))


def applies(p: Policy, env: Env) -> bool:
    """True when the policy's scope and every condition hold. Raises EvalError."""
    if not (_scope(p.principal, env.principal, env.store) and _scope(p.action, env.action, env.store) and _scope(p.resource, env.resource, env.store)):
        return False
    for c in p.conditions:
        v = _bool(evaluate(c["body"], env), f"`{c['kind']}` condition")
        if v != (c["kind"] == "when"):
            return False
    return True


def is_authorized(policies: dict[str, Policy], env: Env) -> dict:
    """Cedar's authorization: {"decision", "reasons", "errors": [(id, message)]}.
    A satisfied forbid denies. Otherwise a satisfied permit allows. Otherwise deny."""
    permits, forbids, errors = [], [], []
    for pid in sorted(policies):
        p = policies[pid]
        try:
            if applies(p, env):
                (permits if p.permit else forbids).append(pid)
        except EvalError as err:
            errors.append((pid, str(err)))
    if forbids:
        return {"decision": "deny", "reasons": forbids, "errors": errors}
    if permits:
        return {"decision": "allow", "reasons": permits, "errors": errors}
    return {"decision": "deny", "reasons": [], "errors": errors}
