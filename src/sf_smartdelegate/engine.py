"""The engine: one object that issues and exchanges capability tokens,
answers authorization requests, applies field obligations and writes the
audit log. This is the reference implementation; spec/conformance/vectors
defines its behaviour and every other port must match it.

Decision order for `authorize` / `filter` (first failure wins, default deny):
  1. token: signature, issuer, expiry, revocation (own id and every ancestor)
  2. catalog: the resource path must be known
  3. tenant: token tenant must equal the resource tenant, when both exist
  4. capability: the token's `cap` must cover the action and the resource
  5. policy: Cedar, forbid overrides permit, an erroring forbid denies
  6. obligations from the permits that decided: row filter, rate limit
  7. budget: `context.spend` against every token in the delegation chain
  8. human approval, last so nobody is asked to approve a doomed request
  9. fields: capability deny lists, then policy per field (default deny)
 10. strict mode (inputs): any denied field present in the data denies
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from . import __version__, audit, bundle, cedar, fields, tokens
from .backend import Backend
from .canon import hash_value, sha256_hex
from .errors import EngineError, rule_id
from .state import State
from .tokens import Cap

if os.name == "nt":  # pragma: no cover - not exercised on Linux
    import msvcrt
else:
    import fcntl

_COLUMN = re.compile(r"^[A-Za-z0-9_]+$")


class _Deny(Exception):
    def __init__(self, code: str, detail: str):
        self.code, self.detail = code, detail


class _Principal:
    def __init__(self, user, chain, tenant, task, jti, anc, cap: Cap, exp, role=None, groups=None):
        self.user, self.chain, self.tenant, self.task = user, chain, tenant, task
        self.jti, self.anc, self.cap, self.exp = jti, anc, cap, exp
        #: budgets of ancestor tokens, as carried by the token: {token id: {currency: amount}}
        self.lim: dict = {}
        #: the role the human is acting in for this task, or None
        self.role = role
        #: live group membership [{type, id}] that replaces entities.json for
        #: this user, or None to use entities.json
        self.groups = groups

    @property
    def leaf(self) -> str:
        return self.chain[-1] if self.chain else ""

    def to_json(self) -> dict:
        return {"user": self.user, "agent": self.leaf, "chain": self.chain, "tenant": self.tenant,
                "task": self.task, "role": self.role, "token_id": self.jti}

    @classmethod
    def of(cls, claims: dict) -> "_Principal":
        p = cls(tokens.user_of(claims), tokens.chain_of(claims), claims.get("tnt"), claims.get("task"),
                claims["jti"], list(claims.get("anc") or []), Cap.from_json(claims["cap"]), claims["exp"],
                claims.get("role"), claims.get("grp"))
        p.lim = dict(claims.get("lim") or {})
        return p


class _Outcome:
    def __init__(self):
        self.allow = False
        self.reason = ""
        self.detail = ""
        self.policies: list = []
        self.principal: _Principal | None = None
        self.mask: fields.Mask | None = None
        self.field_allow: list = []
        self.field_deny: list = []
        self.field_redact: list = []
        self.row_filter: list = []
        self.rate: list = []            # (key, limit, window)
        self.rate_limit: dict | None = None
        self.approval: dict | None = None
        self.approved: tuple | None = None
        self.spend: tuple | None = None
        self.errors: list = []
        self.trace: list = []


def _s(v, key):
    x = v.get(key) if isinstance(v, dict) else None
    return x if isinstance(x, str) and x else None


def _req(v, key) -> str:
    x = _s(v, key)
    if x is None:
        raise EngineError("invalid_input", f"'{key}' is required")
    return x


def _int(v, key, default):
    x = v.get(key)
    return x if isinstance(x, int) and not isinstance(x, bool) else default


def _entity(type_: str, id_: str) -> cedar.Entity:
    if not cedar.valid_type(type_):
        raise EngineError("invalid_input", f"'{type_}' is not a valid entity type")
    return cedar.Entity(type_, id_)


def _lookup(root, dotted: str):
    cur = root
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True


def _parse_row_filter(expr: str, ctx: dict) -> list:
    """`column == context.key`, `column == "literal"`, `column == 42`, joined by `&&`."""
    out = []
    for clause in expr.split("&&"):
        parts = [p.strip() for p in clause.split("==", 1)]
        if len(parts) != 2 or not _COLUMN.match(parts[0]):
            raise _Deny("policy_error", f"row_filter clause '{clause.strip()}' is not `column == value`")
        rhs = parts[1]
        if rhs.startswith("context."):
            value, found = _lookup(ctx, rhs[8:])
            if not found or isinstance(value, (dict, list, float)) or value is None:
                raise _Deny("obligation_unresolved", f"row filter needs {rhs}, which the request did not supply")
        elif len(rhs) >= 2 and rhs[0] == '"' and rhs[-1] == '"':
            value = rhs[1:-1]
        elif re.match(r"^-?\d+$", rhs):
            value = int(rhs)
        else:
            raise _Deny("policy_error", f"row_filter value '{rhs}' is not context.<key>, a quoted string or an integer")
        out.append({"column": parts[0], "op": "eq", "value": value})
    return out


def _parse_rate(expr: str):
    m = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s*$", expr or "")
    if not m or int(m.group(2)) <= 0:
        return None
    return int(m.group(1)), int(m.group(2))


class Engine(Backend):
    """config: {"bundle_dir", "state_dir", "issuer", "mode", ...}; see spec/API.md.

    One engine is safe to share between threads; calls are serialised. Engines
    in different processes that share a state directory are serialised by a
    lock file in it."""

    def __init__(self, config: dict):
        if not isinstance(config, dict):
            raise EngineError("invalid_input", "config must be an object")
        c = config
        self.bundle_dir = Path(_req(c, "bundle_dir"))
        self.state_dir = Path(c["state_dir"]) if _s(c, "state_dir") else None
        self.issuer = _s(c, "issuer") or "smartdelegate://local"
        mode = _s(c, "mode") or "enforce"
        if mode not in ("enforce", "shadow"):
            raise EngineError("invalid_config", "mode must be 'enforce' or 'shadow'")
        self.shadow = mode == "shadow"
        self.trust_caller_chain = c.get("trust_caller_chain") is True
        self.allow_test_clock = c.get("allow_test_clock") is True
        self.bundle_public_key = _s(c, "bundle_public_key")
        self.max_ttl = _int(c, "max_ttl", 3600)
        self.default_ttl = _int(c, "default_ttl", 900)
        self.max_depth = _int(c, "max_depth", 4)
        self.approval_ttl = _int(c, "approval_ttl", 900)
        self.require_role = c.get("require_role") is True
        self.idp = None
        idp = c.get("idp")
        if isinstance(idp, dict):
            jwks = idp.get("jwks")
            if not isinstance(jwks, dict):
                try:
                    jwks = json.loads(Path(_req(idp, "jwks_file")).read_text(encoding="utf-8"))
                except EngineError:
                    raise
                except Exception as e:
                    raise EngineError("invalid_config", f"jwks_file: {e}") from None
            gmap = idp.get("group_map")
            if gmap is not None and not (isinstance(gmap, dict) and all(isinstance(x, str) for x in gmap.values())):
                raise EngineError("invalid_config", "idp.group_map must map a claim value to a group id")
            gtype = _s(idp, "group_type") or "Group"
            if not cedar.valid_type(gtype):
                raise EngineError("invalid_config", "idp.group_type is not a valid entity type")
            self.idp = {"issuer": _req(idp, "issuer"), "audience": _req(idp, "audience"), "jwks": jwks,
                        "user_claim": _s(idp, "user_claim") or "sub", "groups_claim": _s(idp, "groups_claim"),
                        "jwks_file": _s(idp, "jwks_file") if not isinstance(idp.get("jwks"), dict) else None,
                        "group_type": gtype, "group_map": gmap}

        self.bundle = bundle.Bundle(self.bundle_dir, self.bundle_public_key)
        if self.state_dir:
            try:
                self.state_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise EngineError("state_io", f"{self.state_dir}: {e}") from None

        private = None
        if c.get("verify_only") is True:
            pass
        elif _s(c, "signing_key"):
            private = c["signing_key"]
        elif self.state_dir:
            kp = self.state_dir / "signing_key.pk8.b64"
            if kp.exists():
                private = self._read_key(kp)
            else:
                private, public = bundle.keygen()
                # Two engines can start on an empty state directory at once.
                # Write the key to a private temporary file and hard-link it
                # into place: the link either creates the key or fails because
                # the other engine already did, and nobody reads half a key.
                tmp = self.state_dir / f".signing_key.{os.getpid()}.{secrets.token_hex(4)}.tmp"
                try:
                    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        f.write(private)
                    try:
                        os.link(tmp, kp)
                        (self.state_dir / "signing_key.pub.b64").write_text(public, encoding="utf-8")
                    except FileExistsError:
                        private = self._read_key(kp)
                    except OSError:
                        # a file system without hard links: fall back to exclusive create
                        try:
                            fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                            with os.fdopen(fd, "w", encoding="utf-8") as f:
                                f.write(private)
                            (self.state_dir / "signing_key.pub.b64").write_text(public, encoding="utf-8")
                        except FileExistsError:
                            private = self._read_key(kp)
                except OSError as e:
                    raise EngineError("state_io", f"{kp}: {e.strerror or e}") from None
                finally:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
        else:
            private = bundle.keygen()[0]
        trusted = [k for k in (c.get("trusted_keys") or []) if isinstance(k, str)]
        self.keys = tokens.Keys(private, trusted)

        self._lock_file = open(self.state_dir / "lock", "a+b") if self.state_dir else None
        self._mutex = threading.RLock()
        try:
            with self._locked():
                self.state = State(self.state_dir)
                self.audit = audit.AuditLog(self.state_dir / "audit.jsonl") if (self.state_dir and c.get("audit", True) is not False) else None
        except BaseException:
            self.close()
            raise
        self._rate: dict = {}
        self._counter = 0

    @staticmethod
    def _read_key(kp: Path) -> str:
        """The signing key file. An empty file means another process is still
        writing it: wait for the content. An empty key is never read as "no
        key", which would silently turn an issuer into a verify-only engine."""
        deadline = time.monotonic() + 30
        while True:
            try:
                text = kp.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeDecodeError) as e:
                raise EngineError("state_io", f"{kp}: {e}") from None
            if text:
                return text
            if time.monotonic() > deadline:
                raise EngineError("state_io", f"{kp} is empty")
            time.sleep(0.05)

    # -- plumbing --------------------------------------------------------------
    class _Guard:
        def __init__(self, engine):
            self.e = engine

        def __enter__(self):
            self.e._mutex.acquire()
            f = self.e._lock_file
            if f is not None:
                try:
                    if os.name == "nt":  # pragma: no cover
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                    else:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                except OSError as e:
                    self.e._mutex.release()
                    raise EngineError("state_io", f"cannot lock the state directory: {e}") from None

        def __exit__(self, *exc):
            f = self.e._lock_file
            try:
                if f is not None:
                    if os.name == "nt":  # pragma: no cover
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            finally:
                self.e._mutex.release()

    def _locked(self):
        return Engine._Guard(self)

    def close(self) -> None:
        if getattr(self, "_lock_file", None) is not None:
            self._lock_file.close()
            self._lock_file = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def call(self, op: str, payload: Any) -> dict:
        """JSON in, JSON out. Never raises on bad input; errors come back as
        {"ok": false, "error": {"code", "message"}}."""
        try:
            with self._locked():
                if not isinstance(payload, dict):
                    raise EngineError("invalid_input", "the request body must be a JSON object")
                self.state.refresh()
                out = self._dispatch(op, payload)
                out["ok"] = True
                return out
        except EngineError as e:
            return e.to_json()
        except RecursionError:
            return EngineError("invalid_input", "the request is nested too deeply").to_json()
        except OSError as e:
            return EngineError("state_io", str(e)).to_json()
        except Exception as e:  # a bug must surface as a refusal, never as an allow or a crash
            return EngineError("internal", f"{type(e).__name__}: {e}").to_json()

    def _dispatch(self, op: str, i: dict) -> dict:
        if op == "authorize":
            return self._decide(i, False)
        if op == "filter":
            return self._decide(i, True)
        if op == "explain":
            j = dict(i, explain=True, dry_run=True)
            return self._decide(j, "data" in i)
        if op == "issue_token":
            return self._issue_token(i)
        if op == "exchange_token":
            return self._exchange_token(i)
        if op == "inspect_token":
            return self._inspect_token(i)
        if op == "apply_obligations":
            return self._apply_obligations(i)
        if op == "revoke":
            return self._revoke(i)
        if op == "approve":
            return self._approve(i)
        if op == "approvals":
            return {"pending": self.state.data["pending"], "granted": self.state.data["approvals"]}
        if op == "audit_verify":
            if self.audit is None:
                raise EngineError("no_audit", "this engine has no audit log (no state_dir, or audit is off)")
            if not self.audit.path.exists():
                return {"records": 0, "head": audit.GENESIS}
            return audit.verify(self.audit.path)
        if op == "audit_tail":
            if self.audit is None:
                raise EngineError("no_audit", "this engine has no audit log")
            return {"records": audit.tail(self.audit.path, _int(i, "n", 20))}
        if op == "info":
            return self.info_dict()
        if op == "reload":
            # a bundle that fails to load leaves the old one in force
            new_bundle = bundle.Bundle(self.bundle_dir, self.bundle_public_key)
            # the provider's signing keys are re-read too, so a key rotation
            # needs a reload, not a restart; a file that fails to load leaves
            # the old keys in force
            if self.idp and self.idp.get("jwks_file"):
                try:
                    jwks = json.loads(Path(self.idp["jwks_file"]).read_text(encoding="utf-8"))
                    assert isinstance(jwks, dict) and isinstance(jwks.get("keys"), list)
                except Exception as e:
                    raise EngineError("invalid_config", f"jwks_file: {e}") from None
                self.idp["jwks"] = jwks
            self.bundle = new_bundle
            self._audit({"event": "bundle_reloaded", "policy_version": self.bundle.version}, int(time.time()))
            return self.info_dict()
        raise EngineError("unknown_op", f"no operation named '{op}'")

    def info_dict(self) -> dict:
        return {"version": __version__, "implementation": "python", "policy_version": self.bundle.version,
                "bundle_signed_by": self.bundle.signed_by, "policies": len(self.bundle.policies),
                "resources": sorted(self.bundle.catalog), "roles": sorted(self.bundle.roles), "mode": "shadow" if self.shadow else "enforce",
                "issuer": self.issuer, "key_id": self.keys.kid, "public_key": self.keys.public_b64,
                "can_issue": self.keys.can_sign(), "oidc": self.idp["issuer"] if self.idp else None}

    def _now(self, i: dict) -> int:
        n = i.get("now")
        if self.allow_test_clock and isinstance(n, int) and not isinstance(n, bool):
            return n
        return int(time.time())

    def _audit(self, record: dict, ts: int) -> None:
        """Fail closed: when the decision cannot be recorded, the operation
        fails and the caller gets an error instead of an allow."""
        if self.audit is not None:
            try:
                self.audit.append(record, ts)
            except EngineError as e:
                raise EngineError("audit_io", f"the decision could not be recorded, so it is refused: {e.message}") from None

    # -- tokens ----------------------------------------------------------------
    def _verify_token(self, token: str, now: int) -> dict:
        """Raises _Deny; `claims` is attached when the signature was good, so
        an expired or revoked token's denial can still be attributed."""
        try:
            claims = self.keys.verify(token, self.issuer)
        except ValueError as e:
            raise _Deny("token_invalid", str(e)) from None
        d = None
        if not tokens.chain_of(claims):
            raise _Deny("token_invalid", "the token names no agent")
        if claims["exp"] <= now:
            d = _Deny("token_expired", "the capability token has expired")
        elif claims["iat"] > now + 60:
            d = _Deny("token_invalid", "the capability token is dated in the future")
        else:
            for tid in list(claims["anc"]) + [claims["jti"]]:
                if tid in self.state.data["revoked"]:
                    d = _Deny("token_revoked", f"token {tid} in the delegation chain was revoked")
                    break
            # offboarding: every token of this user issued up to the cut-off is dead
            cutoff = self.state.data["revoked_users"].get(tokens.user_of(claims))
            if d is None and isinstance(cutoff, int) and not isinstance(cutoff, bool) and claims["iat"] <= cutoff:
                d = _Deny("token_revoked", "every token issued for this user up to the cut-off was revoked")
        if d is not None:
            d.claims = claims
            raise d
        return claims

    def _iam_context(self, p: _Principal) -> dict:
        return {
            "user_attrs": self.bundle.attrs.get(f"User::{p.user}", {}),
            "user": {"__entity": {"type": "User", "id": p.user}},
            "user_id": p.user,
            "chain": list(p.chain),
            "depth": len(p.chain),
            "root_agent": {"__entity": {"type": "Agent", "id": p.chain[0] if p.chain else ""}},
            "tenant": p.tenant or "",
            "task": p.task or "",
            "role": p.role or "",
        }

    def _store_for(self, p: _Principal) -> cedar.Store:
        """The entity store this principal is judged against. A token that
        carries live group membership replaces what entities.json says about
        that user; everything else is unchanged."""
        if p.groups is None:
            return self.bundle.store
        return self.bundle.store.with_parents(cedar.Entity("User", p.user), [cedar.Entity(g["type"], g["id"]) for g in p.groups])

    def _groups(self, raw, default_type: str, mapping: dict | None) -> list:
        """Normalise group membership supplied at issuance: names or {type,
        id}. Groups that entities.json does not define are dropped; the result
        is sorted and free of duplicates, so every port writes the same claim."""
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            raise EngineError("invalid_input", "groups must be a list of group names or {type, id}")
        out = set()
        for g in raw:
            if isinstance(g, str):
                if mapping is not None:
                    if g not in mapping:
                        continue
                    g = mapping[g]
                t, n = default_type, g
            elif isinstance(g, dict) and isinstance(g.get("type"), str) and isinstance(g.get("id"), str):
                t, n = g["type"], g["id"]
            else:
                raise EngineError("invalid_input", "groups must be a list of group names or {type, id}")
            if cedar.valid_type(t) and cedar.Entity(t, n) in self.bundle.store:
                out.add((t, n))
        return [{"type": t, "id": n} for t, n in sorted(out)]

    def _apply_role(self, name: str, p: _Principal, cap: Cap | None, ttl: int) -> tuple:
        """The human lends the agent one of their roles for this task. Returns
        the capability and lifetime the token gets; raises when the human does
        not hold the role or asks for more than the role allows."""
        role = self.bundle.roles.get(name)
        if role is None:
            raise EngineError("unknown_role", f"roles.json defines no role named '{name}'")
        user = cedar.Entity("User", p.user)
        store = self._store_for(p)
        held = store.ancestors(user) | {user}
        if not any(m in held for m in role.members):
            raise EngineError("role_not_held", f"user '{p.user}' does not hold the role '{name}'")
        if role.agents is not None and not any(tokens.matches(a, p.leaf) for a in role.agents):
            raise EngineError("role_exceeded", f"agent '{p.leaf}' may not be started in the role '{name}'")
        if role.tasks is not None and not (p.task and any(tokens.matches(t, p.task) for t in role.tasks)):
            raise EngineError("role_exceeded", f"the role '{name}' covers only tasks matching: {', '.join(role.tasks)}")
        if cap is None:
            cap = Cap.from_json(role.cap.to_json())
        else:
            # what the role never sees, the token never sees
            cap.deny_labels = sorted(set(cap.deny_labels) | set(role.cap.deny_labels))
            cap.deny_fields = sorted(set(cap.deny_fields) | set(role.cap.deny_fields))
            try:
                cap.check_narrower_than(role.cap)
            except EngineError as e:
                why = e.message.replace("the parent token", "the role").replace("the parent's", "the role's").replace("by the parent", "by the role")
                raise EngineError("role_exceeded", f"more than the role '{name}' allows: {why}") from None
        return cap, (min(ttl, role.max_ttl) if role.max_ttl else ttl)

    def _evaluate(self, principal: cedar.Entity, action: str, resource: cedar.Entity, ctx, store: cedar.Store) -> dict:
        r = cedar.is_authorized(self.bundle.policies, cedar.Env(principal, _entity("Action", action), resource, ctx, store))
        errors, forbid_error = [], False
        for pid, msg in r["errors"]:
            is_forbid = not self.bundle.policies[pid].permit
            forbid_error = forbid_error or is_forbid
            errors.append({"policy": pid, "effect": "forbid" if is_forbid else "permit", "error": msg})
        return {"allow": r["decision"] == "allow" and not forbid_error, "policies": r["reasons"],
                "errors": errors, "forbid_error": forbid_error}

    def _check_delegation(self, delegator: cedar.Entity, agent: str, p: _Principal, cap: Cap, ttl: int) -> None:
        """Is `delegator` allowed to hand `cap` to `agent`? Governed by the
        same policies as everything else: action "delegate" on the Agent."""
        agent_uid = _entity("Agent", agent)
        if agent_uid not in self.bundle.store:
            raise EngineError("unknown_agent", f"agent '{agent}' is not registered in entities.json")
        try:
            ctx = cedar.from_json({"iam": self._iam_context(p),
                                   "requested": {"actions": cap.actions, "resources": cap.resources, "ttl": ttl, "budget": cap.budget}})
        except ValueError as e:
            raise EngineError("invalid_input", str(e)) from None
        v = self._evaluate(delegator, "delegate", agent_uid, ctx, self._store_for(p))
        if not v["allow"]:
            why = "no policy permits it" if not v["policies"] else "forbidden by " + ", ".join(v["policies"])
            raise EngineError("delegation_denied", f"{delegator} may not delegate to agent '{agent}': {why}")

    @staticmethod
    def _parse_cap(i: dict):
        if i.get("cap") is None:
            return None
        cap = Cap.from_json(i["cap"])
        cap.validate()
        return cap

    def _mint(self, claims: dict, event: str, now: int) -> dict:
        claims["jti"] = secrets.token_hex(12)
        token = self.keys.sign(claims)
        cap = claims["cap"]
        if cap["budget"]:
            self.state.data["limits"][claims["jti"]] = dict(cap["budget"])
            self.state.prune(now)
            self.state.save()
        user, chain = tokens.user_of(claims), tokens.chain_of(claims)
        self._audit({"event": event, "token_id": claims["jti"], "user": user, "chain": chain, "tenant": claims.get("tnt"),
                     "task": claims.get("task"), "role": claims.get("role"), "ancestors": claims["anc"], "exp": claims["exp"], "cap": cap,
                     "policy_version": self.bundle.version}, now)
        return {"token": token, "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
                "token_id": claims["jti"], "expires_at": claims["exp"], "expires_in": claims["exp"] - now,
                "user": user, "chain": chain, "role": claims.get("role"), "task": claims.get("task"), "cap": cap}

    def _ttl(self, i: dict) -> int:
        return max(1, min(_int(i, "ttl", self.default_ttl), self.max_ttl))

    def _issue_token(self, i: dict) -> dict:
        now = self._now(i)
        idt = _s(i, "id_token")
        if idt:
            if not self.idp:
                raise EngineError("no_idp", "no OIDC provider is configured")
            claims = tokens.verify_id_token(idt, self.idp["jwks"], self.idp["issuer"], self.idp["audience"], now)
            user = claims.get(self.idp["user_claim"])
            if not isinstance(user, str) or not user:
                raise EngineError("id_token_invalid", f"ID token has no '{self.idp['user_claim']}' claim")
            if _s(i, "user") and i["user"] != user:
                raise EngineError("id_token_invalid", "the ID token belongs to a different user")
            # Offboarding also covers sign-ins that happened before it: an ID
            # token issued at or before the user's revoke cut-off cannot start
            # a new agent, however long the provider says it lives.
            cutoff = self.state.data["revoked_users"].get(user)
            if isinstance(cutoff, int) and not isinstance(cutoff, bool):
                iat = claims.get("iat")
                if not isinstance(iat, int) or isinstance(iat, bool) or iat <= cutoff:
                    raise EngineError("id_token_invalid", "the ID token was issued before this user was revoked; sign in again")
            groups = None
            if self.idp["groups_claim"]:
                # the identity provider is the authority on what this human
                # is a member of right now; a missing claim means "of nothing".
                # A dotted name reads a nested claim (Keycloak: realm_access.roles).
                raw = claims.get(self.idp["groups_claim"])
                if raw is None and "." in self.idp["groups_claim"]:
                    raw, found = _lookup(claims, self.idp["groups_claim"])
                    raw = raw if found else None
                try:
                    groups = self._groups([] if raw is None else raw, self.idp["group_type"], self.idp["group_map"])
                except EngineError:
                    raise EngineError("id_token_invalid", f"the '{self.idp['groups_claim']}' claim is not a list of group names") from None
        else:
            user = _req(i, "user")
            groups = self._groups(i["groups"], "Group", None) if i.get("groups") is not None else None
        agent = _req(i, "agent")
        cap = self._parse_cap(i)
        role = _s(i, "role")
        if role is None and self.require_role:
            raise EngineError("role_required", "this engine issues tokens only for a named role")
        if cap is None and role is None:
            raise EngineError("invalid_cap", "'cap' is required: a root token must state what it may do")
        ttl = self._ttl(i)
        p = _Principal(user, [agent], _s(i, "tenant"), _s(i, "task"), None, [], cap, now + ttl, role, groups)
        if role is not None:
            cap, ttl = self._apply_role(role, p, cap, ttl)
            p.cap, p.exp = cap, now + ttl
        self._check_delegation(_entity("User", user), agent, p, cap, ttl)
        claims = {"iss": self.issuer, "aud": tokens.AUDIENCE, "sub": f"user:{user}", "iat": now, "exp": now + ttl, "jti": "",
                  "act": tokens.act_for(p.chain), "anc": [], "cap": cap.to_json()}
        if p.tenant:
            claims["tnt"] = p.tenant
        if p.task:
            claims["task"] = p.task
        if role is not None:
            claims["role"] = role
        if groups is not None:
            claims["grp"] = groups
        return self._mint(claims, "token_issued", now)

    def _exchange_token(self, i: dict) -> dict:
        now = self._now(i)
        try:
            parent = self._verify_token(_req(i, "subject_token"), now)
        except _Deny as d:
            raise EngineError(d.code, d.detail) from None
        pp = _Principal.of(parent)
        actor = _req(i, "actor")
        if len(pp.chain) >= self.max_depth:
            raise EngineError("depth_exceeded", f"delegation chains are limited to {self.max_depth} agents")
        cap = self._parse_cap(i) or pp.cap
        cap.check_narrower_than(pp.cap)
        exp = min(now + self._ttl(i), parent["exp"])
        if _s(i, "task") and pp.task and i["task"] != pp.task:
            raise EngineError("widening", "a sub-agent token cannot change the task it was issued for")
        if _s(i, "role") and i["role"] != pp.role:
            raise EngineError("widening", "a sub-agent token cannot change the role it was issued for")
        self._check_delegation(_entity("Agent", pp.leaf), actor, pp, cap, exp - now)
        chain = pp.chain + [actor]
        claims = {"iss": self.issuer, "aud": tokens.AUDIENCE, "sub": parent["sub"], "iat": now, "exp": exp, "jti": "",
                  "act": tokens.act_for(chain), "anc": list(parent["anc"]) + [parent["jti"]], "cap": cap.to_json()}
        if parent.get("tnt"):
            claims["tnt"] = parent["tnt"]
        task = pp.task or _s(i, "task")
        if task:
            claims["task"] = task
        if pp.role is not None:
            claims["role"] = pp.role
        if pp.groups is not None:
            claims["grp"] = pp.groups
        # every ancestor's budget travels with the token (see the budget check)
        lim = dict(parent.get("lim") or {})
        if pp.cap.budget:
            lim[parent["jti"]] = dict(pp.cap.budget)
        if lim:
            claims["lim"] = lim
        return self._mint(claims, "token_exchanged", now)

    def _inspect_token(self, i: dict) -> dict:
        now = self._now(i)
        try:
            c = self._verify_token(_req(i, "token"), now)
        except _Deny as d:
            return {"valid": False, "reason": d.code, "detail": d.detail}
        return {"valid": True, "claims": c, "chain": tokens.chain_of(c), "user": tokens.user_of(c), "expires_in": c["exp"] - now}

    def _revoke(self, i: dict) -> dict:
        now = self._now(i)
        if "user" in i:
            # Offboarding, or a human who lost a role: one call ends every
            # token already issued for them, sub-agents included. New tokens
            # are a matter of role membership, not of this list.
            user = i["user"]
            if not isinstance(user, str) or not user:
                raise EngineError("invalid_input", "'user' must be a non-empty string")
            # the cut-off only ever moves forward: a clock that steps back (or a
            # second machine with a slower clock) must not revive dead tokens
            prev = self.state.data["revoked_users"].get(user)
            cutoff = max(now, prev) if isinstance(prev, int) and not isinstance(prev, bool) else now
            self.state.data["revoked_users"][user] = cutoff
            self.state.save()
            self._audit({"event": "user_revoked", "user": user, "issued_up_to": cutoff, "by": _s(i, "by")}, now)
            return {"revoked_user": user, "issued_up_to": cutoff}
        t = _s(i, "token")
        if t:
            try:
                c = self.keys.verify(t, self.issuer)
            except ValueError as e:
                raise EngineError("token_invalid", str(e)) from None
            tid, exp = c["jti"], c["exp"]
        else:
            tid, exp = _req(i, "token_id"), now + self.max_ttl
        self.state.data["revoked"][tid] = exp
        self.state.save()
        self._audit({"event": "token_revoked", "token_id": tid, "by": _s(i, "by")}, now)
        return {"revoked": tid}

    def _approve(self, i: dict) -> dict:
        now = self._now(i)
        aid, by = _req(i, "approval_id"), _req(i, "by")
        pending = self.state.data["pending"].get(aid)
        if pending is None:
            raise EngineError("unknown_approval", "no pending request with that approval id")
        if pending["user"] == by:
            raise EngineError("self_approval", "the user an agent acts for cannot approve that agent's request")
        # who may approve is itself policy: action "approve" on the agent
        ctx = cedar.from_json({"label": pending["label"], "for_user": pending["user"], "action": pending["action"]})
        v = self._evaluate(_entity("User", by), "approve", _entity("Agent", pending["agent"]), ctx, self.bundle.store)
        if not v["allow"]:
            raise EngineError("approval_denied", f"no policy lets '{by}' approve this request")
        del self.state.data["pending"][aid]
        exp = now + _int(i, "ttl", self.approval_ttl)
        self.state.data["approvals"][aid] = {"by": by, "exp": exp}
        self.state.save()
        self._audit({"event": "approval_granted", "approval_id": aid, "by": by, "label": pending["label"],
                     "for_user": pending["user"], "agent": pending["agent"], "action": pending["action"],
                     "resource": pending["resource"]}, now)
        return {"approved": aid, "by": by, "expires_at": exp}

    def _apply_obligations(self, i: dict) -> dict:
        """Apply the obligations of an earlier decision to data that arrived
        later. Pure: it authorises nothing by itself."""
        ob = i.get("obligations")
        if not isinstance(ob, dict):
            raise EngineError("invalid_input", "'obligations' from a decision is required")
        if "data" not in i:
            raise EngineError("invalid_input", "'data' is required")
        f = ob.get("fields")
        if not isinstance(f, dict):
            raise EngineError("invalid_input", "obligations.fields is missing; only an allow decision carries a field mask")
        names = lambda k: [x for x in (f.get(k) or []) if isinstance(x, str)] if isinstance(f.get(k), list) else []
        status = {}
        for n in names("allow"):
            status[n] = fields.ALLOW
        for n in names("deny"):
            status[n] = fields.DENY
        for n in names("redact"):
            status[n] = fields.REDACT
        rf = ob.get("row_filter") if isinstance(ob.get("row_filter"), list) else []
        data, masked, dropped = fields.apply(i["data"], fields.Mask(status), [c for c in rf if isinstance(c, dict)])
        did = _s(i, "decision_id")
        if did:
            self._audit({"event": "obligations_applied", "decision_id": did, "masked": masked, "rows_dropped": dropped}, self._now(i))
        return {"data": data, "masked": masked, "rows_dropped": dropped}

    # -- decisions ---------------------------------------------------------------
    def _evaluate_request(self, i: dict, now: int, dry_run: bool) -> _Outcome:
        o = _Outcome()
        try:
            self._steps(o, i, now, dry_run)
        except _Deny as d:
            o.reason, o.detail = d.code, d.detail
            o.trace.append({"check": d.code, "result": "deny", "detail": d.detail})
        return o

    def _steps(self, o: _Outcome, i: dict, now: int, dry_run: bool) -> None:
        def passed(check, msg):
            o.trace.append({"check": check, "result": "pass", "detail": msg})

        action = _req(i, "action")
        res = i.get("resource")
        if not isinstance(res, dict):
            raise EngineError("invalid_input", "'resource' must be an object with a 'path'")
        path = _req(res, "path")
        rid = _s(res, "id") or "any"
        caller_ctx = i.get("context")
        if caller_ctx is None:
            caller_ctx = {}
        if not isinstance(caller_ctx, dict):
            raise EngineError("invalid_context", "'context' must be an object")
        if "iam" in caller_ctx:
            raise EngineError("invalid_context", "'iam' is reserved: identity comes from the token, not from the caller")

        # 1. principal
        token, chain = _s(i, "token"), i.get("chain")
        if token:
            try:
                principal = _Principal.of(self._verify_token(token, now))
            except _Deny as d:
                if getattr(d, "claims", None):
                    o.principal = _Principal.of(d.claims)
                raise
        elif chain is not None and self.trust_caller_chain and isinstance(chain, dict):
            agents = [a for a in (chain.get("agents") or []) if isinstance(a, str)] if isinstance(chain.get("agents"), list) else []
            if not agents:
                raise EngineError("invalid_input", "chain.agents must list at least one agent")
            principal = _Principal(_req(chain, "user"), agents, _s(chain, "tenant"), _s(chain, "task"), None, [], Cap.unrestricted(), now,
                                   _s(chain, "role"), self._groups(chain["groups"], "Group", None) if chain.get("groups") is not None else None)
        elif chain is not None:
            raise _Deny("token_invalid", "this engine does not trust caller-supplied chains; send a capability token")
        else:
            raise _Deny("token_invalid", "no capability token was presented")
        o.principal = principal
        passed("token", f"user {principal.user} via {' -> '.join(principal.chain)}")

        # 2. catalog
        rdef = self.bundle.catalog.get(path)
        if rdef is None:
            raise _Deny("unknown_resource", f"'{path}' is not in the catalog")

        # 3. tenant
        attrs = res.get("attrs")
        if attrs is None:
            attrs = {}
        if not isinstance(attrs, dict):
            raise EngineError("invalid_input", "resource.attrs must be an object")
        rt = attrs.get("tenant")
        if principal.tenant and isinstance(rt, str) and principal.tenant != rt:
            raise _Deny("tenant_mismatch", f"token tenant '{principal.tenant}' cannot touch a resource of tenant '{rt}'")

        # 4. capability
        if not principal.cap.allows_action(action):
            raise _Deny("capability_action", f"the token does not carry action '{action}'")
        if not principal.cap.allows_resource(path, rid):
            raise _Deny("capability_resource", f"the token does not cover {path}/{rid}")
        passed("capability", "token covers the action and the resource")

        # 5. policy
        etype = rdef["entity_type"]
        r_uid = _entity(etype, rid)
        if isinstance(i.get("fields"), list):
            field_names = []
            for f in i["fields"]:
                if not isinstance(f, str) or f not in rdef["fields"]:
                    raise _Deny("unknown_field", f"'{path}.{f}' is not in the catalog")
                field_names.append(f)
        else:
            field_names = sorted(rdef["fields"])
        extra = []
        if r_uid not in self.bundle.store:
            extra.append({"uid": {"type": etype, "id": rid}, "attrs": attrs, "parents": []})
        elif attrs:
            raise EngineError("invalid_input", f"{r_uid} is defined in entities.json; do not send attrs for it")
        for n in field_names:
            fid = f"{path}.{n}"
            extra.append({"uid": {"type": "Field", "id": fid},
                          "attrs": {"path": fid, "name": n, "resource": path, "labels": rdef["fields"][n]["labels"],
                                    "of": {"__entity": {"type": etype, "id": rid}}},
                          "parents": [{"type": etype, "id": rid}]})
        try:
            store = self._store_for(principal).overlay(extra)
        except ValueError as e:
            raise EngineError("invalid_input", f"resource entity: {e}") from None
        full_ctx = dict(caller_ctx)
        full_ctx["iam"] = self._iam_context(principal)
        try:
            ctx = cedar.from_json(full_ctx)
        except ValueError as e:
            raise EngineError("invalid_context", f"{e} (use integers, strings, booleans, lists and objects; no floats or nulls)") from None
        p_uid = _entity("Agent", principal.leaf)
        v = self._evaluate(p_uid, action, r_uid, ctx, store)
        o.errors.extend(v["errors"])
        o.policies = v["policies"]
        if not v["allow"]:
            if v["forbid_error"]:
                raise _Deny("policy_error", "a forbid policy failed to evaluate, so the request is denied")
            if not v["policies"]:
                raise _Deny("no_matching_permit", "no policy permits this request")
            raise _Deny("policy_forbid", "forbidden by " + ", ".join(v["policies"]))
        passed("policy", "permitted by " + ", ".join(v["policies"]))

        # 6. obligations carried by the permits that decided
        approval_label = None
        for pid in v["policies"]:
            ann = self.bundle.policies[pid].annotations
            if "row_filter" in ann:
                try:
                    o.row_filter.extend(_parse_row_filter(ann["row_filter"], full_ctx))
                except _Deny as d:
                    raise _Deny(d.code, f"{pid}: {d.detail}") from None
            if "rate_limit" in ann:
                rate = _parse_rate(ann["rate_limit"])
                if rate is None:
                    raise _Deny("policy_error", f'{pid}: rate_limit must be "<count>/<seconds>"')
                o.rate.append((f"{pid}|{principal.leaf}|{principal.user}", rate[0], rate[1]))
            if "require_approval" in ann:
                approval_label = ann["require_approval"]
        for key, n, w in o.rate:
            q = self._rate.setdefault(key, deque())
            while q and q[0] <= now - w:
                q.popleft()
            o.rate_limit = {"limit": n, "window_seconds": w, "used": len(q)}
            if len(q) >= n:
                raise _Deny("rate_limited", f"more than {n} calls in {w} seconds")

        # 7. budget
        if "spend" in caller_ctx:
            sp = caller_ctx["spend"]
            cur = sp.get("currency") if isinstance(sp, dict) else None
            amount = sp.get("amount") if isinstance(sp, dict) else None
            if not isinstance(cur, str) or not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
                raise EngineError("invalid_context", "context.spend must be {currency: string, amount: non-negative integer in minor units}")
            if principal.jti is None:
                raise _Deny("budget_exceeded", "spending needs a capability token with a budget")
            if cur not in principal.cap.budget:
                raise _Deny("budget_exceeded", f"the token carries no {cur} budget")
            ledger, limits = self.state.data["ledger"], self.state.data["limits"]
            spent = lambda tid: ledger.get(tid, {}).get(cur, 0)
            own = principal.cap.budget[cur]
            if spent(principal.jti) + amount > own:
                raise _Deny("budget_exceeded", f"{amount} {cur} would exceed this token's budget of {own} (already spent {spent(principal.jti)})")
            for a in principal.anc:
                # An ancestor's budget is in this engine's state when it issued
                # the ancestor, and in the token's `lim` claim always: a
                # verify-only engine elsewhere must enforce it too.
                limit = limits.get(a, {}).get(cur)
                if limit is None:
                    limit = principal.lim.get(a, {}).get(cur)
                if limit is not None and spent(a) + amount > limit:
                    raise _Deny("budget_exceeded", f"{amount} {cur} would exceed the budget of ancestor token {a}")
            o.spend = (cur, amount)
            passed("budget", "within the budget of every token in the chain")

        # 8. human approval
        if approval_label is not None:
            aid = hash_value({"user": principal.user, "chain": principal.chain, "tenant": principal.tenant, "action": action,
                              "resource": f"{path}/{rid}", "attrs": attrs, "context": caller_ctx, "label": approval_label})[:24]
            grant = self.state.data["approvals"].get(aid)
            if grant and grant["exp"] > now:
                o.approved = (aid, grant["by"])
                passed("approval", f"approved by {grant['by']}")
            else:
                if not dry_run:
                    self.state.data["pending"][aid] = {"label": approval_label, "user": principal.user, "agent": principal.leaf,
                                                       "action": action, "resource": f"{path}/{rid}", "requested_at": now}
                    self.state.save()
                o.approval = {"id": aid, "label": approval_label}
                raise _Deny("approval_required", f"a human must approve this ({approval_label})")

        # 9. fields
        status, field_trace = {}, []
        for n in field_names:
            fid = f"{path}.{n}"
            fdef = rdef["fields"][n]
            if fid in principal.cap.deny_fields or any(l in principal.cap.deny_labels for l in fdef["labels"]):
                allowed, by = False, "capability"
            else:
                fv = self._evaluate(p_uid, action, cedar.Entity("Field", fid), ctx, store)
                o.errors.extend(fv["errors"])
                allowed, by = fv["allow"], (fv["policies"] or "no_matching_permit")
            if allowed:
                o.field_allow.append(n)
                status[n] = fields.ALLOW
            else:
                o.field_deny.append(n)
                if fdef["mask"] == "redact":
                    o.field_redact.append(n)
                    status[n] = fields.REDACT
                else:
                    status[n] = fields.DENY
            field_trace.append({"field": n, "effect": "allow" if allowed else "deny", "by": by})
        o.trace.append({"check": "fields", "result": "pass", "fields": field_trace})
        o.mask = fields.Mask(status)
        o.allow = True
        o.reason = "policy_permit"

    def _decide(self, i: dict, with_data: bool) -> dict:
        now = self._now(i)
        dry_run = i.get("dry_run") is True
        strict = i.get("strict") is True
        if with_data and "data" not in i:
            raise EngineError("invalid_input", "'data' is required for filter")
        data = i.get("data") if with_data else None
        o = self._evaluate_request(i, now, dry_run)

        # 10. strict mode: for tool *inputs*, where silently dropping a field
        # would change what the agent asked for
        if o.allow and strict and with_data:
            denied = fields.apply(data, o.mask, [])[1]
            if denied:
                o.allow = False
                o.reason = "field_denied"
                o.detail = "the input contains fields this principal may not use: " + ", ".join(denied)
                o.trace.append({"check": "field_denied", "result": "deny", "detail": o.detail})

        # commit the side effects of an allowed call
        if o.allow and not dry_run:
            for key, _, _ in o.rate:
                self._rate.setdefault(key, deque()).append(now)
            dirty = False
            if o.spend and o.principal:
                cur, amount = o.spend
                for tid in o.principal.anc + [o.principal.jti]:
                    bucket = self.state.data["ledger"].setdefault(tid, {})
                    bucket[cur] = bucket.get(cur, 0) + amount
                dirty = True
            if o.approved:
                # an approval is good for one call
                self.state.data["approvals"].pop(o.approved[0], None)
                dirty = True
            if dirty:
                self.state.save()

        would_deny = not o.allow
        shadowed = self.shadow and would_deny
        out: dict = {"effect": "allow" if (o.allow or shadowed) else "deny",
                     "reason": "shadow_allow" if shadowed else o.reason}
        out["rule"] = rule_id(out["reason"])
        if o.detail and not shadowed:
            out["detail"] = o.detail
        out["policies"] = o.policies
        out["policy_version"] = self.bundle.version
        out["principal"] = o.principal.to_json() if o.principal else None
        if self.shadow:
            out["shadow"] = True
            if would_deny:
                out["would_deny"] = {"reason": o.reason, "detail": o.detail}
        if o.approval:
            out["approval"] = o.approval

        obligations: dict = {}
        masked: list = []
        rows_dropped = 0
        if o.allow:
            obligations["fields"] = {"allow": o.field_allow, "deny": o.field_deny, "redact": o.field_redact}
            if o.row_filter:
                obligations["row_filter"] = o.row_filter
            if o.rate_limit:
                obligations["rate_limit"] = o.rate_limit
            if o.approved:
                obligations["approved"] = {"id": o.approved[0], "by": o.approved[1]}
        if with_data:
            if o.allow:
                filtered, masked, rows_dropped = fields.apply(data, o.mask, o.row_filter)
                if self.shadow:
                    # shadow mode never changes data; it reports what it would do
                    out.update(data=data, would_mask=masked, would_drop_rows=rows_dropped)
                else:
                    out.update(data=filtered, masked=masked, rows_dropped=rows_dropped)
            else:
                out["data"] = data if shadowed else None
        out["obligations"] = obligations
        if o.errors:
            out["policy_errors"] = o.errors
        if i.get("explain") is True:
            out["explain"] = o.trace

        self._counter += 1
        request_hash = hash_value({"action": i.get("action"), "resource": i.get("resource"), "context": i.get("context"),
                                   "token_id": o.principal.jti if o.principal else None})
        decision_id = "d-" + sha256_hex(f"{request_hash}{now}{self._counter}{os.getpid()}".encode())[:16]
        out["decision_id"] = decision_id

        if not dry_run:
            p = o.principal
            res = i.get("resource") if isinstance(i.get("resource"), dict) else {}
            self._audit({
                "event": "decision", "decision_id": decision_id, "op": "filter" if with_data else "authorize",
                "effect": "allow" if o.allow else "deny", "reason": o.reason, "detail": o.detail,
                "enforced": not self.shadow, "policies": o.policies, "policy_version": self.bundle.version,
                "user": p.user if p else None, "chain": p.chain if p else None, "role": p.role if p else None, "tenant": p.tenant if p else None,
                "task": p.task if p else None, "token_id": p.jti if p else None, "token_exp": p.exp if p else None,
                "action": i.get("action"),
                "resource": f"{_s(res, 'path') or '?'}/{_s(res, 'id') or 'any'}",
                "obligations": obligations, "masked": masked, "rows_dropped": rows_dropped, "approval": o.approval,
                "spend": {"currency": o.spend[0], "amount": o.spend[1]} if o.spend else None,
                "request_hash": request_hash,
            }, now)
        return out
