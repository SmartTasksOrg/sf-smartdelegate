#!/usr/bin/env python3
"""SmartDelegate as an MCP server (stdio, newline-delimited JSON-RPC 2.0).

It lets an orchestrator ask SmartDelegate questions and mint sub-agent
tokens. It is not the enforcement point: that is `smartdelegate mcp-proxy`,
which sits in front of other MCP servers. See README.md in this folder.

    python integrations/mcp/server.py --bundle bundle --state state [--ops] [--admin [--allow-tools LIST]] [--govern]
    python integrations/mcp/server.py --config smartdelegate.json [--admin] [--token-file FILE]

Tools
  whoami    what the current token is: user, agent chain, role, task, capability
  roles     the roles of the loaded bundle and their ceilings
  check     would this call be allowed? Dry run: nothing is spent, counted or logged
  explain   the same, with every check and every field decision
  narrow    a token for a sub-agent that carries part of what a token holds, never more

Monitoring tools (only with --ops; they read, they change nothing)
  status             version, policy version, mode, roles, counts, audit head, warnings
  audit_tail         the newest audit records, optionally filtered
  audit_verify       recompute the audit hash chain
  pending_approvals  requests held for a human, with their age
  anomalies          the newest audit records summarised by rule id, user and agent,
                     with findings where a count crosses a threshold

Privileged tools (only with --admin)
  delegate      a human lends an agent one role for one task
  approve       approve a held request      } only when also named in --allow-tools,
  revoke_user   end every token of a human  } e.g. --admin --allow-tools revoke_user
  reload        reload the bundle           }
--admin alone exposes `delegate` only, as it always did. With --allow-tools the
privileged tools are exactly the ones listed (delegate,approve,revoke_user,reload).

--govern  every monitoring and privileged tool call is first authorized by the
          engine against the caller's capability token: action "read"
          (monitoring) or "operate" (privileged) on smartdelegate.ops/<tool>.
          That decision is not a dry run, so each call is in the audit log with
          the human, the agent chain and the role. `by` is then the token's
          user. A bundle fragment with matching roles: agents/bundle-example.

The current token is the `token` argument of a call, else --token-file
(re-read on every call), else SMARTDELEGATE_TOKEN: the same convention as
`smartdelegate mcp-proxy`.

--admin makes this process an issuer of root tokens. Whoever can call the
server can then act as any user in the bundle, within that user's roles.
Start it with --admin only where the caller is the trusted orchestrator.

Standard library plus the smartdelegate package; the `mcp` package is not used.
"""
from __future__ import annotations

import datetime
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

from sf_smartdelegate import __version__, core
from sf_smartdelegate.cli import Args, load_config
from sf_smartdelegate.engine import Engine
from sf_smartdelegate.errors import EngineError, rule_id

PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
SERVER = {"name": "smartdelegate", "version": __version__}

_CAP = {"type": "object", "description": "A capability: what the token may do at most.",
        "properties": {"actions": {"type": "array", "items": {"type": "string"}},
                       "resources": {"type": "array", "items": {"type": "string"}, "description": "<path>/<id>, one trailing * allowed"},
                       "deny_labels": {"type": "array", "items": {"type": "string"}},
                       "deny_fields": {"type": "array", "items": {"type": "string"}},
                       "budget": {"type": "object", "additionalProperties": {"type": "integer"}, "description": "currency -> minor units"}},
        "additionalProperties": False}
_TOKEN = {"type": "string", "description": "A capability token. Default: the server's current token."}
_REQUEST = {"token": _TOKEN,
            "action": {"type": "string"},
            "resource": {"type": "string", "description": "Catalog path, e.g. crm.customer"},
            "id": {"type": "string", "description": "Resource id. Default: any"},
            "attrs": {"type": "object", "description": "Resource attributes policies read"},
            "context": {"type": "object", "description": "Request context, e.g. {\"spend\": {\"currency\": \"EUR\", \"amount\": 6000}}"},
            "data": {"description": "A record or a list of records. When given, the answer carries it masked."}}


def _schema(properties: dict, required: list) -> dict:
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}


TOOLS = [
    {"name": "whoami", "description": "Inspect a capability token: user, agent chain, role, task, capability, seconds left.",
     "inputSchema": _schema({"token": _TOKEN}, [])},
    {"name": "roles", "description": "List the roles of the loaded bundle: who holds each one and the most a token issued under it can carry.",
     "inputSchema": _schema({}, [])},
    {"name": "check", "description": "Would this call be allowed for the token? A dry run: no budget is spent, no rate is counted, "
                                     "no approval is consumed and nothing is written to the audit log. With `data`, returns it masked.",
     "inputSchema": _schema(_REQUEST, ["action", "resource"])},
    {"name": "explain", "description": "Like check, with the trace of every check and every field decision.",
     "inputSchema": _schema(_REQUEST, ["action", "resource"])},
    {"name": "narrow", "description": "Issue a token for a sub-agent from a token you hold. It can carry less than the parent, never more "
                                      "(a wider request is refused with DELEGATE-WIDENING).",
     "inputSchema": _schema({"token": dict(_TOKEN, description="The parent token. Default: the server's current token."),
                             "actor": {"type": "string", "description": "The sub-agent that receives the token"},
                             "capability": _CAP, "ttl": {"type": "integer", "description": "Seconds"}}, ["actor"])},
]
_BY = {"type": "string", "description": "Who is doing this (a human's user id). Recorded by the engine. With --govern it is the "
                                         "user of the capability token and may be omitted."}
_GOVERNED_TOKEN = dict(_TOKEN, description="With --govern: the capability token this call is authorized against. "
                                           "Default: the server's current token.")
OPS_TOOLS = [
    {"name": "status", "description": "Health of this engine: version, policy version, mode, roles, counts (policies, resources, audit records, "
                                      "pending and granted approvals), the audit head hash, the age of the last directory sync when one is "
                                      "recorded, and warnings (shadow mode, unsigned bundle, no audit log, test switches on).",
     "inputSchema": _schema({"token": _GOVERNED_TOKEN}, [])},
    {"name": "audit_tail", "description": "The newest audit records. `n` is how many of the newest records to look at (default 20, at most "
                                          "2000); the filters select among those. Decision records carry `rule` (DELEGATE-*). Records hold "
                                          "field names, never field values or tokens.",
     "inputSchema": _schema({"token": _GOVERNED_TOKEN, "n": {"type": "integer"},
                             "event": {"type": "string", "description": "e.g. decision, token_issued, token_exchanged, token_revoked, user_revoked, approval_granted, bundle_reloaded"},
                             "rule": {"type": "string", "description": "e.g. DELEGATE-POLICY-FORBID"},
                             "user": {"type": "string"}, "decision_id": {"type": "string"}}, [])},
    {"name": "audit_verify", "description": "Recompute the audit hash chain. Returns the number of records and the head hash; a broken chain "
                                            "is an error naming the first bad line. Keep the head hash somewhere the engine's host cannot "
                                            "change: the chain alone cannot show that the newest records were removed.",
     "inputSchema": _schema({"token": _GOVERNED_TOKEN}, [])},
    {"name": "pending_approvals", "description": "Requests that wait for a human: id, label, the user and agent that asked, action, resource, "
                                                 "age in seconds. Read-only; approving is the privileged tool `approve`.",
     "inputSchema": _schema({"token": _GOVERNED_TOKEN}, [])},
    {"name": "anomalies", "description": "Summarise the newest `n` audit records (default 500, at most 5000) by rule id, user and agent, and "
                                         "list findings where a count reaches a threshold. `thresholds` overrides the defaults by name.",
     "inputSchema": _schema({"token": _GOVERNED_TOKEN, "n": {"type": "integer"},
                             "thresholds": {"type": "object", "additionalProperties": {"type": "integer"}}}, [])},
]
#: Defaults of the `anomalies` tool. They are starting points, not calibrated values.
THRESHOLDS = {
    "min_decisions": 20,                 # deny_rate is not reported on fewer decisions than this
    "deny_rate_percent": 50,             # share of decisions that were denials
    "capability_denies_per_agent": 5,    # CAPABILITY-ACTION / -RESOURCE by one agent: it keeps asking outside its token
    "revoked_token_uses_per_user": 3,    # TOKEN-REVOKED: a revoked token is still being presented
    "invalid_tokens": 5,                 # TOKEN-INVALID: forged, altered or foreign tokens
    "expired_token_uses_per_user": 10,   # TOKEN-EXPIRED: an agent that does not renew
    "budget_denies_per_token": 3,        # BUDGET-EXCEEDED on one token
    "rate_limited_per_agent": 5,         # RATE-LIMITED
    "policy_errors": 1,                  # POLICY-ERROR: a forbid failed to evaluate
    "unknown_resources_per_agent": 3,    # UNKNOWN-RESOURCE / UNKNOWN-FIELD: catalog drift or probing
    "user_revocations": 3,               # user_revoked events: offboarding wave, or revoke used to stop work
    "issuance_refusals": 5,              # WIDENING / ROLE-NOT-HELD / ROLE-EXCEEDED ... refused by this server
    "pending_approvals": 5,              # held requests waiting
    "oldest_pending_seconds": 900,       # the oldest held request has waited this long
}
PRIVILEGED = ("approve", "revoke_user", "reload", "delegate")      # listing order; `delegate` stays last
ADMIN_TOOLS = [
    {"name": "approve", "description": "Approve a held request as the human `by`. The engine refuses the user the agent acts for "
                                       "(DELEGATE-SELF-APPROVAL) and anyone no policy lets approve (DELEGATE-APPROVAL-DENIED). "
                                       "Only with --admin and --allow-tools approve.",
     "inputSchema": _schema({"token": _GOVERNED_TOKEN, "approval_id": {"type": "string"}, "by": _BY,
                             "ttl": {"type": "integer", "description": "Seconds the approval stays usable"}}, ["approval_id"])},
    {"name": "revoke_user", "description": "Offboarding: end every capability token already issued for this human, sub-agent tokens "
                                           "included. Not undoable. Only with --admin and --allow-tools revoke_user.",
     "inputSchema": _schema({"token": _GOVERNED_TOKEN, "user": {"type": "string"}, "by": _BY}, ["user"])},
    {"name": "reload", "description": "Reload the bundle (and the identity provider's keys when they come from a file). A bundle that "
                                      "fails to load leaves the old one in force. Only with --admin and --allow-tools reload.",
     "inputSchema": _schema({"token": _GOVERNED_TOKEN, "by": _BY}, [])},
]
DELEGATE = {"name": "delegate", "description": "A human lends an agent one role they hold, for one task. Returns a capability token that "
                                               "cannot carry more than the role allows. Available only when the server runs with --admin.",
            "inputSchema": _schema({"user": {"type": "string"}, "agent": {"type": "string"}, "role": {"type": "string"},
                                    "task": {"type": "string"}, "capability": _CAP, "ttl": {"type": "integer", "description": "Seconds"},
                                    "groups": {"type": "array", "items": {"type": "string"},
                                               "description": "The user's live group membership, when known from the identity provider"},
                                    "tenant": {"type": "string"}, "by": _BY, "token": _GOVERNED_TOKEN}, ["user", "agent", "role"])}
ADMIN_TOOLS.append(DELEGATE)
_BY_NAME = {t["name"]: t for t in TOOLS + OPS_TOOLS + ADMIN_TOOLS}
OPS_RESOURCE = "smartdelegate.ops"


class ToolError(Exception):
    """A tool call that fails: returned as a tool result with isError."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class BadParams(Exception):
    """A malformed tools/call: returned as JSON-RPC error -32602."""


class Server:
    def __init__(self, engine: Engine, admin: bool = False, token_file: str | None = None, ops: bool = False,
                 allow_tools: list | None = None, govern: bool = False, log=None):
        """`allow_tools`: the privileged tools this process exposes. None means
        "what --admin always meant": `delegate` only. Without `admin` no
        privileged tool is exposed, whatever the list says."""
        self.engine, self.admin, self.token_file, self.ops, self.govern = engine, admin, token_file, ops, govern
        allow = ["delegate"] if allow_tools is None else list(allow_tools)
        unknown = sorted(set(allow) - set(PRIVILEGED))
        if unknown:
            raise ValueError("not a privileged tool: " + ", ".join(unknown) + " (choose from " + ", ".join(sorted(PRIVILEGED)) + ")")
        if allow_tools is not None and not admin:
            raise ValueError("--allow-tools needs --admin: without it no privileged tool is exposed")
        self.privileged = tuple(n for n in PRIVILEGED if admin and n in allow)
        self.refusals: Counter = Counter()      # issuance refusals seen by this process (they are not in the audit log)
        self._log = log or (lambda line: print(line, file=sys.stderr, flush=True))

    # -- tools -----------------------------------------------------------------
    def tools(self) -> list:
        return TOOLS + (OPS_TOOLS if self.ops else []) + [_BY_NAME[n] for n in self.privileged]

    def _gate(self, name: str, args: dict) -> str | None:
        """Is this monitoring or privileged tool switched on, and (with
        --govern) does the caller's token allow it? Returns the human the call
        is attributed to. Every refusal is a ToolError; nothing runs after one."""
        privileged = name in PRIVILEGED
        if privileged and not self.admin:
            raise ToolError("admin_required", "this server was started without --admin, so it exposes no privileged tool"
                            if name != "delegate" else "this server was started without --admin, so it does not issue root tokens")
        if privileged and name not in self.privileged:
            raise ToolError("tool_not_allowed", f"'{name}' is not in this server's --allow-tools list")
        if not privileged and not self.ops:
            raise ToolError("ops_required", "this server was started without --ops, so it exposes no monitoring tool")
        by = args.get("by")
        if by is not None and not isinstance(by, str):
            raise BadParams(f"{name}: 'by' must be a string")
        if self.govern:
            d = self._engine("authorize", {"token": self._current_token(args), "action": "operate" if privileged else "read",
                                           "resource": {"path": OPS_RESOURCE, "id": name}})
            if d.get("effect") != "allow" or d.get("would_deny"):
                # shadow mode reports instead of enforcing; a management tool is never run on a would-be denial
                reason = (d.get("would_deny") or {}).get("reason") or d.get("reason") or "deny"
                raise ToolError(str(reason), f"the capability token does not allow '{name}' ({OPS_RESOURCE}/{name}): "
                                             + str((d.get("would_deny") or {}).get("detail") or d.get("detail") or "not permitted"))
            user = (d.get("principal") or {}).get("user")
            if by is not None and by != user:
                raise ToolError("invalid_input", "with --govern, `by` is the user of the capability token; omit it or pass that user")
            by = user
        elif privileged and name != "delegate" and (not isinstance(by, str) or not by):
            raise BadParams(f"{name}: 'by' is required and must be a non-empty string")
        return by

    def _current_token(self, args: dict) -> str:
        token = args.get("token")
        if token is None and self.token_file:
            try:
                with open(self.token_file, encoding="utf-8") as f:
                    token = f.read().strip()
            except OSError:
                token = ""
        if token is None:
            token = os.environ.get("SMARTDELEGATE_TOKEN", "")
        if not isinstance(token, str) or not token:
            raise ToolError("token_invalid", "no capability token: pass `token`, or start the server with --token-file or SMARTDELEGATE_TOKEN")
        return token

    def _engine(self, op: str, payload: dict) -> dict:
        result = self.engine.call(op, payload)
        if not result.get("ok"):
            err = result.get("error") or {}
            raise ToolError(err.get("code", "error"), err.get("message", "unknown error"))
        result.pop("ok", None)
        return result

    def _request(self, args: dict) -> dict:
        res = {"path": args["resource"], "id": args.get("id") or "any"}
        if args.get("attrs") is not None:
            res["attrs"] = args["attrs"]
        body = {"token": self._current_token(args), "action": args["action"], "resource": res, "dry_run": True}
        if args.get("context") is not None:
            body["context"] = args["context"]
        if args.get("data") is not None:
            body["data"] = args["data"]
        return body

    @staticmethod
    def _grant(r: dict) -> dict:
        return {k: r.get(k) for k in ("token", "token_id", "user", "chain", "role", "cap", "expires_at", "expires_in")}

    def call_tool(self, name: str, args: dict) -> dict:
        if name == "whoami":
            r = self._engine("inspect_token", {"token": self._current_token(args)})
            if not r.get("valid"):
                return {"valid": False, "reason": r.get("reason"), "rule": rule_id(str(r.get("reason") or "token_invalid")), "detail": r.get("detail")}
            c = r["claims"]
            return {"valid": True, "user": r["user"], "chain": r["chain"], "agent": r["chain"][-1], "role": c.get("role"),
                    "task": c.get("task"), "tenant": c.get("tnt"), "token_id": c["jti"], "cap": c["cap"], "expires_in": r["expires_in"]}
        if name == "roles":
            return {"roles": [{"name": r.name, "members": r.members, "ceiling": r.ceiling.to_json(), "max_ttl": r.max_ttl,
                               "tasks": r.tasks, "agents": r.agents} for r in core.roles(self.engine)]}
        if name == "check":
            body = self._request(args)
            return self._engine("filter" if "data" in body else "authorize", body)
        if name == "explain":
            return self._engine("explain", self._request(args))
        if name == "narrow":
            body = {"subject_token": self._current_token(args), "actor": args["actor"], "cap": args.get("capability"), "ttl": args.get("ttl")}
            return self._grant(self._engine("exchange_token", {k: v for k, v in body.items() if v is not None}))
        if name not in _BY_NAME:
            raise BadParams(f"unknown tool: {name}")
        by = self._gate(name, args)
        if name == "delegate":
            body = {"user": args["user"], "agent": args["agent"], "role": args["role"], "task": args.get("task"),
                    "cap": args.get("capability"), "ttl": args.get("ttl"), "groups": args.get("groups"), "tenant": args.get("tenant")}
            out = self._grant(self._engine("issue_token", {k: v for k, v in body.items() if v is not None}))
            # the engine's token_issued record does not hold who asked; say it where an operator can see it
            self._log(f"smartdelegate mcp server: delegate user={args['user']} agent={args['agent']} role={args['role']} "
                      f"token_id={out['token_id']} by={by or 'unstated'}")
            return out
        if name == "approve":
            body = {"approval_id": args["approval_id"], "by": by, "ttl": args.get("ttl")}
            return self._engine("approve", {k: v for k, v in body.items() if v is not None})
        if name == "revoke_user":
            return dict(self._engine("revoke", {"user": args["user"], "by": by}), by=by)
        if name == "reload":
            info = self._engine("reload", {})
            self._log(f"smartdelegate mcp server: reload policy_version={info['policy_version']} by={by}")
            return {"reloaded": True, "policy_version": info["policy_version"], "roles": info["roles"], "by": by}
        if name == "status":
            return self._status()
        if name == "audit_tail":
            return {"records": self._records(self._count(args, 20, 2000), args)}
        if name == "audit_verify":
            return self._engine("audit_verify", {})
        if name == "pending_approvals":
            return self._pending()
        return self._anomalies(args)

    # -- monitoring ------------------------------------------------------------
    @staticmethod
    def _count(args: dict, default: int, most: int) -> int:
        n = args.get("n", default)
        if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
            raise BadParams("'n' must be a positive integer")
        return min(n, most)

    def _records(self, n: int, filters: dict | None = None) -> list:
        """The newest `n` audit records, decision records with their rule id."""
        out = []
        for r in self._engine("audit_tail", {"n": n})["records"]:
            if not isinstance(r, dict):
                continue
            if r.get("event") == "decision":
                r = dict(r, rule=rule_id(str(r.get("reason") or "deny")))
            if all(r.get(k) == v for k, v in (filters or {}).items() if k in ("event", "rule", "user", "decision_id")):
                out.append(r)
        return out

    def _pending(self) -> dict:
        a = self._engine("approvals", {})
        now = int(time.time())
        pending = [{"id": i, **{k: v.get(k) for k in ("label", "user", "agent", "action", "resource", "requested_at")},
                    "age_seconds": max(0, now - v["requested_at"]) if isinstance(v.get("requested_at"), int) else None}
                   for i, v in sorted((a.get("pending") or {}).items()) if isinstance(v, dict)]
        return {"pending": pending, "granted": len(a.get("granted") or {})}

    def _audit_head(self) -> dict:
        r = self.engine.call("audit_verify", {})
        if r.get("ok"):
            return {"records": r["records"], "head": r["head"], "chain": "verifies"}
        return {"chain": "broken" if (r.get("error") or {}).get("code") == "audit_broken" else "unavailable", "error": r.get("error")}

    def _status(self) -> dict:
        info = self._engine("info", {})
        pending = self._pending()
        e = self.engine
        warnings = []
        if info.get("mode") == "shadow":
            warnings.append("shadow mode: denials are logged, not enforced")
        if not info.get("bundle_signed_by"):
            warnings.append("the bundle is not signature-checked (no bundle_public_key configured)")
        if getattr(e, "audit", None) is None:
            warnings.append("no audit log (no state directory, or audit is off)")
        if getattr(e, "allow_test_clock", False):
            warnings.append("allow_test_clock is on: any caller can set the clock. Tests only")
        if getattr(e, "trust_caller_chain", False):
            warnings.append("trust_caller_chain is on: callers state user, role and groups without a token. Tests only")
        if not getattr(e, "require_role", False):
            warnings.append("require_role is off: a root token can be issued without a role")
        audit_ = self._audit_head()
        if audit_["chain"] == "broken":
            warnings.append("the audit hash chain does not verify")
        sync = None
        try:
            side = json.loads((Path(e.bundle_dir) / "entities.sync.json").read_text(encoding="utf-8"))
            stamp = datetime.datetime.strptime(side["synced_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
            sync = {"source": side.get("source"), "synced_at": side["synced_at"], "age_seconds": max(0, int(time.time() - stamp.timestamp()))}
        except (OSError, ValueError, KeyError, TypeError):
            pass                                  # no directory sync has written the sidecar
        return {"version": info["version"], "implementation": info["implementation"], "mode": info["mode"],
                "policy_version": info["policy_version"], "bundle_signed_by": info["bundle_signed_by"], "issuer": info["issuer"],
                "key_id": info["key_id"], "can_issue": info["can_issue"], "oidc": info["oidc"], "roles": info["roles"],
                "counts": {"policies": info["policies"], "resources": len(info["resources"]), "roles": len(info["roles"]),
                           "audit_records": audit_.get("records"), "pending_approvals": len(pending["pending"]),
                           "granted_approvals": pending["granted"]},
                "audit": audit_, "directory_sync": sync,
                "server": {"ops": self.ops, "admin": self.admin, "privileged_tools": list(self.privileged), "govern": self.govern},
                "warnings": warnings}

    def _anomalies(self, args: dict) -> dict:
        limits = dict(THRESHOLDS)
        over = args.get("thresholds")
        if over is not None:
            if not isinstance(over, dict) or set(over) - set(limits) or not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in over.values()):
                raise BadParams("anomalies: 'thresholds' maps a known threshold name to a non-negative integer; names: " + ", ".join(sorted(limits)))
            limits.update(over)
        records = self._records(self._count(args, 500, 5000))
        decisions = [r for r in records if r.get("event") == "decision"]
        denies = [r for r in decisions if r.get("effect") == "deny"]
        agent = lambda r: (r.get("chain") or ["?"])[-1] if isinstance(r.get("chain"), list) else "?"
        by_rule = Counter(r["rule"] for r in decisions)
        findings = []

        def finding(code, severity, count, limit, detail, **who):
            findings.append({"code": code, "severity": severity, "count": count, "threshold": limit, "detail": detail, **who})

        def per(key, rules, name, code, severity, detail):
            for who, n in sorted(Counter(key(r) for r in denies if r["rule"] in rules).items(), key=lambda kv: (-kv[1], str(kv[0]))):
                if n >= limits[name] > 0:
                    finding(code, severity, n, limits[name], detail, subject=who)

        if len(decisions) >= limits["min_decisions"] and limits["deny_rate_percent"] > 0 and len(denies) * 100 >= limits["deny_rate_percent"] * len(decisions):
            finding("deny_rate", "warning", len(denies), limits["deny_rate_percent"], f"{len(denies)} of {len(decisions)} decisions were denials")
        per(agent, ("DELEGATE-CAPABILITY-ACTION", "DELEGATE-CAPABILITY-RESOURCE"), "capability_denies_per_agent", "capability_probing", "warning",
            "an agent keeps asking for actions or resources its token does not carry")
        per(lambda r: r.get("user"), ("DELEGATE-TOKEN-REVOKED",), "revoked_token_uses_per_user", "revoked_token_in_use", "high",
            "a revoked token is still being presented: the agent was not stopped, or the token was copied")
        per(lambda r: r.get("user"), ("DELEGATE-TOKEN-EXPIRED",), "expired_token_uses_per_user", "expired_token_in_use", "info",
            "an expired token is still being presented")
        per(lambda r: r.get("token_id"), ("DELEGATE-BUDGET-EXCEEDED",), "budget_denies_per_token", "budget_exhausted", "warning",
            "a token keeps asking to spend beyond its budget or an ancestor's")
        per(agent, ("DELEGATE-RATE-LIMITED",), "rate_limited_per_agent", "rate_limited", "info", "an agent keeps hitting a rate limit")
        per(agent, ("DELEGATE-UNKNOWN-RESOURCE", "DELEGATE-UNKNOWN-FIELD"), "unknown_resources_per_agent", "catalog_miss", "warning",
            "requests name resources or fields the catalog does not have: catalog drift, a misconfigured enforcement point, or probing")
        for rules, name, code, severity, detail in (
                (("DELEGATE-TOKEN-INVALID",), "invalid_tokens", "invalid_tokens", "high", "forged, altered, foreign or missing tokens were presented"),
                (("DELEGATE-POLICY-ERROR",), "policy_errors", "policy_error", "high", "a forbid policy failed to evaluate, so requests were denied: fix the policy or the attributes the enforcement point sends")):
            n = sum(by_rule[r] for r in rules)
            if n >= limits[name] > 0:
                finding(code, severity, n, limits[name], detail)
        events = Counter(str(r.get("event")) for r in records)
        if events["user_revoked"] >= limits["user_revocations"] > 0:
            finding("user_revocations", "warning", events["user_revoked"], limits["user_revocations"],
                    "several users were revoked: an offboarding wave, a directory sync with --revoke, or revoke used to stop work",
                    subject=sorted({str(r.get("user")) for r in records if r.get("event") == "user_revoked"}))
        unenforced = sum(1 for r in decisions if r.get("enforced") is False and r.get("effect") == "deny")
        if unenforced:
            finding("not_enforced", "high", unenforced, 1, "denials were logged in shadow mode and not enforced")
        refused = sum(self.refusals.values())
        if refused >= limits["issuance_refusals"] > 0:
            finding("issuance_refusals", "warning", refused, limits["issuance_refusals"],
                    "this server refused token requests (see issuance_refusals): a caller keeps asking for more than it may hold")
        pending = self._pending()["pending"]
        oldest = max((p["age_seconds"] or 0 for p in pending), default=0)
        if (len(pending) >= limits["pending_approvals"] > 0) or (pending and oldest >= limits["oldest_pending_seconds"] > 0):
            finding("approval_backlog", "warning", len(pending), limits["pending_approvals"],
                    f"{len(pending)} request(s) wait for a human; the oldest for {oldest} s")
        audit_ = self._audit_head()
        if audit_["chain"] == "broken":
            finding("audit_chain_broken", "critical", 1, 1, str((audit_.get("error") or {}).get("message")))
        ts = [r["ts"] for r in records if isinstance(r.get("ts"), int)]
        return {"window": {"records": len(records), "decisions": len(decisions), "denials": len(denies),
                           "from_ts": min(ts) if ts else None, "to_ts": max(ts) if ts else None},
                "by_rule": dict(sorted(by_rule.items())), "events": dict(sorted(events.items())),
                "denials_by_user": dict(sorted(Counter(str(r.get("user")) for r in denies).items())),
                "denials_by_agent": dict(sorted(Counter(agent(r) for r in denies).items())),
                "issuance_refusals": {"counts": dict(sorted(self.refusals.items())),
                                      "note": "refused token requests (DELEGATE-WIDENING, DELEGATE-ROLE-NOT-HELD, DELEGATE-ROLE-EXCEEDED, ...) "
                                              "are answered to the caller and are not written to the audit log; these are the ones this "
                                              "server process refused since it started"},
                "thresholds": limits, "findings": findings}

    def _validate(self, name: str, args: dict) -> None:
        tool = _BY_NAME.get(name)
        if tool is None:
            raise BadParams(f"unknown tool: {name}")
        schema = tool["inputSchema"]
        unknown = sorted(set(args) - set(schema["properties"]))
        if unknown:
            # a misspelt argument must not silently change the question
            raise BadParams(f"{name}: unknown argument(s): {', '.join(unknown)}")
        for key in schema["required"]:
            if not isinstance(args.get(key), str) or not args[key]:
                raise BadParams(f"{name}: '{key}' is required and must be a non-empty string")
        ttl = args.get("ttl")
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0):
            # the engine would fall back to its default lifetime
            raise BadParams(f"{name}: 'ttl' must be a positive integer (seconds)")

    # -- JSON-RPC --------------------------------------------------------------
    def handle(self, msg) -> dict | None:
        """One decoded message in, one reply out (None for notifications and
        for anything that is not a request)."""
        if not isinstance(msg, dict):
            # arrays are JSON-RPC batches, which this server does not accept
            return _error(None, -32600, "invalid request: expected one JSON-RPC object")
        if "method" not in msg:
            return None if ("result" in msg or "error" in msg) else _error(msg.get("id"), -32600, "invalid request: no method")
        id_, method = msg.get("id"), msg["method"]
        is_request = "id" in msg and isinstance(id_, (str, int)) and not isinstance(id_, bool)
        if not isinstance(method, str) or msg.get("jsonrpc") != "2.0" or ("id" in msg and not is_request):
            return _error(id_ if is_request else None, -32600, "invalid request")
        if not is_request:
            return None     # notifications/initialized and the like
        params = msg.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _error(id_, -32602, "params must be an object")
        if method == "initialize":
            asked = params.get("protocolVersion")
            return _result(id_, {"protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                                 "capabilities": {"tools": {}}, "serverInfo": SERVER,
                                 "instructions": "Ask SmartDelegate what a capability token may do, and narrow a token for a sub-agent. "
                                                 "This server answers questions; enforcement happens at the proxy or the guard."
                                                 + (" Monitoring tools (status, audit_tail, audit_verify, pending_approvals, anomalies) "
                                                    "read and change nothing." if self.ops else "")
                                                 + (" Privileged tools change authority and need a human's decision: "
                                                    + ", ".join(self.privileged) + "." if self.privileged else "")})
        if method == "ping":
            return _result(id_, {})
        if method == "tools/list":
            return _result(id_, {"tools": self.tools()})
        if method == "tools/call":
            name, args = params.get("name"), params.get("arguments")
            if args is None:
                args = {}
            if not isinstance(name, str) or not isinstance(args, dict):
                return _error(id_, -32602, "tools/call needs a tool name and an arguments object")
            try:
                self._validate(name, args)
                return _result(id_, _tool_result(self.call_tool(name, args), False))
            except BadParams as e:
                return _error(id_, -32602, str(e))
            except ToolError as e:
                if name in ("narrow", "delegate") and e.code not in ("admin_required", "tool_not_allowed"):
                    self.refusals[rule_id(e.code)] += 1
                return _result(id_, _tool_result({"error": {"code": e.code, "rule": rule_id(e.code), "message": e.message, "by": "smartdelegate"}}, True))
            except EngineError as e:
                return _result(id_, _tool_result({"error": {"code": e.code, "rule": rule_id(e.code), "message": e.message, "by": "smartdelegate"}}, True))
        return _error(id_, -32601, f"method not found: {method}")

    def serve(self, stdin=None, stdout=None) -> int:
        stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
        for line in stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):
                reply = _error(None, -32700, "parse error: the line is not JSON")
            else:
                try:
                    reply = self.handle(msg)
                except Exception as e:      # a bug answers this request and leaves the server running
                    reply = _error(msg.get("id") if isinstance(msg, dict) else None, -32603, f"internal error ({type(e).__name__})")
            if reply is not None:
                stdout.write(json.dumps(reply, separators=(",", ":")) + "\n")
                stdout.flush()
        return 0


def _result(id_, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _tool_result(value: dict, is_error: bool) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "structuredContent": value, "isError": is_error}


def main(argv: list | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("--help", "-h") for a in raw):
        print(__doc__)
        return 0
    switches = ("--admin", "--ops", "--govern")
    admin, ops, govern = (s in raw for s in switches)
    args = Args([a for a in raw if a not in switches])     # the CLI's own option parsing: --config, --bundle, --state
    unknown = sorted(set(args.flags) - {"config", "bundle", "state", "token-file", "shadow", "allow-tools"})
    if unknown or args.pos:
        print("smartdelegate mcp server: unknown option(s): " + ", ".join(["--" + u for u in unknown] + args.pos), file=sys.stderr)
        return 1
    allow = [t for t in args.flag("allow-tools").split(",") if t] if args.has("allow-tools") else None
    try:
        Server(None, admin=admin, allow_tools=allow)        # the flags are checked before anything is opened
    except ValueError as e:
        print(f"smartdelegate mcp server: {e}", file=sys.stderr)
        return 1
    cfg = load_config(args)
    try:
        engine = Engine(cfg)
    except EngineError as e:
        print(f"smartdelegate mcp server: {e}", file=sys.stderr)
        return 1
    if govern and OPS_RESOURCE not in engine.bundle.catalog:
        print(f"smartdelegate mcp server: --govern needs the resource '{OPS_RESOURCE}' in the bundle's catalog (see agents/bundle-example); "
              "without it every monitoring and privileged tool call is denied", file=sys.stderr)
    if not cfg.get("state_dir"):
        print("smartdelegate mcp server: no state directory, so the signing key lives only in this process. "
              "Tokens issued here will not verify anywhere else; pass --state DIR (the enforcement point's state directory).",
              file=sys.stderr)
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    with engine:
        try:
            return Server(engine, admin=admin, token_file=args.flag("token-file"), ops=ops, allow_tools=allow, govern=govern).serve()
        except (BrokenPipeError, KeyboardInterrupt):
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
