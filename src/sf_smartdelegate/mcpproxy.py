"""MCP proxy (`smartdelegate mcp-proxy`), stdio transport: the enforcement point
for Model Context Protocol tools.

    agent <-stdio-> smartdelegate mcp-proxy <-stdio-> real MCP server

    tools/list   tools without a mapping are hidden
    tools/call   authorised first; arguments are field-checked (strict);
                 results are masked before they reach the model. A mapping
                 with `lookup` first calls a read tool of the server itself
                 and takes resource attributes from the record it returns
    other        only an allow-list of methods passes (default deny)

The capability token comes from SMARTDELEGATE_TOKEN or --token-file (re-read on
every call, so the agent runtime can rotate it per task).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading

from .httpproxy import EARLY_DENIALS, expr_problem, resolve_expr

WITHHELD = "[withheld by SmartDelegate: this tool output is not JSON, so it cannot be field-checked]"
BASE_METHODS = ["initialize", "ping", "tools/list", "tools/call"]
TOOL_KEYS = {"action", "resource", "id", "attrs", "attrs_from_request", "lookup", "attrs_from_record", "spend", "input", "response"}
LOOKUP_ID = "smartdelegate-lookup-"
LOOKUP_TIMEOUT = 60.0


def tool_error(id_, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": {"content": [{"type": "text", "text": text}], "isError": True}}


def filter_result(engine, result: dict, obligations, decision_id) -> dict:
    def apply(data):
        r = engine.call("apply_obligations", {"obligations": obligations, "data": data, "decision_id": decision_id})
        return (r["data"], True) if r.get("ok") else (None, False)

    # keep only the members we know how to check; `_meta` and anything a
    # server invents could carry record data
    out = {k: v for k, v in result.items() if k in ("content", "structuredContent", "isError")}
    if "structuredContent" in out:
        out["structuredContent"] = apply(out["structuredContent"])[0]
    if isinstance(out.get("content"), list):
        items = []
        for item in out["content"]:
            text = item.get("text") if isinstance(item, dict) and item.get("type") == "text" else None
            parsed = None
            if isinstance(text, str):
                try:
                    parsed = json.loads(text)
                except (ValueError, RecursionError):
                    parsed = None
            if isinstance(parsed, (dict, list)):
                data, ok = apply(parsed)
                items.append({"type": "text", "text": json.dumps(data, separators=(",", ":")) if ok else WITHHELD})
            else:
                # plain text, images, audio, embedded resources: no field identity
                items.append({"type": "text", "text": WITHHELD})
        out["content"] = items
    return out


def _from_args(expr) -> bool:
    return isinstance(expr, str) and expr.startswith("args.")


def check_tools(tools: dict) -> tuple:
    """-> (errors, notes). Errors stop the proxy; notes are printed at start."""
    errors, notes = [], []
    if not isinstance(tools, dict) or not isinstance(tools.get("tools"), dict):
        return ["the tools file needs \"tools\" (an object)"], notes
    if set(tools) - {"server", "allow_methods", "tools"}:
        errors.append(f"unknown top-level key(s) {', '.join(sorted(set(tools) - {'server', 'allow_methods', 'tools'}))}")
    for name, m in tools["tools"].items():
        if not isinstance(m, dict):
            errors.append(f"tool {name}: the mapping is not an object")
            continue
        unknown = sorted(set(m) - TOOL_KEYS)
        if unknown:
            errors.append(f"tool {name}: unknown key(s) {', '.join(unknown)} (a misspelt key must not silently drop a check)")
        for key in ("action", "resource"):
            if not (isinstance(m.get(key), str) and m[key]):
                errors.append(f"tool {name}: \"{key}\" is required")
        if "id" in m and expr_problem(m["id"], ("args",)):
            errors.append(f"tool {name}: id: {expr_problem(m['id'], ('args',))}")
        if "input" in m:
            why = expr_problem(m["input"], ("args",), whole=True)
            if why or not isinstance(m["input"], str):
                why = why or 'must be "args" (all arguments) or "args.<name>"'
                errors.append(f"tool {name}: input: {why}")
        if "spend" in m:
            sp = m["spend"]
            if not isinstance(sp, dict) or set(sp) != {"currency", "amount"}:
                errors.append(f"tool {name}: \"spend\" must be {{\"currency\": ..., \"amount\": ...}}")
            else:
                for k in ("currency", "amount"):
                    if expr_problem(sp[k], ("args",)):
                        errors.append(f"tool {name}: spend.{k}: {expr_problem(sp[k], ('args',))}")
        if m.get("response", "filter") not in ("filter", "passthrough"):
            errors.append(f"tool {name}: \"response\" must be \"filter\" or \"passthrough\"")
        if isinstance(m.get("lookup"), dict):
            if set(m["lookup"]) - {"tool", "arguments"}:
                errors.append(f"tool {name}: lookup: unknown key(s) {', '.join(sorted(set(m['lookup']) - {'tool', 'arguments'}))}")
            for k, expr in (m["lookup"].get("arguments") or {}).items() if isinstance(m["lookup"].get("arguments", {}), dict) else []:
                if expr_problem(expr, ("args",)):
                    errors.append(f"tool {name}: lookup.arguments.{k}: {expr_problem(expr, ('args',))}")
        seen: dict = {}
        for key in ("attrs", "attrs_from_request", "attrs_from_record"):
            v = m.get(key)
            if v is None:
                continue
            if not isinstance(v, dict):
                errors.append(f"tool {name}: \"{key}\" must be an object")
                continue
            for attr, expr in v.items():
                if attr in seen:
                    errors.append(f"tool {name}: attribute '{attr}' is in \"{seen[attr]}\" and in \"{key}\"")
                seen[attr] = key
                if key == "attrs" and (expr == "args" or ((isinstance(expr, (dict, list, float)) or expr is None) and not (isinstance(expr, dict) and set(expr) == {"literal"}))):
                    errors.append(f"tool {name}: attrs.{attr} must be a constant: a string, an integer or a boolean")
                if key == "attrs" and _from_args(expr):
                    errors.append(f"tool {name}: attrs.{attr} = \"{expr}\" comes from the call's arguments, which the agent writes. "
                                  f"Move it to \"attrs_from_request\" (a claim), or take it from the record with \"lookup\" and \"attrs_from_record\"")
                if key == "attrs_from_request" and not _from_args(expr):
                    errors.append(f"tool {name}: attrs_from_request.{attr} must be \"args.<name>\"")
                if key == "attrs_from_record" and not (isinstance(expr, str) and expr):
                    errors.append(f"tool {name}: attrs_from_record.{attr} must name a field of the record")
        lk = m.get("lookup")
        if m.get("attrs_from_record") and lk is None:
            errors.append(f"tool {name}: \"attrs_from_record\" needs \"lookup\"")
        if lk is not None and not (isinstance(lk, dict) and isinstance(lk.get("tool"), str) and isinstance(lk.get("arguments", {}), dict)):
            errors.append(f"tool {name}: \"lookup\" must be {{\"tool\": <name>, \"arguments\": {{...}}}}")
        if isinstance(m.get("attrs_from_request"), dict) and m["attrs_from_request"]:
            notes.append(f"tool {name} trusts request-supplied attributes: {', '.join(sorted(m['attrs_from_request']))}")
    return errors, notes


def record_of(result) -> dict | None:
    """The record a lookup tool returned: `structuredContent`, or the first text item that is a JSON object."""
    if not isinstance(result, dict) or result.get("isError"):
        return None
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    for item in result.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
            try:
                v = json.loads(item["text"])
            except (ValueError, RecursionError):
                return None
            return v if isinstance(v, dict) else None
    return None


def decide_call(engine, tools: dict, token: str, name: str, arguments, lookup=None) -> tuple:
    """-> (decision, None) when allowed, or (None, denial text). `lookup(tool, arguments)`
    calls a tool of the server with the proxy's own authority and returns its result."""
    mapping = (tools.get("tools") or {}).get(name)
    if not isinstance(mapping, dict):
        return None, f"Denied by SmartDelegate: tool '{name}' has no access mapping (default deny)."
    sources = {"args": arguments if isinstance(arguments, dict) else {}}
    get = lambda e: resolve_expr(e, sources, {})
    rid, found = get(mapping["id"]) if "id" in mapping else ("any", True)
    context = {"mcp": {"server": str(tools.get("server") or "mcp"), "tool": name}}
    resource = {"path": mapping.get("resource"), "id": rid if found and isinstance(rid, str) else "any"}
    attrs, has_attrs = {}, False
    for key in ("attrs", "attrs_from_request"):
        if isinstance(mapping.get(key), dict):
            has_attrs = True
            for k, expr in mapping[key].items():
                v, ok = get(expr)
                if not ok:
                    return None, f"Denied by SmartDelegate: the call lacks the value for resource attribute '{k}'."
                attrs[k] = v

    def refusal(d: dict) -> str:
        err = d.get("error") or {}
        text = f"Denied by SmartDelegate ({d.get('reason') or err.get('code') or 'deny'}): {d.get('detail') or err.get('message') or 'not permitted'}."
        aid = (d.get("approval") or {}).get("id")
        if aid:
            text += f" A human can approve it with id {aid}; then retry the same call."
        return text

    if isinstance(mapping.get("lookup"), dict):
        # 1. what does not depend on the record is decided first
        pre = {"token": token, "action": mapping.get("action"), "resource": dict(resource, attrs=dict(attrs)) if has_attrs else dict(resource), "context": context}
        d = engine.call("authorize", dict(pre, dry_run=True))
        if not d.get("ok"):
            return None, refusal(d)
        if d.get("effect") != "allow" and d.get("reason") in EARLY_DENIALS:
            d = engine.call("authorize", pre)
            if not d.get("ok") or d.get("effect") != "allow":
                return None, refusal(d)
        # 2. the record, asked of the server by the proxy itself
        largs = {}
        for k, expr in (mapping["lookup"].get("arguments") or {}).items():
            v, ok = get(expr)
            if not ok:
                return None, f"Denied by SmartDelegate: the call lacks the argument '{k}' needed to look the record up."
            largs[k] = v
        record = record_of(lookup(mapping["lookup"]["tool"], largs)) if lookup else None
        if record is None:
            return None, "Denied by SmartDelegate (lookup_failed): the record could not be looked up, so the call cannot be decided."
        # 3. attributes from the record
        for k, expr in (mapping.get("attrs_from_record") or {}).items():
            cur, ok = record, True
            for part in str(expr).split("."):
                if not isinstance(cur, dict) or part not in cur:
                    ok = False
                    break
                cur = cur[part]
            if not ok or isinstance(cur, float) or not isinstance(cur, (str, int, bool)):
                return None, f"Denied by SmartDelegate (lookup_failed): the record has no usable value for resource attribute '{k}'."
            attrs[k] = cur
            has_attrs = True

    req = {"token": token, "action": mapping.get("action"), "resource": resource, "context": context}
    if has_attrs:
        resource["attrs"] = attrs
    if isinstance(mapping.get("spend"), dict):
        cur, ok1 = get(mapping["spend"].get("currency"))
        amount, ok2 = get(mapping["spend"].get("amount"))
        if not (ok1 and ok2 and isinstance(cur, str) and isinstance(amount, int) and not isinstance(amount, bool)):
            return None, "Denied by SmartDelegate: this tool spends money: it needs a currency and an integer amount in minor units."
        req["context"]["spend"] = {"currency": cur, "amount": amount}
    op = "authorize"
    if "input" in mapping:
        data, ok = get(mapping["input"])
        if not (ok and isinstance(data, dict)):
            # the mapping says these arguments hold record data; without an object there is nothing to check, and nothing is waved through
            return None, "Denied by SmartDelegate (invalid_input): this tool takes record data as an object, and the call does not carry one."
        req.update(data=data, strict=True)   # the part of the arguments that is record data
        op = "filter"
    d = engine.call(op, req)
    if not d.get("ok") or d.get("effect") != "allow":
        return None, refusal(d)
    d["_mode"] = mapping.get("response") or "filter"
    return d, None


def run(engine, tools: dict, command: list, token_file: str | None) -> int:
    errors, notes = check_tools(tools)
    if errors:
        print("smartdelegate: the tools file is refused:\n  " + "\n  ".join(errors), file=sys.stderr, flush=True)
        return 1
    for note in notes:
        print(f"smartdelegate mcp proxy: {note}", file=sys.stderr, flush=True)
    allowed = BASE_METHODS + [m for m in (tools.get("allow_methods") or []) if isinstance(m, str)]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1)
    out_lock = threading.Lock()
    pending: dict = {}
    pending_lock = threading.Lock()
    lookups = [0]

    def lookup(tool: str, arguments: dict):
        """Call a tool of the server for the proxy itself; its result never goes to the agent."""
        lookups[0] += 1
        lid = f"{LOOKUP_ID}{lookups[0]}"
        waiter = {"done": threading.Event(), "msg": None}
        with pending_lock:
            pending[json.dumps(lid)] = waiter
        try:
            child.stdin.write(json.dumps({"jsonrpc": "2.0", "id": lid, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}, separators=(",", ":")) + "\n")
            child.stdin.flush()
        except (OSError, ValueError):
            return None
        if not waiter["done"].wait(LOOKUP_TIMEOUT):
            with pending_lock:
                pending.pop(json.dumps(lid), None)
            return None
        msg = waiter["msg"]
        return msg.get("result") if isinstance(msg, dict) else None

    def send(msg: dict):
        with out_lock:
            sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
            sys.stdout.flush()

    def from_server():
        for line in child.stdout:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if not isinstance(msg, dict):
                continue
            if "method" in msg:
                # Server-initiated requests (sampling, elicitation, roots) are
                # not mediated, and log/progress notifications can carry record
                # data. Only the "tool list changed" signal passes.
                if "id" not in msg and msg["method"] == "notifications/tools/list_changed":
                    send(msg)
                continue
            with pending_lock:
                entry = pending.pop(json.dumps(msg.get("id")), None)
            if isinstance(entry, dict) and "done" in entry:
                entry["msg"] = msg          # the answer to the proxy's own lookup
                entry["done"].set()
                continue
            if entry == "list":
                listed = (msg.get("result") or {}).get("tools")
                if isinstance(listed, list):
                    msg["result"]["tools"] = [t for t in listed if isinstance(t, dict) and t.get("name") in (tools.get("tools") or {})]
            elif isinstance(entry, dict) and entry["_mode"] != "passthrough":
                if isinstance(msg.get("result"), dict):
                    msg["result"] = filter_result(engine, msg["result"], entry.get("obligations"), entry.get("decision_id"))
                elif "error" in msg:
                    # error text can echo record data
                    code = msg["error"].get("code") if isinstance(msg["error"], dict) else -32000
                    msg["error"] = {"code": code, "message": "tool failed (details withheld by SmartDelegate)"}
            send(msg)

    reader = threading.Thread(target=from_server, daemon=True)
    reader.start()
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if not isinstance(msg, dict) or "method" not in msg:
                continue        # batches, and replies to server requests we never forwarded
            method, id_ = str(msg["method"]), msg.get("id")
            if method.startswith("notifications/"):
                child.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
                child.stdin.flush()
                continue
            if isinstance(id_, str) and id_.startswith(LOOKUP_ID):
                send({"jsonrpc": "2.0", "id": id_, "error": {"code": -32600, "message": "request ids starting with 'smartdelegate-lookup-' are reserved"}})
                continue
            if method not in allowed:
                if id_ is not None:
                    send({"jsonrpc": "2.0", "id": id_, "error": {"code": -32601, "message": f"method '{method}' is blocked by SmartDelegate"}})
                continue
            if method == "tools/list":
                with pending_lock:
                    pending[json.dumps(id_)] = "list"
            elif method == "tools/call":
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                if token_file:
                    try:
                        token = open(token_file, encoding="utf-8").read().strip()
                    except OSError:
                        token = ""
                else:
                    token = os.environ.get("SMARTDELEGATE_TOKEN", "")
                decision, denial = decide_call(engine, tools, token, str(params.get("name") or ""), params.get("arguments"), lookup)
                if denial:
                    send(tool_error(id_, denial))
                    continue
                with pending_lock:
                    pending[json.dumps(id_)] = decision
            child.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
            child.stdin.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    try:
        child.stdin.close()
    except OSError:
        pass
    reader.join(timeout=10)
    child.wait(timeout=10)
    return 0
