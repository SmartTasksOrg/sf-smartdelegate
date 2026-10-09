"""HTTP egress proxy (`smartdelegate http-proxy`): the enforcement point for REST tools.

The agent calls  http://<proxy>/<upstream>/<path>  with its capability token
as the bearer credential. The proxy
  1. matches the call to a route (no route: 403, default deny)
  2. parses the query strictly and forwards only what it parsed
  3. on a route with `lookup`, fetches the record with its own credential and
     takes resource attributes from it (`attrs_from_record`)
  4. asks the engine for a decision (strict field check on JSON bodies)
  5. forwards with the *upstream's* credential, which the agent never holds
  6. applies the field mask and row filter to the JSON response
The normative description is spec/API.md, "Proxy configuration".
Responses are buffered. A response that is not JSON cannot be field-checked
and is withheld unless the route says "response": "passthrough".
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

from .daemon import JsonHandler, listen_address

_SAFE_PARAM = re.compile(r"^[A-Za-z0-9\-_.~:@]+$")
MAX_RESPONSE = 32 * 1024 * 1024
_QUERY_NAME = re.compile(r"^[A-Za-z0-9_.\-]+$")
_HEX = "0123456789abcdefABCDEF"
#: denials that do not depend on resource attributes: decided before a lookup,
#: so a caller outside the tenant or the capability learns nothing from it
EARLY_DENIALS = ("token_invalid", "token_expired", "token_revoked", "unknown_resource", "tenant_mismatch",
                 "capability_action", "capability_resource")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


# no proxy from the environment, no redirects: the route table decides where calls go
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def match_path(pattern: str, path: str):
    ps, xs = pattern.strip("/").split("/"), path.strip("/").split("/")
    if len(ps) != len(xs):
        return None
    params = {}
    for p, x in zip(ps, xs):
        if p.startswith("{") and p.endswith("}"):
            # A path parameter is forwarded verbatim and is also the resource
            # id that was authorised. Anything an upstream could decode into a
            # different path (%2F, .., ;) must never get that far.
            if not _SAFE_PARAM.match(x) or x in (".", ".."):
                return None
            params[p[1:-1]] = x
        elif p != x:
            return None
    return params


def resolve_expr(expr, sources: dict, params: dict):
    """"args.x.y" / "body.x" / "query.x" look into `sources`; "{name}" is a
    path parameter; anything else is a literal. Returns (value, found)."""
    if isinstance(expr, dict) and set(expr) == {"literal"}:
        return expr["literal"], True
    if not isinstance(expr, str):
        return expr, True
    if expr.startswith("{") and expr.endswith("}"):
        return params.get(expr[1:-1]), expr[1:-1] in params
    if expr in sources:
        return sources[expr], True          # the whole object: "args", "body", "query"
    head, _, tail = expr.partition(".")
    if tail and head in sources:
        cur = sources[head]
        for part in tail.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return None, False
            cur = cur[part]
        return cur, True
    return expr, True


def parse_query(raw: str, allowed: list):
    """-> ([(name, value)], None) or (None, (code, message)).

    The proxy authorises on exactly what it forwards, so a query the proxy
    and an upstream could read differently is refused, not interpreted:
    a name that is not listed, a name that appears twice (compared without
    regard to case), a name that is empty or not written literally
    (percent-encoded, `+`), a `;`, a malformed percent-escape, a value that
    is not UTF-8 or holds a control character. Values are percent-decoded
    (RFC 3986: `+` is a plus sign)."""
    if ";" in raw:
        return None, ("query_ambiguous", "';' in a query string is read as a separator by some servers and as data by others")
    pairs, seen = [], set()
    for seg in raw.split("&"):
        if seg == "":
            continue
        name, _, value = seg.partition("=")
        if name == "":
            return None, ("query_ambiguous", "a query parameter has no name")
        if not _QUERY_NAME.match(name):
            return None, ("query_ambiguous", "query parameter names must be written literally: letters, digits, '_', '.', '-'")
        if name not in allowed:
            return None, ("query_not_allowed", f"query parameter '{name}' is not allowed on this route")
        if name.lower() in seen:
            return None, ("query_duplicate", f"query parameter '{name}' appears more than once")
        seen.add(name.lower())
        out, i = bytearray(), 0
        while i < len(value):
            c = value[i]
            if c == "%":
                if len(value) - i < 3 or value[i + 1] not in _HEX or value[i + 2] not in _HEX:
                    return None, ("query_ambiguous", f"query parameter '{name}' has a malformed percent-escape")
                out.append(int(value[i + 1:i + 3], 16))
                i += 3
            elif not 0x21 <= ord(c) <= 0x7E:
                return None, ("query_ambiguous", f"query parameter '{name}' holds a character that must be percent-encoded")
            else:
                out.append(ord(c))
                i += 1
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            return None, ("query_ambiguous", f"query parameter '{name}' is not UTF-8")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
            return None, ("query_ambiguous", f"query parameter '{name}' holds a control character")
        pairs.append((name, text))
    return pairs, None


def serialise_query(pairs: list) -> str:
    return "&".join(f"{n}={urllib.parse.quote(v, safe='-_.~')}" for n, v in pairs)


ROUTE_KEYS = {"upstream", "method", "path", "action", "resource", "id", "attrs", "attrs_from_request", "lookup", "attrs_from_record",
              "spend", "request", "response", "data_key", "keep", "query"}


def expr_problem(expr, sources: tuple, params: set | None = None, whole: bool = False) -> str | None:
    """Why `expr` cannot stand where a value is taken from the request, or None.

    Allowed: `<source>.<a>[.<b>…]` for a source in `sources`; `{name}` for a path
    parameter in `params`; `<source>` alone when `whole`; `{"literal": value}`; a JSON
    number or boolean (it can only mean itself). A bare string is refused: `"args"`
    for `"args.changes"`, or `"body.amount"` misspelt, must not quietly become a
    constant and switch a check off."""
    if isinstance(expr, dict):
        return None if set(expr) == {"literal"} else "an object here must be {\"literal\": <value>}"
    if isinstance(expr, bool) or isinstance(expr, (int, float)):
        return None
    if not isinstance(expr, str) or expr == "":
        return "must be an expression or {\"literal\": <value>}"
    if expr.startswith("{") and expr.endswith("}"):
        if params is not None and expr[1:-1] in params:
            return None
        return f"{expr} is not a path parameter of this route" if params is not None else "path parameters do not exist here"
    head, dot, tail = expr.partition(".")
    if head in sources:
        if dot and tail and all(tail.split(".")):
            return None
        if not dot and whole:
            return None
        return f"\"{expr}\" names the whole {head}; a member is needed here (\"{head}.<name>\")" if not dot else f"\"{expr}\" is not a path into {head}"
    return (f"\"{expr}\" is not an expression ({', '.join(s + '.<name>' for s in sources)}"
            + (", {param}" if params is not None else "") + "); write {\"literal\": \"" + expr + "\"} if the constant is meant")


def missing_environment(routes: dict) -> list:
    """`env:NAME` references whose variable is unset or empty: the proxy must not start half-configured."""
    out = []
    for name, up in (routes.get("upstreams") or {}).items():
        if not isinstance(up, dict):
            continue
        refs = [("base_url", up.get("base_url"))] + [(f"headers.{k}", v) for k, v in (up.get("headers") or {}).items()]
        for where, v in refs:
            if isinstance(v, str) and v.startswith("env:") and not os.environ.get(v[4:]):
                out.append(f"upstream {name}: {where} is \"{v}\" and the environment variable {v[4:]} is not set")
    return out


def _path_params(pattern: str) -> set:
    return {p[1:-1] for p in str(pattern).strip("/").split("/") if p.startswith("{") and p.endswith("}")}


def check_routes(routes: dict) -> tuple:
    """-> (errors, notes). Errors stop the proxy; notes are printed at start."""
    errors, notes = [], []
    if not isinstance(routes, dict) or not isinstance(routes.get("upstreams"), dict) or not isinstance(routes.get("routes"), list):
        return ["the routes file needs \"upstreams\" (an object) and \"routes\" (a list)"], notes
    if set(routes) - {"upstreams", "routes", "listen"}:
        errors.append(f"unknown top-level key(s) {', '.join(sorted(set(routes) - {'upstreams', 'routes', 'listen'}))}")
    for name, up in routes["upstreams"].items():
        if not isinstance(up, dict) or not isinstance(up.get("base_url"), str) or set(up) - {"base_url", "headers"} or not isinstance(up.get("headers", {}), dict):
            errors.append(f"upstream {name}: needs \"base_url\" (a string) and may have \"headers\" (an object); nothing else")
    for n, r in enumerate(routes["routes"]):
        if not isinstance(r, dict):
            errors.append(f"route {n}: not an object")
            continue
        label = f"route {n} ({r.get('method')} /{r.get('upstream')}{r.get('path')})"
        params = _path_params(r.get("path", ""))
        unknown = sorted(set(r) - ROUTE_KEYS)
        if unknown:
            errors.append(f"{label}: unknown key(s) {', '.join(unknown)} (a misspelt key must not silently drop a check)")
        if not isinstance(r.get("upstream"), str) or r["upstream"] not in routes["upstreams"]:
            errors.append(f"{label}: there is no upstream named \"{r.get('upstream')}\"")
        for key in ("method", "path", "action", "resource"):
            if not (isinstance(r.get(key), str) and r[key]):
                errors.append(f"{label}: \"{key}\" is required")
        if "id" in r and expr_problem(r["id"], ("body", "query"), params):
            errors.append(f"{label}: id: {expr_problem(r['id'], ('body', 'query'), params)}")
        if "spend" in r:
            sp = r["spend"]
            if not isinstance(sp, dict) or set(sp) != {"currency", "amount"}:
                errors.append(f"{label}: \"spend\" must be {{\"currency\": ..., \"amount\": ...}}")
            else:
                for k in ("currency", "amount"):
                    why = expr_problem(sp[k], ("body", "query"), params)
                    if why:
                        errors.append(f"{label}: spend.{k}: {why}")
        if r.get("request", "checked") not in ("checked", "unchecked"):
            errors.append(f"{label}: \"request\" must be \"checked\" or \"unchecked\"")
        if r.get("response", "filter") not in ("filter", "passthrough"):
            errors.append(f"{label}: \"response\" must be \"filter\" or \"passthrough\"")
        for key in ("query", "keep"):
            if key in r and not (isinstance(r[key], list) and all(isinstance(x, str) for x in r[key])):
                errors.append(f"{label}: \"{key}\" must be a list of names")
        if "data_key" in r and not isinstance(r["data_key"], str):
            errors.append(f"{label}: \"data_key\" must be a string")
        seen: dict = {}
        for key in ("attrs", "attrs_from_request", "attrs_from_record"):
            v = r.get(key)
            if v is None:
                continue
            if not isinstance(v, dict):
                errors.append(f"{label}: \"{key}\" must be an object")
                continue
            for name, expr in v.items():
                if name in seen:
                    errors.append(f"{label}: attribute '{name}' is in \"{seen[name]}\" and in \"{key}\"")
                seen[name] = key
                from_request = isinstance(expr, str) and expr.split(".", 1)[0] in ("body", "query") and "." in expr
                if key == "attrs" and isinstance(expr, str) and expr in ("body", "query"):
                    errors.append(f"{label}: attrs.{name} = \"{expr}\" names the whole {expr} of the request; an attribute fixed by the route is a constant or a path parameter")
                if key == "attrs" and (isinstance(expr, (dict, list, float)) or expr is None) and not (isinstance(expr, dict) and set(expr) == {"literal"}):
                    errors.append(f"{label}: attrs.{name} must be a string, an integer, a boolean or a path parameter")
                if key == "attrs" and from_request:
                    errors.append(f"{label}: attrs.{name} = \"{expr}\" comes from the request, which the agent writes. "
                                  f"Move it to \"attrs_from_request\" (a claim), or take it from the record with \"lookup\" and \"attrs_from_record\"")
                if key == "attrs" and isinstance(expr, str) and expr.startswith("{") and expr.endswith("}") and expr[1:-1] not in params:
                    errors.append(f"{label}: attrs.{name} names the path parameter {expr}, which the path does not have")
                if key == "attrs_from_request" and not from_request:
                    errors.append(f"{label}: attrs_from_request.{name} must be \"body.<field>\" or \"query.<name>\"")
                if key == "attrs_from_record" and not (isinstance(expr, str) and expr):
                    errors.append(f"{label}: attrs_from_record.{name} must name a field of the record (\"a.b\")")
        lookup = r.get("lookup")
        if r.get("attrs_from_record") and lookup is None:
            errors.append(f"{label}: \"attrs_from_record\" needs \"lookup\"")
        if lookup is not None:
            if not (isinstance(lookup, str) and lookup.startswith("/")):
                errors.append(f"{label}: \"lookup\" must be a path on the same upstream, starting with '/'")
            else:
                unknown = sorted(x for x in _path_params(lookup) - params if not (x.split(".", 1)[0] in ("body", "query") and "." in x))
                if unknown:
                    errors.append(f"{label}: \"lookup\" uses {unknown}: a placeholder must be a path parameter of the route, {{body.<field>}} or {{query.<name>}}")
        claimed = sorted(r.get("attrs_from_request") or {}) if isinstance(r.get("attrs_from_request"), dict) else []
        if claimed:
            notes.append(f"{label} trusts request-supplied attributes: {', '.join(claimed)}")
            if isinstance(r.get("data_key"), str):
                notes.append(f"warning: {label} is a list route decided on request-supplied attributes; "
                             f"only a row filter in the deciding policy controls which records come back")
    return errors, notes


class _Handler(JsonHandler):
    def deny(self, status: int, code: str, detail: str, extra: dict | None = None):
        err = {"code": code, "message": detail, "by": "smartdelegate"}
        err.update(extra or {})
        self.send_json(status, {"error": err})

    def _upstream_headers(self, upstream: dict) -> dict:
        headers = {}
        for k, v in (upstream.get("headers") or {}).items():
            v = str(v)
            headers[k] = os.environ.get(v[4:], "") if v.startswith("env:") else v
        return headers

    @staticmethod
    def _base(upstream: dict) -> str:
        v = str(upstream.get("base_url", ""))
        return (os.environ.get(v[4:], "") if v.startswith("env:") else v).rstrip("/")

    def _fetch(self, method: str, target: str, headers: dict, data: bytes | None):
        """-> (status, content type, payload bytes), or (None, code, message). A payload over the cap comes back longer than MAX_RESPONSE."""
        try:
            resp = _OPENER.open(urllib.request.Request(target, data=data, headers=headers, method=method), timeout=60)
        except urllib.error.HTTPError as e:
            resp = e
        except (urllib.error.URLError, OSError, ValueError) as e:
            return None, "upstream_unreachable", str(e)
        try:
            with resp:
                status = resp.status if hasattr(resp, "status") else resp.code
                ctype = resp.headers.get("Content-Type") or "application/octet-stream"
                payload = resp.read(MAX_RESPONSE + 1)
        except OSError as e:
            return None, "upstream_unreachable", str(e)
        return status, ctype, payload

    def _handle(self):
        srv = self.server
        routes, engine = srv.routes, srv.engine
        method = self.command.upper()
        full, _, query = self.path.partition("?")
        up_name, _, rest = full.lstrip("/").partition("/")
        rest = "/" + rest
        # The body is read by Content-Length and by nothing else. A request framed any other way would
        # leave bytes on the connection that this server and whatever sits in front of it could read
        # as two different requests, so it is refused and the connection is closed.
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            if self.headers.get("Content-Length") is not None:
                return self.deny(400, "invalid_input", "a request with both Transfer-Encoding and Content-Length is refused")
            return self.deny(411, "length_required", "send the body with Content-Length; Transfer-Encoding is not accepted")
        lengths = self.headers.get_all("Content-Length") or []
        if len(lengths) > 1 or (lengths and not lengths[0].strip().isdigit()):
            self.close_connection = True
            return self.deny(400, "invalid_input", "Content-Length must appear once and be a number")
        raw, err = self.read_body()
        if err:
            self.close_connection = True
            return self.deny(400, "invalid_input", err)
        upstream = (routes.get("upstreams") or {}).get(up_name)
        if not isinstance(upstream, dict):
            return self.deny(403, "no_route", "unknown upstream")
        route = params = None
        for r in routes.get("routes") or []:
            if r.get("upstream") == up_name and str(r.get("method", "")).upper() == method:
                params = match_path(str(r.get("path", "")), rest)
                if params is not None:
                    route = r
                    break
        if route is None:
            return self.deny(403, "no_route", "no route covers this call, so it is denied")
        # the query: only listed names, each once, forwarded as parsed
        pairs, bad = parse_query(query, [q for q in (route.get("query") or []) if isinstance(q, str)])
        if bad:
            return self.deny(400, bad[0], bad[1])
        qmap = dict(pairs)
        forward_query = serialise_query(pairs)
        token = self.bearer()
        if not token:
            return self.deny(401, "token_invalid", "send the capability token as a Bearer credential")
        body = None
        if raw:
            try:
                body = json.loads(raw)
            except (ValueError, RecursionError):
                return self.deny(415, "invalid_input", "request bodies must be JSON so they can be field-checked")
        sources = {"body": body, "query": qmap}
        get = lambda e: resolve_expr(e, sources, params)

        rid, found = get(route["id"]) if "id" in route else ("any", True)
        attrs, has_attrs = {}, False
        for key in ("attrs", "attrs_from_request"):
            if isinstance(route.get(key), dict):
                has_attrs = True
                for k, expr in route[key].items():
                    v, ok = get(expr)
                    if not ok:
                        return self.deny(400, "invalid_input", f"the request lacks the value for resource attribute '{k}'")
                    attrs[k] = v
        context = {"http": {"method": method, "upstream": up_name, "path": rest}}
        resource = {"path": route.get("resource"), "id": rid if found and isinstance(rid, str) else "any"}
        base, up_headers = self._base(upstream), self._upstream_headers(upstream)

        record, lookup_path = None, None
        if isinstance(route.get("lookup"), str):
            # 1. what does not depend on the record is decided first: a caller whose token,
            #    tenant or capability does not cover this resource causes no upstream call
            pre = {"token": token, "action": route.get("action"), "resource": dict(resource, attrs=dict(attrs)) if has_attrs else dict(resource), "context": context}
            d = engine.call("authorize", dict(pre, dry_run=True))
            if not d.get("ok"):
                e = d.get("error") or {}
                return self.deny(400, e.get("code", "invalid_input"), e.get("message", ""))
            if d.get("effect") != "allow" and d.get("reason") in EARLY_DENIALS:
                d = engine.call("authorize", pre)       # the same refusal, this time on the record
                if d.get("effect") != "allow":
                    return self.deny(403, d.get("reason", "deny"), d.get("detail", ""), {"decision_id": d.get("decision_id"), "approval": None})
            # 2. the record, with the proxy's own credential
            segs = []
            for seg in route["lookup"].strip("/").split("/"):
                if seg.startswith("{") and seg.endswith("}"):
                    v, ok = get(seg) if seg[1:-1] in params else get(seg[1:-1])
                    # a value from the body or the query becomes part of a path: the same characters as a path parameter, nothing else
                    if not ok or not isinstance(v, str) or not _SAFE_PARAM.match(v) or v in (".", ".."):
                        return self.deny(400, "invalid_input", f"the request lacks a usable value for {seg} in the lookup path")
                    seg = v
                segs.append(seg)
            lookup_path = "/" + "/".join(segs)
            status, ctype, payload = self._fetch("GET", base + lookup_path, dict(up_headers), None)
            if status is None:
                return self.deny(502, ctype, payload)
            if status == 404:
                return self.deny(404, "not_found", "the upstream has no such record")
            if status != 200 or len(payload) > MAX_RESPONSE:
                return self.deny(502, "lookup_failed", f"the lookup of the record did not succeed (upstream status {status})")
            try:
                record = json.loads(payload)
            except (ValueError, RecursionError):
                record = None
            if not isinstance(record, dict):
                return self.deny(502, "lookup_failed", "the lookup did not return a JSON object")
            # 3. attributes from the record
            for k, expr in (route.get("attrs_from_record") or {}).items():
                cur, ok = record, True
                for part in str(expr).split("."):
                    if not isinstance(cur, dict) or part not in cur:
                        ok = False
                        break
                    cur = cur[part]
                if not ok or isinstance(cur, float) or not isinstance(cur, (str, int, bool)):
                    return self.deny(502, "lookup_failed", f"the record has no usable value for resource attribute '{k}'")
                attrs[k] = cur
                has_attrs = True

        req = {"token": token, "action": route.get("action"), "resource": resource, "context": context}
        if has_attrs:
            resource["attrs"] = attrs
        if isinstance(route.get("spend"), dict):
            cur, ok1 = get(route["spend"].get("currency"))
            amount, ok2 = get(route["spend"].get("amount"))
            if not (ok1 and ok2 and isinstance(cur, str) and isinstance(amount, int) and not isinstance(amount, bool)):
                return self.deny(400, "invalid_input", "this route spends money: the body must carry the currency and an integer amount in minor units")
            req["context"]["spend"] = {"currency": cur, "amount": amount}
        if isinstance(body, dict) and route.get("request") != "unchecked":
            req.update(data=body, strict=True)
            op = "filter"
        else:
            op = "authorize"
        # The decision also reserves the spend and uses up an approval, before the upstream is
        # called: a budget must never be overrun, so it is not refunded when the upstream refuses.
        d = engine.call(op, req)
        if not d.get("ok"):
            e = d.get("error") or {}
            return self.deny(400, e.get("code", "invalid_input"), e.get("message", ""))
        if d.get("effect") != "allow":
            return self.deny(403, d.get("reason", "deny"), d.get("detail", ""), {"decision_id": d.get("decision_id"), "approval": d.get("approval")})

        passthrough = route.get("response") == "passthrough"
        if record is not None and method == "GET" and lookup_path == rest and not pairs and not passthrough:
            # a read of the record that was just fetched: answer from it, no second fetch
            status, payload = 200, json.dumps(record).encode("utf-8")
        else:
            # forward with the upstream's own credential, and the query as parsed
            target = base + rest + (f"?{forward_query}" if forward_query else "")
            headers = dict(up_headers)
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            status, ctype, payload = self._fetch(method, target, headers, data)
            if status is None:
                return self.deny(502, ctype, payload)
        if len(payload) > MAX_RESPONSE:
            return self.deny(502, "unfilterable_response", "the upstream response is too large to check")
        if passthrough:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if not payload.strip():
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            upstream_json = json.loads(payload)
        except (ValueError, RecursionError):
            return self.deny(502, "unfilterable_response", "the upstream response is not JSON, so it cannot be field-checked and is withheld",
                             {"decision_id": d.get("decision_id")})
        if status >= 400:
            # upstream error bodies can echo record data; return the status only
            return self.deny(status, "upstream_error", "the upstream returned an error; its body is withheld")
        # {"items": [...], "next": "..."} envelopes: filter the records, keep only the keys the route lists
        key = route.get("data_key") if isinstance(route.get("data_key"), str) else None
        records = upstream_json.get(key) if (key and isinstance(upstream_json, dict)) else (None if key else upstream_json)
        applied = engine.call("apply_obligations", {"obligations": d.get("obligations"), "data": records, "decision_id": d.get("decision_id")})
        if not applied.get("ok"):
            return self.deny(502, "unfilterable_response", (applied.get("error") or {}).get("message", ""))
        if key:
            out = {key: applied["data"]}
            for keep in route.get("keep") or []:
                if isinstance(upstream_json, dict) and keep in upstream_json:
                    out[keep] = upstream_json[keep]
        else:
            out = applied["data"]
        self.send_json(status, out, {"X-SmartDelegate-Decision": str(d.get("decision_id")), "X-SmartDelegate-Masked": str(len(applied.get("masked") or []))})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


def serve(engine, routes: dict, listen: str) -> None:
    errors, notes = check_routes(routes)
    errors = errors or missing_environment(routes)
    if errors:
        raise SystemExit("smartdelegate: the routes file is refused:\n  " + "\n  ".join(errors))
    server = ThreadingHTTPServer(listen_address(listen), _Handler)
    server.daemon_threads = True
    server.engine, server.routes = engine, routes
    host, port = server.server_address[:2]
    print(f"smartdelegate http proxy listening on http://{host}:{port}", file=sys.stderr, flush=True)
    for note in notes:
        print(f"smartdelegate http proxy: {note}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
