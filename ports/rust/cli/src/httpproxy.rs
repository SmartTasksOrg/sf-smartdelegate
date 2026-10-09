//! HTTP egress proxy: the enforcement point for REST tools.
//!
//! The agent calls  http://<proxy>/<upstream>/<path>  with its capability
//! token as the bearer credential. The proxy
//!   1. matches the call to a route (no route: 403, default deny)
//!   2. asks the engine for a decision (strict field check on JSON bodies)
//!   3. forwards with the *upstream's* credential, which the agent never holds
//!   4. applies the field mask and row filter to the JSON response
//! Responses are buffered. A response that is not JSON cannot be field-checked
//! and is blocked unless the route says `"response": "passthrough"`.

use crate::http::{Request, Response, MAX_BODY};
use crate::util::{die, expr_problem, is_literal, json_arg, one_of, record_attr, resolve_expr, unknown_keys, Args, EARLY_DENIALS};
use serde_json::{json, Map, Value};
use smartdelegate_core::Engine;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, Mutex};

/// The largest upstream response the proxy handles (it is buffered whole).
const MAX_RESPONSE: u64 = 32 * 1024 * 1024;

/// A path parameter is forwarded verbatim and is also the resource id that
/// was authorised. Anything an upstream could decode into a different path
/// (%2F, .., ;) must never get that far.
fn safe_param(x: &str) -> bool {
    !x.is_empty() && x != "." && x != ".." && x.chars().all(|c| c.is_ascii_alphanumeric() || "-_.~:@".contains(c))
}

fn match_path(pattern: &str, path: &str) -> Option<HashMap<String, String>> {
    let (ps, xs): (Vec<&str>, Vec<&str>) = (pattern.trim_matches('/').split('/').collect(), path.trim_matches('/').split('/').collect());
    if ps.len() != xs.len() {
        return None;
    }
    let mut params = HashMap::new();
    for (p, x) in ps.iter().zip(xs.iter()) {
        if p.starts_with('{') && p.ends_with('}') && p.len() >= 2 {
            if !safe_param(x) {
                return None;
            }
            params.insert(p[1..p.len() - 1].to_string(), x.to_string());
        } else if p != x {
            return None;
        }
    }
    Some(params)
}

/// The query, read strictly: `Ok(pairs of (name, decoded value))`, or
/// `Err((code, message))`.
///
/// The proxy authorises on exactly what it forwards, so a query the proxy and
/// an upstream could read differently is refused, not interpreted: a name
/// that is not listed, a name that appears twice (compared without regard to
/// case), a name that is empty or not written literally (percent-encoded,
/// `+`), a `;`, a malformed percent-escape, a value that is not UTF-8 or
/// holds a control character. Values are percent-decoded (RFC 3986: `+` is a
/// plus sign).
pub fn parse_query(raw: &str, allowed: &[&str]) -> Result<Vec<(String, String)>, (&'static str, String)> {
    if raw.contains(';') {
        return Err(("query_ambiguous", "';' in a query string is read as a separator by some servers and as data by others".into()));
    }
    let mut pairs = Vec::new();
    let mut seen = HashSet::new();
    for seg in raw.split('&') {
        if seg.is_empty() {
            continue;
        }
        let (name, value) = seg.split_once('=').unwrap_or((seg, ""));
        if name.is_empty() {
            return Err(("query_ambiguous", "a query parameter has no name".into()));
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
            return Err(("query_ambiguous", "query parameter names must be written literally: letters, digits, '_', '.', '-'".into()));
        }
        if !allowed.contains(&name) {
            return Err(("query_not_allowed", format!("query parameter '{name}' is not allowed on this route")));
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(("query_duplicate", format!("query parameter '{name}' appears more than once")));
        }
        let bytes = value.as_bytes();
        let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'%' {
                match (bytes.get(i + 1).copied().and_then(hex), bytes.get(i + 2).copied().and_then(hex)) {
                    (Some(h), Some(l)) => out.push(h * 16 + l),
                    _ => return Err(("query_ambiguous", format!("query parameter '{name}' has a malformed percent-escape"))),
                }
                i += 3;
            } else if !(0x21..=0x7E).contains(&c) {
                return Err(("query_ambiguous", format!("query parameter '{name}' holds a character that must be percent-encoded")));
            } else {
                out.push(c);
                i += 1;
            }
        }
        let text = String::from_utf8(out).map_err(|_| ("query_ambiguous", format!("query parameter '{name}' is not UTF-8")))?;
        if text.chars().any(|ch| (ch as u32) < 0x20 || ch as u32 == 0x7F) {
            return Err(("query_ambiguous", format!("query parameter '{name}' holds a control character")));
        }
        pairs.push((name.to_string(), text));
    }
    Ok(pairs)
}

/// `name=value&...` in the order received, every byte of a value
/// percent-encoded except `A-Z a-z 0-9 - _ . ~`.
pub fn serialise_query(pairs: &[(String, String)]) -> String {
    let mut out = String::new();
    for (i, (n, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(n);
        out.push('=');
        for b in v.bytes() {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

fn path_params(pattern: &str) -> HashSet<String> {
    pattern.trim_matches('/').split('/').filter(|p| p.len() >= 2 && p.starts_with('{') && p.ends_with('}')).map(|p| p[1..p.len() - 1].to_string()).collect()
}

/// How a value of the routes file is shown in a message.
fn shown(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// `body.<field>` or `query.<name>`: a value the agent writes.
fn from_request(expr: &Value) -> bool {
    expr.as_str().and_then(|e| e.split_once('.')).map(|(head, _)| head == "body" || head == "query").unwrap_or(false)
}

const ROUTE_KEYS: [&str; 16] = [
    "upstream", "method", "path", "action", "resource", "id", "attrs", "attrs_from_request", "lookup", "attrs_from_record", "spend", "request", "response", "data_key", "keep", "query",
];

/// `env:NAME` references whose variable is unset or empty: the proxy must
/// not start half-configured.
pub fn missing_environment(routes: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for (name, up) in routes["upstreams"].as_object().into_iter().flatten() {
        if !up.is_object() {
            continue;
        }
        let mut refs = vec![("base_url".to_string(), up.get("base_url"))];
        for (k, v) in up["headers"].as_object().into_iter().flatten() {
            refs.push((format!("headers.{k}"), Some(v)));
        }
        for (place, v) in refs {
            if let Some(var) = v.and_then(|v| v.as_str()).and_then(|v| v.strip_prefix("env:")) {
                if std::env::var(var).map(|x| x.is_empty()).unwrap_or(true) {
                    out.push(format!("upstream {name}: {place} is \"env:{var}\" and the environment variable {var} is not set"));
                }
            }
        }
    }
    out
}

/// `(errors, notes)`. Errors stop the proxy; notes are printed at start.
pub fn check_routes(routes: &Value) -> (Vec<String>, Vec<String>) {
    let (mut errors, mut notes) = (Vec::new(), Vec::new());
    let list = match (routes.get("upstreams").map(|u| u.is_object()), routes.get("routes").and_then(|r| r.as_array())) {
        (Some(true), Some(list)) if routes.is_object() => list,
        _ => return (vec!["the routes file needs \"upstreams\" (an object) and \"routes\" (a list)".into()], notes),
    };
    // closed key sets everywhere: a misspelt key must not silently drop a check
    let top = unknown_keys(routes.as_object().expect("checked above"), &["upstreams", "routes", "listen"]);
    if !top.is_empty() {
        errors.push(format!("unknown top-level key(s) {}", top.join(", ")));
    }
    let upstreams = routes["upstreams"].as_object().expect("checked above");
    for (name, up) in upstreams {
        let ok = up.as_object().map(|o| o.get("base_url").map(|b| b.is_string()).unwrap_or(false) && unknown_keys(o, &["base_url", "headers"]).is_empty() && o.get("headers").map(|h| h.is_object()).unwrap_or(true)).unwrap_or(false);
        if !ok {
            errors.push(format!("upstream {name}: needs \"base_url\" (a string) and may have \"headers\" (an object); nothing else"));
        }
    }
    for (n, r) in list.iter().enumerate() {
        let Some(robj) = r.as_object() else {
            errors.push(format!("route {n}: not an object"));
            continue;
        };
        let label = format!("route {n} ({} /{}{})", shown(r.get("method")), shown(r.get("upstream")), shown(r.get("path")));
        let params = path_params(&r.get("path").map(|p| shown(Some(p))).unwrap_or_default());
        let unknown = unknown_keys(robj, &ROUTE_KEYS);
        if !unknown.is_empty() {
            errors.push(format!("{label}: unknown key(s) {} (a misspelt key must not silently drop a check)", unknown.join(", ")));
        }
        if !r.get("upstream").and_then(|u| u.as_str()).map(|u| upstreams.contains_key(u)).unwrap_or(false) {
            errors.push(format!("{label}: there is no upstream named \"{}\"", shown(r.get("upstream"))));
        }
        for key in ["method", "path", "action", "resource"] {
            if !r.get(key).and_then(|v| v.as_str()).map(|v| !v.is_empty()).unwrap_or(false) {
                errors.push(format!("{label}: \"{key}\" is required"));
            }
        }
        let request_sources = ["body", "query"];
        if let Some(why) = r.get("id").and_then(|e| expr_problem(e, &request_sources, Some(&params), false)) {
            errors.push(format!("{label}: id: {why}"));
        }
        if let Some(sp) = r.get("spend") {
            match sp.as_object().filter(|o| o.len() == 2 && o.contains_key("currency") && o.contains_key("amount")) {
                None => errors.push(format!("{label}: \"spend\" must be {{\"currency\": ..., \"amount\": ...}}")),
                Some(o) => {
                    for k in ["currency", "amount"] {
                        if let Some(why) = expr_problem(&o[k], &request_sources, Some(&params), false) {
                            errors.push(format!("{label}: spend.{k}: {why}"));
                        }
                    }
                }
            }
        }
        if !one_of(r, "request", &["checked", "unchecked"]) {
            errors.push(format!("{label}: \"request\" must be \"checked\" or \"unchecked\""));
        }
        if !one_of(r, "response", &["filter", "passthrough"]) {
            errors.push(format!("{label}: \"response\" must be \"filter\" or \"passthrough\""));
        }
        for key in ["query", "keep"] {
            if let Some(v) = r.get(key) {
                if !v.as_array().map(|a| a.iter().all(|x| x.is_string())).unwrap_or(false) {
                    errors.push(format!("{label}: \"{key}\" must be a list of names"));
                }
            }
        }
        if r.get("data_key").map(|k| !k.is_string()).unwrap_or(false) {
            errors.push(format!("{label}: \"data_key\" must be a string"));
        }
        let mut seen: Vec<(String, &str)> = Vec::new();
        for key in ["attrs", "attrs_from_request", "attrs_from_record"] {
            let v = match r.get(key) {
                None | Some(Value::Null) => continue,
                Some(Value::Object(m)) => m,
                Some(_) => {
                    errors.push(format!("{label}: \"{key}\" must be an object"));
                    continue;
                }
            };
            for (name, expr) in v {
                if let Some((_, first)) = seen.iter().find(|(k, _)| k == name) {
                    errors.push(format!("{label}: attribute '{name}' is in \"{first}\" and in \"{key}\""));
                }
                seen.retain(|(k, _)| k != name);
                seen.push((name.clone(), key));
                let claimed = from_request(expr);
                let text = expr.as_str().unwrap_or("");
                if key == "attrs" && (text == "body" || text == "query") {
                    errors.push(format!("{label}: attrs.{name} = \"{text}\" names the whole {text} of the request; an attribute fixed by the route is a constant or a path parameter"));
                }
                let constant = expr.is_string() || expr.is_boolean() || expr.is_i64() || expr.is_u64() || is_literal(expr);
                if key == "attrs" && !constant {
                    errors.push(format!("{label}: attrs.{name} must be a string, an integer, a boolean or a path parameter"));
                }
                if key == "attrs" && claimed {
                    errors.push(format!(
                        "{label}: attrs.{name} = \"{text}\" comes from the request, which the agent writes. Move it to \"attrs_from_request\" (a claim), or take it from the record with \"lookup\" and \"attrs_from_record\""
                    ));
                }
                if key == "attrs" && text.len() >= 2 && text.starts_with('{') && text.ends_with('}') && !params.contains(&text[1..text.len() - 1]) {
                    errors.push(format!("{label}: attrs.{name} names the path parameter {text}, which the path does not have"));
                }
                if key == "attrs_from_request" && !claimed {
                    errors.push(format!("{label}: attrs_from_request.{name} must be \"body.<field>\" or \"query.<name>\""));
                }
                if key == "attrs_from_record" && text.is_empty() {
                    errors.push(format!("{label}: attrs_from_record.{name} must name a field of the record (\"a.b\")"));
                }
            }
        }
        let lookup = r.get("lookup").filter(|l| !l.is_null());
        let has_record_attrs = match r.get("attrs_from_record") {
            None | Some(Value::Null) | Some(Value::Bool(false)) => false,
            Some(Value::Object(m)) => !m.is_empty(),
            Some(Value::Array(a)) => !a.is_empty(),
            Some(Value::String(s)) => !s.is_empty(),
            Some(Value::Number(x)) => x.as_f64() != Some(0.0),
            Some(Value::Bool(true)) => true,
        };
        if has_record_attrs && lookup.is_none() {
            errors.push(format!("{label}: \"attrs_from_record\" needs \"lookup\""));
        }
        if let Some(l) = lookup {
            match l.as_str().filter(|s| s.starts_with('/')) {
                None => errors.push(format!("{label}: \"lookup\" must be a path on the same upstream, starting with '/'")),
                Some(path) => {
                    let mut unknown: Vec<String> = path_params(path).into_iter().filter(|x| !params.contains(x) && !from_request(&json!(x))).collect();
                    unknown.sort();
                    if !unknown.is_empty() {
                        let listed = unknown.iter().map(|x| format!("'{x}'")).collect::<Vec<_>>().join(", ");
                        errors.push(format!("{label}: \"lookup\" uses [{listed}]: a placeholder must be a path parameter of the route, {{body.<field>}} or {{query.<name>}}"));
                    }
                }
            }
        }
        if let Some(m) = r.get("attrs_from_request").and_then(|a| a.as_object()).filter(|m| !m.is_empty()) {
            let mut claimed: Vec<&str> = m.keys().map(|k| k.as_str()).collect();
            claimed.sort();
            notes.push(format!("{label} trusts request-supplied attributes: {}", claimed.join(", ")));
            if r.get("data_key").map(|k| k.is_string()).unwrap_or(false) {
                notes.push(format!("warning: {label} is a list route decided on request-supplied attributes; only a row filter in the deciding policy controls which records come back"));
            }
        }
    }
    (errors, notes)
}

fn deny(status: u16, code: &str, detail: &str, extra: Value) -> Response {
    let mut body = json!({"error": {"code": code, "message": detail, "by": "smartdelegate"}});
    if let (Some(o), Some(e)) = (body["error"].as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    Response::json(status, &body)
}

/// `"env:NAME"` reads the environment variable when a request is forwarded.
fn setting(v: Option<&Value>) -> String {
    let text = match v {
        None => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => shown(Some(other)),
    };
    match text.strip_prefix("env:") {
        Some(name) => std::env::var(name).unwrap_or_default(),
        None => text,
    }
}

fn upstream_headers(upstream: &Value) -> Vec<(String, String)> {
    upstream["headers"].as_object().map(|hs| hs.iter().map(|(k, v)| (k.clone(), setting(Some(v)))).collect()).unwrap_or_default()
}

/// One call to the upstream with its own credential: `Ok((status, content
/// type, body))`, or `Err(message)` when it cannot be reached. One byte more
/// than the limit is read, so that "too large" is known and can be refused;
/// a response is never cut short and handed on as complete.
fn fetch(http: &ureq::Agent, method: &str, target: &str, headers: &[(String, String)], body: Option<&Value>) -> Result<(u16, String, Vec<u8>), String> {
    // identity: the bytes handed on are the bytes the upstream holds
    let mut out = http.request(method, target).set("Accept-Encoding", "identity");
    for (k, v) in headers {
        out = out.set(k, v);
    }
    let result = match body {
        None => out.call(),
        Some(b) => out.set("Content-Type", "application/json").send_bytes(b.to_string().as_bytes()),
    };
    let resp = match result {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(e.to_string()),
    };
    let status = resp.status();
    let ctype = resp.header("Content-Type").unwrap_or("application/octet-stream").to_string();
    let mut payload = Vec::new();
    resp.into_reader().take(MAX_RESPONSE + 1).read_to_end(&mut payload).map_err(|e| e.to_string())?;
    Ok((status, ctype, payload))
}

fn call(engine: &Mutex<Engine>, op: &str, input: &Value) -> Value {
    match engine.lock() {
        Ok(mut e) => e.call(op, input),
        Err(_) => smartdelegate_core::Error::new("internal", "engine unavailable").to_json(),
    }
}

/// The steps, in the order of spec/API.md "Proxy configuration": body,
/// route, query, token, JSON, attributes, lookup, spend, decision, upstream,
/// response. The first step that fails answers; nothing later happens.
fn handle(req: Request, engine: &Arc<Mutex<Engine>>, routes: &Value, http: &ureq::Agent) -> Response {
    let (full_path, query) = req.target.split_once('?').unwrap_or((req.target.as_str(), ""));
    // methods are case-sensitive; these five are the ones the proxy mediates
    let method = req.method.clone();
    if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
        return deny(501, "invalid_input", &format!("unsupported method ('{method}')"), json!({}));
    }
    let trimmed = full_path.trim_start_matches('/');
    let (up_name, rest) = trimmed.split_once('/').unwrap_or((trimmed, ""));
    let rest = format!("/{rest}");

    // 1. the body
    // 1. the body. A request that is not framed by exactly one Content-Length
    // was refused by the server before a byte of a body was read, and its
    // connection is closed: what follows is never read as a request.
    let raw = match &req.body {
        Ok(raw) => raw,
        Err(bad) => return deny(bad.status, bad.code, &bad.message, json!({})),
    };
    debug_assert!(raw.len() <= MAX_BODY);

    // 2. the route
    let Some(upstream) = routes["upstreams"].get(up_name).filter(|u| u.is_object()) else { return deny(403, "no_route", "unknown upstream", json!({})) };
    let empty = vec![];
    let found = routes["routes"].as_array().unwrap_or(&empty).iter().find_map(|r| {
        if r["upstream"].as_str() != Some(up_name) || r.get("method").map(|m| shown(Some(m)).to_uppercase()) != Some(method.clone()) {
            return None;
        }
        match_path(&r.get("path").map(|p| shown(Some(p))).unwrap_or_default(), &rest).map(|p| (r, p))
    });
    let Some((route, params)) = found else { return deny(403, "no_route", "no route covers this call, so it is denied", json!({})) };

    // 3. the query: only listed names, each once, forwarded as parsed
    let allowed: Vec<&str> = route["query"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
    let pairs = match parse_query(query, &allowed) {
        Ok(p) => p,
        Err((code, message)) => return deny(400, code, &message, json!({})),
    };
    let forward_query = serialise_query(&pairs);
    let qmap: Map<String, Value> = pairs.iter().map(|(n, v)| (n.clone(), json!(v))).collect();

    // 4. the token
    let Some(token) = req.bearer().filter(|t| !t.is_empty()) else { return deny(401, "token_invalid", "send the capability token as a Bearer credential", json!({})) };

    // 5. a body is JSON
    let body: Value = if raw.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(raw) {
            Ok(v) => v,
            Err(_) => return deny(415, "invalid_input", "request bodies must be JSON so they can be field-checked", json!({})),
        }
    };
    let sources = json!({"body": body, "query": qmap});
    let get = |expr: &Value| resolve_expr(expr, &sources, &params);

    // 6. id and the attributes the route and the request state
    let id = match route.get("id") {
        Some(expr) => get(expr).and_then(|v| v.as_str().map(String::from)).unwrap_or_else(|| "any".into()),
        None => "any".into(),
    };
    let mut attrs = Map::new();
    let mut has_attrs = false;
    for key in ["attrs", "attrs_from_request"] {
        if let Some(m) = route[key].as_object() {
            has_attrs = true;
            for (k, expr) in m {
                match get(expr) {
                    Some(v) => {
                        attrs.insert(k.clone(), v);
                    }
                    None => return deny(400, "invalid_input", &format!("the request lacks the value for resource attribute '{k}'"), json!({})),
                }
            }
        }
    }
    let context = json!({"http": {"method": method, "upstream": up_name, "path": rest}});
    let resource = |attrs: &Map<String, Value>, has: bool| {
        let mut r = json!({"path": route.get("resource").cloned().unwrap_or(Value::Null), "id": id});
        if has {
            r["attrs"] = Value::Object(attrs.clone());
        }
        r
    };
    let action = route.get("action").cloned().unwrap_or(Value::Null);
    let base = setting(upstream.get("base_url")).trim_end_matches('/').to_string();
    let up_headers = upstream_headers(upstream);

    // 7. the record the call is about, with the proxy's own credential
    let mut record: Option<Value> = None;
    let mut lookup_path = String::new();
    if let Some(template) = route["lookup"].as_str() {
        // What does not depend on the record is decided first: a caller whose
        // token, tenant or capability does not cover this resource causes no
        // upstream call, and gets the same answer for a record that exists
        // and one that does not.
        let pre = json!({"token": token, "action": action, "resource": resource(&attrs, has_attrs), "context": context});
        let mut dry = pre.clone();
        dry["dry_run"] = json!(true);
        let d = call(engine, "authorize", &dry);
        if d["ok"] != json!(true) {
            return deny(400, d["error"]["code"].as_str().unwrap_or("invalid_input"), d["error"]["message"].as_str().unwrap_or(""), json!({}));
        }
        if d["effect"] != json!("allow") && d["reason"].as_str().map(|r| EARLY_DENIALS.contains(&r)).unwrap_or(false) {
            // the same refusal, this time on the record
            let d = call(engine, "authorize", &pre);
            if d["effect"] != json!("allow") {
                let extra = json!({"decision_id": d["decision_id"], "approval": null});
                return deny(403, d["reason"].as_str().unwrap_or("deny"), d["detail"].as_str().unwrap_or(""), extra);
            }
        }
        let mut segs = Vec::new();
        for seg in template.trim_matches('/').split('/') {
            if seg.len() >= 2 && seg.starts_with('{') && seg.ends_with('}') {
                let inner = &seg[1..seg.len() - 1];
                let v = if params.contains_key(inner) { get(&json!(seg)) } else { get(&json!(inner)) };
                // a value from the body or the query becomes part of a path:
                // the same characters as a path parameter, nothing else
                match v.as_ref().and_then(|v| v.as_str()).filter(|s| safe_param(s)) {
                    Some(s) => segs.push(s.to_string()),
                    None => return deny(400, "invalid_input", &format!("the request lacks a usable value for {seg} in the lookup path"), json!({})),
                }
            } else {
                segs.push(seg.to_string());
            }
        }
        lookup_path = format!("/{}", segs.join("/"));
        let (status, _, payload) = match fetch(http, "GET", &format!("{base}{lookup_path}"), &up_headers, None) {
            Ok(r) => r,
            Err(e) => return deny(502, "upstream_unreachable", &e, json!({})),
        };
        if status == 404 {
            return deny(404, "not_found", "the upstream has no such record", json!({}));
        }
        if status != 200 || payload.len() as u64 > MAX_RESPONSE {
            return deny(502, "lookup_failed", &format!("the lookup of the record did not succeed (upstream status {status})"), json!({}));
        }
        let Some(rec) = serde_json::from_slice::<Value>(&payload).ok().filter(|v| v.is_object()) else {
            return deny(502, "lookup_failed", "the lookup did not return a JSON object", json!({}));
        };
        if let Some(m) = route["attrs_from_record"].as_object() {
            for (k, expr) in m {
                match record_attr(&rec, &shown(Some(expr))) {
                    Some(v) => {
                        attrs.insert(k.clone(), v);
                        has_attrs = true;
                    }
                    None => return deny(502, "lookup_failed", &format!("the record has no usable value for resource attribute '{k}'"), json!({})),
                }
            }
        }
        record = Some(rec);
    }

    // 8. spend
    let mut input = json!({"token": token, "action": action, "resource": resource(&attrs, has_attrs), "context": context});
    if let Some(sp) = route.get("spend").filter(|s| s.is_object()) {
        match (sp.get("currency").and_then(&get), sp.get("amount").and_then(&get)) {
            (Some(c), Some(a)) if c.is_string() && (a.is_i64() || a.is_u64()) => input["context"]["spend"] = json!({"currency": c, "amount": a}),
            _ => return deny(400, "invalid_input", "this route spends money: the body must carry the currency and an integer amount in minor units", json!({})),
        }
    }

    // 9. the decision. It also reserves the spend and uses up an approval,
    // before the upstream is called: a budget must never be overrun, so it
    // is not refunded when the upstream refuses.
    let op = if body.is_object() && route["request"].as_str() != Some("unchecked") {
        input["data"] = body.clone();
        input["strict"] = json!(true);
        "filter"
    } else {
        "authorize"
    };
    let decision = call(engine, op, &input);
    if decision["ok"] != json!(true) {
        return deny(400, decision["error"]["code"].as_str().unwrap_or("invalid_input"), decision["error"]["message"].as_str().unwrap_or(""), json!({}));
    }
    if decision["effect"] != json!("allow") {
        let extra = json!({"decision_id": decision["decision_id"], "approval": decision["approval"]});
        return deny(403, decision["reason"].as_str().unwrap_or("deny"), decision["detail"].as_str().unwrap_or(""), extra);
    }

    // 10. the upstream call
    let passthrough = route["response"].as_str() == Some("passthrough");
    let (status, ctype, payload) = match &record {
        // a read of the record that was just fetched: answer from it, no second fetch
        Some(rec) if method == "GET" && lookup_path == rest && pairs.is_empty() && !passthrough => (200, String::new(), rec.to_string().into_bytes()),
        _ => {
            // with the upstream's own credential, and the query as parsed
            let target = format!("{base}{rest}{}", if forward_query.is_empty() { String::new() } else { format!("?{forward_query}") });
            match fetch(http, &method, &target, &up_headers, if body.is_null() { None } else { Some(&body) }) {
                Ok(r) => r,
                Err(e) => return deny(502, "upstream_unreachable", &e, json!({})),
            }
        }
    };

    // 11. the response
    if payload.len() as u64 > MAX_RESPONSE {
        return deny(502, "unfilterable_response", "the upstream response is too large to check", json!({}));
    }
    if passthrough {
        // status, content type and the bytes exactly as received
        return Response::new(status, Some(&ctype), payload);
    }
    if payload.iter().all(|b| b.is_ascii_whitespace() || *b == 0x0b) {
        return Response::new(status, None, Vec::new());
    }
    // anything that is not JSON (not UTF-8 included) cannot be field-checked
    let Ok(upstream_json) = serde_json::from_slice::<Value>(&payload) else {
        return deny(502, "unfilterable_response", "the upstream response is not JSON, so it cannot be field-checked and is withheld", json!({"decision_id": decision["decision_id"]}));
    };
    if status >= 400 {
        // upstream error bodies can echo record data; return the status only
        return deny(status, "upstream_error", "the upstream returned an error; its body is withheld", json!({}));
    }
    // {"items": [...], "next": "..."} envelopes: filter the records, keep
    // only the envelope keys the route lists
    let key = route["data_key"].as_str();
    let records = match key {
        Some(k) => upstream_json.as_object().and_then(|o| o.get(k)).cloned().unwrap_or(Value::Null),
        None => upstream_json.clone(),
    };
    let applied = call(engine, "apply_obligations", &json!({"obligations": decision["obligations"], "data": records, "decision_id": decision["decision_id"]}));
    if applied["ok"] != json!(true) {
        return deny(502, "unfilterable_response", applied["error"]["message"].as_str().unwrap_or(""), json!({}));
    }
    let out = match key {
        Some(k) => {
            let mut m = Map::new();
            m.insert(k.to_string(), applied["data"].clone());
            for keep in route["keep"].as_array().unwrap_or(&empty).iter().filter_map(|x| x.as_str()) {
                if let Some(v) = upstream_json.as_object().and_then(|o| o.get(keep)) {
                    m.insert(keep.to_string(), v.clone());
                }
            }
            Value::Object(m)
        }
        None => applied["data"].clone(),
    };
    Response::json(status, &out)
        .with_header("X-SmartDelegate-Decision", &shown(Some(&decision["decision_id"])))
        .with_header("X-SmartDelegate-Masked", &applied["masked"].as_array().map(|a| a.len()).unwrap_or(0).to_string())
}

pub fn run(args: &Args) -> ! {
    let (engine, _) = crate::engine_from(args);
    let routes = json_arg(&format!("@{}", args.req("routes")));
    let (mut errors, notes) = check_routes(&routes);
    if errors.is_empty() {
        errors = missing_environment(&routes);
    }
    if !errors.is_empty() {
        die(&format!("the routes file is refused:\n  {}", errors.join("\n  ")));
    }
    let listen = args.flag("listen").or_else(|| routes["listen"].as_str().map(String::from)).unwrap_or_else(|| "127.0.0.1:8182".into());
    let server = crate::serve::listen_on(&listen);
    let engine = Arc::new(Mutex::new(engine));
    // the listen line stays first: whoever started the proxy reads the address from it
    eprintln!("smartdelegate http proxy listening on http://{}", server.addr());
    for note in &notes {
        eprintln!("smartdelegate http proxy: {note}");
    }
    // the routes file has a closed set of keys; the cap is a flag
    let max = crate::serve::max_concurrent(args, &json!({}));
    // no proxy from the environment, no redirects: the route table decides
    // where calls go. One agent for all requests: it pools upstream
    // connections and is safe to share.
    let http = ureq::AgentBuilder::new().redirects(0).try_proxy_from_env(false).timeout(std::time::Duration::from_secs(60)).build();
    let refusal = |status: u16, code: &str, message: &str| Response::json(status, &json!({"error": {"code": code, "message": message, "by": "smartdelegate"}}));
    server.serve(
        max,
        move |req| handle(req, &engine, &routes, &http),
        move || refusal(503, "overloaded", "too many requests in progress; try again").with_header("Retry-After", "1"),
        move |status, why| refusal(status, "invalid_input", why),
    );
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(extra: Value) -> (Vec<String>, Vec<String>) {
        let mut route = json!({"upstream": "crm", "method": "GET", "path": "/customers/{id}", "action": "read", "resource": "crm.customer"});
        for (k, v) in extra.as_object().unwrap() {
            route[k] = v.clone();
        }
        check_routes(&json!({"upstreams": {"crm": {"base_url": "http://127.0.0.1:9"}}, "routes": [route]}))
    }

    #[test]
    fn request_supplied_attributes_must_be_declared() {
        assert_eq!(one(json!({"attrs": {"tenant": "acme", "id": "{id}", "n": 5, "b": true, "l": {"literal": "body.x"}}})), (vec![], vec![]));
        // every form an expression may take
        for good in [
            json!({"id": "{id}"}),
            json!({"id": "body.a.b"}),
            json!({"id": "query.id"}),
            json!({"id": {"literal": "any"}}),
            json!({"id": 5}),
            json!({"id": true}),
            json!({"spend": {"currency": {"literal": "EUR"}, "amount": "body.amount"}}),
            json!({"spend": {"currency": "query.c", "amount": 100}}),
            json!({"request": "checked", "response": "filter", "query": [], "keep": ["next"], "data_key": "items"}),
            json!({"request": "unchecked", "response": "passthrough"}),
            json!({"attrs_from_record": {}}),
            json!({"attrs_from_record": null, "attrs": null}),
        ] {
            assert_eq!(one(good.clone()), (vec![], vec![]), "{good}");
        }
        for bad in [
            json!({"attrs": {"region": "query.region"}}),
            json!({"attrs": {"owner": "body.owner"}}),
            json!({"attrs": {"x": "{nope}"}}),
            json!({"attrs_from_request": {"region": "EU"}}),
            json!({"attrs_from_request": {"region": "{id}"}}),
            json!({"attrs_from_request": {"region": "body"}}),
            json!({"attrs_from_request": {"region": 5}}),
            json!({"attrs_from_record": {"region": "region"}}),
            json!({"lookup": "customers/{id}"}),
            json!({"lookup": 5}),
            json!({"lookup": "/customers/{other}"}),
            json!({"attrs": {"region": "EU"}, "attrs_from_request": {"region": "query.region"}}),
            json!({"lookup": "/customers/{id}", "attrs_from_record": {"region": ""}}),
            json!({"lookup": "/customers/{id}", "attrs_from_record": {"region": 5}}),
            json!({"attrs": []}),
            json!({"attrs_from_request": "query.region"}),
            // closed key sets, required keys, expressions (0.3, final)
            json!({"atrs": {"tenant": "acme"}}),
            json!({"attrs_from_requests": {"region": "query.region"}}),
            json!({"upstream": "nope"}),
            json!({"method": ""}),
            json!({"action": 5}),
            json!({"resource": null}),
            json!({"id": "body"}),
            json!({"id": "query"}),
            json!({"id": "bdy.id"}),
            json!({"id": "body."}),
            json!({"id": "body.a..b"}),
            json!({"id": "{nope}"}),
            json!({"id": ""}),
            json!({"id": null}),
            json!({"id": ["x"]}),
            json!({"id": {"literal": 1, "x": 2}}),
            json!({"id": {"value": 1}}),
            json!({"spend": {"currency": "body.currency"}}),
            json!({"spend": {"currency": "body.currency", "amount": "body.amount", "x": 1}}),
            json!({"spend": {"currency": "EUR", "amount": "body.amount"}}),
            json!({"spend": {"currency": {"literal": "EUR"}, "amount": "amount"}}),
            json!({"spend": "body"}),
            json!({"request": "strict"}),
            json!({"request": null}),
            json!({"response": "raw"}),
            json!({"response": true}),
            json!({"query": "limit"}),
            json!({"query": ["limit", 5]}),
            json!({"keep": {"next": true}}),
            json!({"data_key": 5}),
            json!({"attrs": {"x": "body"}}),
            json!({"attrs": {"x": "query"}}),
            json!({"attrs": {"x": 1.5}}),
            json!({"attrs": {"x": null}}),
            json!({"attrs": {"x": ["a"]}}),
            json!({"attrs": {"x": {"a": 1}}}),
        ] {
            let (errors, _) = one(bad.clone());
            assert_eq!(errors.len(), 1, "{bad}: {errors:?}");
            assert!(errors[0].starts_with("route 0 ("), "{errors:?}");
        }
        let (errors, notes) = one(json!({"attrs_from_request": {"region": "query.region", "a": "body.a.b"}, "lookup": "/customers/{id}", "attrs_from_record": {"owner": "owner.id"}}));
        assert_eq!(errors, Vec::<String>::new());
        assert_eq!(notes, vec!["route 0 (GET /crm/customers/{id}) trusts request-supplied attributes: a, region"]);
        let (errors, notes) = one(json!({"attrs_from_request": {"region": "query.region"}, "data_key": "items"}));
        assert_eq!((errors.len(), notes.len()), (0, 2));
        assert!(notes[1].starts_with("warning: route 0 (GET /crm/customers/{id}) is a list route decided on request-supplied attributes"));
        assert_eq!(one(json!({"lookup": "/c/{body.customer_id}/{query.x}/{id}"})), (vec![], vec![]));
        let (errors, _) = one(json!({"lookup": "/c/{b}/{a}/{body}"}));
        assert!(errors[0].contains("\"lookup\" uses ['a', 'b', 'body']"), "{errors:?}");
        for malformed in [json!([]), json!({}), json!({"upstreams": {}}), json!({"upstreams": [], "routes": []}), json!({"upstreams": {}, "routes": {}}), json!("x")] {
            assert_eq!(check_routes(&malformed).0.len(), 1, "{malformed}");
        }
        assert_eq!(check_routes(&json!({"upstreams": {}, "routes": [5, "x"]})).0, vec!["route 0: not an object", "route 1: not an object"]);
        for (doc, n) in [
            (json!({"upstreams": {}, "routes": [], "listen": "127.0.0.1:1"}), 0),
            (json!({"upstreams": {}, "routes": [], "max_concurrent": 5, "zzz": 1}), 1),
            (json!({"upstreams": {"a": {}}, "routes": []}), 1),
            (json!({"upstreams": {"a": {"base_url": 5}}, "routes": []}), 1),
            (json!({"upstreams": {"a": {"base_url": "http://x", "header": {}}}, "routes": []}), 1),
            (json!({"upstreams": {"a": {"base_url": "http://x", "headers": []}}, "routes": []}), 1),
            (json!({"upstreams": {"a": {"base_url": "http://x", "headers": null}}, "routes": []}), 1),
            (json!({"upstreams": {"a": "http://x", "b": {"base_url": "http://x", "headers": {"K": "v"}}}, "routes": []}), 1),
        ] {
            assert_eq!(check_routes(&doc).0.len(), n, "{doc}");
        }
        assert_eq!(check_routes(&json!({"upstreams": {}, "routes": [], "max_concurrent": 5, "zzz": 1})).0, vec!["unknown top-level key(s) max_concurrent, zzz"]);
        let (errors, _) = one(json!({"id": "customer"}));
        assert_eq!(errors, vec!["route 0 (GET /crm/customers/{id}): id: \"customer\" is not an expression (body.<name>, query.<name>, {param}); write {\"literal\": \"customer\"} if the constant is meant"]);
        // an unset or empty environment variable is found only in a file that is otherwise sound
        let env_doc = json!({"upstreams": {"a": {"base_url": "env:SD_TEST_NO_SUCH_VARIABLE", "headers": {"K": "env:SD_TEST_NO_SUCH_VARIABLE_2", "L": "env:PATH", "M": "plain"}}, "b": {"base_url": "http://x"}}, "routes": []});
        assert_eq!(check_routes(&env_doc).0, Vec::<String>::new());
        assert_eq!(
            missing_environment(&env_doc),
            vec![
                "upstream a: base_url is \"env:SD_TEST_NO_SUCH_VARIABLE\" and the environment variable SD_TEST_NO_SUCH_VARIABLE is not set",
                "upstream a: headers.K is \"env:SD_TEST_NO_SUCH_VARIABLE_2\" and the environment variable SD_TEST_NO_SUCH_VARIABLE_2 is not set",
            ]
        );
        assert_eq!(check_routes(&json!({"upstreams": {}, "routes": []})), (vec![], vec![]));
    }

    fn q(raw: &str, allowed: &[&str]) -> Result<Vec<(String, String)>, &'static str> {
        parse_query(raw, allowed).map_err(|(code, _)| code)
    }

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn query_parsing_and_what_is_forwarded() {
        let all = ["a", "b", "c", "d", "A", "q.x", "A-b_c"];
        let parsed = q("a=x%20y&b=%2B1&c=p+q&&d", &all).unwrap();
        assert_eq!(parsed, pairs(&[("a", "x y"), ("b", "+1"), ("c", "p+q"), ("d", "")]));
        assert_eq!(serialise_query(&parsed), "a=x%20y&b=%2B1&c=p%2Bq&d=");
        assert_eq!(q("a=caf%C3%A9", &all).unwrap(), pairs(&[("a", "caf\u{e9}")]));
        assert_eq!(serialise_query(&pairs(&[("a", "caf\u{e9}"), ("b", "~-_.aZ09"), ("c", "/?#&=%")])), "a=caf%C3%A9&b=~-_.aZ09&c=%2F%3F%23%26%3D%25");
        assert_eq!(q("", &all).unwrap(), vec![]);
        assert_eq!(q("&&&", &all).unwrap(), vec![]);
        assert_eq!(q("a=b=c&q.x=1&A-b_c=", &all).unwrap(), pairs(&[("a", "b=c"), ("q.x", "1"), ("A-b_c", "")]));
        assert_eq!(q("a=%41%7e", &all).unwrap(), pairs(&[("a", "A~")]));
        for (raw, code) in [
            ("a=1;b=2", "query_ambiguous"),
            ("z=1;", "query_ambiguous"),
            ("=1", "query_ambiguous"),
            ("%61=1", "query_ambiguous"),
            ("a+b=1", "query_ambiguous"),
            ("a[]=1", "query_ambiguous"),
            ("z=1", "query_not_allowed"),
            ("a=1&z", "query_not_allowed"),
            ("D=1", "query_not_allowed"),
            ("a=1&a=2", "query_duplicate"),
            ("a=1&A=2", "query_duplicate"),
            ("a=1&b=2&a", "query_duplicate"),
            ("a=%zz", "query_ambiguous"),
            ("a=%", "query_ambiguous"),
            ("a=%4", "query_ambiguous"),
            ("a=%00", "query_ambiguous"),
            ("a=%1f", "query_ambiguous"),
            ("a=%7F", "query_ambiguous"),
            ("a=%ff", "query_ambiguous"),
            ("a=%C3%28", "query_ambiguous"),
            ("a=caf\u{e9}", "query_ambiguous"),
            ("a=x y", "query_ambiguous"),
            ("a=x\ty", "query_ambiguous"),
            // the checks run per piece, left to right, in the order of the spec
            ("z=%zz", "query_not_allowed"),
            ("a=1&a=%zz", "query_duplicate"),
            ("a=%zz&z=1", "query_ambiguous"),
        ] {
            assert_eq!(q(raw, &all), Err(code), "{raw}");
        }
        assert_eq!(q("a=1", &[]), Err("query_not_allowed"));
    }

    #[test]
    fn path_parameters_are_one_safe_segment() {
        let m = |p: &str, x: &str| match_path(p, x).map(|h| {
            let mut v: Vec<_> = h.into_iter().collect();
            v.sort();
            v
        });
        assert_eq!(m("/c/{id}", "/c/c-1"), Some(vec![("id".to_string(), "c-1".to_string())]));
        assert_eq!(m("/c/{id}", "/c/a.b~c:d@e_f"), Some(vec![("id".to_string(), "a.b~c:d@e_f".to_string())]));
        for bad in ["/c/..", "/c/.", "/c/a%2Fb", "/c/a;b", "/c/a b", "/c/", "/c/a/b", "/c", "/d/a", "/c/caf\u{e9}"] {
            assert_eq!(m("/c/{id}", bad), None, "{bad}");
        }
    }
}
