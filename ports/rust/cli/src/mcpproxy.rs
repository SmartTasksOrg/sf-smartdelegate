//! MCP proxy (stdio transport): the enforcement point for Model Context
//! Protocol tools. It sits between the agent's MCP client and the real MCP
//! server:
//!
//!   agent <-stdio-> smartdelegate mcp-proxy <-stdio-> real MCP server
//!
//!   tools/list   tools without a mapping are hidden
//!   tools/call   authorised first; arguments are field-checked (strict);
//!                results are masked before they reach the model. A mapping
//!                with `lookup` first calls a read tool of the server itself
//!                and takes resource attributes from the record it returns
//!   other        only an allow-list of methods passes (default deny)
//!
//! The capability token comes from SMARTDELEGATE_TOKEN or --token-file (re-read on
//! every call, so the agent runtime can rotate it per task).

use crate::util::{die, expr_problem, is_literal, json_arg, one_of, record_attr, resolve_expr, unknown_keys, Args, EARLY_DENIALS};
use serde_json::{json, Map, Value};
use smartdelegate_core::Engine;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

enum Pending {
    List,
    Call { obligations: Value, decision_id: Value, mode: String },
    /// the proxy's own lookup: the answer goes to the waiting call, never to the agent
    Lookup(Sender<Value>),
}

const WITHHELD: &str = "[withheld by SmartDelegate: this tool output is not JSON, so it cannot be field-checked]";
const LOOKUP_ID: &str = "smartdelegate-lookup-";
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);

type PendingMap = Arc<Mutex<HashMap<String, Pending>>>;

fn send(out: &Mutex<std::io::Stdout>, msg: &Value) {
    if let Ok(mut o) = out.lock() {
        let _ = writeln!(o, "{msg}");
        let _ = o.flush();
    }
}

fn tool_error(id: &Value, text: String) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": text}], "isError": true}})
}

fn apply(engine: &Mutex<Engine>, obligations: &Value, decision_id: &Value, data: &Value) -> Option<Value> {
    let r = engine.lock().ok()?.call("apply_obligations", &json!({"obligations": obligations, "data": data, "decision_id": decision_id}));
    (r["ok"] == json!(true)).then(|| r["data"].clone())
}

fn filter_result(engine: &Mutex<Engine>, result: &mut Value, obligations: &Value, decision_id: &Value) {
    // keep only the members we know how to check; `_meta` and anything a
    // server invents could carry record data
    if let Some(o) = result.as_object_mut() {
        o.retain(|k, _| k == "content" || k == "structuredContent" || k == "isError");
    }
    if let Some(sc) = result.get("structuredContent").cloned() {
        result["structuredContent"] = apply(engine, obligations, decision_id, &sc).unwrap_or(Value::Null);
    }
    if let Some(items) = result.get_mut("content").and_then(|c| c.as_array_mut()) {
        for item in items.iter_mut() {
            let text = if item.is_object() && item["type"] == json!("text") { item["text"].as_str() } else { None };
            let parsed = text.and_then(|t| serde_json::from_str::<Value>(t).ok()).filter(|v| v.is_object() || v.is_array());
            // plain text, images, audio, embedded resources: no field
            // identity. The item is replaced whole: nothing else it carried
            // (annotations, anything a server invents) is handed on.
            let text = match parsed.and_then(|v| apply(engine, obligations, decision_id, &v)) {
                Some(v) => v.to_string(),
                None => WITHHELD.to_string(),
            };
            *item = json!({"type": "text", "text": text});
        }
    }
}

fn from_args(expr: &Value) -> bool {
    expr.as_str().map(|e| e.starts_with("args.")).unwrap_or(false)
}

const TOOL_KEYS: [&str; 10] = ["action", "resource", "id", "attrs", "attrs_from_request", "lookup", "attrs_from_record", "spend", "input", "response"];

/// `(errors, notes)`. Errors stop the proxy; notes are printed at start.
pub fn check_tools(tools: &Value) -> (Vec<String>, Vec<String>) {
    let (mut errors, mut notes) = (Vec::new(), Vec::new());
    let Some(map) = tools.get("tools").and_then(|t| t.as_object()) else {
        return (vec!["the tools file needs \"tools\" (an object)".into()], notes);
    };
    let top = unknown_keys(tools.as_object().expect("checked above"), &["server", "allow_methods", "tools"]);
    if !top.is_empty() {
        errors.push(format!("unknown top-level key(s) {}", top.join(", ")));
    }
    let args = ["args"];
    for (name, m) in map {
        let Some(mobj) = m.as_object() else {
            errors.push(format!("tool {name}: the mapping is not an object"));
            continue;
        };
        let unknown = unknown_keys(mobj, &TOOL_KEYS);
        if !unknown.is_empty() {
            errors.push(format!("tool {name}: unknown key(s) {} (a misspelt key must not silently drop a check)", unknown.join(", ")));
        }
        for key in ["action", "resource"] {
            if !m.get(key).and_then(|v| v.as_str()).map(|v| !v.is_empty()).unwrap_or(false) {
                errors.push(format!("tool {name}: \"{key}\" is required"));
            }
        }
        if let Some(why) = m.get("id").and_then(|e| expr_problem(e, &args, None, false)) {
            errors.push(format!("tool {name}: id: {why}"));
        }
        if let Some(input) = m.get("input") {
            // "args" (all arguments) or "args.<name>": the part that is record data
            let why = expr_problem(input, &args, None, true).or_else(|| (!input.is_string()).then(|| "must be \"args\" (all arguments) or \"args.<name>\"".to_string()));
            if let Some(why) = why {
                errors.push(format!("tool {name}: input: {why}"));
            }
        }
        if let Some(sp) = m.get("spend") {
            match sp.as_object().filter(|o| o.len() == 2 && o.contains_key("currency") && o.contains_key("amount")) {
                None => errors.push(format!("tool {name}: \"spend\" must be {{\"currency\": ..., \"amount\": ...}}")),
                Some(o) => {
                    for k in ["currency", "amount"] {
                        if let Some(why) = expr_problem(&o[k], &args, None, false) {
                            errors.push(format!("tool {name}: spend.{k}: {why}"));
                        }
                    }
                }
            }
        }
        if !one_of(m, "response", &["filter", "passthrough"]) {
            errors.push(format!("tool {name}: \"response\" must be \"filter\" or \"passthrough\""));
        }
        if let Some(lk) = m.get("lookup").and_then(|l| l.as_object()) {
            let unknown = unknown_keys(lk, &["tool", "arguments"]);
            if !unknown.is_empty() {
                errors.push(format!("tool {name}: lookup: unknown key(s) {}", unknown.join(", ")));
            }
            for (k, expr) in lk.get("arguments").and_then(|a| a.as_object()).into_iter().flatten() {
                if let Some(why) = expr_problem(expr, &args, None, false) {
                    errors.push(format!("tool {name}: lookup.arguments.{k}: {why}"));
                }
            }
        }
        let mut seen: Vec<(String, &str)> = Vec::new();
        for key in ["attrs", "attrs_from_request", "attrs_from_record"] {
            let v = match m.get(key) {
                None | Some(Value::Null) => continue,
                Some(Value::Object(v)) => v,
                Some(_) => {
                    errors.push(format!("tool {name}: \"{key}\" must be an object"));
                    continue;
                }
            };
            for (attr, expr) in v {
                if let Some((_, first)) = seen.iter().find(|(k, _)| k == attr) {
                    errors.push(format!("tool {name}: attribute '{attr}' is in \"{first}\" and in \"{key}\""));
                }
                seen.retain(|(k, _)| k != attr);
                seen.push((attr.clone(), key));
                let constant = expr.is_string() || expr.is_boolean() || expr.is_i64() || expr.is_u64() || is_literal(expr);
                if key == "attrs" && (expr.as_str() == Some("args") || !constant) {
                    errors.push(format!("tool {name}: attrs.{attr} must be a constant: a string, an integer or a boolean"));
                }
                if key == "attrs" && from_args(expr) {
                    errors.push(format!(
                        "tool {name}: attrs.{attr} = \"{}\" comes from the call's arguments, which the agent writes. Move it to \"attrs_from_request\" (a claim), or take it from the record with \"lookup\" and \"attrs_from_record\"",
                        expr.as_str().unwrap_or("")
                    ));
                }
                if key == "attrs_from_request" && !from_args(expr) {
                    errors.push(format!("tool {name}: attrs_from_request.{attr} must be \"args.<name>\""));
                }
                if key == "attrs_from_record" && expr.as_str().map(|e| e.is_empty()).unwrap_or(true) {
                    errors.push(format!("tool {name}: attrs_from_record.{attr} must name a field of the record"));
                }
            }
        }
        let lk = m.get("lookup").filter(|l| !l.is_null());
        let has_record_attrs = match m.get("attrs_from_record") {
            Some(Value::Object(o)) => !o.is_empty(),
            Some(Value::Array(a)) => !a.is_empty(),
            Some(Value::String(s)) => !s.is_empty(),
            Some(Value::Number(x)) => x.as_f64() != Some(0.0),
            Some(Value::Bool(b)) => *b,
            None | Some(Value::Null) => false,
        };
        if has_record_attrs && lk.is_none() {
            errors.push(format!("tool {name}: \"attrs_from_record\" needs \"lookup\""));
        }
        if let Some(lk) = lk {
            let ok = lk.is_object() && lk["tool"].is_string() && lk.get("arguments").map(|a| a.is_object()).unwrap_or(true);
            if !ok {
                errors.push(format!("tool {name}: \"lookup\" must be {{\"tool\": <name>, \"arguments\": {{...}}}}"));
            }
        }
        if let Some(claimed) = m.get("attrs_from_request").and_then(|a| a.as_object()).filter(|a| !a.is_empty()) {
            let mut names: Vec<&str> = claimed.keys().map(|k| k.as_str()).collect();
            names.sort();
            notes.push(format!("tool {name} trusts request-supplied attributes: {}", names.join(", ")));
        }
    }
    (errors, notes)
}

/// The record a lookup tool returned: `structuredContent`, or the first text
/// item when it is a JSON object.
fn record_of(result: Option<&Value>) -> Option<Value> {
    let result = result.filter(|r| r.is_object())?;
    let truthy = match &result["isError"] {
        Value::Null | Value::Bool(false) => false,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Bool(true) => true,
    };
    if truthy {
        return None;
    }
    if result["structuredContent"].is_object() {
        return Some(result["structuredContent"].clone());
    }
    for item in result["content"].as_array()? {
        if item.is_object() && item["type"] == json!("text") {
            if let Some(text) = item["text"].as_str() {
                return serde_json::from_str::<Value>(text).ok().filter(|v| v.is_object());
            }
        }
    }
    None
}

fn refusal(d: &Value) -> String {
    let nonempty = |v: &Value| v.as_str().filter(|s| !s.is_empty()).map(String::from);
    let code = nonempty(&d["reason"]).or_else(|| nonempty(&d["error"]["code"])).unwrap_or_else(|| "deny".into());
    let why = nonempty(&d["detail"]).or_else(|| nonempty(&d["error"]["message"])).unwrap_or_else(|| "not permitted".into());
    let mut text = format!("Denied by SmartDelegate ({code}): {why}.");
    if let Some(a) = nonempty(&d["approval"]["id"]) {
        text.push_str(&format!(" A human can approve it with id {a}; then retry the same call."));
    }
    text
}

/// `Ok(decision)` when the call is allowed, `Err(denial text)` otherwise.
/// `lookup(tool, arguments)` calls a tool of the server with the proxy's own
/// authority and returns its result.
fn decide_call(engine: &Mutex<Engine>, tools: &Value, token: &str, name: &str, arguments: Option<&Value>, lookup: &mut dyn FnMut(&str, Value) -> Option<Value>) -> Result<(Value, String), String> {
    let Some(mapping) = tools["tools"].get(name).filter(|m| m.is_object()) else {
        return Err(format!("Denied by SmartDelegate: tool '{name}' has no access mapping (default deny)."));
    };
    let call = |op: &str, input: &Value| engine.lock().map(|mut e| e.call(op, input)).unwrap_or_else(|_| json!({"ok": false}));
    let sources = json!({"args": arguments.filter(|a| a.is_object()).cloned().unwrap_or_else(|| json!({}))});
    let none = HashMap::new();
    let get = |expr: &Value| resolve_expr(expr, &sources, &none);
    let id = match mapping.get("id") {
        Some(expr) => get(expr).and_then(|v| v.as_str().map(String::from)).unwrap_or_else(|| "any".into()),
        None => "any".into(),
    };
    let server = match &tools["server"] {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Null | Value::String(_) | Value::Bool(false) => "mcp".into(),
        other => other.to_string(),
    };
    let context = json!({"mcp": {"server": server, "tool": name}});
    let action = mapping.get("action").cloned().unwrap_or(Value::Null);
    let mut attrs = Map::new();
    let mut has_attrs = false;
    for key in ["attrs", "attrs_from_request"] {
        if let Some(m) = mapping[key].as_object() {
            has_attrs = true;
            for (k, expr) in m {
                match get(expr) {
                    Some(v) => {
                        attrs.insert(k.clone(), v);
                    }
                    None => return Err(format!("Denied by SmartDelegate: the call lacks the value for resource attribute '{k}'.")),
                }
            }
        }
    }
    let resource = |attrs: &Map<String, Value>, has: bool| {
        let mut r = json!({"path": mapping.get("resource").cloned().unwrap_or(Value::Null), "id": id});
        if has {
            r["attrs"] = Value::Object(attrs.clone());
        }
        r
    };

    if let Some(lk) = mapping.get("lookup").filter(|l| l.is_object()) {
        // 1. what does not depend on the record is decided first
        let pre = json!({"token": token, "action": action, "resource": resource(&attrs, has_attrs), "context": context});
        let mut dry = pre.clone();
        dry["dry_run"] = json!(true);
        let d = call("authorize", &dry);
        if d["ok"] != json!(true) {
            return Err(refusal(&d));
        }
        if d["effect"] != json!("allow") && d["reason"].as_str().map(|r| EARLY_DENIALS.contains(&r)).unwrap_or(false) {
            let d = call("authorize", &pre);
            if d["ok"] != json!(true) || d["effect"] != json!("allow") {
                return Err(refusal(&d));
            }
        }
        // 2. the record, asked of the server by the proxy itself
        let mut largs = Map::new();
        if let Some(m) = lk["arguments"].as_object() {
            for (k, expr) in m {
                match get(expr) {
                    Some(v) => {
                        largs.insert(k.clone(), v);
                    }
                    None => return Err(format!("Denied by SmartDelegate: the call lacks the argument '{k}' needed to look the record up.")),
                }
            }
        }
        let result = lookup(lk["tool"].as_str().unwrap_or(""), Value::Object(largs));
        let Some(record) = record_of(result.as_ref()) else {
            return Err("Denied by SmartDelegate (lookup_failed): the record could not be looked up, so the call cannot be decided.".into());
        };
        // 3. attributes from the record
        if let Some(m) = mapping["attrs_from_record"].as_object() {
            for (k, expr) in m {
                let field = expr.as_str().map(String::from).unwrap_or_else(|| expr.to_string());
                match record_attr(&record, &field) {
                    Some(v) => {
                        attrs.insert(k.clone(), v);
                        has_attrs = true;
                    }
                    None => return Err(format!("Denied by SmartDelegate (lookup_failed): the record has no usable value for resource attribute '{k}'.")),
                }
            }
        }
    }

    let mut input = json!({"token": token, "action": action, "resource": resource(&attrs, has_attrs), "context": context});
    if let Some(sp) = mapping.get("spend").filter(|s| s.is_object()) {
        match (sp.get("currency").and_then(&get), sp.get("amount").and_then(&get)) {
            (Some(c), Some(a)) if c.is_string() && (a.is_i64() || a.is_u64()) => input["context"]["spend"] = json!({"currency": c, "amount": a}),
            _ => return Err("Denied by SmartDelegate: this tool spends money: it needs a currency and an integer amount in minor units.".into()),
        }
    }
    // The part of the arguments that is record data is field-checked. The
    // mapping says these arguments hold record data: without an object there
    // is nothing to check, and nothing is waved through.
    let op = match mapping.get("input") {
        None => "authorize",
        Some(expr) => match get(expr).filter(|d| d.is_object()) {
            Some(data) => {
                input["data"] = data;
                input["strict"] = json!(true);
                "filter"
            }
            None => return Err("Denied by SmartDelegate (invalid_input): this tool takes record data as an object, and the call does not carry one.".into()),
        },
    };
    let d = call(op, &input);
    if d["ok"] != json!(true) || d["effect"] != json!("allow") {
        return Err(refusal(&d));
    }
    let mode = mapping["response"].as_str().filter(|m| !m.is_empty()).unwrap_or("filter").to_string();
    Ok((d, mode))
}

/// Call a tool of the server for the proxy itself; its result never goes to the agent.
fn lookup_call(child_in: &mut ChildStdin, pending: &PendingMap, counter: &mut u64, tool: &str, arguments: Value) -> Option<Value> {
    *counter += 1;
    let lid = json!(format!("{LOOKUP_ID}{counter}"));
    let (tx, rx) = channel();
    pending.lock().ok()?.insert(lid.to_string(), Pending::Lookup(tx));
    let msg = json!({"jsonrpc": "2.0", "id": lid, "method": "tools/call", "params": {"name": tool, "arguments": arguments}});
    let answer = if writeln!(child_in, "{msg}").and_then(|_| child_in.flush()).is_err() { None } else { rx.recv_timeout(LOOKUP_TIMEOUT).ok() };
    if answer.is_none() {
        if let Ok(mut p) = pending.lock() {
            p.remove(&lid.to_string());
        }
    }
    answer.and_then(|m| m.get("result").cloned())
}

pub fn run(args: &Args) -> ! {
    if args.rest.is_empty() {
        die("usage: smartdelegate mcp-proxy --tools FILE [--token-file F] -- <mcp server command...>");
    }
    let (engine, _) = crate::engine_from(args);
    let engine = Arc::new(Mutex::new(engine));
    let tools = json_arg(&format!("@{}", args.req("tools")));
    let (errors, notes) = check_tools(&tools);
    if !errors.is_empty() {
        die(&format!("the tools file is refused:\n  {}", errors.join("\n  ")));
    }
    for note in &notes {
        eprintln!("smartdelegate mcp proxy: {note}");
    }
    let token_file = args.flag("token-file");
    let mut allowed: Vec<String> = ["initialize", "ping", "tools/list", "tools/call"].iter().map(|s| s.to_string()).collect();
    for m in tools["allow_methods"].as_array().cloned().unwrap_or_default() {
        if let Some(s) = m.as_str() {
            allowed.push(s.to_string());
        }
    }

    let mut child = Command::new(&args.rest[0])
        .args(&args.rest[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| die(&format!("cannot start MCP server '{}': {e}", args.rest[0])));
    let mut child_in = child.stdin.take().unwrap();
    let child_out = child.stdout.take().unwrap();
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
    let mut lookups = 0u64;

    // server -> agent
    let (out2, pending2, engine2, tools2) = (out.clone(), pending.clone(), engine.clone(), tools.clone());
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(child_out).lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(mut msg) = serde_json::from_str::<Value>(&line) else { continue };
            if !msg.is_object() {
                continue;
            }
            if msg.get("method").is_some() {
                // Server-initiated requests (sampling, elicitation, roots) are
                // not mediated, and log/progress notifications can carry
                // record data. Only the "tool list changed" signal passes.
                if msg.get("id").is_none() && msg["method"] == json!("notifications/tools/list_changed") {
                    send(&out2, &msg);
                }
                continue;
            }
            let key = msg["id"].to_string();
            let entry = pending2.lock().ok().and_then(|mut p| p.remove(&key));
            match entry {
                Some(Pending::Lookup(tx)) => {
                    // the answer to the proxy's own lookup
                    let _ = tx.send(msg);
                    continue;
                }
                Some(Pending::List) => {
                    if let Some(list) = msg["result"]["tools"].as_array().cloned() {
                        let kept: Vec<Value> = list.into_iter().filter(|t| t.is_object() && t["name"].as_str().map(|n| tools2["tools"].get(n).is_some()).unwrap_or(false)).collect();
                        msg["result"]["tools"] = json!(kept);
                    }
                }
                Some(Pending::Call { obligations, decision_id, mode }) if mode != "passthrough" => {
                    if msg["result"].is_object() {
                        filter_result(&engine2, &mut msg["result"], &obligations, &decision_id);
                    } else if msg.get("error").is_some() {
                        // error text can echo record data
                        let code = if msg["error"].is_object() { msg["error"]["code"].clone() } else { json!(-32000) };
                        msg["error"] = json!({"code": code, "message": "tool failed (details withheld by SmartDelegate)"});
                    }
                }
                _ => {}
            }
            send(&out2, &msg);
        }
    });

    // agent -> server
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
        if !msg.is_object() || msg.get("method").is_none() {
            // batches, and replies to server requests we never forwarded
            continue;
        }
        let method = msg["method"].as_str().map(String::from).unwrap_or_else(|| msg["method"].to_string());
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        if method.starts_with("notifications/") {
            let _ = writeln!(child_in, "{msg}");
            let _ = child_in.flush();
            continue;
        }
        if id.as_str().map(|i| i.starts_with(LOOKUP_ID)).unwrap_or(false) {
            send(&out, &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "request ids starting with 'smartdelegate-lookup-' are reserved"}}));
            continue;
        }
        if !allowed.contains(&method) {
            if !id.is_null() {
                send(&out, &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("method '{method}' is blocked by SmartDelegate")}}));
            }
            continue;
        }
        if method == "tools/list" {
            pending.lock().unwrap().insert(id.to_string(), Pending::List);
        }
        if method == "tools/call" {
            let params = &msg["params"];
            // a name that is not a string names no mapping; it is shown as written
            let name = match &params["name"] {
                Value::String(n) => n.clone(),
                Value::Null | Value::Bool(false) => String::new(),
                Value::Number(n) if n.as_f64() == Some(0.0) => String::new(),
                Value::Bool(true) => "True".into(),
                other => other.to_string(),
            };
            let token = match &token_file {
                Some(f) => std::fs::read_to_string(f).map(|s| s.trim().to_string()).unwrap_or_default(),
                None => std::env::var("SMARTDELEGATE_TOKEN").unwrap_or_default(),
            };
            let mut lookup = |tool: &str, arguments: Value| lookup_call(&mut child_in, &pending, &mut lookups, tool, arguments);
            match decide_call(&engine, &tools, &token, &name, params.get("arguments"), &mut lookup) {
                Err(denial) => {
                    send(&out, &tool_error(&id, denial));
                    continue;
                }
                Ok((d, mode)) => {
                    pending.lock().unwrap().insert(id.to_string(), Pending::Call { obligations: d["obligations"].clone(), decision_id: d["decision_id"].clone(), mode });
                }
            }
        }
        if writeln!(child_in, "{msg}").is_err() {
            break;
        }
        let _ = child_in.flush();
    }
    drop(child_in);
    let _ = reader.join();
    let _ = child.wait();
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(extra: Value) -> (Vec<String>, Vec<String>) {
        let mut mapping = json!({"action": "read", "resource": "crm.customer"});
        match extra.as_object() {
            Some(o) => o.iter().for_each(|(k, v)| mapping[k] = v.clone()),
            None => mapping = extra,
        }
        check_tools(&json!({"tools": {"t": mapping}}))
    }

    #[test]
    fn the_tools_file_is_checked_at_start() {
        let lookup = json!({"tool": "get", "arguments": {"id": "args.id", "kind": {"literal": "fixed"}}});
        assert_eq!(one(json!({"attrs": {"tenant": "acme", "n": 5}})), (vec![], vec![]));
        assert_eq!(one(json!({"lookup": lookup, "attrs_from_record": {"region": "region", "o": "owner.id"}})), (vec![], vec![]));
        assert_eq!(one(json!({"lookup": {"tool": "get"}})), (vec![], vec![]));
        for good in [
            json!({"id": "args.customer_id", "input": "args", "response": "passthrough"}),
            json!({"id": {"literal": "fixed"}, "input": "args.changes.inner", "response": "filter"}),
            json!({"spend": {"currency": {"literal": "EUR"}, "amount": "args.amount"}}),
            json!({"spend": {"currency": "args.c", "amount": 100}}),
            json!({"lookup": {"tool": "get", "arguments": {"id": "args.id", "kind": {"literal": "fixed"}, "n": 5, "deep": true}}}),
            json!({"attrs": {"tenant": "acme", "n": 5, "b": false, "l": {"literal": [1]}}, "attrs_from_record": {}}),
        ] {
            assert_eq!(one(good.clone()), (vec![], vec![]), "{good}");
        }
        assert_eq!(check_tools(&json!({"server": "s", "allow_methods": [], "tools": {}})), (vec![], vec![]));
        assert_eq!(check_tools(&json!({"servr": "s", "tools": {}})).0, vec!["unknown top-level key(s) servr"]);
        assert_eq!(one(json!({"input": "changes"})).0, vec!["tool t: input: \"changes\" is not an expression (args.<name>); write {\"literal\": \"changes\"} if the constant is meant"]);
        for bad in [
            json!({"attrs": {"region": "args.region"}}),
            json!({"attrs_from_request": {"region": "EU"}}),
            json!({"attrs_from_request": {"region": "body.region"}}),
            json!({"attrs_from_request": {"region": 5}}),
            json!({"attrs_from_record": {"region": "region"}}),
            json!({"lookup": lookup, "attrs_from_record": {"region": ""}}),
            json!({"lookup": lookup, "attrs_from_record": {"region": 5}}),
            json!({"lookup": "get"}),
            json!({"lookup": {"arguments": {}}}),
            json!({"lookup": {"tool": "get", "arguments": []}}),
            json!({"attrs": {"region": "EU"}, "attrs_from_request": {"region": "args.region"}}),
            json!({"attrs": []}),
            json!("mapping"),
            // closed key sets, required keys, expressions (0.3, final)
            json!({"inputs": "args.changes"}),
            json!({"action": ""}),
            json!({"resource": 5}),
            json!({"id": "args"}),
            json!({"id": "customer_id"}),
            json!({"id": "{id}"}),
            json!({"id": "body.id"}),
            json!({"input": "changes"}),
            json!({"input": "args."}),
            json!({"input": {"literal": {"a": 1}}}),
            json!({"input": 5}),
            json!({"input": null}),
            json!({"spend": {"currency": "args.currency"}}),
            json!({"spend": {"currency": "EUR", "amount": "args.amount"}}),
            json!({"spend": {"currency": "args.c", "amount": "args"}}),
            json!({"response": "raw"}),
            json!({"lookup": {"tool": "get", "argument": {}}}),
            json!({"lookup": {"tool": "get", "arguments": {"id": "customer_id"}}}),
            json!({"lookup": {"tool": "get", "arguments": {"id": "args"}}}),
            json!({"attrs": {"x": "args"}}),
            json!({"attrs": {"x": 1.5}}),
            json!({"attrs": {"x": null}}),
            json!({"attrs": {"x": {"a": 1}}}),
        ] {
            let (errors, _) = one(bad.clone());
            assert_eq!(errors.len(), 1, "{bad}: {errors:?}");
            assert!(errors[0].starts_with("tool t: "), "{errors:?}");
        }
        let (errors, notes) = one(json!({"attrs_from_request": {"region": "args.region", "a": "args.a.b"}}));
        assert_eq!((errors, notes), (vec![], vec!["tool t trusts request-supplied attributes: a, region".to_string()]));
        for malformed in [json!([]), json!({}), json!({"tools": []}), json!("x")] {
            assert_eq!(check_tools(&malformed).0.len(), 1, "{malformed}");
        }
    }

    #[test]
    fn the_record_of_a_lookup() {
        let rec = |v: Value| record_of(Some(&v));
        assert_eq!(rec(json!({"structuredContent": {"a": 1}, "content": [{"type": "text", "text": "{\"a\": 2}"}]})), Some(json!({"a": 1})));
        assert_eq!(rec(json!({"structuredContent": [1], "content": [{"type": "text", "text": "{\"a\": 2}"}]})), Some(json!({"a": 2})));
        assert_eq!(rec(json!({"content": [{"type": "image"}, "junk", {"type": "text", "text": "{\"a\": 3}"}, {"type": "text", "text": "{\"a\": 4}"}]})), Some(json!({"a": 3})));
        // the first text item decides: if it is not a JSON object there is no record
        assert_eq!(rec(json!({"content": [{"type": "text", "text": "words"}, {"type": "text", "text": "{\"a\": 4}"}]})), None);
        assert_eq!(rec(json!({"content": [{"type": "text", "text": "[1]"}]})), None);
        assert_eq!(rec(json!({"isError": true, "structuredContent": {"a": 1}})), None);
        assert_eq!(rec(json!({"content": []})), None);
        assert_eq!(rec(json!({})), None);
        assert_eq!(rec(json!("x")), None);
        assert_eq!(record_of(None), None);
        assert_eq!(record_attr(&json!({"a": {"b": "x"}, "n": 1, "t": true, "f": 1.5, "z": null}), "a.b"), Some(json!("x")));
        for (field, want) in [("n", Some(json!(1))), ("t", Some(json!(true))), ("f", None), ("z", None), ("a", None), ("a.c", None), ("n.x", None), ("", None)] {
            assert_eq!(record_attr(&json!({"a": {"b": "x"}, "n": 1, "t": true, "f": 1.5, "z": null}), field), want, "{field}");
        }
    }
}
