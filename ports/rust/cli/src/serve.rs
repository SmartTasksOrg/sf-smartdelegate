//! REST decision daemon. See docs/openapi.yaml.
//!
//! Two keys guard it:
//!   pep key    enforcement points: /v1/authorize, /v1/filter, /v1/explain,
//!              /v1/obligations/apply, /v1/token/inspect, /v1/info
//!   admin key  /v1/admin/* and issuing a root token without an OIDC ID token
//! /v1/token needs no key for token exchange (holding the parent token is the
//! authority) or for issuance backed by a verified OIDC ID token.
//! TLS is not terminated here: bind to loopback or put it behind a mesh.

use crate::http::{Request, Response, Server};
use crate::util::{die, same, Args};
use serde_json::{json, Value};
use smartdelegate_core::Engine;
use std::sync::{Arc, Mutex};

fn respond(status: u16, body: &Value) -> Response {
    Response::json(status, body)
}

fn read_json(req: &Request) -> Result<Value, String> {
    let raw = req.body.as_ref().map_err(|e| e.message.clone())?;
    let text = std::str::from_utf8(raw).map_err(|e| format!("body is not JSON: {e}"))?;
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(text).map_err(|e| format!("body is not JSON: {e}"))
}

/// How many requests may be in progress at once: `--max-concurrent`, or
/// `max_concurrent` in the configuration, default 256.
pub const DEFAULT_MAX_CONCURRENT: usize = 256;

pub fn max_concurrent(args: &Args, cfg: &Value) -> usize {
    let n = match args.flag("max-concurrent") {
        Some(v) => v.parse::<usize>().unwrap_or_else(|_| die("--max-concurrent must be a positive number")),
        None => cfg["max_concurrent"].as_u64().map(|n| n as usize).unwrap_or(DEFAULT_MAX_CONCURRENT),
    };
    if n == 0 {
        die("max_concurrent must be at least 1");
    }
    n
}

pub fn listen_on(listen: &str) -> Server {
    Server::bind(listen).unwrap_or_else(|e| die(&format!("cannot listen on {listen}: {e}")))
}

/// 503 with `Retry-After`, for a request that arrives while `max_concurrent`
/// others are in progress.
pub fn busy(body: &Value) -> Response {
    Response::json(503, body).with_header("Retry-After", "1")
}

fn handle(req: Request, engine: &Arc<Mutex<Engine>>, admin_key: &str, pep_key: &str) -> Response {
    let (path, query) = req.target.split_once('?').unwrap_or((req.target.as_str(), ""));
    let method = req.method.as_str();
    let key = req.bearer().unwrap_or_default();
    let is_admin = same(&key, admin_key);
    let is_pep = is_admin || same(&key, pep_key);
    let unauthorized = smartdelegate_core::Error::new("unauthorized", "missing or wrong API key").to_json();

    // The framing rule of the proxy holds here too: a request not framed by
    // exactly one Content-Length is refused before anything else (the server
    // has read no body and closes the connection), whatever its method.
    if let Err(bad) = &req.body {
        return respond(bad.status, &smartdelegate_core::Error::new(bad.code, bad.message.clone()).to_json());
    }
    if path == "/healthz" {
        return respond(200, &json!({"ok": true}));
    }
    let body = if method == "POST" {
        match read_json(&req) {
            Ok(b) => b,
            Err(m) => return respond(400, &smartdelegate_core::Error::new("invalid_input", m).to_json()),
        }
    } else {
        json!({})
    };

    let (op, allowed, input): (&str, bool, Value) = match (method, path) {
        ("GET", "/v1/info") => ("info", is_pep, body),
        ("POST", "/v1/authorize") => ("authorize", is_pep, body),
        ("POST", "/v1/filter") => ("filter", is_pep, body),
        ("POST", "/v1/explain") => ("explain", is_pep, body),
        ("POST", "/v1/obligations/apply") => ("apply_obligations", is_pep, body),
        ("POST", "/v1/token/inspect") => ("inspect_token", is_pep, body),
        ("POST", "/v1/token") => {
            if body.get("subject_token").is_some() {
                ("exchange_token", true, body)
            } else if body.get("id_token").is_some() {
                // identity must come from the ID token alone
                let mut b = body;
                b.as_object_mut().map(|o| o.remove("user"));
                ("issue_token", true, b)
            } else {
                ("issue_token", is_admin, body)
            }
        }
        ("POST", "/v1/admin/revoke") => ("revoke", is_admin, body),
        ("POST", "/v1/admin/approve") => ("approve", is_admin, body),
        ("POST", "/v1/admin/reload") => ("reload", is_admin, body),
        ("GET", "/v1/admin/approvals") => ("approvals", is_admin, body),
        ("GET", "/v1/admin/audit/verify") => ("audit_verify", is_admin, body),
        ("GET", "/v1/admin/audit/tail") => {
            let n = query.split('&').find_map(|kv| kv.strip_prefix("n=")).and_then(|v| v.parse::<u64>().ok()).unwrap_or(20);
            ("audit_tail", is_admin, json!({"n": n}))
        }
        _ => return respond(404, &smartdelegate_core::Error::new("not_found", "no such endpoint").to_json()),
    };
    if !allowed {
        return respond(401, &unauthorized);
    }
    let result = match engine.lock() {
        Ok(mut e) => e.call(op, &input),
        Err(_) => smartdelegate_core::Error::new("poisoned", "engine is unusable after an internal error").to_json(),
    };
    let status = if result["ok"] == json!(true) { 200 } else if result["error"]["code"] == json!("poisoned") { 500 } else { 400 };
    respond(status, &result)
}

pub fn run(args: &Args) -> ! {
    let (engine, cfg) = crate::engine_from(args);
    let listen = args.flag("listen").or_else(|| cfg["listen"].as_str().map(String::from)).unwrap_or_else(|| "127.0.0.1:8181".into());
    let admin_key = cfg["admin_key"].as_str().unwrap_or("").to_string();
    let pep_key = cfg["pep_key"].as_str().unwrap_or("").to_string();
    if admin_key.len() < 16 || pep_key.len() < 16 {
        die("serve needs admin_key and pep_key (16+ characters) in the config or SMARTDELEGATE_ADMIN_KEY / SMARTDELEGATE_PEP_KEY");
    }
    let server = listen_on(&listen);
    let engine = Arc::new(Mutex::new(engine));
    eprintln!("smartdelegate daemon listening on http://{}", server.addr());
    let max = max_concurrent(args, &cfg);
    server.serve(
        max,
        move |req| handle(req, &engine, &admin_key, &pep_key),
        || busy(&smartdelegate_core::Error::new("overloaded", "too many requests in progress; try again").to_json()),
        |status, why| respond(status, &smartdelegate_core::Error::new("invalid_input", why).to_json()),
    );
    std::process::exit(0)
}
