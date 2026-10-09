use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub fn die(msg: &str) -> ! {
    eprintln!("smartdelegate: {msg}");
    std::process::exit(1)
}

pub fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

const SWITCHES: &[&str] = &["raw", "strict", "dry-run", "shadow", "help"];

pub struct Args {
    pub pos: Vec<String>,
    flags: HashMap<String, String>,
    pub rest: Vec<String>,
}

impl Args {
    pub fn parse(argv: Vec<String>) -> Args {
        let mut a = Args { pos: vec![], flags: HashMap::new(), rest: vec![] };
        let mut i = 0;
        while i < argv.len() {
            let x = &argv[i];
            if x == "--" {
                a.rest = argv[i + 1..].to_vec();
                break;
            }
            if let Some(name) = x.strip_prefix("--").or_else(|| x.strip_prefix('-').filter(|n| n.len() == 1)) {
                if SWITCHES.contains(&name) {
                    a.flags.insert(name.to_string(), "true".into());
                } else if let Some((k, v)) = name.split_once('=') {
                    a.flags.insert(k.to_string(), v.to_string());
                } else {
                    i += 1;
                    let v = argv.get(i).cloned().unwrap_or_else(|| die(&format!("--{name} needs a value")));
                    a.flags.insert(name.to_string(), v);
                }
            } else {
                a.pos.push(x.clone());
            }
            i += 1;
        }
        if a.has("help") {
            a.pos = vec!["help".into()];
        }
        a
    }
    pub fn flag(&self, k: &str) -> Option<String> {
        self.flags.get(k).cloned()
    }
    pub fn has(&self, k: &str) -> bool {
        self.flags.contains_key(k)
    }
    pub fn req(&self, k: &str) -> String {
        self.flag(k).unwrap_or_else(|| die(&format!("--{k} is required")))
    }
}

/// A JSON value given inline or as @file (friendlier in PowerShell and cmd).
pub fn json_arg(s: &str) -> Value {
    let text = match s.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{path}: {e}"))),
        None => s.to_string(),
    };
    serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap_or_else(|e| die(&format!("not valid JSON ({e}): {s}")))
}

pub fn random_key() -> String {
    // 32 random bytes from the same generator that makes signing keys
    let (sk, _) = smartdelegate_core::bundle::keygen().unwrap_or_else(|e| die(&e.to_string()));
    smartdelegate_core::canon::sha256_hex(sk.as_bytes())[..40].to_string()
}

fn resolve(base: &Path, p: &str) -> String {
    let pb = PathBuf::from(p);
    if pb.is_absolute() { p.to_string() } else { base.join(pb).to_string_lossy().to_string() }
}

/// Config file + command-line overrides. Relative paths in the file are
/// relative to the file.
pub fn load_config(args: &Args) -> Value {
    let path = args.flag("config").or_else(|| std::env::var("SMARTDELEGATE_CONFIG").ok()).or_else(|| Path::new("smartdelegate.json").exists().then(|| "smartdelegate.json".to_string()));
    let mut cfg = json!({});
    if let Some(p) = &path {
        let text = std::fs::read_to_string(p).unwrap_or_else(|e| die(&format!("{p}: {e}")));
        cfg = serde_json::from_str(text.trim_start_matches('\u{feff}')).unwrap_or_else(|e| die(&format!("{p}: {e}")));
        let base = Path::new(p).parent().map(|x| x.to_path_buf()).unwrap_or_default();
        for k in ["bundle_dir", "state_dir"] {
            if let Some(v) = cfg[k].as_str().map(String::from) {
                cfg[k] = json!(resolve(&base, &v));
            }
        }
        if let Some(v) = cfg["idp"]["jwks_file"].as_str().map(String::from) {
            cfg["idp"]["jwks_file"] = json!(resolve(&base, &v));
        }
    }
    if let Some(b) = args.flag("bundle") {
        cfg["bundle_dir"] = json!(b);
    }
    if let Some(s) = args.flag("state") {
        cfg["state_dir"] = json!(s);
    }
    if args.has("shadow") {
        cfg["mode"] = json!("shadow");
    }
    for (k, env) in [("admin_key", "SMARTDELEGATE_ADMIN_KEY"), ("pep_key", "SMARTDELEGATE_PEP_KEY")] {
        if let Ok(v) = std::env::var(env) {
            cfg[k] = json!(v);
        }
    }
    if cfg["bundle_dir"].is_null() {
        die("no bundle: run `smartdelegate init <dir>`, or pass --config FILE or --bundle DIR");
    }
    cfg
}

/// Constant-time comparison for API keys.
pub fn same(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Resolve a mapping expression: `{"literal": v}` is v; "args.x.y" /
/// "body.x" / "query.x" look into `sources` (through objects only); "args",
/// "body", "query" alone are the whole object; "{name}" is a path parameter;
/// anything else is a literal. `None`: the request does not have the value.
pub fn resolve_expr(expr: &Value, sources: &Value, params: &HashMap<String, String>) -> Option<Value> {
    if let Some(o) = expr.as_object() {
        if o.len() == 1 && o.contains_key("literal") {
            return Some(o["literal"].clone());
        }
    }
    let Some(s) = expr.as_str() else { return Some(expr.clone()) };
    if s.len() >= 2 && s.starts_with('{') && s.ends_with('}') {
        return params.get(&s[1..s.len() - 1]).map(|v| json!(v));
    }
    if let Some(whole) = sources.get(s) {
        return Some(whole.clone());
    }
    let (head, tail) = s.split_once('.').unwrap_or((s, ""));
    if !tail.is_empty() && sources.get(head).is_some() {
        let mut cur = &sources[head];
        for part in tail.split('.') {
            cur = cur.as_object()?.get(part)?;
        }
        return Some(cur.clone());
    }
    Some(json!(s))
}

/// Is this `{"literal": <value>}`?
pub fn is_literal(expr: &Value) -> bool {
    expr.as_object().map(|o| o.len() == 1 && o.contains_key("literal")).unwrap_or(false)
}

/// Why `expr` cannot stand where a value is taken from the request, or `None`.
///
/// Allowed: `<source>.<a>[.<b>...]` for a source in `sources`; `{name}` for a
/// path parameter in `params`; `<source>` alone when `whole`;
/// `{"literal": value}`; a JSON number or boolean (it can only mean itself).
/// A bare string is refused: "args" for "args.changes", or "body.amount"
/// misspelt, must not quietly become a constant and switch a check off.
pub fn expr_problem(expr: &Value, sources: &[&str], params: Option<&std::collections::HashSet<String>>, whole: bool) -> Option<String> {
    let text = match expr {
        Value::Object(_) => return if is_literal(expr) { None } else { Some("an object here must be {\"literal\": <value>}".into()) },
        Value::Bool(_) | Value::Number(_) => return None,
        Value::String(s) if !s.is_empty() => s.as_str(),
        _ => return Some("must be an expression or {\"literal\": <value>}".into()),
    };
    if text.starts_with('{') && text.ends_with('}') {
        return match params {
            Some(p) if text.len() >= 2 && p.contains(&text[1..text.len() - 1]) => None,
            Some(_) => Some(format!("{text} is not a path parameter of this route")),
            None => Some("path parameters do not exist here".into()),
        };
    }
    let (head, tail) = match text.split_once('.') {
        Some((h, t)) => (h, Some(t)),
        None => (text, None),
    };
    if sources.contains(&head) {
        return match tail {
            Some(t) if !t.is_empty() && t.split('.').all(|part| !part.is_empty()) => None,
            None if whole => None,
            None => Some(format!("\"{text}\" names the whole {head}; a member is needed here (\"{head}.<name>\")")),
            Some(_) => Some(format!("\"{text}\" is not a path into {head}")),
        };
    }
    let forms = sources.iter().map(|s| format!("{s}.<name>")).collect::<Vec<_>>().join(", ");
    Some(format!("\"{text}\" is not an expression ({forms}{}); write {{\"literal\": \"{text}\"}} if the constant is meant", if params.is_some() { ", {param}" } else { "" }))
}

/// The keys of `obj` that are not in `allowed`, sorted.
pub fn unknown_keys(obj: &serde_json::Map<String, Value>, allowed: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = obj.keys().filter(|k| !allowed.contains(&k.as_str())).cloned().collect();
    v.sort();
    v
}

/// Is `v` one of the allowed words, when the key is present at all?
pub fn one_of(obj: &Value, key: &str, allowed: &[&str]) -> bool {
    match obj.get(key) {
        None => true,
        Some(v) => v.as_str().map(|s| allowed.contains(&s)).unwrap_or(false),
    }
}

/// A member of a looked-up record, `a.b` for a nested one, when it is a
/// string, an integer or a boolean. Anything else cannot be an attribute.
pub fn record_attr(record: &Value, dotted: &str) -> Option<Value> {
    let mut cur = record;
    for part in dotted.split('.') {
        cur = cur.as_object()?.get(part)?;
    }
    (cur.is_string() || cur.is_boolean() || cur.is_i64() || cur.is_u64()).then(|| cur.clone())
}

/// Denials that do not depend on resource attributes: decided before a
/// lookup, so a caller outside the tenant or the capability learns nothing
/// from it.
pub const EARLY_DENIALS: [&str; 7] = ["token_invalid", "token_expired", "token_revoked", "unknown_resource", "tenant_mismatch", "capability_action", "capability_resource"];

pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

pub fn bench(args: &Args) -> ! {
    let n: usize = args.flag("n").and_then(|x| x.parse().ok()).unwrap_or(5000);
    let cap = json!({"actions": ["read"], "resources": ["crm.customer/*"]});
    let mut times = Vec::with_capacity(n);
    let label;
    if let Some(url) = args.flag("url") {
        let key = args.req("pep-key");
        let token = args.req("token");
        label = format!("daemon at {url}");
        let agent = ureq::AgentBuilder::new().build();
        let body = json!({"token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}});
        for _ in 0..n {
            let t = std::time::Instant::now();
            let r = agent.post(&format!("{url}/v1/authorize")).set("Authorization", &format!("Bearer {key}")).send_json(body.clone());
            if r.is_err() {
                die("request failed; is the daemon running and are the key and token right?");
            }
            let _ = r.unwrap().into_string();
            times.push(t.elapsed().as_secs_f64() * 1000.0);
        }
    } else {
        let mut cfg = load_config(args);
        let state = std::env::temp_dir().join(format!("smartdelegate-bench-{}", std::process::id()));
        cfg["state_dir"] = json!(state.to_string_lossy());
        let mut e = smartdelegate_core::Engine::new(&cfg).unwrap_or_else(|e| die(&e.to_string()));
        let t = e.call("issue_token", &json!({"user": "alice", "agent": "support-bot", "cap": cap}));
        let token = t["token"].as_str().unwrap_or_else(|| die("bench needs the example bundle (user alice, agent support-bot)")).to_string();
        label = "in-process, example bundle, audit log on, 12 field decisions per call".to_string();
        let input = json!({"token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}});
        for _ in 0..n {
            let t = std::time::Instant::now();
            let r = e.call("authorize", &input);
            times.push(t.elapsed().as_secs_f64() * 1000.0);
            if r["effect"] != json!("allow") {
                die("unexpected deny during bench");
            }
        }
        let _ = std::fs::remove_dir_all(&state);
    }
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("{}", pretty(&json!({
        "what": label, "calls": n,
        "p50_ms": (percentile(&times, 0.50) * 1000.0).round() / 1000.0,
        "p99_ms": (percentile(&times, 0.99) * 1000.0).round() / 1000.0,
        "max_ms": (times.last().copied().unwrap_or(0.0) * 1000.0).round() / 1000.0,
    })));
    std::process::exit(0)
}
