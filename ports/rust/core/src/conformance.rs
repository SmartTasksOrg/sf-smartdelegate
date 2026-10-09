//! Runs one conformance case: a list of steps, each an engine operation with
//! an expected (partial) result. `"save"` stores a value from the result and
//! `"$name"` strings in later inputs are replaced by it.
//!
//! Language bindings implement the same ~30 lines themselves so that the
//! vectors exercise the binding, not just the core. The C runner, which has
//! no JSON library, calls this through the ABI.

use crate::Engine;
use serde_json::{json, Map, Value};

pub fn substitute(v: &Value, vars: &Map<String, Value>) -> Value {
    match v {
        Value::String(s) if s.starts_with('$') => vars.get(&s[1..]).cloned().unwrap_or_else(|| v.clone()),
        Value::Array(a) => Value::Array(a.iter().map(|x| substitute(x, vars)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), substitute(x, vars))).collect()),
        other => other.clone(),
    }
}

/// Every key in `expect` must be present and equal in `actual`; objects are
/// compared recursively, everything else exactly.
pub fn subset(expect: &Value, actual: &Value, path: &str) -> Option<String> {
    match (expect, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (k, ev) in e {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                match a.get(k) {
                    Some(av) => {
                        if let Some(m) = subset(ev, av, &p) {
                            return Some(m);
                        }
                    }
                    None if ev.is_null() => {}
                    None => return Some(format!("{p}: missing, expected {ev}")),
                }
            }
            None
        }
        _ if expect == actual => None,
        _ => Some(format!("{path}: expected {expect}, got {actual}")),
    }
}

/// The engine configuration for one case of a vector file: the standard
/// conformance settings, with the file's top-level `"config"` merged over
/// them (a suite may add settings, e.g. an identity provider).
pub fn case_config(bundle_dir: &std::path::Path, state_dir: &std::path::Path, doc: &Value) -> Value {
    let mut cfg = json!({
        "bundle_dir": bundle_dir.to_string_lossy(),
        "state_dir": state_dir.to_string_lossy(),
        "allow_test_clock": true,
        "max_depth": 3,
    });
    if let (Some(base), Some(extra)) = (cfg.as_object_mut(), doc.get("config").and_then(|c| c.as_object())) {
        for (k, v) in extra {
            base.insert(k.clone(), v.clone());
        }
    }
    cfg
}

pub fn run_case(engine: &mut Engine, case: &Value) -> Value {
    let mut vars = Map::new();
    let mut failures = Vec::new();
    let empty = vec![];
    for (i, step) in case["steps"].as_array().unwrap_or(&empty).iter().enumerate() {
        let op = step["op"].as_str().unwrap_or("");
        let input = substitute(&step["input"], &vars);
        let result = engine.call(op, &input);
        if let Some(save) = step["save"].as_object() {
            for (name, key) in save {
                // dotted path into the result, e.g. "approval.id"
                let mut cur = &result;
                for part in key.as_str().unwrap_or("").split('.') {
                    cur = &cur[part];
                }
                vars.insert(name.clone(), cur.clone());
            }
        }
        if let Some(m) = subset(&step["expect"], &result, "") {
            failures.push(json!({"step": i, "op": op, "mismatch": m}));
        }
    }
    json!({"name": case["name"], "passed": failures.is_empty(), "failures": failures})
}

/// Runs the unit tests in `<bundle>/tests/*.json` against a throwaway engine
/// (no state directory, no audit log, test clock on).
pub fn run_bundle_tests(bundle_dir: &std::path::Path) -> crate::Result<Value> {
    let mut results = Vec::new();
    let mut failed = 0;
    let tdir = bundle_dir.join("tests");
    let mut files: Vec<_> = match std::fs::read_dir(&tdir) {
        Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().map(|x| x == "json").unwrap_or(false)).collect(),
        Err(_) => vec![],
    };
    files.sort();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| crate::Error::new("bundle_io", e.to_string()))?;
        let doc: Value = serde_json::from_str(&text).map_err(|e| crate::Error::new("test_parse", format!("{}: {e}", f.display())))?;
        let empty = vec![];
        for case in doc["cases"].as_array().unwrap_or(&empty) {
            // a fresh engine per case keeps budgets and rate limits isolated
            let mut engine = Engine::new(&json!({
                "bundle_dir": bundle_dir.to_string_lossy(), "allow_test_clock": true, "trust_caller_chain": true, "audit": false,
            }))?;
            let r = run_case(&mut engine, case);
            if r["passed"] != json!(true) {
                failed += 1;
            }
            results.push(r);
        }
    }
    Ok(json!({"total": results.len(), "failed": failed, "results": results}))
}
