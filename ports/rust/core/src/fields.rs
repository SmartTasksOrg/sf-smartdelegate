//! Applying a field mask and a row filter to JSON data.
//!
//! Field paths are relative to the resource: `email`, `address.zip`,
//! `orders[].total`. `[]` stands for "each element of this array".
//!
//! Rules (fail closed):
//!  * a denied path is dropped, or replaced by "[REDACTED]" when the catalog
//!    says `mask: redact`; its whole subtree goes with it
//!  * an allowed path is kept; children that have their own catalog entry are
//!    still checked one by one, other children are kept with the parent
//!  * a path the catalog does not list, under no allowed parent, is dropped

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Copy, PartialEq)]
pub enum Status {
    Allow,
    Deny,
    Redact,
}

pub struct Mask {
    pub status: BTreeMap<String, Status>,
}

impl Mask {
    fn has_children(&self, path: &str) -> bool {
        let a = format!("{path}.");
        let b = format!("{path}[]");
        self.status.keys().any(|k| k.starts_with(&a) || k.starts_with(&b))
    }
}

fn join(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}.{key}")
    }
}

fn walk_value(v: &Value, path: &str, inherit: bool, mask: &Mask, masked: &mut BTreeSet<String>) -> Option<Value> {
    match v {
        Value::Object(m) => Some(Value::Object(walk_object(m, path, inherit, mask, masked))),
        Value::Array(a) => {
            let p = format!("{path}[]");
            let st = mask.status.get(&p).copied();
            let mut out = Vec::new();
            for el in a {
                match st {
                    Some(Status::Deny) => {
                        masked.insert(p.clone());
                    }
                    Some(Status::Redact) => {
                        masked.insert(p.clone());
                        out.push(json!(REDACTED));
                    }
                    Some(Status::Allow) => {
                        if let Some(x) = walk_value(el, &p, true, mask, masked) {
                            out.push(x)
                        }
                    }
                    None => {
                        if el.is_object() || el.is_array() {
                            if let Some(x) = walk_value(el, &p, inherit, mask, masked) {
                                out.push(x)
                            }
                        } else if inherit {
                            out.push(el.clone());
                        } else {
                            masked.insert(p.clone());
                        }
                    }
                }
            }
            Some(Value::Array(out))
        }
        other => {
            if inherit {
                Some(other.clone())
            } else {
                None
            }
        }
    }
}

fn walk_object(m: &Map<String, Value>, prefix: &str, inherit: bool, mask: &Mask, masked: &mut BTreeSet<String>) -> Map<String, Value> {
    let mut out = Map::new();
    for (k, v) in m {
        let p = join(prefix, k);
        match mask.status.get(&p).copied() {
            Some(Status::Deny) => {
                masked.insert(p);
            }
            Some(Status::Redact) => {
                masked.insert(p);
                out.insert(k.clone(), json!(REDACTED));
            }
            Some(Status::Allow) => {
                if mask.has_children(&p) {
                    if let Some(x) = walk_value(v, &p, true, mask, masked) {
                        out.insert(k.clone(), x);
                    }
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            None => {
                if inherit && !mask.has_children(&p) {
                    out.insert(k.clone(), v.clone());
                } else if (v.is_object() || v.is_array()) && mask.has_children(&p) {
                    if let Some(x) = walk_value(v, &p, inherit, mask, masked) {
                        out.insert(k.clone(), x);
                    }
                } else if inherit {
                    out.insert(k.clone(), v.clone());
                } else {
                    masked.insert(p);
                }
            }
        }
    }
    out
}

pub struct Filtered {
    pub data: Value,
    pub masked: Vec<String>,
    pub rows_dropped: usize,
}

fn row_matches(row: &Value, filter: &[Value]) -> bool {
    filter.iter().all(|c| {
        let col = c["column"].as_str().unwrap_or("");
        match row.get(col) {
            Some(v) => *v == c["value"],
            None => false,
        }
    })
}

/// `data` is one record (object) or a list of records (array of objects).
pub fn apply(data: &Value, mask: &Mask, row_filter: &[Value]) -> Filtered {
    let mut masked = BTreeSet::new();
    let mut rows_dropped = 0;
    let out = match data {
        Value::Array(rows) => {
            let mut kept = Vec::new();
            for r in rows {
                match r {
                    Value::Object(m) if row_matches(r, row_filter) => {
                        kept.push(Value::Object(walk_object(m, "", false, mask, &mut masked)))
                    }
                    _ => rows_dropped += 1,
                }
            }
            Value::Array(kept)
        }
        Value::Object(m) => {
            if row_matches(data, row_filter) {
                Value::Object(walk_object(m, "", false, mask, &mut masked))
            } else {
                rows_dropped = 1;
                Value::Null
            }
        }
        // A bare scalar has no field identity, so nothing can authorise it.
        _ => {
            rows_dropped = 1;
            Value::Null
        }
    };
    Filtered { data: out, masked: masked.into_iter().collect(), rows_dropped }
}

/// Which data paths would be touched by the mask (used by strict mode).
pub fn denied_in(data: &Value, mask: &Mask) -> Vec<String> {
    apply(data, mask, &[]).masked
}
