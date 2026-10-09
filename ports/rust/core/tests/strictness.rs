//! The "Strictness (0.3)" rules of spec/PORTING.md, one test per rule.
//! (`containsAll` / `containsAny` are covered by the eval cases, which
//! `conformance.rs` re-checks against Cedar.)
use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use smartdelegate_core::Engine;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const B64U: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn spec_bundle() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec/conformance/bundle")
}

/// A fresh directory under the system temp dir, removed on drop.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!("smartdelegate-strict-{}-{}-{}", std::process::id(), tag, N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

/// A private copy of the conformance bundle that a test may damage.
fn bundle_copy(tmp: &Tmp) -> PathBuf {
    let b = tmp.path().join("bundle");
    copy_dir(&spec_bundle(), &b);
    b
}

fn engine(state: &Path) -> Engine {
    Engine::new(&json!({"bundle_dir": spec_bundle().to_string_lossy(), "state_dir": state.to_string_lossy(), "allow_test_clock": true})).expect("engine")
}

fn load_error(bundle: &Path) -> String {
    match Engine::new(&json!({"bundle_dir": bundle.to_string_lossy()})) {
        Ok(_) => "(loaded)".to_string(),
        Err(e) => e.code,
    }
}

fn read_json(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn write_json(p: &Path, v: &Value) {
    std::fs::write(p, serde_json::to_string_pretty(v).unwrap() + "\n").unwrap();
}

const CAP: &str = r#"{"actions": ["read"], "resources": ["crm.customer/*"]}"#;

fn issue(e: &mut Engine, extra: Value) -> Value {
    let mut input = json!({"user": "alice", "agent": "support-bot", "cap": serde_json::from_str::<Value>(CAP).unwrap(), "now": 1000});
    for (k, v) in extra.as_object().unwrap() {
        input[k] = v.clone();
    }
    let r = e.call("issue_token", &input);
    assert_eq!(r["ok"], json!(true), "{r}");
    r
}

fn read_customer(token: &str) -> Value {
    json!({"token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}, "now": 1001})
}

/// Every way a token is presented must refuse `token` with `token_invalid`.
fn assert_token_invalid(e: &mut Engine, token: &str, why: &str) {
    let d = e.call("authorize", &read_customer(token));
    assert_eq!((&d["ok"], &d["effect"], &d["reason"]), (&json!(true), &json!("deny"), &json!("token_invalid")), "{why}: {d}");
    assert_eq!(d["rule"], json!("DELEGATE-TOKEN-INVALID"), "{why}");
    let i = e.call("inspect_token", &json!({"token": token, "now": 1001}));
    assert_eq!((&i["valid"], &i["reason"]), (&json!(false), &json!("token_invalid")), "{why}: {i}");
    let x = e.call("exchange_token", &json!({"subject_token": token, "actor": "refund-helper", "now": 1001}));
    assert_eq!((&x["ok"], &x["error"]["code"]), (&json!(false), &json!("token_invalid")), "{why}: {x}");
    let r = e.call("revoke", &json!({"token": token, "now": 1001}));
    assert_eq!((&r["ok"], &r["error"]["code"]), (&json!(false), &json!("token_invalid")), "{why}: {r}");
}

// ---- audit lines end at \n and nowhere else ---------------------------------

#[test]
fn audit_lines_end_at_newline_only() {
    let tmp = Tmp::new("audit");
    let state = tmp.path().join("state");
    // U+2028, U+2029 and U+0085 are written as themselves by canonical JSON
    let task = "line\u{2028}para\u{2029}nel\u{0085}end";
    let mut a = engine(&state);
    let t = issue(&mut a, json!({"task": task}));
    let token = t["token"].as_str().unwrap().to_string();
    let d = a.call("authorize", &read_customer(&token));
    assert_eq!(d["effect"], json!("allow"), "{d}");

    let raw = std::fs::read_to_string(state.join("audit.jsonl")).unwrap();
    assert!(raw.contains('\u{2028}') && raw.contains('\u{2029}') && raw.contains('\u{0085}'), "the separators are written as themselves");
    assert_eq!(raw.matches('\n').count(), 2, "one line feed per record");

    let v = a.call("audit_verify", &json!({}));
    assert_eq!((&v["ok"], &v["records"]), (&json!(true), &json!(2)), "{v}");
    let tail = a.call("audit_tail", &json!({"n": 10}));
    let recs = tail["records"].as_array().unwrap();
    assert_eq!(recs.len(), 2, "{tail}");
    assert_eq!((&recs[0]["event"], &recs[0]["task"]), (&json!("token_issued"), &json!(task)));
    assert_eq!((&recs[1]["event"], &recs[1]["task"]), (&json!("decision"), &json!(task)));

    // a second engine on the same state directory reads the log, chains onto
    // it, and the first engine chains onto that
    let mut b = engine(&state);
    let v = b.call("audit_verify", &json!({}));
    assert_eq!((&v["ok"], &v["records"]), (&json!(true), &json!(2)), "{v}");
    assert_eq!(b.call("authorize", &read_customer(&token))["effect"], json!("allow"));
    assert_eq!(a.call("authorize", &read_customer(&token))["effect"], json!("allow"));
    for e in [&mut a, &mut b] {
        let v = e.call("audit_verify", &json!({}));
        assert_eq!((&v["ok"], &v["records"]), (&json!(true), &json!(4)), "{v}");
        let tail = e.call("audit_tail", &json!({"n": 3}));
        let recs = tail["records"].as_array().unwrap();
        assert_eq!(recs.iter().map(|r| r["seq"].as_u64().unwrap()).collect::<Vec<_>>(), vec![2, 3, 4]);
        assert!(recs.iter().all(|r| r["task"] == json!(task)));
    }
}

// ---- base64url is strict ----------------------------------------------------

#[test]
fn base64url_is_strict() {
    let tmp = Tmp::new("b64");
    let mut e = engine(&tmp.path().join("state"));
    let token = issue(&mut e, json!({}))["token"].as_str().unwrap().to_string();
    assert_eq!(e.call("authorize", &read_customer(&token))["effect"], json!("allow"));
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    assert_token_invalid(&mut e, &format!("{token}!!!!"), "junk after the signature");
    for junk in ["!", "=", " ", "\n", "\t", "+", "/", "*", "\u{00e9}"] {
        assert_token_invalid(&mut e, &format!("{token}{junk}"), &format!("{junk:?} appended"));
        assert_token_invalid(&mut e, &format!("{junk}{token}"), &format!("{junk:?} prepended"));
        for seg in 0..3 {
            for at in [0, parts[seg].len() / 2, parts[seg].len()] {
                let mut p: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
                p[seg].insert_str(at, junk);
                assert_token_invalid(&mut e, &p.join("."), &format!("{junk:?} in segment {seg} at {at}"));
            }
        }
    }
    // padding, even the "correct" amount, is not part of the spelling
    for seg in 0..3 {
        let mut p: Vec<String> = parts.iter().map(|s| s.to_string()).collect();
        let pad = "=".repeat((4 - p[seg].len() % 4) % 4);
        if !pad.is_empty() {
            p[seg].push_str(&pad);
            assert_token_invalid(&mut e, &p.join("."), &format!("padding on segment {seg}"));
        }
    }
    // One token has one spelling: a different last character that decodes to
    // the same bytes (unused trailing bits set) is refused. A signature is
    // 64 bytes = 86 characters, so its last character carries 4 unused bits.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let sig = parts[2];
    assert_eq!(sig.len(), 86);
    let last = ALPHABET.iter().position(|c| *c == sig.as_bytes()[85]).unwrap();
    assert_eq!(last & 0x0f, 0, "a canonical signature leaves the unused bits clear");
    for bits in 1..16 {
        let alt = format!("{}.{}.{}{}", parts[0], parts[1], &sig[..85], ALPHABET[last | bits] as char);
        assert_token_invalid(&mut e, &alt, "non-canonical trailing bits in the signature");
    }
    assert_token_invalid(&mut e, &format!("{}.{}", parts[0], parts[1]), "two parts");
    assert_token_invalid(&mut e, &format!("{token}.{}", parts[2]), "four parts");
    // the untouched token still works
    assert_eq!(e.call("authorize", &read_customer(&token))["effect"], json!("allow"));
}

// ---- entity type names match in full ----------------------------------------

#[test]
fn entity_type_with_trailing_newline_is_rejected() {
    let tmp = Tmp::new("type");
    let mut e = engine(&tmp.path().join("state"));
    let token = issue(&mut e, json!({}))["token"].as_str().unwrap().to_string();
    for bad in ["User\n", "User ", " User", "User\r\n", "A::B\n", "A:: B", "", "1User", "A::"] {
        // in the request context
        let mut req = read_customer(&token);
        req["context"] = json!({"who": {"__entity": {"type": bad, "id": "alice"}}});
        let r = e.call("authorize", &req);
        assert_eq!((&r["ok"], &r["error"]["code"]), (&json!(false), &json!("invalid_context")), "context type {bad:?}: {r}");
        // nested, and inside a list
        req["context"] = json!({"a": {"b": [{"__entity": {"type": bad, "id": "alice"}}]}});
        let r = e.call("authorize", &req);
        assert_eq!((&r["ok"], &r["error"]["code"]), (&json!(false), &json!("invalid_context")), "nested context type {bad:?}: {r}");
        // in the attributes of the resource
        let mut req = read_customer(&token);
        req["resource"]["attrs"] = json!({"owner": {"__entity": {"type": bad, "id": "alice"}}});
        let r = e.call("authorize", &req);
        assert_eq!((&r["ok"], &r["error"]["code"]), (&json!(false), &json!("invalid_input")), "attrs type {bad:?}: {r}");
        // a group of that type is not a group entities.json defines
        let t = issue(&mut e, json!({"groups": [{"type": bad, "id": "support"}, "support"]}));
        let i = e.call("inspect_token", &json!({"token": t["token"], "now": 1001}));
        assert_eq!(i["claims"]["grp"], json!([{"type": "Group", "id": "support"}]), "group type {bad:?}");
        // engine configuration
        let cfg = json!({"bundle_dir": spec_bundle().to_string_lossy(), "idp": {"issuer": "i", "audience": "a", "jwks": {"keys": []}, "group_type": bad}});
        if !bad.is_empty() {
            assert_eq!(Engine::new(&cfg).err().map(|e| e.code).as_deref(), Some("invalid_config"), "group_type {bad:?}");
        }
    }
    // the well-formed spelling is fine everywhere
    let mut req = read_customer(&token);
    req["context"] = json!({"who": {"__entity": {"type": "User", "id": "alice"}}});
    assert_eq!(e.call("authorize", &req)["effect"], json!("allow"));

    // bundle files
    for bad in ["User\n", "Group ", " Agent", "A::B\n"] {
        let t = Tmp::new("type-bundle");
        let b = bundle_copy(&t);
        let orig = read_json(&b.join("entities.json"));
        let mut ents = orig.clone();
        ents.as_array_mut().unwrap().push(json!({"uid": {"type": bad, "id": "x"}, "attrs": {}, "parents": []}));
        write_json(&b.join("entities.json"), &ents);
        assert_eq!(load_error(&b), "entities_parse", "uid type {bad:?}");
        let mut ents = orig.clone();
        ents.as_array_mut().unwrap().push(json!({"uid": {"type": "User", "id": "x"}, "attrs": {}, "parents": [{"type": bad, "id": "support"}]}));
        write_json(&b.join("entities.json"), &ents);
        assert_eq!(load_error(&b), "entities_parse", "parent type {bad:?}");
        let mut ents = orig.clone();
        ents.as_array_mut().unwrap().push(json!({"uid": {"type": "User", "id": "x"}, "attrs": {"boss": {"__entity": {"type": bad, "id": "bob"}}}, "parents": []}));
        write_json(&b.join("entities.json"), &ents);
        assert_eq!(load_error(&b), "entities_parse", "attribute type {bad:?}");
        write_json(&b.join("entities.json"), &orig);

        let orig = read_json(&b.join("catalog.json"));
        let mut cat = orig.clone();
        cat["resources"]["crm.customer"]["entity_type"] = json!(bad);
        write_json(&b.join("catalog.json"), &cat);
        assert_eq!(load_error(&b), "catalog_parse", "catalog type {bad:?}");
        write_json(&b.join("catalog.json"), &orig);

        let orig = read_json(&b.join("roles.json"));
        let mut roles = orig.clone();
        roles["roles"]["auditor"]["members"] = json!([{"type": bad, "id": "compliance"}]);
        write_json(&b.join("roles.json"), &roles);
        assert_eq!(load_error(&b), "roles_parse", "role member type {bad:?}");
        write_json(&b.join("roles.json"), &orig);

        // compiled policies, with and without the sources next to them
        let orig = read_json(&b.join("policies.json"));
        for (name, policy) in [
            ("scope ==", json!({"effect": "permit", "principal": {"op": "==", "entity": {"type": bad, "id": "x"}}, "action": {"op": "All"}, "resource": {"op": "All"}, "conditions": []})),
            ("scope is", json!({"effect": "permit", "principal": {"op": "is", "entity_type": bad}, "action": {"op": "All"}, "resource": {"op": "All"}, "conditions": []})),
            ("literal", json!({"effect": "permit", "principal": {"op": "All"}, "action": {"op": "All"}, "resource": {"op": "All"},
                "conditions": [{"kind": "when", "body": {"==": {"left": {"Var": "principal"}, "right": {"Value": {"__entity": {"type": bad, "id": "x"}}}}}}]})),
        ] {
            let mut doc = orig.clone();
            doc["policies"]["strict-test"] = policy;
            write_json(&b.join("policies.json"), &doc);
            assert_eq!(load_error(&b), "policy_parse", "policy {name} type {bad:?}");
        }
        write_json(&b.join("policies.json"), &orig);
        assert_eq!(load_error(&b), "(loaded)");
    }
}

// ---- policy JSON shapes are checked at load ---------------------------------

#[test]
fn malformed_policy_json_shapes_are_policy_parse() {
    let permit = |principal: Value, body: Option<Value>| {
        let conditions = match body {
            Some(b) => json!([{"kind": "when", "body": b}]),
            None => json!([]),
        };
        json!({"effect": "permit", "principal": principal, "action": {"op": "All"}, "resource": {"op": "All"}, "conditions": conditions})
    };
    let all = || json!({"op": "All"});
    let lit = |v: Value| json!({"==": {"left": v, "right": {"Value": 1}}});
    let mut cases: Vec<(&str, Value)> = vec![
        ("conditions is an object", {
            let mut p = permit(all(), None);
            p["conditions"] = json!({});
            p
        }),
        ("conditions is a string", {
            let mut p = permit(all(), None);
            p["conditions"] = json!("when");
            p
        }),
        ("annotations is an array", {
            let mut p = permit(all(), None);
            p["annotations"] = json!([]);
            p
        }),
        ("annotations is a string", {
            let mut p = permit(all(), None);
            p["annotations"] = json!("id");
            p
        }),
        ("Set literal is an object", permit(all(), Some(lit(json!({"Set": {}}))))),
        ("Set literal is a string", permit(all(), Some(lit(json!({"Set": "ab"}))))),
        ("Record literal is an array", permit(all(), Some(lit(json!({"Record": []}))))),
        ("Record literal is a string", permit(all(), Some(lit(json!({"Record": "ab"}))))),
        ("like pattern is a string", permit(all(), Some(json!({"like": {"left": {"Value": "abc"}, "pattern": "a*"}})))),
        ("like pattern is an object", permit(all(), Some(json!({"like": {"left": {"Value": "abc"}, "pattern": {"Literal": "a"}}})))),
        ("like pattern element is not Wildcard or Literal", permit(all(), Some(json!({"like": {"left": {"Value": "abc"}, "pattern": ["a"]}})))),
        ("scope entities is an object", permit(json!({"op": "in", "entities": {"type": "Group", "id": "support"}}), None)),
        ("scope entities is a string", {
            let mut p = permit(all(), None);
            p["action"] = json!({"op": "in", "entities": "read"});
            p
        }),
        ("a policy is an array", json!([])),
        ("a policy is a string", json!("permit")),
    ];
    // the well-formed spellings of the same constructs load
    let good = vec![
        permit(all(), Some(lit(json!({"Set": [{"Value": 1}]})))),
        permit(all(), Some(lit(json!({"Record": {"a": {"Value": 1}}})))),
        permit(all(), Some(json!({"like": {"left": {"Value": "abc"}, "pattern": [{"Literal": "a"}, "Wildcard"]}}))),
        permit(json!({"op": "in", "entity": {"type": "Group", "id": "support"}}), None),
        {
            let mut p = permit(all(), None);
            p["action"] = json!({"op": "in", "entities": [{"type": "Action", "id": "read"}]});
            p["annotations"] = json!({"id": "strict-test"});
            p
        },
    ];
    for with_sources in [true, false] {
        let tmp = Tmp::new("shapes");
        let b = bundle_copy(&tmp);
        if !with_sources {
            std::fs::remove_dir_all(b.join("policies")).unwrap();
        }
        let orig = read_json(&b.join("policies.json"));
        assert_eq!(load_error(&b), "(loaded)");
        for g in &good {
            let mut doc = orig.clone();
            doc["policies"]["strict-test"] = g.clone();
            write_json(&b.join("policies.json"), &doc);
            // with the sources present, an extra compiled policy is stale
            assert_eq!(load_error(&b), if with_sources { "bundle_stale" } else { "(loaded)" }, "{g}");
        }
        for (name, bad) in cases.drain(..).collect::<Vec<_>>().into_iter().map(|c| { cases.push(c.clone()); c }) {
            let mut doc = orig.clone();
            doc["policies"]["strict-test"] = bad;
            write_json(&b.join("policies.json"), &doc);
            assert_eq!(load_error(&b), "policy_parse", "{name} (sources present: {with_sources})");
        }
        for (name, doc) in [
            ("policies is an array", json!({"format": orig["format"], "sources": orig["sources"], "policies": []})),
            ("policies is missing", json!({"format": orig["format"], "sources": orig["sources"]})),
            ("the document is an array", json!([])),
            ("the document is a string", json!("policies")),
        ] {
            write_json(&b.join("policies.json"), &doc);
            let code = load_error(&b);
            // a document without the source hashes cannot be shown to be current
            let ok = code == "policy_parse" || (with_sources && !doc.is_object() && code == "bundle_stale");
            assert!(ok, "{name} (sources present: {with_sources}): {code}");
        }
        std::fs::write(b.join("policies.json"), "{not json").unwrap();
        assert_eq!(load_error(&b), "policy_parse", "not JSON");
        write_json(&b.join("policies.json"), &orig);
        assert_eq!(load_error(&b), "(loaded)");
    }
}

// ---- token claims -------------------------------------------------------------

struct Signer {
    key: Ed25519KeyPair,
    private_b64: String,
    kid: String,
}

impl Signer {
    fn new() -> Signer {
        let (sk, _) = smartdelegate_core::bundle::keygen().unwrap();
        let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&B64.decode(&sk).unwrap()).unwrap();
        let kid = smartdelegate_core::canon::sha256_hex(key.public_key().as_ref())[..16].to_string();
        Signer { key, private_b64: sk, kid }
    }
    /// A correctly signed token with exactly these claims.
    fn token(&self, claims: &Value) -> String {
        let head = B64U.encode(json!({"typ": "JWT", "alg": "EdDSA", "kid": self.kid}).to_string());
        let body = B64U.encode(claims.to_string());
        let sig = self.key.sign(format!("{head}.{body}").as_bytes());
        format!("{head}.{body}.{}", B64U.encode(sig.as_ref()))
    }
}

#[test]
fn malformed_token_claims_are_token_invalid() {
    let tmp = Tmp::new("claims");
    let signer = Signer::new();
    let mut e = Engine::new(&json!({
        "bundle_dir": spec_bundle().to_string_lossy(), "state_dir": tmp.path().join("state").to_string_lossy(),
        "allow_test_clock": true, "signing_key": signer.private_b64,
    }))
    .unwrap();
    let good = json!({
        "iss": "smartdelegate://local", "aud": "smartdelegate", "sub": "user:alice", "iat": 1000, "exp": 1900, "jti": "t-1",
        "act": {"sub": "agent:support-bot"}, "anc": [], "cap": serde_json::from_str::<Value>(CAP).unwrap(),
    });
    // the forger is sound: an honest token made this way is accepted
    let d = e.call("authorize", &read_customer(&signer.token(&good)));
    assert_eq!(d["effect"], json!("allow"), "{d}");
    let with = |k: &str, v: Value| {
        let mut c = good.clone();
        c[k] = v;
        c
    };
    let mut ancestors = good.clone();
    ancestors["anc"] = json!(["t-0"]);
    assert_eq!(e.call("authorize", &read_customer(&signer.token(&ancestors)))["effect"], json!("allow"));

    for (why, claims) in [
        ("anc is a string", with("anc", json!("t-0"))),
        ("anc is an empty string", with("anc", json!(""))),
        ("anc is an object", with("anc", json!({"0": "t-0"}))),
        ("anc holds a number", with("anc", json!([1]))),
        ("anc holds a list", with("anc", json!([["t-0"]]))),
        ("anc is a number", with("anc", json!(7))),
        ("role is empty", with("role", json!(""))),
        ("role is null", with("role", Value::Null)),
        ("role is a list", with("role", json!(["auditor"]))),
        ("grp is a string", with("grp", json!("support"))),
        ("grp holds a name", with("grp", json!(["support"]))),
        ("grp member without an id", with("grp", json!([{"type": "Group"}]))),
        ("grp is null", with("grp", Value::Null)),
        ("exp is a string", with("exp", json!("1900"))),
        ("iat is a float", with("iat", json!(1000.5))),
        ("jti is a number", with("jti", json!(1))),
        ("act is a string", with("act", json!("agent:support-bot"))),
        ("cap is a list", with("cap", json!([]))),
        ("cap has an unknown field", with("cap", json!({"actions": ["read"], "resources": ["*"], "resorces": ["*"]}))),
        ("cap.actions is a string", with("cap", json!({"actions": "read", "resources": ["*"]}))),
    ] {
        assert_token_invalid(&mut e, &signer.token(&claims), why);
    }
}

// ---- files that are not UTF-8, entities.json that is not a list of objects --

const NOT_UTF8: &[u8] = b"{\"revoked\": {\"\xff\xfe\": 1}}\n";

#[test]
fn non_utf8_state_file_is_state_io() {
    let tmp = Tmp::new("state");
    let state = tmp.path().join("state");
    let mut e = engine(&state);
    let token = issue(&mut e, json!({}))["token"].as_str().unwrap().to_string();
    std::fs::write(state.join("state.json"), NOT_UTF8).unwrap();
    // an engine that is running refuses every operation
    for (op, input) in [("authorize", read_customer(&token)), ("info", json!({})), ("revoke", json!({"token_id": "x"})), ("approvals", json!({}))] {
        let r = e.call(op, &input);
        assert_eq!((&r["ok"], &r["error"]["code"]), (&json!(false), &json!("state_io")), "{op}: {r}");
        assert_eq!(r["error"]["rule"], json!("DELEGATE-STATE-IO"));
    }
    // and a new one does not start
    let cfg = json!({"bundle_dir": spec_bundle().to_string_lossy(), "state_dir": state.to_string_lossy()});
    assert_eq!(Engine::new(&cfg).err().map(|e| e.code).as_deref(), Some("state_io"));
    // valid UTF-8 that is not a state document is the same failure
    for junk in ["[]", "{\"revoked\": []}", "not json", "\"x\""] {
        std::fs::write(state.join("state.json"), junk).unwrap();
        assert_eq!(Engine::new(&cfg).err().map(|e| e.code).as_deref(), Some("state_io"), "{junk}");
        assert_eq!(e.call("authorize", &read_customer(&token))["error"]["code"], json!("state_io"), "{junk}");
    }
}

#[test]
fn non_utf8_audit_log_is_audit_broken() {
    let tmp = Tmp::new("auditutf8");
    let state = tmp.path().join("state");
    let mut e = engine(&state);
    let token = issue(&mut e, json!({}))["token"].as_str().unwrap().to_string();
    let log = state.join("audit.jsonl");
    let good = std::fs::read(&log).unwrap();

    // a byte that is not UTF-8 inside the first record
    let mut bad = good.clone();
    let at = bad.iter().position(|b| *b == b'a').unwrap();
    bad[at] = 0xff;
    std::fs::write(&log, &bad).unwrap();
    let v = e.call("audit_verify", &json!({}));
    assert_eq!((&v["ok"], &v["error"]["code"]), (&json!(false), &json!("audit_broken")), "{v}");
    let cfg = json!({"bundle_dir": spec_bundle().to_string_lossy(), "state_dir": state.to_string_lossy(), "allow_test_clock": true});
    assert_eq!(Engine::new(&cfg).err().map(|e| e.code).as_deref(), Some("audit_broken"));
    // reading the tail never fails on it; it shows what can be read
    let t = e.call("audit_tail", &json!({"n": 5}));
    assert_eq!(t["ok"], json!(true), "{t}");

    // garbage appended by something else: the next decision cannot be chained
    // onto it, so it is refused rather than allowed without a record
    let mut bad = good.clone();
    bad.extend_from_slice(b"\xff\xfe\xfd\n");
    std::fs::write(&log, &bad).unwrap();
    let d = e.call("authorize", &read_customer(&token));
    assert_eq!((&d["ok"], &d["error"]["code"]), (&json!(false), &json!("audit_io")), "{d}");
    let v = e.call("audit_verify", &json!({}));
    assert_eq!(v["error"]["code"], json!("audit_broken"), "{v}");
    assert_eq!(Engine::new(&cfg).err().map(|e| e.code).as_deref(), Some("audit_broken"));

    // restored, everything works again
    std::fs::write(&log, &good).unwrap();
    assert_eq!(Engine::new(&cfg).map(|_| ()).map_err(|e| e.code), Ok(()));
    assert_eq!(e.call("audit_verify", &json!({}))["records"], json!(1));
}

#[test]
fn non_utf8_bundle_file_is_bundle_io() {
    for name in ["policies.json", "entities.json", "catalog.json", "roles.json", "policies/crm.cedar"] {
        let tmp = Tmp::new("bundleutf8");
        let b = bundle_copy(&tmp);
        let mut bytes = std::fs::read(b.join(name)).unwrap();
        bytes.extend_from_slice(b"\xff\xfe");
        std::fs::write(b.join(name), &bytes).unwrap();
        assert_eq!(load_error(&b), "bundle_io", "{name}");
        // a running engine keeps its bundle when a reload fails
        let good = Tmp::new("bundleutf8-live");
        let live = bundle_copy(&good);
        let mut e = Engine::new(&json!({"bundle_dir": live.to_string_lossy()})).unwrap();
        let version = e.call("info", &json!({}))["policy_version"].clone();
        std::fs::write(live.join(name), &bytes).unwrap();
        let r = e.call("reload", &json!({}));
        assert_eq!((&r["ok"], &r["error"]["code"]), (&json!(false), &json!("bundle_io")), "{name}: {r}");
        assert_eq!(e.call("info", &json!({}))["policy_version"], version);
    }
    // the signature file, when a signature is required
    let tmp = Tmp::new("sigutf8");
    let b = bundle_copy(&tmp);
    let (sk, pk) = smartdelegate_core::bundle::keygen().unwrap();
    smartdelegate_core::bundle::sign(&b, &sk).unwrap();
    let cfg = json!({"bundle_dir": b.to_string_lossy(), "bundle_public_key": pk});
    assert!(Engine::new(&cfg).is_ok());
    std::fs::write(b.join("bundle.sig.json"), b"\xff\xfe{}").unwrap();
    assert_eq!(Engine::new(&cfg).err().map(|e| e.code).as_deref(), Some("bundle_io"));
}

#[test]
fn entities_json_must_be_a_list_of_objects() {
    let tmp = Tmp::new("entities");
    let b = bundle_copy(&tmp);
    let orig = std::fs::read_to_string(b.join("entities.json")).unwrap();
    for bad in [
        "{}", "{\"entities\": []}", "\"entities\"", "7", "null", "true", "[1]", "[\"User::alice\"]", "[[]]", "[null]",
        "[{\"uid\": {\"type\": \"User\", \"id\": \"alice\"}}, 3]", "[{}]", "[{\"uid\": \"User::alice\"}]", "[{\"uid\": {\"type\": \"User\"}}]",
        "[{\"uid\": {\"type\": \"User\", \"id\": \"a\"}, \"attrs\": []}]", "[{\"uid\": {\"type\": \"User\", \"id\": \"a\"}, \"parents\": {}}]",
        "[{\"uid\": {\"type\": \"User\", \"id\": \"a\"}}, {\"uid\": {\"type\": \"User\", \"id\": \"a\"}}]", "not json",
    ] {
        std::fs::write(b.join("entities.json"), bad).unwrap();
        assert_eq!(load_error(&b), "entities_parse", "{bad}");
    }
    for good in ["[]", "[{\"uid\": {\"type\": \"User\", \"id\": \"a\"}}]", "[{\"uid\": {\"__entity\": {\"type\": \"User\", \"id\": \"a\"}}, \"attrs\": {}, \"parents\": []}]"] {
        std::fs::write(b.join("entities.json"), good).unwrap();
        assert_eq!(load_error(&b), "(loaded)", "{good}");
    }
    std::fs::write(b.join("entities.json"), orig).unwrap();
    assert_eq!(load_error(&b), "(loaded)");
}

// ---- creating the signing key ---------------------------------------------------

/// Not a test of its own: the body of one racing process. With
/// SMARTDELEGATE_RACE_DIR set it waits for the start signal, opens an
/// engine on that state directory and prints the key it ended up with.
#[test]
fn signing_key_race_child() {
    let Ok(dir) = std::env::var("SMARTDELEGATE_RACE_DIR") else { return };
    let dir = PathBuf::from(dir);
    while !dir.join("go").exists() {
        std::hint::spin_loop();
    }
    let mut e = engine(&dir.join("state"));
    let info = e.call("info", &json!({}));
    let t = issue(&mut e, json!({}));
    println!("RACE-KEY {} {}", info["public_key"].as_str().unwrap(), t["token"].as_str().unwrap());
}

#[test]
fn two_processes_creating_the_signing_key_end_up_with_one() {
    for round in 0..5 {
        let tmp = Tmp::new("race");
        std::fs::create_dir_all(tmp.path().join("state")).unwrap();
        let children: Vec<_> = (0..8)
            .map(|_| {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "signing_key_race_child", "--nocapture", "--test-threads", "1"])
                    .env("SMARTDELEGATE_RACE_DIR", tmp.path())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap()
            })
            .collect();
        // let them all reach the starting line, then release them together
        std::thread::sleep(std::time::Duration::from_millis(300));
        std::fs::write(tmp.path().join("go"), "").unwrap();
        let mut keys = Vec::new();
        let mut tokens = Vec::new();
        for c in children {
            let out = c.wait_with_output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            assert!(out.status.success(), "round {round}: a racing process failed:\n{text}\n{}", String::from_utf8_lossy(&out.stderr));
            let line = text.lines().find_map(|l| l.split("RACE-KEY ").nth(1)).unwrap_or_else(|| panic!("no key reported:\n{text}"));
            let mut it = line.split(' ');
            keys.push(it.next().unwrap().to_string());
            tokens.push(it.next().unwrap().to_string());
        }
        assert_eq!(keys.len(), 8);
        assert!(keys.iter().all(|k| k == &keys[0]), "round {round}: the processes disagree about the key: {keys:?}");
        let state = tmp.path().join("state");
        assert_eq!(std::fs::read_to_string(state.join("signing_key.pub.b64")).unwrap(), keys[0]);
        let stray: Vec<_> = std::fs::read_dir(&state).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).filter(|n| n.ends_with(".tmp")).collect();
        assert!(stray.is_empty(), "temporary key files left behind: {stray:?}");
        // every token any of them issued is good for a late-comer, and all
        // eight issuances are in one unbroken audit chain
        let mut late = engine(&state);
        assert_eq!(late.call("info", &json!({}))["public_key"], json!(keys[0]));
        for t in &tokens {
            let d = late.call("authorize", &read_customer(t));
            assert_eq!(d["effect"], json!("allow"), "round {round}: {d}");
        }
        let v = late.call("audit_verify", &json!({}));
        assert_eq!((&v["ok"], &v["records"]), (&json!(true), &json!(16)), "round {round}: {v}");
    }
}

#[test]
fn threads_creating_the_signing_key_end_up_with_one() {
    let tmp = Tmp::new("race-threads");
    let state = tmp.path().join("state");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (state, barrier) = (state.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                engine(&state).call("info", &json!({}))["public_key"].as_str().unwrap().to_string()
            })
        })
        .collect();
    let keys: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(keys.iter().all(|k| k == &keys[0]), "{keys:?}");
}

// ---- revoking a user, and state written by other ports ------------------------

#[test]
fn revoked_users_is_optional_in_state_and_unknown_keys_are_kept() {
    let tmp = Tmp::new("offboard");
    let state = tmp.path().join("state");
    let mut e = engine(&state);
    let t = issue(&mut e, json!({"task": "ticket-1"}));
    assert_eq!((&t["task"], &t["role"]), (&json!("ticket-1"), &Value::Null));
    let token = t["token"].as_str().unwrap().to_string();
    // a state file from before the key existed, with a key this port does not know
    std::fs::write(state.join("state.json"), r#"{"revoked":{},"approvals":{},"pending":{},"ledger":{},"limits":{},"future_key":{"a":[1,2]}}"#).unwrap();
    assert_eq!(e.call("authorize", &read_customer(&token))["effect"], json!("allow"));

    for bad in [json!(""), json!(7), Value::Null, json!(["alice"]), json!({"id": "alice"})] {
        // `user` takes precedence, so a good token next to it does not rescue the call
        let r = e.call("revoke", &json!({"user": bad, "token": token, "now": 1001}));
        assert_eq!((&r["ok"], &r["error"]["code"]), (&json!(false), &json!("invalid_input")), "{r}");
    }
    let r = e.call("revoke", &json!({"user": "alice", "token_id": "ignored", "by": "hr", "now": 1000}));
    assert_eq!((&r["ok"], &r["revoked_user"], &r["issued_up_to"], &r["revoked"]), (&json!(true), &json!("alice"), &json!(1000), &Value::Null), "{r}");
    let saved = read_json(&state.join("state.json"));
    assert_eq!(saved["revoked_users"], json!({"alice": 1000}));
    assert_eq!(saved["future_key"], json!({"a": [1, 2]}), "a key written by another port survives a save");
    assert_eq!(saved["revoked"], json!({}), "token_id was not also revoked");

    // iat == cut-off is revoked; the denial is attributed to the principal
    let d = e.call("authorize", &read_customer(&token));
    assert_eq!((&d["effect"], &d["reason"], &d["principal"]["user"]), (&json!("deny"), &json!("token_revoked"), &json!("alice")), "{d}");
    // a token issued after the cut-off works, and a second engine sees the same
    let later = e.call("issue_token", &json!({"user": "alice", "agent": "support-bot", "cap": serde_json::from_str::<Value>(CAP).unwrap(), "now": 1001}));
    let mut other = engine(&state);
    assert_eq!(other.call("authorize", &read_customer(later["token"].as_str().unwrap()))["effect"], json!("allow"));
    assert_eq!(other.call("authorize", &read_customer(&token))["reason"], json!("token_revoked"));
    let tail = e.call("audit_tail", &json!({"n": 50}));
    let ev = tail["records"].as_array().unwrap().iter().find(|r| r["event"] == json!("user_revoked")).expect("user_revoked is audited").clone();
    assert_eq!((&ev["user"], &ev["issued_up_to"], &ev["by"]), (&json!("alice"), &json!(1000), &json!("hr")));
    // entries are never pruned: still there long after, when a token with a budget triggers pruning
    let far = 1000 + 400 * 86_400;
    let r = e.call("issue_token", &json!({"user": "bob", "agent": "support-bot", "cap": {"actions": ["read"], "resources": ["crm.customer/*"], "budget": {"EUR": 5}}, "now": far}));
    assert_eq!(r["ok"], json!(true), "{r}");
    assert_eq!(read_json(&state.join("state.json"))["revoked_users"], json!({"alice": 1000}));
}

// ---- an empty signing key file is still being written -------------------------

#[test]
fn empty_signing_key_file_is_waited_for() {
    let tmp = Tmp::new("emptykey");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let kp = state.join("signing_key.pk8.b64");
    // another port has created the file and has not written it yet
    std::fs::write(&kp, "").unwrap();
    let (sk, pk) = smartdelegate_core::bundle::keygen().unwrap();
    let writer = {
        let (kp, sk) = (kp.clone(), sk.clone());
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(400));
            std::fs::write(&kp, format!("{sk}\n")).unwrap();
        })
    };
    let started = std::time::Instant::now();
    let mut e = engine(&state);
    assert!(started.elapsed() >= std::time::Duration::from_millis(300), "the engine waited for the key");
    writer.join().unwrap();
    let info = e.call("info", &json!({}));
    assert_eq!((&info["public_key"], &info["can_issue"]), (&json!(pk), &json!(true)), "{info}");
    let token = issue(&mut e, json!({}))["token"].as_str().unwrap().to_string();
    assert_eq!(e.call("authorize", &read_customer(&token))["effect"], json!("allow"));
    // the key on disk is the writer's, untouched
    assert_eq!(std::fs::read_to_string(&kp).unwrap().trim(), sk);
}

#[test]
fn signing_key_file_that_stays_empty_is_state_io() {
    for content in ["", "\n", "  \r\n"] {
        let tmp = Tmp::new("emptykey-forever");
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let kp = state.join("signing_key.pk8.b64");
        std::fs::write(&kp, content).unwrap();
        let cfg = json!({"bundle_dir": spec_bundle().to_string_lossy(), "state_dir": state.to_string_lossy(), "signing_key_wait_ms": 250});
        let started = std::time::Instant::now();
        let err = Engine::new(&cfg).err().expect("an empty key is not 'no key'");
        assert_eq!(err.code, "state_io", "{content:?}: {}", err.message);
        assert!(started.elapsed() >= std::time::Duration::from_millis(250), "it waited before giving up");
        assert_eq!(std::fs::read_to_string(&kp).unwrap(), content, "the file was neither replaced nor filled");
        assert!(!state.join("signing_key.pub.b64").exists(), "no key was generated in its place");
    }
}

// ---- an ancestor's budget travels with the token (`lim`) ----------------------

fn refund_cap(eur: i64) -> Value {
    json!({"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": eur}})
}

fn spend(e: &mut Engine, token: &Value, amount: i64) -> Value {
    e.call("authorize", &json!({
        "token": token, "action": "create", "resource": {"path": "billing.refund", "id": "r"}, "now": 1001,
        "context": {"spend": {"currency": "EUR", "amount": amount}},
    }))
}

#[test]
fn a_verifier_with_its_own_state_enforces_an_ancestors_budget() {
    let tmp = Tmp::new("lim");
    let mut issuer = engine(&tmp.path().join("issuer"));
    let parent = issuer.call("issue_token", &json!({"user": "alice", "agent": "support-bot", "now": 1000, "cap": refund_cap(10000)}));
    assert_eq!(parent["ok"], json!(true), "{parent}");
    let i = issuer.call("inspect_token", &json!({"token": parent["token"], "now": 1000}));
    assert!(i["claims"].get("lim").is_none(), "a root token has no ancestors and so no lim: {i}");
    let kids: Vec<Value> = (0..3)
        .map(|_| {
            let k = issuer.call("exchange_token", &json!({"subject_token": parent["token"], "actor": "refund-helper", "ttl": 300, "now": 1000, "cap": refund_cap(6000)}));
            assert_eq!(k["ok"], json!(true), "{k}");
            k
        })
        .collect();
    let mut lim = serde_json::Map::new();
    lim.insert(parent["token_id"].as_str().unwrap().to_string(), json!({"EUR": 10000}));
    let i = issuer.call("inspect_token", &json!({"token": kids[0]["token"], "now": 1000}));
    assert_eq!(i["claims"]["lim"], Value::Object(lim.clone()), "{i}");
    // a grandchild carries the limits of both ancestors
    let grand = issuer.call("exchange_token", &json!({"subject_token": kids[0]["token"], "actor": "summarizer", "ttl": 200, "now": 1000, "cap": refund_cap(100)}));
    assert_eq!(grand["ok"], json!(true), "{grand}");
    lim.insert(kids[0]["token_id"].as_str().unwrap().to_string(), json!({"EUR": 6000}));
    let i = issuer.call("inspect_token", &json!({"token": grand["token"], "now": 1000}));
    assert_eq!(i["claims"]["lim"], Value::Object(lim), "{i}");

    // an engine elsewhere: its own state directory, no signing key
    let vdir = tmp.path().join("verifier");
    let mut verifier = Engine::new(&json!({
        "bundle_dir": spec_bundle().to_string_lossy(), "state_dir": vdir.to_string_lossy(), "allow_test_clock": true,
        "verify_only": true, "trusted_keys": [issuer.call("info", &json!({}))["public_key"]],
    }))
    .unwrap();
    assert_eq!(spend(&mut verifier, &kids[0]["token"], 5000)["effect"], json!("allow"));
    assert_eq!(spend(&mut verifier, &kids[1]["token"], 5000)["effect"], json!("allow"));
    let third = spend(&mut verifier, &kids[2]["token"], 5000);
    assert_eq!((&third["effect"], &third["reason"]), (&json!("deny"), &json!("budget_exceeded")), "{third}");
    // the verifier knew the parent's limit only from the token
    assert_eq!(read_json(&vdir.join("state.json"))["limits"], json!({}));
    // the grandchild is held to the parent's budget too (10000 is spent)
    let g = spend(&mut verifier, &grand["token"], 50);
    assert_eq!((&g["effect"], &g["reason"]), (&json!("deny"), &json!("budget_exceeded")), "{g}");
    // tokens without a budget anywhere in the family have no lim
    let plain = issue(&mut issuer, json!({}));
    let child = issuer.call("exchange_token", &json!({"subject_token": plain["token"], "actor": "refund-helper", "ttl": 300, "now": 1000}));
    let i = issuer.call("inspect_token", &json!({"token": child["token"], "now": 1000}));
    assert!(i["valid"] == json!(true) && i["claims"].get("lim").is_none(), "{i}");
}

#[test]
fn the_issuers_own_record_of_a_limit_wins_over_the_claim_and_malformed_lim_is_token_invalid() {
    let tmp = Tmp::new("limclaims");
    let signer = Signer::new();
    let mut e = Engine::new(&json!({
        "bundle_dir": spec_bundle().to_string_lossy(), "state_dir": tmp.path().join("state").to_string_lossy(),
        "allow_test_clock": true, "signing_key": signer.private_b64,
    }))
    .unwrap();
    let good = json!({
        "iss": "smartdelegate://local", "aud": "smartdelegate", "sub": "user:alice", "iat": 1000, "exp": 1900, "jti": "kid-1",
        "act": {"sub": "agent:refund-helper", "act": {"sub": "agent:support-bot"}}, "anc": ["root-1"],
        "lim": {"root-1": {"EUR": 300}}, "cap": refund_cap(6000),
    });
    let with = |v: Value| {
        let mut c = good.clone();
        c["lim"] = v;
        c
    };
    // an honest token made this way is held to lim
    let d = spend(&mut e, &json!(signer.token(&good)), 301);
    assert_eq!((&d["effect"], &d["reason"]), (&json!("deny"), &json!("budget_exceeded")), "{d}");
    assert_eq!(spend(&mut e, &json!(signer.token(&good)), 300)["effect"], json!("allow"));
    // an empty lim, and one for a currency that is not spent, are well formed
    for ok in [json!({}), json!({"root-1": {}}), json!({"root-1": {"USD": 0}})] {
        let mut c = with(ok.clone());
        c["jti"] = json!(format!("kid-{ok}"));
        c["anc"] = json!([format!("root-{ok}")]);
        // (inspected, not spent: refunds are rate limited to 3 a minute)
        let i = e.call("inspect_token", &json!({"token": signer.token(&c), "now": 1001}));
        assert_eq!(i["valid"], json!(true), "{ok}: {i}");
    }
    for bad in [
        json!("x"), json!([]), Value::Null, json!(7), json!({"a": 5}), json!({"a": {"EUR": -1}}), json!({"a": {"EUR": "9"}}),
        json!({"a": {"EUR": 1.5}}), json!({"a": {"EUR": true}}), json!({"a": {"EUR": null}}), json!({"a": []}), json!({"a": "EUR"}),
        json!({"root-1": {"EUR": 300}, "b": {"EUR": [1]}}),
    ] {
        assert_token_invalid(&mut e, &signer.token(&with(bad.clone())), &format!("lim {bad}"));
    }

    // When this engine issued the ancestor, its own record is the limit: a
    // claim cannot raise it.
    let parent = e.call("issue_token", &json!({"user": "alice", "agent": "support-bot", "now": 1000, "cap": refund_cap(1000)}));
    let mut forged = good.clone();
    forged["jti"] = json!("kid-2");
    forged["anc"] = json!([parent["token_id"]]);
    forged["lim"] = json!({parent["token_id"].as_str().unwrap(): {"EUR": 999999}});
    let d = e.call("authorize", &json!({
        "token": signer.token(&forged), "action": "create", "resource": {"path": "billing.refund", "id": "r"}, "now": 1200,
        "context": {"spend": {"currency": "EUR", "amount": 1001}},
    }));
    assert_eq!((&d["effect"], &d["reason"]), (&json!("deny"), &json!("budget_exceeded")), "{d}");
}

#[test]
fn the_user_cut_off_never_moves_back() {
    let tmp = Tmp::new("cutoff");
    let state = tmp.path().join("state");
    let mut e = engine(&state);
    let r = e.call("revoke", &json!({"user": "alice", "now": 2000}));
    assert_eq!(r["issued_up_to"], json!(2000));
    let r = e.call("revoke", &json!({"user": "alice", "by": "sync", "now": 1500}));
    assert_eq!((&r["ok"], &r["revoked_user"], &r["issued_up_to"]), (&json!(true), &json!("alice"), &json!(2000)), "{r}");
    assert_eq!(read_json(&state.join("state.json"))["revoked_users"], json!({"alice": 2000}));
    let tail = e.call("audit_tail", &json!({"n": 1}));
    let last = &tail["records"][0];
    assert_eq!((&last["event"], &last["issued_up_to"], &last["ts"], &last["by"]), (&json!("user_revoked"), &json!(2000), &json!(1500), &json!("sync")), "{last}");
    assert_eq!(e.call("revoke", &json!({"user": "alice", "now": 2500}))["issued_up_to"], json!(2500));
    // a stored value that is not an integer (written by something else) is replaced
    std::fs::write(state.join("state.json"), r#"{"revoked_users":{"alice":"soon"}}"#).unwrap();
    assert_eq!(e.call("revoke", &json!({"user": "alice", "now": 100}))["issued_up_to"], json!(100));
}

// ---- an approval is bound to resource.attrs -----------------------------------

#[test]
fn an_approval_is_bound_to_the_resource_attributes() {
    let tmp = Tmp::new("approval");
    let mut e = engine(&tmp.path().join("state"));
    let t = e.call("issue_token", &json!({"user": "alice", "agent": "support-bot", "now": 1000, "cap": refund_cap(20000)}));
    assert_eq!(t["ok"], json!(true), "{t}");
    let ask = |e: &mut Engine, attrs: Option<Value>, dry: bool| {
        let mut req = json!({
            "token": t["token"], "action": "create", "resource": {"path": "billing.refund", "id": "r-1"}, "now": 1001,
            "context": {"spend": {"currency": "EUR", "amount": 15000}}, "dry_run": dry,
        });
        if let Some(a) = attrs {
            req["resource"]["attrs"] = a;
        }
        e.call("authorize", &req)
    };
    let id = |d: &Value| {
        assert_eq!((&d["effect"], &d["reason"]), (&json!("deny"), &json!("approval_required")), "{d}");
        d["approval"]["id"].as_str().unwrap().to_string()
    };
    let emp1 = json!({"employee": "emp-1", "meta": {"n": 3, "name": "Zoë"}});
    let emp1_shuffled: Value = serde_json::from_str(r#"{"meta": {"name": "Zoë", "n": 3}, "employee": "emp-1"}"#).unwrap();
    let emp2 = json!({"employee": "emp-2", "meta": {"n": 3, "name": "Zoë"}});
    let a1 = id(&ask(&mut e, Some(emp1.clone()), true));
    assert_eq!(a1.len(), 24);
    assert_eq!(id(&ask(&mut e, Some(emp1_shuffled.clone()), true)), a1, "key order does not matter");
    let a2 = id(&ask(&mut e, Some(emp2.clone()), true));
    let none = id(&ask(&mut e, None, true));
    assert_eq!(id(&ask(&mut e, Some(Value::Null), true)), none, "null attrs are no attrs");
    assert_eq!(id(&ask(&mut e, Some(json!({})), true)), none, "empty attrs are no attrs");
    assert!(a1 != a2 && a1 != none && a2 != none, "{a1} {a2} {none}");
    assert_ne!(id(&ask(&mut e, Some(json!({"employee": "emp-1", "meta": {"n": 4, "name": "Zoë"}})), true)), a1, "a nested value counts");

    // approve the request about emp-1; the same request naming emp-2 is still held
    assert_eq!(id(&ask(&mut e, Some(emp1.clone()), false)), a1);
    let ok = e.call("approve", &json!({"approval_id": a1, "by": "bob", "now": 1002}));
    assert_eq!(ok["ok"], json!(true), "{ok}");
    assert_eq!(id(&ask(&mut e, Some(emp2), false)), a2);
    assert_eq!(id(&ask(&mut e, None, false)), none);
    let granted = e.call("approvals", &json!({}));
    assert!(granted["granted"].get(&a1).is_some(), "the approval was not consumed by another request: {granted}");
    let d = ask(&mut e, Some(emp1_shuffled), false);
    assert_eq!((&d["effect"], &d["obligations"]["approved"]["id"]), (&json!("allow"), &json!(a1)), "{d}");
    // single use: the grant is gone once it has let one call through
    let granted = e.call("approvals", &json!({}));
    assert!(granted["granted"].get(&a1).is_none(), "{granted}");
    let _ = emp1;
}

// ---- reload re-reads idp.jwks_file ----------------------------------------------

impl Signer {
    fn jwk(&self) -> Value {
        json!({"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": self.kid, "x": B64U.encode(self.key.public_key().as_ref())})
    }
    fn jwks(&self) -> String {
        json!({"keys": [self.jwk()]}).to_string()
    }
    fn id_token(&self, user: &str) -> String {
        self.token(&json!({"iss": "https://idp.example.test", "aud": "client-1", "sub": user, "iat": 900, "exp": 5000}))
    }
}

#[test]
fn reload_rereads_the_jwks_file_and_a_broken_one_keeps_the_old_keys() {
    let tmp = Tmp::new("jwks");
    let bundle = bundle_copy(&tmp);
    let jwks_path = tmp.path().join("jwks.json");
    let (old, new) = (Signer::new(), Signer::new());
    std::fs::write(&jwks_path, old.jwks()).unwrap();
    let mut e = Engine::new(&json!({
        "bundle_dir": bundle.to_string_lossy(), "state_dir": tmp.path().join("state").to_string_lossy(), "allow_test_clock": true,
        "idp": {"issuer": "https://idp.example.test", "audience": "client-1", "jwks_file": jwks_path.to_string_lossy()},
    }))
    .unwrap();
    let issue_with = |e: &mut Engine, s: &Signer| {
        let r = e.call("issue_token", &json!({"id_token": s.id_token("alice"), "agent": "support-bot", "role": "support-agent", "now": 1000}));
        if r["ok"] == json!(true) {
            assert_eq!(r["user"], json!("alice"));
            "ok".to_string()
        } else {
            r["error"]["code"].as_str().unwrap().to_string()
        }
    };
    assert_eq!(issue_with(&mut e, &old), "ok");
    assert_eq!(issue_with(&mut e, &new), "id_token_invalid");

    // the provider rotates its key: nothing changes until reload
    std::fs::write(&jwks_path, new.jwks()).unwrap();
    assert_eq!(issue_with(&mut e, &old), "ok");
    assert_eq!(issue_with(&mut e, &new), "id_token_invalid");
    let r = e.call("reload", &json!({}));
    assert_eq!(r["ok"], json!(true), "{r}");
    assert_eq!(issue_with(&mut e, &new), "ok");
    assert_eq!(issue_with(&mut e, &old), "id_token_invalid");
    let version = r["policy_version"].clone();

    // a file that does not load leaves the keys in force
    let broken: Vec<Vec<u8>> = vec![
        b"{not json".to_vec(), b"[]".to_vec(), b"\"keys\"".to_vec(), b"{}".to_vec(), b"{\"keys\": {}}".to_vec(), b"{\"keys\": \"x\"}".to_vec(), b"\xff\xfe{\"keys\": []}".to_vec(),
    ];
    for bytes in &broken {
        std::fs::write(&jwks_path, bytes).unwrap();
        let r = e.call("reload", &json!({}));
        assert_eq!((&r["ok"], &r["error"]["code"], &r["error"]["rule"]), (&json!(false), &json!("invalid_config"), &json!("DELEGATE-INVALID-CONFIG")), "{:?}: {r}", String::from_utf8_lossy(bytes));
        assert_eq!(issue_with(&mut e, &new), "ok");
        assert_eq!(issue_with(&mut e, &old), "id_token_invalid");
    }
    std::fs::remove_file(&jwks_path).unwrap();
    assert_eq!(e.call("reload", &json!({}))["error"]["code"], json!("invalid_config"));
    assert_eq!(issue_with(&mut e, &new), "ok");

    // ... and the bundle too: a changed bundle is not taken when the keys fail
    std::fs::write(&jwks_path, b"{not json").unwrap();
    let roles = std::fs::read_to_string(bundle.join("roles.json")).unwrap();
    std::fs::write(bundle.join("roles.json"), roles.replace("\"max_ttl\": 600", "\"max_ttl\": 60")).unwrap();
    assert_eq!(e.call("reload", &json!({}))["error"]["code"], json!("invalid_config"));
    assert_eq!(e.call("info", &json!({}))["policy_version"], version, "the old bundle stays with the old keys");
    // the other way round: good new keys, a bundle that fails
    std::fs::write(&jwks_path, old.jwks()).unwrap();
    std::fs::write(bundle.join("roles.json"), "{\"roles\": {\"x\": {\"taks\": []}}}").unwrap();
    assert_eq!(e.call("reload", &json!({}))["error"]["code"], json!("roles_parse"));
    assert_eq!(issue_with(&mut e, &new), "ok");
    assert_eq!(issue_with(&mut e, &old), "id_token_invalid");
    assert_eq!(e.call("info", &json!({}))["policy_version"], version);
    // both good: both replaced
    std::fs::write(bundle.join("roles.json"), roles.replace("\"max_ttl\": 600", "\"max_ttl\": 60")).unwrap();
    let r = e.call("reload", &json!({}));
    assert_eq!(r["ok"], json!(true), "{r}");
    assert_ne!(r["policy_version"], version);
    assert_eq!(issue_with(&mut e, &old), "ok");
    assert_eq!(issue_with(&mut e, &new), "id_token_invalid");

    // keys given inline are not a file: reload leaves them alone
    let mut inline = Engine::new(&json!({
        "bundle_dir": spec_bundle().to_string_lossy(), "allow_test_clock": true,
        "idp": {"issuer": "https://idp.example.test", "audience": "client-1", "jwks": {"keys": [new.jwk()]}, "jwks_file": tmp.path().join("missing.json").to_string_lossy()},
    }))
    .unwrap();
    assert_eq!(inline.call("reload", &json!({}))["ok"], json!(true));
    assert_eq!(issue_with(&mut inline, &new), "ok");
}
