//! Issue a role token, authorize a call, filter a record.
//!
//!   cargo run --release -p smartdelegate-core --example roles -- ../../spec/conformance/bundle
use serde_json::json;
use smartdelegate_core::Engine;

fn main() {
    let bundle = std::env::args().nth(1).unwrap_or_else(|| "../../spec/conformance/bundle".into());
    // No state_dir: keys live in memory and nothing is written to disk.
    let mut engine = Engine::new(&json!({"bundle_dir": bundle})).expect("the bundle loads");

    // alice lends support-bot her role "support-agent" for one task. The
    // token's capability is the role's ceiling; it cannot carry more.
    let issued = engine.call("issue_token", &json!({"user": "alice", "agent": "support-bot", "role": "support-agent", "task": "ticket-42"}));
    assert_eq!(issued["ok"], json!(true), "{issued}");
    let token = issued["token"].as_str().unwrap().to_string();
    println!("role {} for {} seconds, cap {}", issued["role"], issued["expires_in"], issued["cap"]);

    let decision = engine.call("authorize", &json!({"token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"}}));
    println!("authorize: {} ({})", decision["effect"], decision["rule"]);

    let filtered = engine.call("filter", &json!({
        "token": token, "action": "read", "resource": {"path": "crm.customer", "id": "c-1"},
        "data": {"id": "c-1", "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU"},
    }));
    println!("filter: {} masked {}", filtered["data"], filtered["masked"]);

    // A role the user does not hold is an error result, never a token.
    let refused = engine.call("issue_token", &json!({"user": "alice", "agent": "support-bot", "role": "supervisor", "task": "escalation-1"}));
    println!("supervisor: {} {}", refused["error"]["code"], refused["error"]["rule"]);
}
