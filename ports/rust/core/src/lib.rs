//! SmartDelegate core: policy decisions (Cedar), delegation tokens, field-level
//! obligations and a hash-chained audit log for LLM agents.
//!
//! Every operation is JSON in, JSON out (`Engine::call`). The same surface is
//! exported through the C ABI in `ffi.rs`, so every language binding and the
//! daemon share one implementation and one conformance suite.

pub mod audit;
pub mod bundle;
pub mod canon;
pub mod conformance;
pub mod engine;
pub mod evalspec;
pub mod ffi;
pub mod fields;
pub mod state;
pub mod token;

pub use engine::Engine;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The rule id of a decision reason or an error code:
/// `policy_forbid` -> `DELEGATE-POLICY-FORBID`.
pub fn rule_id(code: &str) -> String {
    format!("DELEGATE-{}", code.to_uppercase().replace('_', "-"))
}

#[derive(Debug, Clone)]
pub struct Error {
    pub code: String,
    pub message: String,
}

impl Error {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Error { code: code.to_string(), message: message.into() }
    }
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"ok": false, "error": {"code": self.code, "message": self.message, "rule": rule_id(&self.code)}})
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
