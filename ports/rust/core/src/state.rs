//! Mutable engine state: revocations, approvals, spend ledger.
//! Persisted as one JSON file in the state directory. The engine holds the
//! state-directory lock for every operation and re-reads the file at the
//! start of each one, so the CLI, the daemon and the proxies that share a
//! state directory see each other's revocations, approvals and spend on the
//! very next call. (Timestamps are not trusted for this: some filesystems
//! only record whole seconds.)

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Approval {
    pub by: String,
    pub exp: i64,
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Pending {
    pub label: String,
    pub user: String,
    pub agent: String,
    pub action: String,
    pub resource: String,
    pub requested_at: i64,
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct Data {
    /// jti -> token expiry (kept so the list can be pruned)
    #[serde(default)]
    pub revoked: BTreeMap<String, i64>,
    #[serde(default)]
    pub approvals: BTreeMap<String, Approval>,
    #[serde(default)]
    pub pending: BTreeMap<String, Pending>,
    /// jti -> currency -> spent (minor units)
    #[serde(default)]
    pub ledger: BTreeMap<String, BTreeMap<String, i64>>,
    /// jti -> currency -> limit (minor units), recorded when the token is issued
    #[serde(default)]
    pub limits: BTreeMap<String, BTreeMap<String, i64>>,
    /// user -> time of the `revoke {"user"}` call: every token of that user
    /// issued at or before it is revoked. Never pruned. A file written
    /// before this key existed has none, which is the empty map.
    #[serde(default)]
    pub revoked_users: BTreeMap<String, serde_json::Value>,
    /// Keys this port does not know, written by another port sharing the
    /// state directory; kept as they are.
    #[serde(flatten)]
    pub other: BTreeMap<String, serde_json::Value>,
}

pub struct State {
    pub data: Data,
    path: Option<PathBuf>,
    /// file content as last read or written; parsing is skipped when unchanged
    raw: String,
}

impl State {
    pub fn open(dir: Option<&Path>) -> Result<Self> {
        let mut s = State { data: Data::default(), path: dir.map(|d| d.join("state.json")), raw: String::new() };
        s.refresh()?;
        Ok(s)
    }

    /// Reload if another process changed the file.
    pub fn refresh(&mut self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if !path.exists() {
            return Ok(());
        }
        let text = std::fs::read_to_string(path).map_err(|e| Error::new("state_io", e.to_string()))?;
        if text == self.raw {
            return Ok(());
        }
        // An unreadable state file must not silently drop revocations.
        // It must be an object: serde would also read a struct from a list.
        let doc: serde_json::Value = serde_json::from_str(&text).map_err(|e| Error::new("state_io", format!("state.json is corrupt: {e}")))?;
        if !doc.is_object() {
            return Err(Error::new("state_io", "state.json is corrupt: not an object"));
        }
        self.data = serde_json::from_value(doc).map_err(|e| Error::new("state_io", format!("state.json is corrupt: {e}")))?;
        self.raw = text;
        Ok(())
    }

    pub fn save(&mut self) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string(&self.data).map_err(|e| Error::new("state_io", e.to_string()))?;
        std::fs::write(&tmp, &text).map_err(|e| Error::new("state_io", e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| Error::new("state_io", e.to_string()))?;
        self.raw = text;
        Ok(())
    }

    pub fn prune(&mut self, now: i64) {
        self.data.revoked.retain(|_, exp| *exp + 86_400 > now);
        self.data.approvals.retain(|_, a| a.exp > now);
        self.data.pending.retain(|_, p| p.requested_at + 86_400 > now);
    }
}
