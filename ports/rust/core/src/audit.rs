//! Append-only, hash-chained decision log (JSON Lines).
//!
//! record.hash = sha256(prev_hash || canonical_json(record without "hash")).
//! Editing, deleting or reordering any line breaks every hash after it.
//! Truncating the tail is only detectable against an externally kept head
//! hash (`audit_verify` returns it; see LIMITATIONS.md).

use crate::canon::{canon, sha256_hex};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    head: String,
    /// file length after our last write; a different length means another
    /// process appended, and we must chain onto its last record
    len: u64,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        let mut seq = 0u64;
        let mut head = GENESIS.to_string();
        // Measured before the log is read: if another process appends in
        // between, the length no longer matches and the next append
        // re-reads the head instead of chaining onto a stale one.
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if path.exists() {
            let v = verify(path)?;
            seq = v["records"].as_u64().unwrap_or(0);
            head = v["head"].as_str().unwrap_or(GENESIS).to_string();
        }
        Ok(AuditLog { path: path.to_path_buf(), seq, head, len })
    }

    /// Pick up the chain head written by another process sharing this log.
    /// The engine holds the state-directory lock while this runs.
    fn resync(&mut self) -> Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if len == self.len {
            return Ok(());
        }
        if len == 0 {
            return Err(Error::new("audit_broken", "the audit log was truncated while in use"));
        }
        let mut f = std::fs::File::open(&self.path).map_err(|e| Error::new("audit_io", e.to_string()))?;
        f.seek(SeekFrom::Start(len.saturating_sub(1 << 20))).map_err(|e| Error::new("audit_io", e.to_string()))?;
        // Bytes, not text: the window may start in the middle of a character.
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes).map_err(|e| Error::new("audit_io", e.to_string()))?;
        let tail = String::from_utf8_lossy(&bytes);
        let last: Value = records(&tail)
            .last()
            .and_then(|(_, l)| serde_json::from_str(l).ok())
            .ok_or_else(|| Error::new("audit_broken", "the last audit record is unreadable"))?;
        match (last["seq"].as_u64(), last["hash"].as_str()) {
            (Some(seq), Some(hash)) => {
                self.seq = seq;
                self.head = hash.to_string();
                self.len = len;
                Ok(())
            }
            _ => Err(Error::new("audit_broken", "the last audit record has no seq/hash")),
        }
    }

    pub fn append(&mut self, mut record: Value, ts: i64) -> Result<String> {
        self.resync()?;
        let obj = record.as_object_mut().ok_or_else(|| Error::new("internal", "audit record must be an object"))?;
        obj.insert("seq".into(), json!(self.seq + 1));
        obj.insert("ts".into(), json!(ts));
        obj.insert("prev".into(), json!(self.head));
        obj.remove("hash");
        let hash = sha256_hex(format!("{}{}", self.head, canon(&record)).as_bytes());
        record.as_object_mut().unwrap().insert("hash".into(), json!(hash));
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| Error::new("audit_io", format!("cannot open audit log: {e}")))?;
        writeln!(f, "{}", canon(&record)).map_err(|e| Error::new("audit_io", format!("cannot write audit log: {e}")))?;
        self.seq += 1;
        self.head = hash.clone();
        self.len = f.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(hash)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// The non-blank lines of a log with their 1-based line numbers. A record
/// ends at `\n` and nowhere else: canonical JSON writes U+2028, U+2029 and
/// U+0085 as themselves, and they are data, not line breaks.
fn records(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split('\n').enumerate().map(|(i, l)| (i + 1, l)).filter(|(_, l)| !l.trim().is_empty())
}

/// Re-computes the whole chain. Returns {ok, records, head} or an error that
/// names the first broken line.
pub fn verify(path: &Path) -> Result<Value> {
    let raw = std::fs::read(path).map_err(|e| Error::new("audit_io", format!("cannot read audit log: {e}")))?;
    let text = String::from_utf8(raw).map_err(|_| Error::new("audit_broken", "the audit log is not UTF-8"))?;
    let mut prev = GENESIS.to_string();
    let mut n = 0u64;
    for (lineno, line) in records(&text) {
        let mut rec: Value = serde_json::from_str(line)
            .map_err(|e| Error::new("audit_broken", format!("line {lineno}: not JSON ({e})")))?;
        let claimed = rec["hash"].as_str().unwrap_or("").to_string();
        if rec["prev"].as_str() != Some(prev.as_str()) {
            return Err(Error::new("audit_broken", format!("line {lineno}: prev hash does not match the line before")));
        }
        if rec["seq"].as_u64() != Some(n + 1) {
            return Err(Error::new("audit_broken", format!("line {lineno}: sequence number is not {}", n + 1)));
        }
        rec.as_object_mut().map(|o| o.remove("hash"));
        let actual = sha256_hex(format!("{}{}", prev, canon(&rec)).as_bytes());
        if actual != claimed {
            return Err(Error::new("audit_broken", format!("line {lineno}: content does not match its hash")));
        }
        prev = claimed;
        n += 1;
    }
    Ok(json!({"ok": true, "records": n, "head": prev}))
}

pub fn tail(path: &Path, n: usize) -> Result<Vec<Value>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = std::fs::read(path).map_err(|e| Error::new("audit_io", e.to_string()))?;
    let text = String::from_utf8_lossy(&raw);
    let lines: Vec<&str> = records(&text).map(|(_, l)| l).collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..].iter().filter_map(|l| serde_json::from_str(l).ok()).collect())
}
