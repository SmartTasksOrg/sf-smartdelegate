//! The engine: one object that issues and exchanges capability tokens,
//! answers authorization requests, applies field obligations and writes the
//! audit log.
//!
//! Decision order for `authorize` / `filter` (first failure wins, default deny):
//!   1. token: signature, issuer, expiry, revocation (own id and every ancestor)
//!   2. catalog: the resource path must be known
//!   3. tenant: token tenant must equal the resource tenant, when both exist
//!   4. capability: the token's `cap` must cover the action and the resource
//!   5. policy: Cedar, forbid overrides permit, an erroring forbid denies
//!   6. obligations from the permits that decided: row filter, rate limit
//!   7. budget: `context.spend` against every token in the delegation chain
//!   8. human approval, last so nobody is asked to approve a doomed request
//!   9. fields: capability deny lists, then Cedar per field (default deny)
//!  10. strict mode (inputs): any denied field present in the data denies

use crate::audit::AuditLog;
use crate::bundle::Bundle;
use crate::canon::{hash_value, sha256_hex};
use crate::fields::{self, Mask, Status};
use crate::state::{Approval, Pending, State};
use crate::token::{self, Cap, Claims, Keys};
use crate::{Error, Result};
use cedar_policy::{Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicyId, Request};
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone)]
pub struct Idp {
    pub issuer: String,
    pub audience: String,
    pub jwks: Value,
    /// Where the keys came from, when they came from a file: `reload` reads it again.
    pub jwks_file: Option<String>,
    pub user_claim: String,
    /// The ID token claim that lists the user's groups, when the identity
    /// provider is the authority on membership.
    pub groups_claim: Option<String>,
    pub group_type: String,
    /// claim value -> group id; values not in the map are dropped
    pub group_map: Option<Map<String, Value>>,
}

pub struct Config {
    pub bundle_dir: PathBuf,
    pub state_dir: Option<PathBuf>,
    pub issuer: String,
    pub shadow: bool,
    pub trust_caller_chain: bool,
    pub allow_test_clock: bool,
    pub bundle_public_key: Option<String>,
    pub max_ttl: i64,
    pub default_ttl: i64,
    pub max_depth: usize,
    pub approval_ttl: i64,
    pub idp: Option<Idp>,
    pub audit: bool,
    pub require_role: bool,
    /// How long to wait for an empty signing key file to be filled by the
    /// process that is creating it. 30 seconds; tests shorten it.
    pub signing_key_wait_ms: u64,
}

#[derive(Clone)]
struct Principal {
    user: String,
    chain: Vec<String>,
    tenant: Option<String>,
    task: Option<String>,
    jti: Option<String>,
    anc: Vec<String>,
    cap: Cap,
    exp: i64,
    /// the role the human is acting in for this task
    role: Option<String>,
    /// live group membership `[{type, id}]` that replaces entities.json for
    /// this user; `None` uses entities.json
    groups: Option<Vec<Value>>,
    /// ancestor token id -> its budget, as carried by the token (`lim`)
    lim: BTreeMap<String, BTreeMap<String, i64>>,
}

impl Principal {
    fn leaf(&self) -> &str {
        self.chain.last().map(|s| s.as_str()).unwrap_or("")
    }
    fn to_json(&self) -> Value {
        json!({
            "user": self.user, "agent": self.leaf(), "chain": self.chain,
            "tenant": self.tenant, "task": self.task, "role": self.role, "token_id": self.jti,
        })
    }
}

struct Verdict {
    allow: bool,
    policies: Vec<String>,
    errors: Vec<Value>,
    forbid_error: bool,
}

#[derive(Default)]
struct Outcome {
    allow: bool,
    reason: String,
    detail: String,
    policies: Vec<String>,
    principal: Option<Principal>,
    mask: Option<Mask>,
    field_allow: Vec<String>,
    field_deny: Vec<String>,
    field_redact: Vec<String>,
    row_filter: Vec<Value>,
    rate: Vec<(String, usize, i64)>,
    rate_limit: Option<Value>,
    approval: Option<Value>,
    approved: Option<(String, String)>,
    spend: Option<(String, i64)>,
    errors: Vec<Value>,
    trace: Vec<Value>,
}

pub struct Engine {
    cfg: Config,
    bundle: Bundle,
    keys: Keys,
    state: State,
    audit: Option<AuditLog>,
    authorizer: Authorizer,
    rate: HashMap<String, VecDeque<i64>>,
    counter: u64,
    /// `<state_dir>/lock`: held for the length of every operation so that
    /// processes sharing a state directory never interleave.
    lock_file: Option<std::fs::File>,
}

struct LockGuard(std::fs::File);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str()).filter(|x| !x.is_empty())
}

fn req<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    s(v, key).ok_or_else(|| Error::new("invalid_input", format!("'{key}' is required")))
}

fn uid(ty: &str, id: &str) -> Result<EntityUid> {
    // The portable grammar is checked first and in full: Cedar's own parser
    // skips surrounding whitespace, so "User\n" would pass it.
    let bad = || Error::new("invalid_input", format!("'{}' is not a valid entity type", ty.escape_debug()));
    if !token::valid_type(ty) {
        return Err(bad());
    }
    let t = EntityTypeName::from_str(ty).map_err(|_| bad())?;
    Ok(EntityUid::from_type_name_and_id(t, EntityId::from_str(id).unwrap()))
}

fn system_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn random_id() -> Result<String> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 12];
    ring::rand::SystemRandom::new().fill(&mut b).map_err(|_| Error::new("crypto", "no randomness available"))?;
    Ok(hex::encode(b))
}

fn lookup<'a>(root: &'a Value, dotted: &str) -> Option<&'a Value> {
    let mut cur = root;
    for part in dotted.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

/// A dotted path through nested objects only.
fn nested<'a>(root: &'a Value, dotted: &str) -> Option<&'a Value> {
    let mut cur = root;
    for part in dotted.split('.') {
        cur = cur.as_object()?.get(part)?;
    }
    Some(cur)
}

/// `column == context.key`, `column == "literal"`, `column == 42`, joined by `&&`.
fn parse_row_filter(expr: &str, ctx: &Value) -> std::result::Result<Vec<Value>, (String, String)> {
    let mut out = Vec::new();
    for clause in expr.split("&&") {
        let parts: Vec<&str> = clause.splitn(2, "==").map(|p| p.trim()).collect();
        if parts.len() != 2 || parts[0].is_empty() || !parts[0].chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(("policy_error".into(), format!("row_filter clause '{}' is not `column == value`", clause.trim())));
        }
        let rhs = parts[1];
        let value = if let Some(key) = rhs.strip_prefix("context.") {
            match lookup(ctx, key) {
                Some(v) if v.is_string() || v.is_i64() || v.is_boolean() => v.clone(),
                _ => return Err(("obligation_unresolved".into(), format!("row filter needs context.{key}, which the request did not supply"))),
            }
        } else if rhs.len() >= 2 && rhs.starts_with('"') && rhs.ends_with('"') {
            json!(rhs[1..rhs.len() - 1])
        } else if let Ok(n) = rhs.parse::<i64>() {
            json!(n)
        } else {
            return Err(("policy_error".into(), format!("row_filter value '{rhs}' is not context.<key>, a quoted string or an integer")));
        };
        out.push(json!({"column": parts[0], "op": "eq", "value": value}));
    }
    Ok(out)
}

fn parse_rate(expr: &str) -> Option<(usize, i64)> {
    let (n, w) = expr.split_once('/')?;
    let n = n.trim().parse::<usize>().ok()?;
    let w = w.trim().parse::<i64>().ok()?;
    if w <= 0 {
        return None;
    }
    Some((n, w))
}

impl Config {
    pub fn from_json(v: &Value) -> Result<(Config, Option<String>, Vec<String>, bool)> {
        let bundle_dir = PathBuf::from(req(v, "bundle_dir")?);
        let state_dir = s(v, "state_dir").map(PathBuf::from);
        let b = |k: &str| v.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
        let n = |k: &str, d: i64| v.get(k).and_then(|x| x.as_i64()).unwrap_or(d);
        let mode = s(v, "mode").unwrap_or("enforce");
        if mode != "enforce" && mode != "shadow" {
            return Err(Error::new("invalid_config", "mode must be 'enforce' or 'shadow'"));
        }
        let idp = match v.get("idp") {
            Some(i) if i.is_object() => {
                let (jwks, jwks_file) = match i.get("jwks") {
                    Some(j) if j.is_object() => (j.clone(), None),
                    _ => {
                        let path = req(i, "jwks_file")?;
                        let text = std::fs::read_to_string(path).map_err(|e| Error::new("invalid_config", format!("jwks_file: {e}")))?;
                        (serde_json::from_str(&text).map_err(|e| Error::new("invalid_config", format!("jwks_file: {e}")))?, Some(path.to_string()))
                    }
                };
                let group_map = match i.get("group_map") {
                    None | Some(Value::Null) => None,
                    Some(Value::Object(m)) if m.values().all(|x| x.is_string()) => Some(m.clone()),
                    Some(_) => return Err(Error::new("invalid_config", "idp.group_map must map a claim value to a group id")),
                };
                let group_type = s(i, "group_type").unwrap_or("Group").to_string();
                if !token::valid_type(&group_type) {
                    return Err(Error::new("invalid_config", "idp.group_type is not a valid entity type"));
                }
                Some(Idp {
                    issuer: req(i, "issuer")?.to_string(),
                    audience: req(i, "audience")?.to_string(),
                    jwks,
                    jwks_file,
                    user_claim: s(i, "user_claim").unwrap_or("sub").to_string(),
                    groups_claim: s(i, "groups_claim").map(String::from),
                    group_type,
                    group_map,
                })
            }
            _ => None,
        };
        let trusted: Vec<String> = v
            .get("trusted_keys")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let cfg = Config {
            bundle_dir,
            state_dir,
            issuer: s(v, "issuer").unwrap_or("smartdelegate://local").to_string(),
            shadow: mode == "shadow",
            trust_caller_chain: b("trust_caller_chain"),
            allow_test_clock: b("allow_test_clock"),
            bundle_public_key: s(v, "bundle_public_key").map(String::from),
            max_ttl: n("max_ttl", 3600),
            default_ttl: n("default_ttl", 900),
            max_depth: n("max_depth", 4) as usize,
            approval_ttl: n("approval_ttl", 900),
            idp,
            audit: v.get("audit").and_then(|x| x.as_bool()).unwrap_or(true),
            require_role: b("require_role"),
            signing_key_wait_ms: v.get("signing_key_wait_ms").and_then(|x| x.as_u64()).unwrap_or(30_000),
        };
        Ok((cfg, s(v, "signing_key").map(String::from), trusted, b("verify_only")))
    }
}

impl Engine {
    pub fn new(config: &Value) -> Result<Engine> {
        let (cfg, inline_key, trusted, verify_only) = Config::from_json(config)?;
        let bundle = Bundle::load(&cfg.bundle_dir, cfg.bundle_public_key.as_deref())?;
        if let Some(d) = &cfg.state_dir {
            std::fs::create_dir_all(d).map_err(|e| Error::new("state_io", format!("{}: {e}", d.display())))?;
        }
        let private = if verify_only {
            None
        } else if inline_key.is_some() {
            inline_key
        } else if let Some(d) = &cfg.state_dir {
            Some(Self::signing_key(d, std::time::Duration::from_millis(cfg.signing_key_wait_ms))?)
        } else {
            Some(crate::bundle::keygen()?.0)
        };
        let keys = Keys::new(private.as_deref(), &trusted)?;
        let lock_file = match &cfg.state_dir {
            Some(d) => Some(std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(d.join("lock")).map_err(|e| Error::new("state_io", format!("lock file: {e}")))?),
            None => None,
        };
        // The state file and the audit log are read under the lock, like
        // every later operation: another process may be writing them now.
        let _guard = match &lock_file {
            Some(f) => Some(LockGuard(f.try_clone().and_then(|c| c.lock().map(|_| c)).map_err(|e| Error::new("state_io", format!("cannot lock the state directory: {e}")))?)),
            None => None,
        };
        let state = State::open(cfg.state_dir.as_deref())?;
        let audit = match (&cfg.state_dir, cfg.audit) {
            (Some(d), true) => Some(AuditLog::open(&d.join("audit.jsonl"))?),
            _ => None,
        };
        drop(_guard);
        Ok(Engine { cfg, bundle, keys, state, audit, authorizer: Authorizer::new(), rate: HashMap::new(), counter: 0, lock_file })
    }

    /// The engine's own signing key, created on first use. Two processes may
    /// start on an empty state directory at once: one creates the key, the
    /// other reads it. Creation happens under the state-directory lock, and
    /// the file appears under its name only once it is complete (it is
    /// written under a temporary name and linked into place, which fails
    /// if the name exists), so a port that does not take the lock never
    /// reads half a key and never has its key replaced.
    ///
    /// A key file found empty is still being written by someone else (a
    /// port that creates the file and then fills it): wait for the content,
    /// for at most `wait`, then fail with `state_io`. An empty key is never
    /// read as "no key".
    fn signing_key(dir: &std::path::Path, wait: std::time::Duration) -> Result<String> {
        let io = |e: std::io::Error| Error::new("state_io", format!("signing key: {e}"));
        let kp = dir.join("signing_key.pk8.b64");
        let read = |p: &std::path::Path| -> Result<String> {
            let deadline = std::time::Instant::now() + wait;
            loop {
                let text = std::fs::read_to_string(p).map_err(io)?;
                if !text.trim().is_empty() {
                    return Ok(text.trim().to_string());
                }
                if std::time::Instant::now() > deadline {
                    return Err(Error::new("state_io", format!("{} is empty", p.display())));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        };
        if kp.exists() {
            return read(&kp);
        }
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("lock")).map_err(io)?;
        lock.lock().map_err(io)?;
        let _guard = LockGuard(lock);
        if kp.exists() {
            return read(&kp);
        }
        let (sk, pk) = crate::bundle::keygen()?;
        let tmp = dir.join(format!("signing_key.pk8.b64.{}.{}.tmp", std::process::id(), random_id()?));
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).map_err(io)?;
            f.write_all(sk.as_bytes()).and_then(|_| f.sync_all()).map_err(io)?;
        }
        let linked = std::fs::hard_link(&tmp, &kp);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                let _ = std::fs::write(dir.join("signing_key.pub.b64"), &pk);
                Ok(sk)
            }
            // a process that does not use the lock created it meanwhile
            Err(_) if kp.exists() => read(&kp),
            Err(e) => Err(io(e)),
        }
    }

    /// JSON in, JSON out. Never panics on bad input; errors come back as
    /// `{"ok": false, "error": {"code", "message", "rule"}}`.
    pub fn call(&mut self, op: &str, input: &Value) -> Value {
        let _guard = match &self.lock_file {
            Some(f) => match f.try_clone().and_then(|c| c.lock().map(|_| c)) {
                Ok(c) => Some(LockGuard(c)),
                Err(e) => return Error::new("state_io", format!("cannot lock the state directory: {e}")).to_json(),
            },
            None => None,
        };
        match self.dispatch(op, input) {
            Ok(mut v) => {
                if let Some(o) = v.as_object_mut() {
                    o.insert("ok".into(), json!(true));
                }
                v
            }
            Err(e) => e.to_json(),
        }
    }

    fn dispatch(&mut self, op: &str, input: &Value) -> Result<Value> {
        if !input.is_object() {
            return Err(Error::new("invalid_input", "the request body must be a JSON object"));
        }
        self.state.refresh()?;
        match op {
            "authorize" => self.decide(input, false),
            "filter" => self.decide(input, true),
            "explain" => {
                let mut i = input.clone();
                i["explain"] = json!(true);
                i["dry_run"] = json!(true);
                self.decide(&i, input.get("data").is_some())
            }
            "issue_token" => self.issue_token(input),
            "exchange_token" => self.exchange_token(input),
            "inspect_token" => self.inspect_token(input),
            "apply_obligations" => self.apply_obligations(input),
            "revoke" => self.revoke(input),
            "approve" => self.approve(input),
            "approvals" => Ok(json!({"pending": self.state.data.pending, "granted": self.state.data.approvals})),
            "audit_verify" => match &self.audit {
                Some(a) if a.path().exists() => crate::audit::verify(a.path()),
                Some(_) => Ok(json!({"records": 0, "head": crate::audit::GENESIS})),
                None => Err(Error::new("no_audit", "this engine has no audit log (no state_dir, or audit is off)")),
            },
            "audit_tail" => match &self.audit {
                Some(a) => Ok(json!({"records": crate::audit::tail(a.path(), input["n"].as_u64().unwrap_or(20) as usize)?})),
                None => Err(Error::new("no_audit", "this engine has no audit log")),
            },
            "info" => Ok(self.info()),
            "reload" => {
                // A bundle that fails to load leaves the old one in force.
                let new_bundle = Bundle::load(&self.cfg.bundle_dir, self.cfg.bundle_public_key.as_deref())?;
                // The provider's signing keys are re-read too, so a key
                // rotation needs a reload, not a restart. If either fails to
                // load, neither is replaced.
                if let Some(idp) = self.cfg.idp.as_mut() {
                    if let Some(path) = &idp.jwks_file {
                        let bad = |m: String| Error::new("invalid_config", format!("jwks_file: {m}"));
                        let text = std::fs::read_to_string(path).map_err(|e| bad(e.to_string()))?;
                        let jwks: Value = serde_json::from_str(&text).map_err(|e| bad(e.to_string()))?;
                        if !(jwks.is_object() && jwks["keys"].is_array()) {
                            return Err(bad("expected {\"keys\": [...]}".into()));
                        }
                        idp.jwks = jwks;
                    }
                }
                self.bundle = new_bundle;
                self.audit_event(json!({"event": "bundle_reloaded", "policy_version": self.bundle.version}), system_now())?;
                Ok(self.info())
            }
            "conformance_case" => Ok(crate::conformance::run_case(self, input)),
            _ => Err(Error::new("unknown_op", format!("no operation named '{op}'"))),
        }
    }

    fn info(&self) -> Value {
        json!({
            "version": crate::VERSION,
            "implementation": "rust",
            "policy_version": self.bundle.version,
            "bundle_signed_by": self.bundle.signed_by,
            "policies": self.bundle.meta.len(),
            "resources": self.bundle.catalog.resources.keys().collect::<Vec<_>>(),
            "roles": self.bundle.roles.keys().collect::<Vec<_>>(),
            "mode": if self.cfg.shadow { "shadow" } else { "enforce" },
            "issuer": self.cfg.issuer,
            "key_id": self.keys.kid,
            "public_key": self.keys.public_b64,
            "can_issue": self.keys.can_sign(),
            "oidc": self.cfg.idp.as_ref().map(|i| i.issuer.clone()),
        })
    }

    fn now(&self, input: &Value) -> i64 {
        if self.cfg.allow_test_clock {
            if let Some(n) = input.get("now").and_then(|x| x.as_i64()) {
                return n;
            }
        }
        system_now()
    }

    /// Fail closed: when the decision cannot be recorded, the operation
    /// fails and the caller gets an error instead of an allow.
    fn audit_event(&mut self, record: Value, ts: i64) -> Result<()> {
        if let Some(a) = self.audit.as_mut() {
            a.append(record, ts).map_err(|e| Error::new("audit_io", format!("the decision could not be recorded, so it is refused: {}", e.message)))?;
        }
        Ok(())
    }

    // ---- tokens -----------------------------------------------------------

    /// On failure the third element carries the claims when the signature
    /// was good (expired, revoked), so the denial can still be attributed in
    /// the audit log. It is never used to authorise anything.
    fn verify_token(&self, token: &str, now: i64) -> std::result::Result<Claims, (String, String, Option<Claims>)> {
        let claims = self.keys.verify(token, &self.cfg.issuer).map_err(|m| ("token_invalid".to_string(), m, None))?;
        if claims.chain().is_empty() {
            return Err(("token_invalid".into(), "the token names no agent".into(), None));
        }
        if claims.exp <= now {
            return Err(("token_expired".into(), "the capability token has expired".into(), Some(claims)));
        }
        if claims.iat > now + 60 {
            return Err(("token_invalid".into(), "the capability token is dated in the future".into(), Some(claims)));
        }
        for id in claims.anc.iter().chain(std::iter::once(&claims.jti)) {
            if self.state.data.revoked.contains_key(id) {
                return Err(("token_revoked".into(), format!("token {id} in the delegation chain was revoked"), Some(claims)));
            }
        }
        // offboarding: every token of this user issued up to the cut-off is dead
        if let Some(cutoff) = self.state.data.revoked_users.get(&claims.user()).and_then(|c| c.as_i64()) {
            if claims.iat <= cutoff {
                return Err(("token_revoked".into(), "every token issued for this user up to the cut-off was revoked".into(), Some(claims)));
            }
        }
        Ok(claims)
    }

    fn principal_of(claims: &Claims) -> Principal {
        Principal {
            user: claims.user(),
            chain: claims.chain(),
            tenant: claims.tnt.clone(),
            task: claims.task.clone(),
            jti: Some(claims.jti.clone()),
            anc: claims.anc.clone(),
            cap: claims.cap.clone(),
            exp: claims.exp,
            role: claims.role.clone(),
            groups: claims.grp.clone(),
            lim: claims.lim.clone().unwrap_or_default(),
        }
    }

    fn iam_context(&self, p: &Principal) -> Value {
        json!({
            "user_attrs": self.bundle.attrs.get(&format!("User::{}", p.user)).cloned().unwrap_or_else(|| json!({})),
            "user": {"__entity": {"type": "User", "id": p.user}},
            "user_id": p.user,
            "chain": p.chain,
            "depth": p.chain.len(),
            "root_agent": {"__entity": {"type": "Agent", "id": p.chain.first().cloned().unwrap_or_default()}},
            "tenant": p.tenant.clone().unwrap_or_default(),
            "task": p.task.clone().unwrap_or_default(),
            "role": p.role.clone().unwrap_or_default(),
        })
    }

    /// The entities this principal is judged against. A token that carries
    /// live group membership replaces what entities.json says about that
    /// user's parents; everything else is unchanged.
    fn store_for(&self, p: &Principal) -> Result<Cow<'_, Entities>> {
        let Some(groups) = &p.groups else { return Ok(Cow::Borrowed(&self.bundle.entities)) };
        let me = ("User".to_string(), p.user.clone());
        let mut user = json!({"uid": {"type": "User", "id": p.user}, "attrs": {}});
        let mut list = Vec::with_capacity(self.bundle.entities_json.len() + 1);
        for e in &self.bundle.entities_json {
            if crate::bundle::uid_parts(&e["uid"]).as_ref() == Some(&me) {
                user = e.clone();
            } else {
                list.push(e.clone());
            }
        }
        user["parents"] = Value::Array(groups.iter().map(|g| json!({"type": g["type"], "id": g["id"]})).collect());
        list.push(user);
        Entities::from_json_value(Value::Array(list), None).map(Cow::Owned).map_err(|e| Error::new("invalid_input", format!("group membership: {e}")))
    }

    /// Normalise group membership supplied at issuance: names or `{type,
    /// id}`. Groups that entities.json does not define are dropped; the
    /// result is sorted and free of duplicates, so every port writes the
    /// same claim.
    fn groups(&self, raw: &Value, default_type: &str, mapping: Option<&Map<String, Value>>) -> Result<Vec<Value>> {
        let bad = || Error::new("invalid_input", "groups must be a list of group names or {type, id}");
        let one;
        let list: &Vec<Value> = match raw {
            Value::String(_) => {
                one = vec![raw.clone()];
                &one
            }
            Value::Array(a) => a,
            _ => return Err(bad()),
        };
        let mut out = BTreeSet::new();
        for g in list {
            let (t, n) = match g {
                Value::String(name) => {
                    let id = match mapping {
                        Some(m) => match m.get(name).and_then(|x| x.as_str()) {
                            Some(mapped) => mapped.to_string(),
                            None => continue,
                        },
                        None => name.clone(),
                    };
                    (default_type.to_string(), id)
                }
                Value::Object(o) => match (o.get("type").and_then(|x| x.as_str()), o.get("id").and_then(|x| x.as_str())) {
                    (Some(t), Some(n)) => (t.to_string(), n.to_string()),
                    _ => return Err(bad()),
                },
                _ => return Err(bad()),
            };
            if token::valid_type(&t) && self.bundle.defined.contains(&(t.clone(), n.clone())) {
                out.insert((t, n));
            }
        }
        Ok(out.into_iter().map(|(t, n)| json!({"type": t, "id": n})).collect())
    }

    /// The human lends the agent one of their roles for this task. Returns
    /// the capability and lifetime the token gets; fails when the human does
    /// not hold the role or asks for more than the role allows.
    fn apply_role(&self, name: &str, p: &Principal, cap: Option<Cap>, ttl: i64) -> Result<(Cap, i64)> {
        let role = self.bundle.roles.get(name).ok_or_else(|| Error::new("unknown_role", format!("roles.json defines no role named '{name}'")))?;
        let user = uid("User", &p.user)?;
        let store = self.store_for(p)?;
        let mut held = false;
        for (t, i) in &role.members {
            let m = uid(t, i)?;
            if m == user || store.is_ancestor_of(&m, &user) {
                held = true;
                break;
            }
        }
        if !held {
            return Err(Error::new("role_not_held", format!("user '{}' does not hold the role '{name}'", p.user)));
        }
        if let Some(agents) = &role.agents {
            if !agents.iter().any(|a| token::matches(a, p.leaf())) {
                return Err(Error::new("role_exceeded", format!("agent '{}' may not be started in the role '{name}'", p.leaf())));
            }
        }
        if let Some(tasks) = &role.tasks {
            if !p.task.as_deref().map(|t| tasks.iter().any(|pat| token::matches(pat, t))).unwrap_or(false) {
                return Err(Error::new("role_exceeded", format!("the role '{name}' covers only tasks matching: {}", tasks.join(", "))));
            }
        }
        let cap = match cap {
            None => role.cap.clone(),
            Some(mut cap) => {
                // what the role never sees, the token never sees
                let union = |a: &[String], b: &[String]| a.iter().chain(b.iter()).cloned().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
                cap.deny_labels = union(&cap.deny_labels, &role.cap.deny_labels);
                cap.deny_fields = union(&cap.deny_fields, &role.cap.deny_fields);
                cap.narrower_than(&role.cap).map_err(|e| Error::new("role_exceeded", format!("more than the role '{name}' allows: {}", e.message)))?;
                cap
            }
        };
        Ok((cap, role.max_ttl.map(|m| ttl.min(m)).unwrap_or(ttl)))
    }

    fn evaluate(&self, principal: &EntityUid, action: &str, resource: &EntityUid, ctx: &Context, entities: &Entities) -> Result<Verdict> {
        let request = Request::new(principal.clone(), uid("Action", action)?, resource.clone(), ctx.clone(), None)
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        let resp = self.authorizer.is_authorized(&request, &self.bundle.policies, entities);
        let mut errors = Vec::new();
        let mut forbid_error = false;
        for e in resp.diagnostics().errors() {
            let cedar_policy::AuthorizationError::PolicyEvaluationError(pe) = e;
            let id = pe.policy_id().to_string();
            let is_forbid = self.bundle.meta.get(&id).map(|m| !m.permit).unwrap_or(true);
            forbid_error |= is_forbid;
            errors.push(json!({"policy": id, "effect": if is_forbid { "forbid" } else { "permit" }, "error": e.to_string()}));
        }
        let mut policies: Vec<String> = resp.diagnostics().reason().map(|p: &PolicyId| p.to_string()).collect();
        policies.sort();
        Ok(Verdict { allow: resp.decision() == Decision::Allow && !forbid_error, policies, errors, forbid_error })
    }

    /// Is `delegator` allowed to hand `cap` to `agent`? Governed by the same
    /// policies as everything else: action "delegate" on the Agent entity.
    fn check_delegation(&self, delegator: EntityUid, agent: &str, p: &Principal, cap: &Cap, ttl: i64) -> Result<()> {
        let agent_uid = uid("Agent", agent)?;
        if self.bundle.entities.get(&agent_uid).is_none() {
            return Err(Error::new("unknown_agent", format!("agent '{agent}' is not registered in entities.json")));
        }
        let ctx = json!({
            "iam": self.iam_context(p),
            "requested": {"actions": cap.actions, "resources": cap.resources, "ttl": ttl, "budget": cap.budget},
        });
        let ctx = Context::from_json_value(ctx, None).map_err(|e| Error::new("invalid_input", e.to_string()))?;
        let store = self.store_for(p)?;
        let v = self.evaluate(&delegator, "delegate", &agent_uid, &ctx, &store)?;
        if !v.allow {
            let why = if v.policies.is_empty() { "no policy permits it".to_string() } else { format!("forbidden by {}", v.policies.join(", ")) };
            return Err(Error::new("delegation_denied", format!("{delegator} may not delegate to agent '{agent}': {why}")));
        }
        Ok(())
    }

    fn parse_cap(input: &Value) -> Result<Option<Cap>> {
        match input.get("cap") {
            None | Some(Value::Null) => Ok(None),
            Some(c) => {
                let cap: Cap = serde_json::from_value(c.clone()).map_err(|e| Error::new("invalid_cap", e.to_string()))?;
                cap.validate()?;
                Ok(Some(cap))
            }
        }
    }

    fn mint(&mut self, mut claims: Claims, event: &str, now: i64) -> Result<Value> {
        claims.jti = random_id()?;
        let token = self.keys.sign(&claims)?;
        if !claims.cap.budget.is_empty() {
            self.state.data.limits.insert(claims.jti.clone(), claims.cap.budget.clone());
            self.state.prune(now);
            self.state.save()?;
        }
        self.audit_event(
            json!({
                "event": event, "token_id": claims.jti, "user": claims.user(), "chain": claims.chain(),
                "tenant": claims.tnt, "task": claims.task, "role": claims.role, "ancestors": claims.anc, "exp": claims.exp,
                "cap": claims.cap, "policy_version": self.bundle.version,
            }),
            now,
        )?;
        Ok(json!({
            "token": token, "token_type": "Bearer", "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "token_id": claims.jti, "expires_at": claims.exp, "expires_in": claims.exp - now,
            "user": claims.user(), "chain": claims.chain(), "role": claims.role, "task": claims.task, "cap": claims.cap,
        }))
    }

    fn issue_token(&mut self, input: &Value) -> Result<Value> {
        let now = self.now(input);
        let (user, groups) = match s(input, "id_token") {
            Some(idt) => {
                let idp = self.cfg.idp.as_ref().ok_or_else(|| Error::new("no_idp", "no OIDC provider is configured"))?;
                let claims = token::verify_id_token(idt, &idp.jwks, &idp.issuer, &idp.audience, now)?;
                let u = s(&claims, &idp.user_claim).ok_or_else(|| Error::new("id_token_invalid", format!("ID token has no '{}' claim", idp.user_claim)))?.to_string();
                if let Some(given) = s(input, "user") {
                    if given != u {
                        return Err(Error::new("id_token_invalid", "the ID token belongs to a different user"));
                    }
                }
                // Offboarding also covers sign-ins that happened before it: an
                // ID token issued at or before the user's revoke cut-off cannot
                // start a new agent, however long the provider says it lives.
                if let Some(cutoff) = self.state.data.revoked_users.get(&u).and_then(|c| c.as_i64()) {
                    if !claims.get("iat").and_then(|x| x.as_i64()).map(|iat| iat > cutoff).unwrap_or(false) {
                        return Err(Error::new("id_token_invalid", "the ID token was issued before this user was revoked; sign in again"));
                    }
                }
                let groups = match &idp.groups_claim {
                    // the identity provider is the authority on what this
                    // human is a member of right now; a missing claim means
                    // "of nothing"
                    Some(claim) => {
                        // The exact name first; a dotted name then reads a
                        // nested claim (Keycloak: realm_access.roles).
                        let found = match claims.get(claim) {
                            None | Some(Value::Null) if claim.contains('.') => nested(&claims, claim),
                            other => other,
                        };
                        let raw = match found {
                            None | Some(Value::Null) => json!([]),
                            Some(v) => v.clone(),
                        };
                        Some(self.groups(&raw, &idp.group_type, idp.group_map.as_ref()).map_err(|_| Error::new("id_token_invalid", format!("the '{claim}' claim is not a list of group names")))?)
                    }
                    None => None,
                };
                (u, groups)
            }
            None => {
                let u = req(input, "user")?.to_string();
                let groups = match input.get("groups") {
                    None | Some(Value::Null) => None,
                    Some(raw) => Some(self.groups(raw, "Group", None)?),
                };
                (u, groups)
            }
        };
        let agent = req(input, "agent")?.to_string();
        let cap = Self::parse_cap(input)?;
        let role = s(input, "role").map(String::from);
        if role.is_none() && self.cfg.require_role {
            return Err(Error::new("role_required", "this engine issues tokens only for a named role"));
        }
        if cap.is_none() && role.is_none() {
            return Err(Error::new("invalid_cap", "'cap' is required: a root token must state what it may do"));
        }
        let mut ttl = input.get("ttl").and_then(|x| x.as_i64()).unwrap_or(self.cfg.default_ttl).clamp(1, self.cfg.max_ttl);
        let mut p = Principal {
            user: user.clone(),
            chain: vec![agent.clone()],
            tenant: s(input, "tenant").map(String::from),
            task: s(input, "task").map(String::from),
            jti: None,
            anc: vec![],
            cap: cap.clone().unwrap_or_else(Cap::unrestricted),
            exp: now + ttl,
            role: role.clone(),
            groups: groups.clone(),
            lim: BTreeMap::new(),
        };
        let cap = match &role {
            Some(name) => {
                let (c, t) = self.apply_role(name, &p, cap, ttl)?;
                ttl = t;
                c
            }
            // checked above: without a role there is a cap
            None => cap.ok_or_else(|| Error::new("invalid_cap", "'cap' is required"))?,
        };
        p.cap = cap.clone();
        p.exp = now + ttl;
        self.check_delegation(uid("User", &user)?, &agent, &p, &cap, ttl)?;
        let claims = Claims {
            iss: self.cfg.issuer.clone(),
            aud: token::AUDIENCE.into(),
            sub: format!("user:{user}"),
            iat: now,
            exp: now + ttl,
            jti: String::new(),
            act: token::act_for(&p.chain),
            tnt: p.tenant.clone(),
            task: p.task.clone(),
            anc: vec![],
            role,
            grp: groups,
            lim: None,
            cap,
        };
        self.mint(claims, "token_issued", now)
    }

    fn exchange_token(&mut self, input: &Value) -> Result<Value> {
        let now = self.now(input);
        let parent = self.verify_token(req(input, "subject_token")?, now).map_err(|(c, m, _)| Error::new(&c, m))?;
        let pp = Self::principal_of(&parent);
        let actor = req(input, "actor")?.to_string();
        if pp.chain.len() >= self.cfg.max_depth {
            return Err(Error::new("depth_exceeded", format!("delegation chains are limited to {} agents", self.cfg.max_depth)));
        }
        let cap = Self::parse_cap(input)?.unwrap_or_else(|| pp.cap.clone());
        cap.narrower_than(&pp.cap)?;
        let ttl = input.get("ttl").and_then(|x| x.as_i64()).unwrap_or(self.cfg.default_ttl).clamp(1, self.cfg.max_ttl);
        let exp = (now + ttl).min(parent.exp);
        if let (Some(t), Some(pt)) = (s(input, "task"), &pp.task) {
            if t != pt {
                return Err(Error::new("widening", "a sub-agent token cannot change the task it was issued for"));
            }
        }
        if let Some(r) = s(input, "role") {
            if pp.role.as_deref() != Some(r) {
                return Err(Error::new("widening", "a sub-agent token cannot change the role it was issued for"));
            }
        }
        self.check_delegation(uid("Agent", pp.leaf())?, &actor, &pp, &cap, exp - now)?;
        let mut chain = pp.chain.clone();
        chain.push(actor);
        let mut anc = parent.anc.clone();
        anc.push(parent.jti.clone());
        // Every ancestor's budget travels with the token, so an engine that
        // did not issue the ancestor can still hold the family to it.
        let mut lim = pp.lim.clone();
        if !pp.cap.budget.is_empty() {
            lim.insert(parent.jti.clone(), pp.cap.budget.clone());
        }
        let claims = Claims {
            iss: self.cfg.issuer.clone(),
            aud: token::AUDIENCE.into(),
            sub: parent.sub.clone(),
            iat: now,
            exp,
            jti: String::new(),
            act: token::act_for(&chain),
            tnt: parent.tnt.clone(),
            task: pp.task.clone().or_else(|| s(input, "task").map(String::from)),
            anc,
            role: pp.role.clone(),
            grp: pp.groups.clone(),
            lim: if lim.is_empty() { None } else { Some(lim) },
            cap,
        };
        self.mint(claims, "token_exchanged", now)
    }

    fn inspect_token(&mut self, input: &Value) -> Result<Value> {
        let now = self.now(input);
        match self.verify_token(req(input, "token")?, now) {
            Ok(c) => Ok(json!({"valid": true, "claims": c, "chain": c.chain(), "user": c.user(), "expires_in": c.exp - now})),
            Err((code, msg, _)) => Ok(json!({"valid": false, "reason": code, "detail": msg})),
        }
    }

    fn revoke(&mut self, input: &Value) -> Result<Value> {
        let now = self.now(input);
        if let Some(user) = input.get("user") {
            // Offboarding, or a human who lost a role: one call ends every
            // token already issued for them, sub-agents included. New tokens
            // are a matter of role membership, not of this list.
            let user = user.as_str().filter(|u| !u.is_empty()).ok_or_else(|| Error::new("invalid_input", "'user' must be a non-empty string"))?.to_string();
            // the cut-off only ever moves forward: a clock that steps back (or
            // a second machine with a slower clock) must not revive dead tokens
            let cutoff = self.state.data.revoked_users.get(&user).and_then(|p| p.as_i64()).map(|p| p.max(now)).unwrap_or(now);
            self.state.data.revoked_users.insert(user.clone(), json!(cutoff));
            self.state.save()?;
            self.audit_event(json!({"event": "user_revoked", "user": user, "issued_up_to": cutoff, "by": s(input, "by")}), now)?;
            return Ok(json!({"revoked_user": user, "issued_up_to": cutoff}));
        }
        let (id, exp) = match s(input, "token") {
            Some(t) => {
                let c = self.keys.verify(t, &self.cfg.issuer).map_err(|m| Error::new("token_invalid", m))?;
                (c.jti, c.exp)
            }
            None => (req(input, "token_id")?.to_string(), now + self.cfg.max_ttl),
        };
        self.state.data.revoked.insert(id.clone(), exp);
        self.state.save()?;
        self.audit_event(json!({"event": "token_revoked", "token_id": id, "by": s(input, "by")}), now)?;
        Ok(json!({"revoked": id}))
    }

    fn approve(&mut self, input: &Value) -> Result<Value> {
        let now = self.now(input);
        let id = req(input, "approval_id")?.to_string();
        let by = req(input, "by")?.to_string();
        let pending = self.state.data.pending.remove(&id).ok_or_else(|| Error::new("unknown_approval", "no pending request with that approval id"))?;
        if pending.user == by {
            self.state.data.pending.insert(id, pending);
            return Err(Error::new("self_approval", "the user an agent acts for cannot approve that agent's request"));
        }
        // who may approve is itself policy: action "approve" on the agent
        let ctx = Context::from_json_value(json!({"label": pending.label, "for_user": pending.user, "action": pending.action}), None)
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        let v = self.evaluate(&uid("User", &by)?, "approve", &uid("Agent", &pending.agent)?, &ctx, &self.bundle.entities)?;
        if !v.allow {
            self.state.data.pending.insert(id, pending);
            return Err(Error::new("approval_denied", format!("no policy lets '{by}' approve this request")));
        }
        let exp = now + input.get("ttl").and_then(|x| x.as_i64()).unwrap_or(self.cfg.approval_ttl);
        self.state.data.approvals.insert(id.clone(), Approval { by: by.clone(), exp });
        self.state.save()?;
        self.audit_event(json!({"event": "approval_granted", "approval_id": id, "by": by, "label": pending.label, "for_user": pending.user, "agent": pending.agent, "action": pending.action, "resource": pending.resource}), now)?;
        Ok(json!({"approved": id, "by": by, "expires_at": exp}))
    }

    /// Apply the obligations of an earlier decision to data that arrived
    /// later (a tool result, an upstream response). Pure: it authorises
    /// nothing by itself, so the caller must pass obligations it received
    /// from `authorize`/`filter` and nothing else.
    fn apply_obligations(&mut self, input: &Value) -> Result<Value> {
        let ob = input.get("obligations").filter(|o| o.is_object()).ok_or_else(|| Error::new("invalid_input", "'obligations' from a decision is required"))?;
        let data = input.get("data").ok_or_else(|| Error::new("invalid_input", "'data' is required"))?;
        let f = ob.get("fields").filter(|f| f.is_object()).ok_or_else(|| Error::new("invalid_input", "obligations.fields is missing; only an allow decision carries a field mask"))?;
        let list = |k: &str| -> Vec<String> { f[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default() };
        let mut status = BTreeMap::new();
        for n in list("allow") {
            status.insert(n, Status::Allow);
        }
        for n in list("deny") {
            status.insert(n, Status::Deny);
        }
        for n in list("redact") {
            status.insert(n, Status::Redact);
        }
        let empty = vec![];
        let rf = ob.get("row_filter").and_then(|r| r.as_array()).unwrap_or(&empty);
        let out = fields::apply(data, &Mask { status }, rf);
        if let Some(did) = s(input, "decision_id") {
            let now = self.now(input);
            self.audit_event(json!({"event": "obligations_applied", "decision_id": did, "masked": out.masked, "rows_dropped": out.rows_dropped}), now)?;
        }
        Ok(json!({"data": out.data, "masked": out.masked, "rows_dropped": out.rows_dropped}))
    }

    // ---- decisions --------------------------------------------------------

    fn evaluate_request(&mut self, input: &Value, now: i64, dry_run: bool) -> Result<Outcome> {
        let mut o = Outcome::default();
        macro_rules! deny {
            ($code:expr, $msg:expr) => {{
                o.reason = $code.to_string();
                o.detail = $msg.to_string();
                o.trace.push(json!({"check": o.reason, "result": "deny", "detail": o.detail}));
                return Ok(o);
            }};
        }
        macro_rules! pass {
            ($check:expr, $msg:expr) => {
                o.trace.push(json!({"check": $check, "result": "pass", "detail": $msg}))
            };
        }

        let action = req(input, "action")?.to_string();
        let res = input.get("resource").filter(|r| r.is_object()).ok_or_else(|| Error::new("invalid_input", "'resource' must be an object with a 'path'"))?;
        let path = req(res, "path")?.to_string();
        let id = s(res, "id").unwrap_or("any").to_string();
        let caller_ctx = match input.get("context") {
            None | Some(Value::Null) => json!({}),
            Some(c) if c.is_object() => c.clone(),
            _ => return Err(Error::new("invalid_context", "'context' must be an object")),
        };
        if caller_ctx.get("iam").is_some() {
            return Err(Error::new("invalid_context", "'iam' is reserved: identity comes from the token, not from the caller"));
        }

        // 1. principal
        let principal = match (s(input, "token"), input.get("chain")) {
            (Some(t), _) => match self.verify_token(t, now) {
                Ok(c) => Self::principal_of(&c),
                Err((code, msg, claims)) => {
                    o.principal = claims.as_ref().map(Self::principal_of);
                    deny!(code, msg)
                }
            },
            (None, Some(ch)) if self.cfg.trust_caller_chain && ch.is_object() => {
                let agents: Vec<String> = ch["agents"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                if agents.is_empty() {
                    return Err(Error::new("invalid_input", "chain.agents must list at least one agent"));
                }
                Principal {
                    user: req(ch, "user")?.to_string(),
                    chain: agents,
                    tenant: s(ch, "tenant").map(String::from),
                    task: s(ch, "task").map(String::from),
                    jti: None,
                    anc: vec![],
                    cap: Cap::unrestricted(),
                    exp: now,
                    role: s(ch, "role").map(String::from),
                    groups: match ch.get("groups") {
                        None | Some(Value::Null) => None,
                        Some(raw) => Some(self.groups(raw, "Group", None)?),
                    },
                    lim: BTreeMap::new(),
                }
            }
            (None, Some(_)) => deny!("token_invalid", "this engine does not trust caller-supplied chains; send a capability token"),
            (None, None) => deny!("token_invalid", "no capability token was presented"),
        };
        o.principal = Some(principal.clone());
        pass!("token", format!("user {} via {}", principal.user, principal.chain.join(" -> ")));

        // 2. catalog
        let rdef = match self.bundle.catalog.resources.get(&path) {
            Some(r) => r.clone(),
            None => deny!("unknown_resource", format!("'{path}' is not in the catalog")),
        };

        // 3. tenant
        let attrs = match res.get("attrs") {
            None | Some(Value::Null) => json!({}),
            Some(a) if a.is_object() => a.clone(),
            _ => return Err(Error::new("invalid_input", "resource.attrs must be an object")),
        };
        if let (Some(t), Some(rt)) = (&principal.tenant, attrs.get("tenant").and_then(|x| x.as_str())) {
            if t != rt {
                deny!("tenant_mismatch", format!("token tenant '{t}' cannot touch a resource of tenant '{rt}'"));
            }
        }

        // 4. capability
        if !principal.cap.allows_action(&action) {
            deny!("capability_action", format!("the token does not carry action '{action}'"));
        }
        if !principal.cap.allows_resource(&path, &id) {
            deny!("capability_resource", format!("the token does not cover {path}/{id}"));
        }
        pass!("capability", "token covers the action and the resource");

        // 5. policy
        let r_uid = uid(&rdef.entity_type, &id)?;
        let field_names: Vec<String> = match input.get("fields").and_then(|f| f.as_array()) {
            Some(list) => {
                let mut names = Vec::new();
                for f in list {
                    let n = f.as_str().unwrap_or("").to_string();
                    if !rdef.fields.contains_key(&n) {
                        deny!("unknown_field", format!("'{path}.{n}' is not in the catalog"));
                    }
                    names.push(n);
                }
                names
            }
            None => rdef.fields.keys().cloned().collect(),
        };
        let mut extra = Vec::new();
        if self.bundle.entities.get(&r_uid).is_none() {
            extra.push(json!({"uid": {"type": rdef.entity_type, "id": id}, "attrs": attrs, "parents": []}));
        } else if attrs.as_object().map(|a| !a.is_empty()).unwrap_or(false) {
            return Err(Error::new("invalid_input", format!("{r_uid} is defined in entities.json; do not send attrs for it")));
        }
        for n in &field_names {
            let fid = format!("{path}.{n}");
            extra.push(json!({
                "uid": {"type": "Field", "id": fid},
                "attrs": {"path": fid, "name": n, "resource": path, "labels": rdef.fields[n].labels,
                          "of": {"__entity": {"type": rdef.entity_type, "id": id}}},
                "parents": [{"type": rdef.entity_type, "id": id}],
            }));
        }
        let entities = self.store_for(&principal)?.into_owned().add_entities_from_json_value(Value::Array(extra), None).map_err(|e| Error::new("invalid_input", format!("resource entity: {e}")))?;
        let mut full_ctx = caller_ctx.clone();
        full_ctx["iam"] = self.iam_context(&principal);
        let ctx = Context::from_json_value(full_ctx.clone(), None).map_err(|e| Error::new("invalid_context", format!("{e} (use integers, strings, booleans, lists and objects; no floats or nulls)")))?;
        let p_uid = uid("Agent", principal.leaf())?;
        let v = self.evaluate(&p_uid, &action, &r_uid, &ctx, &entities)?;
        o.errors.extend(v.errors.clone());
        o.policies = v.policies.clone();
        if !v.allow {
            if v.forbid_error {
                deny!("policy_error", "a forbid policy failed to evaluate, so the request is denied");
            } else if v.policies.is_empty() {
                deny!("no_matching_permit", "no policy permits this request");
            } else {
                deny!("policy_forbid", format!("forbidden by {}", v.policies.join(", ")));
            }
        }
        pass!("policy", format!("permitted by {}", v.policies.join(", ")));

        // 6. obligations carried by the permits that decided
        let mut approval_label: Option<String> = None;
        for pid in &v.policies {
            let Some(meta) = self.bundle.meta.get(pid) else { continue };
            if let Some(expr) = meta.annotations.get("row_filter") {
                match parse_row_filter(expr, &full_ctx) {
                    Ok(mut clauses) => o.row_filter.append(&mut clauses),
                    Err((code, msg)) => deny!(code, format!("{pid}: {msg}")),
                }
            }
            if let Some(expr) = meta.annotations.get("rate_limit") {
                match parse_rate(expr) {
                    Some((n, w)) => o.rate.push((format!("{pid}|{}|{}", principal.leaf(), principal.user), n, w)),
                    None => deny!("policy_error", format!("{pid}: rate_limit must be \"<count>/<seconds>\"")),
                }
            }
            if let Some(label) = meta.annotations.get("require_approval") {
                approval_label = Some(label.clone());
            }
        }
        for (key, n, w) in &o.rate {
            let q = self.rate.entry(key.clone()).or_default();
            while q.front().map(|t| *t <= now - w).unwrap_or(false) {
                q.pop_front();
            }
            o.rate_limit = Some(json!({"limit": n, "window_seconds": w, "used": q.len()}));
            if q.len() >= *n {
                deny!("rate_limited", format!("more than {n} calls in {w} seconds"));
            }
        }

        // 7. budget
        if let Some(sp) = caller_ctx.get("spend") {
            let (cur, amount) = match (sp.get("currency").and_then(|x| x.as_str()), sp.get("amount").and_then(|x| x.as_i64())) {
                (Some(c), Some(a)) if a >= 0 => (c.to_string(), a),
                _ => return Err(Error::new("invalid_context", "context.spend must be {currency: string, amount: non-negative integer in minor units}")),
            };
            let Some(jti) = principal.jti.clone() else { deny!("budget_exceeded", "spending needs a capability token with a budget") };
            let Some(own) = principal.cap.budget.get(&cur).copied() else { deny!("budget_exceeded", format!("the token carries no {cur} budget")) };
            let spent = |st: &State, id: &str| st.data.ledger.get(id).and_then(|m| m.get(&cur)).copied().unwrap_or(0);
            if spent(&self.state, &jti) + amount > own {
                deny!("budget_exceeded", format!("{amount} {cur} would exceed this token's budget of {own} (already spent {})", spent(&self.state, &jti)));
            }
            for a in &principal.anc {
                // An ancestor's budget is in this engine's state when it
                // issued the ancestor, and in the token's `lim` claim always.
                let known = self.state.data.limits.get(a).and_then(|m| m.get(&cur)).copied();
                if let Some(limit) = known.or_else(|| principal.lim.get(a).and_then(|m| m.get(&cur)).copied()) {
                    if spent(&self.state, a) + amount > limit {
                        deny!("budget_exceeded", format!("{amount} {cur} would exceed the budget of ancestor token {a}"));
                    }
                }
            }
            o.spend = Some((cur, amount));
            pass!("budget", "within the budget of every token in the chain");
        }

        // human approval comes last so a request that would fail anyway never
        // reaches an approver
        if let Some(label) = approval_label {
            let aid = hash_value(&json!({
                "user": principal.user, "chain": principal.chain, "tenant": principal.tenant,
                "action": action, "resource": format!("{path}/{id}"), "attrs": attrs, "context": caller_ctx, "label": label,
            }))[..24]
                .to_string();
            match self.state.data.approvals.get(&aid) {
                Some(a) if a.exp > now => {
                    o.approved = Some((aid, a.by.clone()));
                    pass!("approval", format!("approved by {}", a.by));
                }
                _ => {
                    if !dry_run {
                        self.state.data.pending.insert(aid.clone(), Pending {
                            label: label.clone(), user: principal.user.clone(), agent: principal.leaf().to_string(),
                            action: action.clone(), resource: format!("{path}/{id}"), requested_at: now,
                        });
                        self.state.save()?;
                    }
                    o.approval = Some(json!({"id": aid, "label": label}));
                    deny!("approval_required", format!("a human must approve this ({label})"));
                }
            }
        }

        // 9. fields
        let mut status = BTreeMap::new();
        let mut field_trace = Vec::new();
        for n in &field_names {
            let fid = format!("{path}.{n}");
            let fdef = &rdef.fields[n];
            let (allowed, by) = if principal.cap.deny_fields.contains(&fid) || fdef.labels.iter().any(|l| principal.cap.deny_labels.contains(l)) {
                (false, json!("capability"))
            } else {
                let fv = self.evaluate(&p_uid, &action, &uid("Field", &fid)?, &ctx, &entities)?;
                o.errors.extend(fv.errors.clone());
                (fv.allow, if fv.policies.is_empty() { json!("no_matching_permit") } else { json!(fv.policies) })
            };
            if allowed {
                o.field_allow.push(n.clone());
                status.insert(n.clone(), Status::Allow);
            } else {
                o.field_deny.push(n.clone());
                if fdef.mask.as_deref() == Some("redact") {
                    o.field_redact.push(n.clone());
                    status.insert(n.clone(), Status::Redact);
                } else {
                    status.insert(n.clone(), Status::Deny);
                }
            }
            field_trace.push(json!({"field": n, "effect": if allowed { "allow" } else { "deny" }, "by": by}));
        }
        o.trace.push(json!({"check": "fields", "result": "pass", "fields": field_trace}));
        o.mask = Some(Mask { status });
        o.allow = true;
        o.reason = "policy_permit".into();
        Ok(o)
    }

    fn decide(&mut self, input: &Value, with_data: bool) -> Result<Value> {
        let now = self.now(input);
        let dry_run = input.get("dry_run").and_then(|x| x.as_bool()).unwrap_or(false);
        let strict = input.get("strict").and_then(|x| x.as_bool()).unwrap_or(false);
        let data = if with_data {
            Some(input.get("data").ok_or_else(|| Error::new("invalid_input", "'data' is required for filter"))?)
        } else {
            None
        };
        let mut o = self.evaluate_request(input, now, dry_run)?;

        // 10. strict mode: used for tool *inputs*, where silently dropping a
        // field would change what the agent asked for.
        if o.allow && strict {
            if let (Some(d), Some(mask)) = (data, &o.mask) {
                let denied = fields::denied_in(d, mask);
                if !denied.is_empty() {
                    o.allow = false;
                    o.reason = "field_denied".into();
                    o.detail = format!("the input contains fields this principal may not use: {}", denied.join(", "));
                    o.trace.push(json!({"check": "field_denied", "result": "deny", "detail": o.detail}));
                }
            }
        }

        // commit side effects of an allowed call
        if o.allow && !dry_run {
            for (key, _, _) in &o.rate {
                self.rate.entry(key.clone()).or_default().push_back(now);
            }
            let mut dirty = false;
            if let (Some((cur, amount)), Some(p)) = (&o.spend, &o.principal) {
                for id in p.anc.iter().chain(p.jti.iter()) {
                    *self.state.data.ledger.entry(id.clone()).or_default().entry(cur.clone()).or_insert(0) += amount;
                }
                dirty = true;
            }
            if let Some((aid, _)) = &o.approved {
                // an approval is good for one call
                self.state.data.approvals.remove(aid);
                dirty = true;
            }
            if dirty {
                self.state.save()?;
            }
        }

        let would_deny = !o.allow;
        let shadowed = self.cfg.shadow && would_deny;
        let effective_allow = o.allow || shadowed;

        let mut out = Map::new();
        out.insert("effect".into(), json!(if effective_allow { "allow" } else { "deny" }));
        let reason = if shadowed { "shadow_allow" } else { o.reason.as_str() };
        out.insert("reason".into(), json!(reason));
        out.insert("rule".into(), json!(crate::rule_id(reason)));
        if !o.detail.is_empty() && !shadowed {
            out.insert("detail".into(), json!(o.detail));
        }
        out.insert("policies".into(), json!(o.policies));
        out.insert("policy_version".into(), json!(self.bundle.version));
        out.insert("principal".into(), o.principal.as_ref().map(|p| p.to_json()).unwrap_or(Value::Null));
        if self.cfg.shadow {
            out.insert("shadow".into(), json!(true));
            if would_deny {
                out.insert("would_deny".into(), json!({"reason": o.reason, "detail": o.detail}));
            }
        }
        if let Some(a) = &o.approval {
            out.insert("approval".into(), a.clone());
        }

        let mut obligations = Map::new();
        let mut masked: Vec<String> = Vec::new();
        let mut rows_dropped = 0usize;
        if o.allow {
            obligations.insert("fields".into(), json!({"allow": o.field_allow, "deny": o.field_deny, "redact": o.field_redact}));
            if !o.row_filter.is_empty() {
                obligations.insert("row_filter".into(), json!(o.row_filter));
            }
            if let Some(r) = &o.rate_limit {
                obligations.insert("rate_limit".into(), r.clone());
            }
            if let Some((aid, by)) = &o.approved {
                obligations.insert("approved".into(), json!({"id": aid, "by": by}));
            }
        }
        if let Some(d) = data {
            if o.allow {
                let f = fields::apply(d, o.mask.as_ref().unwrap(), &o.row_filter);
                masked = f.masked;
                rows_dropped = f.rows_dropped;
                if self.cfg.shadow {
                    // shadow mode never changes data; it reports what it would do
                    out.insert("data".into(), d.clone());
                    out.insert("would_mask".into(), json!(masked));
                    out.insert("would_drop_rows".into(), json!(rows_dropped));
                } else {
                    out.insert("data".into(), f.data);
                    out.insert("masked".into(), json!(masked));
                    out.insert("rows_dropped".into(), json!(rows_dropped));
                }
            } else if shadowed {
                out.insert("data".into(), d.clone());
            } else {
                out.insert("data".into(), Value::Null);
            }
        }
        out.insert("obligations".into(), Value::Object(obligations.clone()));
        if !o.errors.is_empty() {
            out.insert("policy_errors".into(), json!(o.errors));
        }
        if input.get("explain").and_then(|x| x.as_bool()).unwrap_or(false) {
            out.insert("explain".into(), json!(o.trace));
        }

        self.counter += 1;
        let request_hash = hash_value(&json!({
            "action": input.get("action"), "resource": input.get("resource"), "context": input.get("context"),
            "token_id": o.principal.as_ref().and_then(|p| p.jti.clone()),
        }));
        let decision_id = format!("d-{}", &sha256_hex(format!("{request_hash}{now}{}{}", self.counter, std::process::id()).as_bytes())[..16]);
        out.insert("decision_id".into(), json!(decision_id));

        if !dry_run {
            let p = o.principal.as_ref();
            let res = &input["resource"];
            self.audit_event(
                json!({
                    "event": "decision", "decision_id": decision_id, "op": if with_data { "filter" } else { "authorize" },
                    "effect": if o.allow { "allow" } else { "deny" }, "reason": o.reason, "detail": o.detail,
                    "enforced": !self.cfg.shadow,
                    "policies": o.policies, "policy_version": self.bundle.version,
                    "user": p.map(|p| p.user.clone()), "chain": p.map(|p| p.chain.clone()), "role": p.and_then(|p| p.role.clone()),
                    "tenant": p.and_then(|p| p.tenant.clone()), "task": p.and_then(|p| p.task.clone()),
                    "token_id": p.and_then(|p| p.jti.clone()), "token_exp": p.map(|p| p.exp),
                    "action": input.get("action"),
                    "resource": format!("{}/{}", res["path"].as_str().unwrap_or("?"), res["id"].as_str().unwrap_or("any")),
                    "obligations": obligations, "masked": masked, "rows_dropped": rows_dropped,
                    "approval": o.approval, "spend": o.spend.as_ref().map(|(c, a)| json!({"currency": c, "amount": a})),
                    "request_hash": request_hash,
                }),
                now,
            )?;
        }
        Ok(Value::Object(out))
    }
}
