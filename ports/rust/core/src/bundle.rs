//! Policy bundle: Cedar policies, the entity store, the field catalog, and an
//! optional Ed25519 signature over the file hashes.
//!
//! Layout of a bundle directory:
//!   policies/*.cedar   Cedar policies; `@id("name")` names a policy
//!   entities.json      Cedar entities (users, groups, agents, resources)
//!   catalog.json       resource paths, entity types, fields and labels
//!   roles.json         roles a human can lend to an agent: who holds them and
//!                      the most a token may carry under each (optional)
//!   tests/*.json       policy unit tests (not part of the version hash)
//!   bundle.sig.json    written by `smartdelegate bundle sign`

use crate::canon::{canon, sha256_hex};
use crate::token::Cap;
use crate::{Error, Result};
use base64::Engine as _;
use cedar_policy::{Effect, Entities, Policy, PolicyId, PolicySet};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Deserialize, Clone, Default)]
pub struct FieldDef {
    #[serde(default)]
    pub labels: Vec<String>,
    /// "drop" (default) removes a denied field; "redact" replaces its value.
    #[serde(default)]
    pub mask: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct ResourceDef {
    pub entity_type: String,
    #[serde(default)]
    pub fields: BTreeMap<String, FieldDef>,
}

#[derive(Deserialize, Clone, Default)]
pub struct Catalog {
    #[serde(default)]
    pub resources: BTreeMap<String, ResourceDef>,
}

#[derive(Clone)]
pub struct PolicyMeta {
    pub permit: bool,
    pub annotations: BTreeMap<String, String>,
    pub file: String,
}

/// A role a human holds and can lend to an agent for one task.
#[derive(Clone)]
pub struct Role {
    pub name: String,
    /// `(type, id)`: the user holds the role when it is one of these or has
    /// one of these among its ancestors.
    pub members: Vec<(String, String)>,
    /// The ceiling: the most a token issued under this role can carry.
    pub cap: Cap,
    pub max_ttl: Option<i64>,
    pub tasks: Option<Vec<String>>,
    pub agents: Option<Vec<String>>,
    /// Free-form, for bridges; the engine does not read it.
    pub bindings: Value,
}

const ROLE_KEYS: [&str; 7] = ["description", "members", "cap", "max_ttl", "tasks", "agents", "bindings"];

fn pattern_list(v: &Value, what: &str) -> std::result::Result<Vec<String>, String> {
    let bad = || format!("{what} must be a non-empty list of names, each with at most one trailing *");
    let list = v.as_array().filter(|a| !a.is_empty()).ok_or_else(bad)?;
    list.iter().map(|x| x.as_str().filter(|p| crate::token::valid_pattern(p)).map(String::from).ok_or_else(bad)).collect()
}

impl Role {
    fn parse(name: &str, v: &Value) -> std::result::Result<Role, String> {
        let obj = v.as_object().filter(|_| !name.is_empty()).ok_or_else(|| format!("role '{name}' must be an object"))?;
        // a misspelt key must not silently loosen a role
        let unknown: Vec<&str> = obj.keys().map(|k| k.as_str()).filter(|k| !ROLE_KEYS.contains(k)).collect();
        if !unknown.is_empty() {
            return Err(format!("role '{name}': unknown field(s): {}", unknown.join(", ")));
        }
        let list = obj.get("members").and_then(|m| m.as_array()).filter(|a| !a.is_empty()).ok_or_else(|| format!("role '{name}': members must be a non-empty list of {{type, id}}"))?;
        let mut members = Vec::new();
        for m in list {
            match (m.is_object(), m["type"].as_str().filter(|t| crate::token::valid_type(t)), m["id"].as_str()) {
                (true, Some(t), Some(i)) => members.push((t.to_string(), i.to_string())),
                _ => return Err(format!("role '{name}': each member must be {{type, id}}")),
            }
        }
        let cap_json = obj.get("cap").ok_or_else(|| format!("role '{name}': cap is required"))?;
        if !cap_json.is_object() {
            return Err(format!("role '{name}': cap must be an object"));
        }
        let cap: Cap = serde_json::from_value(cap_json.clone()).map_err(|e| format!("role '{name}': cap: {e}"))?;
        cap.validate().map_err(|e| format!("role '{name}': {}", e.message))?;
        let max_ttl = match obj.get("max_ttl") {
            None => None,
            Some(t) => Some(t.as_i64().filter(|n| *n > 0).ok_or_else(|| format!("role '{name}': max_ttl must be a positive integer"))?),
        };
        let tasks = obj.get("tasks").map(|t| pattern_list(t, &format!("role '{name}': tasks"))).transpose()?;
        let agents = obj.get("agents").map(|t| pattern_list(t, &format!("role '{name}': agents"))).transpose()?;
        let bindings = match obj.get("bindings") {
            None => json!({}),
            Some(b) if b.is_object() => b.clone(),
            Some(_) => return Err(format!("role '{name}': bindings must be an object")),
        };
        Ok(Role { name: name.to_string(), members, cap, max_ttl, tasks, agents, bindings })
    }
}

/// `{type, id}` or `{"__entity": {type, id}}`, as entities.json writes a uid.
pub fn uid_parts(u: &Value) -> Option<(String, String)> {
    let u = u.get("__entity").unwrap_or(u);
    Some((u.get("type")?.as_str()?.to_string(), u.get("id")?.as_str()?.to_string()))
}

pub struct Bundle {
    pub dir: PathBuf,
    pub policies: PolicySet,
    pub meta: BTreeMap<String, PolicyMeta>,
    pub entities: Entities,
    /// "Type::id" -> attrs, as written in entities.json
    pub attrs: BTreeMap<String, Value>,
    /// entities.json as it was read; a token with live group membership is
    /// judged against a copy in which the user's parents are replaced.
    pub entities_json: Vec<Value>,
    /// `(type, id)` of every entity entities.json defines
    pub defined: HashSet<(String, String)>,
    pub roles: BTreeMap<String, Role>,
    pub catalog: Catalog,
    pub version: String,
    pub signed_by: Option<String>,
}

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::new("bundle_io", format!("{}: {e}", path.display())))
}

/// Relative path -> sha256 for every file that defines behaviour.
pub fn manifest(dir: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    // Hash with normalised line endings so a Windows checkout has the same
    // policy version as a Linux one.
    let digest = |p: &Path| -> Result<String> { Ok(sha256_hex(read(p)?.replace("\r\n", "\n").as_bytes())) };
    if !dir.join("policies.json").exists() && !dir.join("policies").is_dir() {
        // a wrong path must not quietly load as "no policies"
        return Err(Error::new("bundle_io", format!("{}: no policies.json and no policies/ directory", dir.display())));
    }
    if dir.join("policies.json").exists() {
        // The compiled form is what every port evaluates, so it is what the
        // version and the signature cover.
        files.insert("policies.json".to_string(), digest(&dir.join("policies.json"))?);
    } else {
        for (rel, p) in cedar_files(dir)? {
            files.insert(rel, digest(&p)?);
        }
    }
    for name in ["entities.json", "catalog.json", "roles.json"] {
        let p = dir.join(name);
        if p.exists() {
            files.insert(name.to_string(), digest(&p)?);
        }
    }
    Ok(files)
}

fn cedar_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let pdir = dir.join("policies");
    if !pdir.exists() {
        return Ok(vec![]);
    }
    let mut names: Vec<PathBuf> = std::fs::read_dir(&pdir)
        .map_err(|e| Error::new("bundle_io", format!("{}: {e}", pdir.display())))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "cedar").unwrap_or(false))
        .collect();
    names.sort();
    Ok(names.into_iter().map(|p| (format!("policies/{}", p.file_name().unwrap().to_string_lossy()), p)).collect())
}

type Loaded = (PolicySet, BTreeMap<String, PolicyMeta>);

fn add_policy(set: &mut PolicySet, meta: &mut BTreeMap<String, PolicyMeta>, id: String, p: &Policy, file: &str) -> Result<()> {
    if meta.contains_key(&id) {
        return Err(Error::new("policy_parse", format!("{file}: duplicate policy id '{id}'")));
    }
    let annotations = p.annotations().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    meta.insert(id.clone(), PolicyMeta { permit: p.effect() == Effect::Permit, annotations, file: file.to_string() });
    set.add(p.new_id(PolicyId::new(&id))).map_err(|e| Error::new("policy_parse", format!("{file}: {e}")))
}

/// Parse `policies/*.cedar`.
fn load_cedar_sources(dir: &Path) -> Result<Loaded> {
    let mut policies = PolicySet::new();
    let mut meta = BTreeMap::new();
    for (rel, path) in cedar_files(dir)? {
        let src = read(&path)?;
        let parsed = PolicySet::from_str(&src).map_err(|e| Error::new("policy_parse", format!("{rel}: {e}")))?;
        if parsed.templates().next().is_some() {
            return Err(Error::new("policy_parse", format!("{rel}: policy templates are not supported")));
        }
        let stem = rel.trim_start_matches("policies/").trim_end_matches(".cedar");
        let mut list: Vec<&Policy> = parsed.policies().collect();
        list.sort_by_key(|p| p.id().to_string());
        for (i, p) in list.iter().enumerate() {
            let id = p.annotation("id").map(|s| s.to_string()).unwrap_or_else(|| format!("{stem}#{i}"));
            add_policy(&mut policies, &mut meta, id, p, &rel)?;
        }
    }
    Ok((policies, meta))
}

/// Read `policies.json` (Cedar's JSON policy form, keyed by id).
fn load_compiled(doc: &Value) -> Result<Loaded> {
    let map = doc["policies"].as_object().ok_or_else(|| Error::new("policy_parse", "policies.json has no 'policies' object"))?;
    let mut policies = PolicySet::new();
    let mut meta = BTreeMap::new();
    for (id, est) in map {
        let p = Policy::from_json(Some(PolicyId::new(id)), est.clone()).map_err(|e| Error::new("policy_parse", format!("policies.json: {id}: {e}")))?;
        add_policy(&mut policies, &mut meta, id.clone(), &p, "policies.json")?;
    }
    Ok((policies, meta))
}

fn compiled_doc(dir: &Path) -> Result<Value> {
    let (set, meta) = load_cedar_sources(dir)?;
    let mut out = serde_json::Map::new();
    for id in meta.keys() {
        let p = set.policy(&PolicyId::new(id)).ok_or_else(|| Error::new("internal", "policy vanished"))?;
        out.insert(id.clone(), p.to_json().map_err(|e| Error::new("policy_parse", format!("{id}: {e}")))?);
    }
    // Hashes of the sources this was compiled from. Ports that cannot parse
    // Cedar text use them to notice a source edited without recompiling.
    let mut sources = serde_json::Map::new();
    for (rel, path) in cedar_files(dir)? {
        sources.insert(rel, json!(sha256_hex(read(&path)?.replace("\r\n", "\n").as_bytes())));
    }
    Ok(json!({"format": "cedar-json/1", "sources": sources, "policies": out}))
}

/// Compile `policies/*.cedar` into `policies.json`: Cedar's own JSON policy
/// form, keyed by policy id. This file is what every language port loads.
pub fn compile(dir: &Path) -> Result<Value> {
    let doc = compiled_doc(dir)?;
    std::fs::write(dir.join("policies.json"), serde_json::to_string_pretty(&doc).unwrap() + "\n").map_err(|e| Error::new("bundle_io", e.to_string()))?;
    Ok(doc)
}

pub fn version_of(files: &BTreeMap<String, String>) -> String {
    sha256_hex(canon(&json!(files)).as_bytes())
}

impl Bundle {
    /// `public_key`: when set, the bundle must carry a valid signature by
    /// that key or loading fails (fail closed).
    pub fn load(dir: &Path, public_key: Option<&str>) -> Result<Bundle> {
        let files = manifest(dir)?;
        let version = version_of(&files);
        let mut signed_by = None;
        if let Some(pk) = public_key {
            verify_signature(dir, &files, pk)?;
            signed_by = Some(key_id(pk)?);
        }

        let (policies, meta) = if dir.join("policies.json").exists() {
            let sources = cedar_files(dir)?;
            let on_disk: Value = serde_json::from_str(&read(&dir.join("policies.json"))?).map_err(|e| Error::new("policy_parse", format!("policies.json: {e}")))?;
            if !sources.is_empty() {
                // policies.json records the hash of each .cedar file it was
                // compiled from: a source edited or added without
                // recompiling is stale, whatever else is wrong
                let mut hashes = serde_json::Map::new();
                for (rel, path) in &sources {
                    hashes.insert(rel.clone(), json!(sha256_hex(read(path)?.replace("\r\n", "\n").as_bytes())));
                }
                if on_disk.get("sources").and_then(|x| x.as_object()) != Some(&hashes) {
                    return Err(Error::new("bundle_stale", "policies.json does not match policies/*.cedar; run `smartdelegate bundle compile`"));
                }
            }
            let loaded = load_compiled(&on_disk)?;
            // This port can also compile: sources and compiled form must
            // agree in full, or a reviewer reads one policy while the engine
            // runs another.
            if !sources.is_empty() && compiled_doc(dir)? != on_disk {
                return Err(Error::new("bundle_stale", "policies.json does not match policies/*.cedar; run `smartdelegate bundle compile`"));
            }
            loaded
        } else {
            load_cedar_sources(dir)?
        };

        let ents_path = dir.join("entities.json");
        let mut attrs = BTreeMap::new();
        let mut entities_json = Vec::new();
        let mut defined = HashSet::new();
        let entities = if ents_path.exists() {
            let mut v: Value = serde_json::from_str(&read(&ents_path)?).map_err(|e| Error::new("entities_parse", e.to_string()))?;
            let list = v.as_array_mut().filter(|a| a.iter().all(|e| e.is_object())).ok_or_else(|| Error::new("entities_parse", "entities.json: expected a list of entities"))?;
            for e in list.iter_mut() {
                // `attrs` and `parents` may be left out (or null); Cedar's
                // own reader insists on both
                for (key, empty) in [("attrs", json!({})), ("parents", json!([]))] {
                    if e.get(key).map(|x| x.is_null()).unwrap_or(true) {
                        e[key] = empty;
                    }
                }
            }
            for e in v.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                let (t, i) = uid_parts(&e["uid"]).filter(|(t, _)| crate::token::valid_type(t)).ok_or_else(|| Error::new("entities_parse", format!("entities.json: malformed entity uid: {}", e["uid"])))?;
                attrs.insert(format!("{t}::{i}"), e.get("attrs").cloned().unwrap_or_else(|| json!({})));
                if !defined.insert((t.clone(), i.clone())) {
                    return Err(Error::new("entities_parse", format!("entities.json: duplicate entity {t}::{i:?}")));
                }
            }
            entities_json = v.as_array().cloned().unwrap_or_default();
            Entities::from_json_value(v, None).map_err(|e| Error::new("entities_parse", e.to_string()))?
        } else {
            Entities::empty()
        };

        let cat_path = dir.join("catalog.json");
        let catalog: Catalog = if cat_path.exists() {
            serde_json::from_str(&read(&cat_path)?).map_err(|e| Error::new("catalog_parse", e.to_string()))?
        } else {
            Catalog::default()
        };
        for (path, def) in &catalog.resources {
            if !crate::token::valid_type(&def.entity_type) {
                return Err(Error::new("catalog_parse", format!("{path}: entity_type is missing or malformed")));
            }
            for (f, fd) in &def.fields {
                if let Some(m) = &fd.mask {
                    if m != "drop" && m != "redact" {
                        return Err(Error::new("catalog_parse", format!("{path}.{f}: mask must be 'drop' or 'redact'")));
                    }
                }
            }
        }

        let mut roles = BTreeMap::new();
        let roles_path = dir.join("roles.json");
        if roles_path.exists() {
            let bad = |m: String| Error::new("roles_parse", format!("roles.json: {m}"));
            let doc: Value = serde_json::from_str(&read(&roles_path).map_err(|e| bad(e.message))?).map_err(|e| bad(e.to_string()))?;
            let map = doc.get("roles").and_then(|r| r.as_object()).ok_or_else(|| bad("expected {\"roles\": {...}}".into()))?;
            for (name, rdef) in map {
                roles.insert(name.clone(), Role::parse(name, rdef).map_err(bad)?);
            }
        }
        Ok(Bundle { dir: dir.to_path_buf(), policies, meta, entities, attrs, entities_json, defined, roles, catalog, version, signed_by })
    }
}

// ---- signing --------------------------------------------------------------

pub fn keygen() -> Result<(String, String)> {
    let rng = ring::rand::SystemRandom::new();
    // PKCS#8 version 1 (RFC 8410), the encoding every port can read: Python's
    // `cryptography` and the JDK both refuse the version 2 form ring emits.
    use ring::rand::SecureRandom;
    let mut seed = [0u8; 32];
    rng.fill(&mut seed).map_err(|_| Error::new("crypto", "key generation failed"))?;
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(&seed);
    let kp = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).map_err(|_| Error::new("crypto", "key generation failed"))?;
    Ok((B64.encode(&der), B64.encode(kp.public_key().as_ref())))
}

pub fn key_id(public_b64: &str) -> Result<String> {
    let raw = B64.decode(public_b64.trim()).map_err(|_| Error::new("crypto", "public key is not base64"))?;
    Ok(sha256_hex(&raw)[..16].to_string())
}

pub fn sign(dir: &Path, private_pkcs8_b64: &str) -> Result<Value> {
    let der = B64.decode(private_pkcs8_b64.trim()).map_err(|_| Error::new("crypto", "private key is not base64"))?;
    let kp = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).map_err(|_| Error::new("crypto", "private key is not Ed25519 PKCS#8"))?;
    let files = manifest(dir)?;
    let version = version_of(&files);
    let public = B64.encode(kp.public_key().as_ref());
    let payload = json!({"files": files, "version": version});
    let sig = kp.sign(canon(&payload).as_bytes());
    let out = json!({
        "files": payload["files"], "version": version,
        "key_id": key_id(&public)?, "alg": "Ed25519",
        "signature": B64.encode(sig.as_ref()),
    });
    std::fs::write(dir.join("bundle.sig.json"), serde_json::to_string_pretty(&out).unwrap())
        .map_err(|e| Error::new("bundle_io", e.to_string()))?;
    Ok(out)
}

fn verify_signature(dir: &Path, files: &BTreeMap<String, String>, public_b64: &str) -> Result<()> {
    let p = dir.join("bundle.sig.json");
    if !p.exists() {
        return Err(Error::new("bundle_unsigned", "a signed bundle is required, but bundle.sig.json is missing"));
    }
    let sig: Value = serde_json::from_str(&read(&p)?).map_err(|e| Error::new("bundle_signature", e.to_string()))?;
    let payload = json!({"files": sig["files"], "version": sig["version"]});
    let raw_sig = B64
        .decode(sig["signature"].as_str().unwrap_or(""))
        .map_err(|_| Error::new("bundle_signature", "signature is not base64"))?;
    let raw_pk = B64.decode(public_b64.trim()).map_err(|_| Error::new("crypto", "public key is not base64"))?;
    UnparsedPublicKey::new(&ED25519, raw_pk)
        .verify(canon(&payload).as_bytes(), &raw_sig)
        .map_err(|_| Error::new("bundle_signature", "bundle signature does not verify with the configured key"))?;
    if json!(files) != sig["files"] {
        return Err(Error::new("bundle_signature", "bundle files changed after signing"));
    }
    Ok(())
}
