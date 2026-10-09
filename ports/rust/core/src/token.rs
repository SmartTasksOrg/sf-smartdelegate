//! Capability tokens: EdDSA-signed JWTs with an RFC 8693 `act` delegation
//! chain and a `cap` claim that can only be narrowed on each hop.

use crate::canon::sha256_hex;
use crate::{Error, Result};
use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
pub const AUDIENCE: &str = "smartdelegate";

// A misspelt key must not silently become "no restriction", and a cap is an
// object: serde alone would also read a struct from a list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(try_from = "Value")]
pub struct Cap {
    /// Action names; a trailing `*` is a prefix wildcard.
    pub actions: Vec<String>,
    /// `<resource path>/<id>` patterns; a trailing `*` is a prefix wildcard.
    pub resources: Vec<String>,
    /// Field labels this token can never see, whatever policy says.
    pub deny_labels: Vec<String>,
    /// Field ids (`crm.customer.ssn`) this token can never see.
    pub deny_fields: Vec<String>,
    /// currency -> total spend limit in minor units (cents).
    pub budget: BTreeMap<String, i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapRaw {
    #[serde(default, deserialize_with = "null_as_default")]
    actions: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    resources: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    deny_labels: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    deny_fields: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    budget: BTreeMap<String, i64>,
}

impl TryFrom<Value> for Cap {
    type Error = String;
    fn try_from(v: Value) -> std::result::Result<Cap, String> {
        if !v.is_object() {
            return Err("cap must be an object".into());
        }
        let r: CapRaw = serde_json::from_value(v).map_err(|e| e.to_string())?;
        Ok(Cap { actions: r.actions, resources: r.resources, deny_labels: r.deny_labels, deny_fields: r.deny_fields, budget: r.budget })
    }
}

fn null_as_default<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A name with at most one `*`, and that one at the end.
pub fn valid_pattern(p: &str) -> bool {
    let mut chars = p.chars();
    chars.next_back().is_some() && !chars.any(|c| c == '*')
}

/// An entity type name of the portable subset: identifiers joined by `::`.
pub fn valid_type(name: &str) -> bool {
    !name.is_empty()
        && name.split("::").all(|part| {
            let mut c = part.chars();
            c.next().map(|f| f.is_ascii_alphabetic() || f == '_').unwrap_or(false) && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
        })
}

impl Cap {
    pub fn unrestricted() -> Cap {
        Cap { actions: vec!["*".into()], resources: vec!["*".into()], deny_labels: vec![], deny_fields: vec![], budget: BTreeMap::new() }
    }

    pub fn validate(&self) -> Result<()> {
        for p in self.actions.iter().chain(self.resources.iter()) {
            if !valid_pattern(p) {
                return Err(Error::new("invalid_cap", format!("pattern '{p}': only one trailing * is allowed")));
            }
        }
        if self.budget.values().any(|v| *v < 0) {
            return Err(Error::new("invalid_cap", "budget cannot be negative"));
        }
        Ok(())
    }

    pub fn allows_action(&self, action: &str) -> bool {
        self.actions.iter().any(|p| matches(p, action))
    }

    pub fn allows_resource(&self, path: &str, id: &str) -> bool {
        let s = format!("{path}/{id}");
        self.resources.iter().any(|p| matches(p, &s))
    }

    /// Ok when `self` grants nothing that `parent` does not grant.
    pub fn narrower_than(&self, parent: &Cap) -> Result<()> {
        for a in &self.actions {
            if !parent.actions.iter().any(|p| covers(p, a)) {
                return Err(Error::new("widening", format!("action '{a}' is not covered by the parent token")));
            }
        }
        for r in &self.resources {
            if !parent.resources.iter().any(|p| covers(p, r)) {
                return Err(Error::new("widening", format!("resource '{r}' is not covered by the parent token")));
            }
        }
        for l in &parent.deny_labels {
            if !self.deny_labels.contains(l) {
                return Err(Error::new("widening", format!("label '{l}' is denied by the parent and must stay denied")));
            }
        }
        for f in &parent.deny_fields {
            if !self.deny_fields.contains(f) {
                return Err(Error::new("widening", format!("field '{f}' is denied by the parent and must stay denied")));
            }
        }
        for (cur, amount) in &self.budget {
            match parent.budget.get(cur) {
                Some(p) if amount <= p => {}
                Some(p) => return Err(Error::new("widening", format!("budget {amount} {cur} exceeds the parent's {p}"))),
                None => return Err(Error::new("widening", format!("the parent token has no {cur} budget to pass on"))),
            }
        }
        Ok(())
    }
}

pub fn matches(pattern: &str, s: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => s.starts_with(prefix),
        None => pattern == s,
    }
}

/// Does `parent` cover every string that `child` covers?
fn covers(parent: &str, child: &str) -> bool {
    match (parent.strip_suffix('*'), child.strip_suffix('*')) {
        (Some(pp), Some(cp)) => cp.starts_with(pp),
        (Some(pp), None) => child.starts_with(pp),
        (None, Some(_)) => false,
        (None, None) => parent == child,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    /// RFC 8693 actor chain: the current actor is outermost.
    pub act: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tnt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// Token ids of every ancestor, root first. Revoking one revokes the subtree.
    #[serde(default)]
    pub anc: Vec<String>,
    /// The role the human lent the agent for this task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Live group membership `[{type, id}]` that replaces what entities.json
    /// says about the user. Absent: entities.json is used as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grp: Option<Vec<Value>>,
    /// Ancestor token id -> that token's budget (currency -> limit). Lets an
    /// engine that did not issue the ancestor (a verify-only engine with its
    /// own state) enforce the ancestor's budget. Absent when no ancestor has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lim: Option<BTreeMap<String, BTreeMap<String, i64>>>,
    pub cap: Cap,
}

impl Claims {
    /// Agents root-first: ["support-bot", "refund-helper"].
    pub fn chain(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = &self.act;
        while let Some(sub) = cur.get("sub").and_then(|s| s.as_str()) {
            out.push(sub.trim_start_matches("agent:").to_string());
            match cur.get("act") {
                Some(next) => cur = next,
                None => break,
            }
        }
        out.reverse();
        out
    }
    pub fn user(&self) -> String {
        self.sub.trim_start_matches("user:").to_string()
    }
}

pub fn act_for(chain: &[String]) -> Value {
    let mut act = Value::Null;
    for agent in chain {
        act = if act.is_null() { json!({"sub": format!("agent:{agent}")}) } else { json!({"sub": format!("agent:{agent}"), "act": act}) };
    }
    act
}

pub struct Keys {
    encoding: Option<EncodingKey>,
    pub kid: Option<String>,
    pub public_b64: Option<String>,
    decoders: BTreeMap<String, DecodingKey>,
}

fn kid_of(public: &[u8]) -> String {
    sha256_hex(public)[..16].to_string()
}

impl Keys {
    pub fn new(private_pkcs8_b64: Option<&str>, trusted_public_b64: &[String]) -> Result<Keys> {
        let mut keys = Keys { encoding: None, kid: None, public_b64: None, decoders: BTreeMap::new() };
        if let Some(b64) = private_pkcs8_b64 {
            let der = B64.decode(b64.trim()).map_err(|_| Error::new("crypto", "signing key is not base64"))?;
            let kp = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).map_err(|_| Error::new("crypto", "signing key is not Ed25519 PKCS#8"))?;
            let public = kp.public_key().as_ref().to_vec();
            let kid = kid_of(&public);
            keys.encoding = Some(EncodingKey::from_ed_der(&der));
            keys.decoders.insert(kid.clone(), DecodingKey::from_ed_der(&public));
            keys.kid = Some(kid);
            keys.public_b64 = Some(B64.encode(&public));
        }
        for b64 in trusted_public_b64 {
            let public = B64.decode(b64.trim()).map_err(|_| Error::new("crypto", "trusted key is not base64"))?;
            keys.decoders.insert(kid_of(&public), DecodingKey::from_ed_der(&public));
        }
        Ok(keys)
    }

    pub fn can_sign(&self) -> bool {
        self.encoding.is_some()
    }

    pub fn sign(&self, claims: &Claims) -> Result<String> {
        let key = self.encoding.as_ref().ok_or_else(|| Error::new("no_signing_key", "this engine can verify tokens but not issue them"))?;
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = self.kid.clone();
        jsonwebtoken::encode(&header, claims, key).map_err(|e| Error::new("crypto", e.to_string()))
    }

    /// Signature, issuer and audience. Time and revocation are checked by the
    /// engine, which owns the clock.
    pub fn verify(&self, token: &str, issuer: &str) -> std::result::Result<Claims, String> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| "token is not a JWT".to_string())?;
        if header.alg != Algorithm::EdDSA {
            return Err("token algorithm is not EdDSA".into());
        }
        let kid = header.kid.ok_or("token has no key id")?;
        let key = self.decoders.get(&kid).ok_or("token was signed by an unknown key")?;
        let mut v = Validation::new(Algorithm::EdDSA);
        v.validate_exp = false;
        v.set_audience(&[AUDIENCE]);
        v.set_issuer(&[issuer]);
        v.required_spec_claims.clear();
        let raw = jsonwebtoken::decode::<Value>(token, key, &v).map(|d| d.claims).map_err(|e| format!("token rejected: {e}"))?;
        // `role` and `grp` are optional, but when present they must be well
        // formed: a null or an empty role is not "no role".
        let role_ok = raw.get("role").map(|r| r.as_str().map(|x| !x.is_empty()).unwrap_or(false)).unwrap_or(true);
        let grp_ok = raw
            .get("grp")
            .map(|g| g.as_array().map(|a| a.iter().all(|x| x.is_object() && x["type"].is_string() && x["id"].is_string())).unwrap_or(false))
            .unwrap_or(true);
        let lim_ok = raw
            .get("lim")
            .map(|l| {
                l.as_object()
                    .map(|m| m.values().all(|b| b.as_object().map(|c| c.values().all(|v| v.as_i64().map(|n| n >= 0).unwrap_or(false))).unwrap_or(false)))
                    .unwrap_or(false)
            })
            .unwrap_or(true);
        if !raw.is_object() || !role_ok || !grp_ok || !lim_ok || !raw["act"].is_object() {
            return Err("token rejected: malformed claims".into());
        }
        serde_json::from_value::<Claims>(raw).map_err(|_| "token rejected: malformed claims".to_string())
    }
}

/// Verify an OIDC ID token against a static JWKS and return its claims.
pub fn verify_id_token(id_token: &str, jwks: &Value, issuer: &str, audience: &str, now: i64) -> Result<Value> {
    let bad = |m: String| Error::new("id_token_invalid", m);
    let header = jsonwebtoken::decode_header(id_token).map_err(|e| bad(e.to_string()))?;
    if !matches!(header.alg, Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::ES256 | Algorithm::ES384 | Algorithm::EdDSA) {
        return Err(bad("unsupported signing algorithm".into()));
    }
    let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(jwks.clone()).map_err(|e| bad(format!("jwks: {e}")))?;
    let jwk = match &header.kid {
        Some(kid) => set.find(kid),
        None if set.keys.len() == 1 => set.keys.first(),
        None => None,
    }
    .ok_or_else(|| bad("no matching key in the JWKS".into()))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| bad(e.to_string()))?;
    let mut v = Validation::new(header.alg);
    v.validate_exp = false;
    v.set_audience(&[audience]);
    v.set_issuer(&[issuer]);
    let claims = jsonwebtoken::decode::<Value>(id_token, &key, &v).map_err(|e| bad(e.to_string()))?.claims;
    // OIDC Core 3.1.3.7: a token issued to another client is not ours even
    // when our client id is among its audiences (another client's access
    // token would otherwise pass as an ID token).
    if let Some(azp) = claims.get("azp") {
        if azp.as_str() != Some(audience) {
            return Err(bad("issued to another client (azp)".into()));
        }
    } else if claims["aud"].as_array().map(|a| a.len() > 1).unwrap_or(false) {
        return Err(bad("several audiences and no azp claim".into()));
    }
    let exp = claims["exp"].as_i64().ok_or_else(|| bad("no exp claim".into()))?;
    if exp <= now {
        return Err(bad("ID token has expired".into()));
    }
    if claims["nbf"].as_i64().map(|n| n > now + 60).unwrap_or(false) {
        return Err(bad("ID token is not valid yet".into()));
    }
    Ok(claims)
}
