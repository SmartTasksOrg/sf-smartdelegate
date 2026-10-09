// Capability tokens: EdDSA-signed JWTs with an RFC 8693 `act` delegation
// chain and a `cap` claim that can only be narrowed on each hop.
import { createPublicKey, constants, verify as cryptoVerify } from 'node:crypto';
import { decodeUtf8, sha256Hex } from './canon.mjs';
import { EngineError } from './errors.mjs';
import { has, isInt, isObj, isStr, keysOf, obj, parse, setOrder, truthy, write } from './json.mjs';
import * as bundle from './bundle.mjs';

export const AUDIENCE = 'smartdelegate';

export function b64u(data) {
  return Buffer.from(data).toString('base64url');
}

const B64U = /^[A-Za-z0-9_-]+$/;

/** base64url, strict: exactly the URL-safe alphabet, no padding, no skipped
 * characters, no impossible length. One token has one spelling. */
export function b64uDec(text) {
  if (typeof text !== 'string' || !B64U.test(text) || text.length % 4 === 1) throw new Error('not base64url');
  return Buffer.from(text, 'base64url');
}

// ---- capability ------------------------------------------------------------

function strList(v, what) {
  if (v === null || v === undefined) return [];
  if (!Array.isArray(v) || !v.every(isStr)) throw new EngineError('invalid_cap', `${what} must be a list of strings`);
  return [...v];
}

/** actions / resources: names with an optional single trailing `*`.
 * resources are `<path>/<id>`. deny_labels / deny_fields: what this token can
 * never see, whatever policy says. budget: currency -> total spend in minor
 * units (BigInt). */
export class Cap {
  constructor(actions, resources, denyLabels, denyFields, budget) {
    this.actions = strList(actions, 'cap.actions');
    this.resources = strList(resources, 'cap.resources');
    this.denyLabels = strList(denyLabels, 'cap.deny_labels');
    this.denyFields = strList(denyFields, 'cap.deny_fields');
    if (!truthy(budget)) budget = obj();
    if (!isObj(budget) || !Object.keys(budget).every((k) => isInt(budget[k]))) {
      throw new EngineError('invalid_cap', 'cap.budget must map currency to an integer amount in minor units');
    }
    this.budget = obj();
    for (const k of keysOf(budget)) this.budget[k] = budget[k];
    setOrder(this.budget, keysOf(budget));
  }

  static fromJson(v) {
    if (!isObj(v)) throw new EngineError('invalid_cap', 'cap must be an object');
    const unknown = Object.keys(v).filter((k) => !['actions', 'resources', 'deny_labels', 'deny_fields', 'budget'].includes(k));
    // a misspelt key must not silently become "no restriction"
    if (unknown.length) throw new EngineError('invalid_cap', `unknown cap field(s): ${unknown.sort().join(', ')}`);
    return new Cap(v.actions, v.resources, v.deny_labels, v.deny_fields, v.budget);
  }

  static unrestricted() {
    return new Cap(['*'], ['*']);
  }

  toJson() {
    const o = obj();
    o.actions = [...this.actions];
    o.resources = [...this.resources];
    o.deny_labels = [...this.denyLabels];
    o.deny_fields = [...this.denyFields];
    o.budget = setOrder(Object.assign(obj(), this.budget), keysOf(this.budget));
    return o;
  }

  validate() {
    for (const p of [...this.actions, ...this.resources]) {
      if (!p || p.slice(0, -1).includes('*')) throw new EngineError('invalid_cap', `pattern '${p}': only one trailing * is allowed`);
    }
    for (const k of Object.keys(this.budget)) {
      if (this.budget[k] < 0n) throw new EngineError('invalid_cap', 'budget cannot be negative');
    }
  }

  allowsAction(action) {
    return this.actions.some((p) => matches(p, action));
  }

  allowsResource(path, id) {
    const s = `${path}/${id}`;
    return this.resources.some((p) => matches(p, s));
  }

  /** Throws `widening` unless this grants nothing the parent does not. */
  checkNarrowerThan(parent) {
    for (const a of this.actions) {
      if (!parent.actions.some((p) => covers(p, a))) throw new EngineError('widening', `action '${a}' is not covered by the parent token`);
    }
    for (const r of this.resources) {
      if (!parent.resources.some((p) => covers(p, r))) throw new EngineError('widening', `resource '${r}' is not covered by the parent token`);
    }
    for (const l of parent.denyLabels) {
      if (!this.denyLabels.includes(l)) throw new EngineError('widening', `label '${l}' is denied by the parent and must stay denied`);
    }
    for (const f of parent.denyFields) {
      if (!this.denyFields.includes(f)) throw new EngineError('widening', `field '${f}' is denied by the parent and must stay denied`);
    }
    for (const cur of Object.keys(this.budget)) {
      if (!has(parent.budget, cur)) throw new EngineError('widening', `the parent token has no ${cur} budget to pass on`);
      if (this.budget[cur] > parent.budget[cur]) {
        throw new EngineError('widening', `budget ${this.budget[cur]} ${cur} exceeds the parent's ${parent.budget[cur]}`);
      }
    }
  }
}

export function matches(pattern, s) {
  return pattern.endsWith('*') ? s.startsWith(pattern.slice(0, -1)) : pattern === s;
}

/** Does `parent` cover every string that `child` covers? */
function covers(parent, child) {
  if (parent.endsWith('*')) {
    const head = parent.slice(0, -1);
    return child.endsWith('*') ? child.replace(/\*+$/, '').startsWith(head) : child.startsWith(head);
  }
  return !child.endsWith('*') && parent === child;
}

// ---- claims ----------------------------------------------------------------

/** RFC 8693 actor chain: the current actor is outermost. */
export function actFor(chain) {
  let act = null;
  for (const agent of chain) {
    const next = obj();
    next.sub = `agent:${agent}`;
    if (act !== null) next.act = act;
    act = next;
  }
  return act;
}

/** Agents root-first: ["support-bot", "refund-helper"]. */
export function chainOf(claims) {
  const out = [];
  let cur = claims.act;
  while (isObj(cur) && typeof cur.sub === 'string') {
    out.push(cur.sub.startsWith('agent:') ? cur.sub.slice(6) : cur.sub);
    cur = cur.act;
  }
  return out.reverse();
}

export function userOf(claims) {
  const sub = typeof claims.sub === 'string' ? claims.sub : '';
  return sub.startsWith('user:') ? sub.slice(5) : sub;
}

/** Why a token was rejected; the engine turns it into `token_invalid`. */
export class TokenError extends Error {}

function split3(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('not three parts');
  return parts;
}

export class Keys {
  constructor(privateB64, trustedPublicB64) {
    this._private = null;
    this.kid = null;
    this.publicB64 = null;
    this._verifiers = new Map();
    if (privateB64) {
      this._private = bundle.loadPrivate(privateB64);
      const raw = bundle.publicRaw(this._private);
      this.kid = sha256Hex(raw).slice(0, 16);
      this.publicB64 = raw.toString('base64');
      this._verifiers.set(this.kid, createPublicKey(this._private));
    }
    for (const b of trustedPublicB64 ?? []) {
      const [key, raw] = bundle.loadPublic(b);
      this._verifiers.set(sha256Hex(raw).slice(0, 16), key);
    }
  }

  canSign() {
    return this._private !== null;
  }

  sign(claims) {
    if (this._private === null) throw new EngineError('no_signing_key', 'this engine can verify tokens but not issue them');
    const header = obj();
    header.typ = 'JWT';
    header.alg = 'EdDSA';
    header.kid = this.kid;
    const head = b64u(write(header, { ascii: true }));
    const body = b64u(write(claims, { ascii: true }));
    return `${head}.${body}.${b64u(bundle.signRaw(this._private, Buffer.from(`${head}.${body}`, 'ascii')))}`;
  }

  /** Signature, issuer, audience and shape. Time and revocation belong to the
   * engine, which owns the clock. Throws TokenError(reason). */
  verify(token, issuer) {
    let headB, bodyB, header, sig;
    try {
      [headB, bodyB] = split3(token);
      header = parse(decodeUtf8(b64uDec(headB)));
      sig = b64uDec(split3(token)[2]);
    } catch {
      throw new TokenError('token is not a JWT');
    }
    if (!isObj(header) || header.alg !== 'EdDSA') throw new TokenError('token algorithm is not EdDSA');
    const kid = header.kid;
    if (typeof kid !== 'string') throw new TokenError('token has no key id');
    const key = this._verifiers.get(kid);
    if (key === undefined) throw new TokenError('token was signed by an unknown key');
    let good = false;
    try {
      good = cryptoVerify(null, Buffer.from(`${headB}.${bodyB}`, 'utf8'), key, sig);
    } catch {
      good = false;
    }
    if (!good) throw new TokenError('token rejected: bad signature');
    let claims;
    try {
      claims = parse(decodeUtf8(b64uDec(bodyB)));
      const must = (ok) => { if (!ok) throw new Error('malformed'); };
      must(isObj(claims));
      for (const k of ['iss', 'aud', 'sub', 'jti']) must(typeof claims[k] === 'string');
      for (const k of ['iat', 'exp']) must(isInt(claims[k]));
      must(isObj(claims.act));
      if (has(claims, 'anc')) must(Array.isArray(claims.anc) && claims.anc.every(isStr));
      else claims.anc = [];
      must(!has(claims, 'role') || (typeof claims.role === 'string' && claims.role !== ''));
      must(!has(claims, 'grp') || (Array.isArray(claims.grp)
        && claims.grp.every((g) => isObj(g) && typeof g.type === 'string' && typeof g.id === 'string')));
      if (has(claims, 'lim')) {
        // ancestors' budgets: {token id: {currency: non-negative integer}}
        const lim = claims.lim;
        must(isObj(lim) && Object.keys(lim).every((a) => isObj(lim[a]) && Object.keys(lim[a]).every((c) => isInt(lim[a][c]) && lim[a][c] >= 0n)));
      }
      must(has(claims, 'cap'));
      claims.cap = Cap.fromJson(claims.cap).toJson();
    } catch {
      throw new TokenError('token rejected: malformed claims');
    }
    if (claims.aud !== AUDIENCE) throw new TokenError('token rejected: wrong audience');
    if (claims.iss !== issuer) throw new TokenError('token rejected: wrong issuer');
    return claims;
  }
}

// ---- OIDC ID tokens --------------------------------------------------------

class BadSignature extends Error {}

const HASH = { 256: 'sha256', 384: 'sha384', 512: 'sha512' };

/** A JWK member (base64url big-endian integer or octet string), re-encoded
 * strictly so the JWK import accepts exactly what the reference accepts. */
const member = (v) => b64u(b64uDec(v));
const unsigned = (v) => {
  // integers may carry leading zero octets; the reference reads them as numbers
  let b = b64uDec(v);
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  return b64u(b);
};
const fixed = (v, size) => {
  let b = b64uDec(v);
  let i = 0;
  while (i < b.length && b[i] === 0) i++;
  b = b.subarray(i);
  if (b.length > size) throw new Error('coordinate does not fit the curve');
  return b64u(Buffer.concat([Buffer.alloc(size - b.length), b]));
};

function verifyJws(alg, jwk, signingInput, sig) {
  let ok;
  if (['RS256', 'RS384', 'RS512'].includes(alg) && jwk.kty === 'RSA') {
    const key = createPublicKey({ key: { kty: 'RSA', n: unsigned(jwk.n), e: unsigned(jwk.e) }, format: 'jwk' });
    ok = cryptoVerify(HASH[alg.slice(2)], signingInput, { key, padding: constants.RSA_PKCS1_PADDING }, sig);
  } else if (['ES256', 'ES384'].includes(alg) && jwk.kty === 'EC') {
    const [crv, size] = alg === 'ES256' ? ['P-256', 32] : ['P-384', 48];
    if (sig.length !== 2 * size) throw new BadSignature();
    const key = createPublicKey({ key: { kty: 'EC', crv, x: fixed(jwk.x, size), y: fixed(jwk.y, size) }, format: 'jwk' });
    ok = cryptoVerify(HASH[alg.slice(2)], signingInput, { key, dsaEncoding: 'ieee-p1363' }, sig);
  } else if (alg === 'EdDSA' && jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
    const raw = b64uDec(jwk.x);
    if (raw.length !== 32) throw new Error('an Ed25519 public key is 32 bytes');
    ok = cryptoVerify(null, signingInput, bundle.publicFromRaw(raw), sig);
  } else {
    throw new Error('unsupported signing algorithm');
  }
  if (!ok) throw new BadSignature();
}

/** Verify an OIDC ID token against a static JWKS and return its claims.
 * `now` is a BigInt; every failure is EngineError `id_token_invalid`. */
export function verifyIdToken(idToken, jwks, issuer, audience, now) {
  const bad = (msg) => new EngineError('id_token_invalid', msg);
  let headB, bodyB, sigB, header, sig, alg;
  try {
    [headB, bodyB, sigB] = split3(idToken);
    header = parse(decodeUtf8(b64uDec(headB)));
    sig = b64uDec(sigB);
    if (!isObj(header) || !has(header, 'alg')) throw new Error('no alg');
    alg = header.alg;
  } catch {
    throw bad('not a JWT');
  }
  const keys = (Array.isArray(jwks.keys) ? jwks.keys : []).filter(isObj);
  const kid = has(header, 'kid') ? header.kid : null;
  let jwk = null;
  if (truthy(kid)) jwk = keys.find((k) => has(k, 'kid') && typeof k.kid === typeof kid && k.kid === kid) ?? null;
  else if (keys.length === 1) jwk = keys[0];
  if (jwk === null) throw bad('no matching key in the JWKS');
  try {
    verifyJws(alg, jwk, Buffer.from(`${headB}.${bodyB}`, 'utf8'), sig);
  } catch (e) {
    if (e instanceof BadSignature) throw bad('signature does not verify');
    throw bad(e.message || 'key or signature is malformed');
  }
  let claims;
  try {
    claims = parse(decodeUtf8(b64uDec(bodyB)));
    if (!isObj(claims)) throw new Error('not an object');
  } catch {
    throw bad('malformed claims');
  }
  const aud = has(claims, 'aud') ? claims.aud : null;
  if (!has(claims, 'iss') || claims.iss !== issuer) throw bad('wrong issuer');
  if (!(aud === audience || (Array.isArray(aud) && aud.includes(audience)))) throw bad('wrong audience');
  // OIDC Core 3.1.3.7: a token issued to another client is not ours even when
  // our client id is among its audiences (access tokens of other clients are)
  if (has(claims, 'azp') && claims.azp !== audience) throw bad('issued to another client (azp)');
  if (Array.isArray(aud) && aud.length > 1 && !has(claims, 'azp')) throw bad('several audiences and no azp claim');
  const exp = claims.exp;
  if (!isInt(exp)) throw bad('no exp claim');
  if (exp <= now) throw bad('ID token has expired');
  const nbf = claims.nbf;
  if (isInt(nbf) && nbf > now + 60n) throw bad('ID token is not valid yet');
  return claims;
}
