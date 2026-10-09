// The engine: one object that issues and exchanges capability tokens, answers
// authorization requests, applies field obligations and writes the audit log.
// A port of the Python reference (src/sf_smartdelegate/engine.py); the
// conformance vectors define its behaviour.
//
// Decision order for `authorize` / `filter` (first failure wins, default deny):
//   1. token: signature, issuer, expiry, revocation (own id and every ancestor)
//   2. catalog: the resource path must be known
//   3. tenant: token tenant must equal the resource tenant, when both exist
//   4. capability: the token's `cap` must cover the action and the resource
//   5. policy: Cedar, forbid overrides permit, an erroring forbid denies
//   6. obligations from the permits that decided: row filter, rate limit
//   7. budget: `context.spend` against every token in the delegation chain
//   8. human approval, last so nobody is asked to approve a doomed request
//   9. fields: capability deny lists, then policy per field (default deny)
//  10. strict mode (inputs): any denied field present in the data denies
import { randomBytes } from 'node:crypto';
import { closeSync, existsSync, linkSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { withOperations } from './api.mjs';
import * as audit from './audit.mjs';
import * as bundle from './bundle.mjs';
import { decodeUtf8, hashInternal, sha256Hex } from './canon.mjs';
import * as cedar from './cedar.mjs';
import { EngineError, ruleId } from './errors.mjs';
import * as fields from './fields.mjs';
import { cmpCodePoint, has, isInt, isObj, obj, parse, toInternal, toPlain, truthy } from './json.mjs';
import { DirLock, sleep } from './lock.mjs';
import { State, int as stateInt } from './state.mjs';
import * as tokens from './tokens.mjs';
import { Cap } from './tokens.mjs';

export const VERSION = '0.3.0';
export const IMPLEMENTATION = 'node';

const COLUMN = /^[A-Za-z0-9_]+$/;

/** Build an object of the internal model, keeping the order of `src`. */
const O = (src) => Object.assign(obj(), src);

class Deny extends Error {
  constructor(code, detail) {
    super(detail);
    this.code = code;
    this.detail = detail;
    this.claims = null;
  }
}

class Principal {
  constructor(user, chain, tenant, task, jti, anc, cap, exp, role = null, groups = null) {
    this.user = user;
    this.chain = chain;
    this.tenant = tenant ?? null;
    this.task = task ?? null;
    this.jti = jti;
    this.anc = anc;
    this.cap = cap;
    this.exp = exp;
    /** the role the human is acting in for this task, or null */
    this.role = role ?? null;
    /** live group membership [{type, id}] that replaces entities.json for
     * this user, or null to use entities.json */
    this.groups = groups ?? null;
    /** budgets of ancestor tokens carried by the token: {token id: {currency: amount}} */
    this.lim = obj();
  }

  get leaf() {
    return this.chain.length ? this.chain[this.chain.length - 1] : '';
  }

  toJson() {
    return O({ user: this.user, agent: this.leaf, chain: [...this.chain], tenant: this.tenant, task: this.task, role: this.role, token_id: this.jti });
  }

  static of(claims) {
    const p = Principal.from(claims);
    if (has(claims, 'lim') && truthy(claims.lim)) p.lim = claims.lim;
    return p;
  }

  static from(claims) {
    return new Principal(tokens.userOf(claims), tokens.chainOf(claims), has(claims, 'tnt') ? claims.tnt : null,
      has(claims, 'task') ? claims.task : null, claims.jti, [...(claims.anc ?? [])], Cap.fromJson(claims.cap), claims.exp,
      has(claims, 'role') ? claims.role : null, has(claims, 'grp') ? claims.grp : null);
  }
}

class Outcome {
  constructor() {
    this.allow = false;
    this.reason = '';
    this.detail = '';
    this.policies = [];
    this.principal = null;
    this.mask = null;
    this.fieldAllow = [];
    this.fieldDeny = [];
    this.fieldRedact = [];
    this.rowFilter = [];
    this.rate = [];            // [key, limit, window]
    this.rateLimit = null;
    this.approval = null;
    this.approved = null;      // [id, by]
    this.spend = null;         // [currency, amount]
    this.errors = [];
    this.trace = [];
  }
}

function s(v, key) {
  const x = isObj(v) ? v[key] : undefined;
  return typeof x === 'string' && x !== '' ? x : null;
}

function req(v, key) {
  const x = s(v, key);
  if (x === null) throw new EngineError('invalid_input', `'${key}' is required`);
  return x;
}

function intOf(v, key, fallback) {
  const x = v[key];
  return isInt(x) ? x : fallback;
}

function entity(type, id) {
  if (!cedar.validType(type)) throw new EngineError('invalid_input', `'${type}' is not a valid entity type`);
  return new cedar.Entity(type, id);
}

/** -> [value, found] */
function lookup(root, dotted) {
  let cur = root;
  for (const part of dotted.split('.')) {
    if (!isObj(cur) || !has(cur, part)) return [null, false];
    cur = cur[part];
  }
  return [cur, true];
}

/** `column == context.key`, `column == "literal"`, `column == 42`, joined by `&&`. */
function parseRowFilter(expr, ctx) {
  if (typeof expr !== 'string') throw new TypeError('row_filter annotation is not a string');
  const out = [];
  for (const clause of expr.split('&&')) {
    const at = clause.indexOf('==');
    const parts = at < 0 ? [clause.trim()] : [clause.slice(0, at).trim(), clause.slice(at + 2).trim()];
    if (parts.length !== 2 || !COLUMN.test(parts[0])) throw new Deny('policy_error', `row_filter clause '${clause.trim()}' is not \`column == value\``);
    const rhs = parts[1];
    let value;
    if (rhs.startsWith('context.')) {
      const [v, found] = lookup(ctx, rhs.slice(8));
      if (!found || v === null || typeof v === 'object' || typeof v === 'number') {
        throw new Deny('obligation_unresolved', `row filter needs ${rhs}, which the request did not supply`);
      }
      value = v;
    } else if (rhs.length >= 2 && rhs[0] === '"' && rhs[rhs.length - 1] === '"') {
      value = rhs.slice(1, -1);
    } else if (/^-?[0-9]+$/.test(rhs)) {
      value = BigInt(rhs);
    } else {
      throw new Deny('policy_error', `row_filter value '${rhs}' is not context.<key>, a quoted string or an integer`);
    }
    out.push(O({ column: parts[0], op: 'eq', value }));
  }
  return out;
}

/** -> [count, seconds] or null */
function parseRate(expr) {
  if (typeof expr !== 'string') throw new TypeError('rate_limit annotation is not a string');
  const m = /^\s*([0-9]+)\s*\/\s*([0-9]+)\s*$/.exec(expr);
  if (!m || BigInt(m[2]) <= 0n) return null;
  return [BigInt(m[1]), BigInt(m[2])];
}

function errorResult(e) {
  let err = e;
  if (!(err instanceof EngineError)) {
    if (err instanceof RangeError && /call stack|nested too deeply/i.test(err.message)) {
      err = new EngineError('invalid_input', 'the request is nested too deeply');
    } else if (err && typeof err.code === 'string' && typeof err.syscall === 'string') {
      err = new EngineError('state_io', err.message);
    } else {
      // a bug must surface as a refusal, never as an allow or a crash
      err = new EngineError('internal', `${err?.name ?? 'Error'}: ${err?.message ?? err}`);
    }
  }
  return O({ ok: false, error: O({ code: err.code, message: err.detail, rule: ruleId(err.code) }) });
}

/** The signing key file. An empty file means another process is still
 * writing it: wait for the content, then fail with state_io. An empty key is
 * never read as "no key", which would silently turn an issuer into a
 * verify-only engine. */
function readKey(kp, waitMs) {
  const deadline = Date.now() + waitMs;
  for (;;) {
    let text;
    try {
      text = decodeUtf8(readFileSync(kp)).trim();
    } catch (e) {
      throw new EngineError('state_io', `${kp}: ${e.message}`);
    }
    if (text !== '') return text;
    if (Date.now() > deadline) throw new EngineError('state_io', `${kp} is empty`);
    sleep(50);
  }
}

/** Read the signing key of a state directory, or create it. Two engines can
 * start on an empty state directory at once (and the other one may be another
 * port, which does not take this port's lock): the key is written to a private
 * temporary file and hard-linked into place, so the link either creates the
 * key or fails because someone else already did, and nobody reads half a key. */
function signingKey(stateDir, waitMs) {
  const kp = join(stateDir, 'signing_key.pk8.b64');
  if (existsSync(kp)) return readKey(kp, waitMs);
  const [sk, pk] = bundle.keygen();
  const pub = join(stateDir, 'signing_key.pub.b64');
  const tmp = join(stateDir, `.signing_key.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
  const create = (path) => {
    const fd = openSync(path, 'wx', 0o600);
    try {
      writeSync(fd, sk);
    } finally {
      closeSync(fd);
    }
  };
  try {
    create(tmp);
    try {
      linkSync(tmp, kp);
      writeFileSync(pub, pk, 'utf8');
      return sk;
    } catch (e) {
      if (e.code === 'EEXIST') return readKey(kp, waitMs);
      // a file system without hard links: fall back to exclusive create
      try {
        create(kp);
        writeFileSync(pub, pk, 'utf8');
        return sk;
      } catch (e2) {
        if (e2.code === 'EEXIST') return readKey(kp, waitMs);
        throw e2;
      }
    }
  } catch (e) {
    if (e instanceof EngineError) throw e;
    throw new EngineError('state_io', `${kp}: ${e.message}`);
  } finally {
    try {
      unlinkSync(tmp);
    } catch {
      // never created, or already gone
    }
  }
}

/** The identity provider's keys from a file. Throws invalid_config. */
function readJwks(file, strict) {
  let jwks;
  try {
    jwks = parse(decodeUtf8(readFileSync(file)));
  } catch (e) {
    throw new EngineError('invalid_config', `jwks_file: ${e.message}`);
  }
  if (!isObj(jwks) || (strict && !Array.isArray(jwks.keys))) throw new EngineError('invalid_config', 'jwks_file: not a JWKS object');
  return jwks;
}

class EngineCore {
  /** config: {bundle_dir, state_dir, issuer, mode, ...}; see spec/API.md.
   * Throws EngineError when the configuration or the bundle is not usable.
   *
   * Calls are synchronous. Engines in different Node.js processes that share
   * a state directory are serialised by a lock file in it (lib/lock.mjs). */
  constructor(config) {
    let c;
    try {
      c = toInternal(config);
    } catch (e) {
      throw new EngineError('invalid_input', `config is not JSON: ${e.message}`);
    }
    if (!isObj(c)) throw new EngineError('invalid_input', 'config must be an object');
    this.bundleDir = req(c, 'bundle_dir');
    this.stateDir = s(c, 'state_dir');
    this.issuer = s(c, 'issuer') ?? 'smartdelegate://local';
    const mode = s(c, 'mode') ?? 'enforce';
    if (mode !== 'enforce' && mode !== 'shadow') throw new EngineError('invalid_config', "mode must be 'enforce' or 'shadow'");
    this.shadow = mode === 'shadow';
    this.trustCallerChain = c.trust_caller_chain === true;
    this.allowTestClock = c.allow_test_clock === true;
    this.bundlePublicKey = s(c, 'bundle_public_key');
    this.maxTtl = intOf(c, 'max_ttl', 3600n);
    this.defaultTtl = intOf(c, 'default_ttl', 900n);
    this.maxDepth = intOf(c, 'max_depth', 4n);
    this.approvalTtl = intOf(c, 'approval_ttl', 900n);
    this.requireRole = c.require_role === true;
    this.idp = null;
    const idp = c.idp;
    if (isObj(idp)) {
      let jwks = idp.jwks, jwksFile = null;
      if (!isObj(jwks)) {
        jwksFile = req(idp, 'jwks_file');
        jwks = readJwks(jwksFile, false);
      }
      const gmap = has(idp, 'group_map') ? idp.group_map : null;
      if (gmap !== null && !(isObj(gmap) && Object.keys(gmap).every((k) => typeof gmap[k] === 'string'))) {
        throw new EngineError('invalid_config', 'idp.group_map must map a claim value to a group id');
      }
      const gtype = s(idp, 'group_type') ?? 'Group';
      if (!cedar.validType(gtype)) throw new EngineError('invalid_config', 'idp.group_type is not a valid entity type');
      this.idp = { issuer: req(idp, 'issuer'), audience: req(idp, 'audience'), jwks, jwksFile, userClaim: s(idp, 'user_claim') ?? 'sub',
        groupsClaim: s(idp, 'groups_claim'), groupType: gtype, groupMap: gmap };
    }

    this.bundle = new bundle.Bundle(this.bundleDir, this.bundlePublicKey);
    this._lock = null;
    if (this.stateDir) {
      try {
        mkdirSync(this.stateDir, { recursive: true });
      } catch (e) {
        throw new EngineError('state_io', `${this.stateDir}: ${e.message}`);
      }
      const opts = {};
      if (isInt(c.lock_timeout_ms)) opts.timeoutMs = Number(c.lock_timeout_ms);
      if (isInt(c.lock_stale_ms)) opts.staleMs = Number(c.lock_stale_ms);
      this._lock = new DirLock(this.stateDir, opts);
    }

    this._rate = new Map();
    this._counter = 0;
    // Before taking the lock: creating the key is atomic by itself, and
    // waiting for another process to finish writing it must not hold up
    // engines that are already running on this directory.
    let priv = null;
    if (c.verify_only === true) {
      priv = null;
    } else if (s(c, 'signing_key')) {
      priv = c.signing_key;
    } else if (this.stateDir) {
      priv = signingKey(this.stateDir, isInt(c.key_wait_ms) ? Number(c.key_wait_ms) : 30000);
    } else {
      priv = bundle.keygen()[0];
    }
    this._acquire();
    try {
      const trusted = (Array.isArray(c.trusted_keys) ? c.trusted_keys : []).filter((k) => typeof k === 'string');
      this.keys = new tokens.Keys(priv, trusted);
      this.state = new State(this.stateDir);
      this.audit = this.stateDir && c.audit !== false ? new audit.AuditLog(join(this.stateDir, 'audit.jsonl')) : null;
    } catch (e) {
      this._release(true);
      this._lock = null;
      if (e instanceof EngineError) throw e;
      throw new EngineError(e && typeof e.syscall === 'string' ? 'state_io' : 'internal', e?.message ?? String(e));
    }
    this._release();
  }

  // -- plumbing --------------------------------------------------------------
  _acquire() {
    if (this._lock) this._lock.acquire();
  }

  _release(quiet = false) {
    if (!this._lock) return;
    try {
      this._lock.release();
    } catch (e) {
      if (!quiet) throw e;
    }
  }

  /** Release what the engine holds. Idempotent. This port holds nothing
   * between calls (the lock is a file that exists only during a call), so
   * this only makes sure no lock of ours is left behind. */
  close() {
    this._release(true);
  }

  /** JSON in, JSON out, with ordinary JavaScript values. Never throws; errors
   * come back as {ok: false, error: {code, message, rule}}.
   *
   * Integers: integer-valued Numbers and BigInts in `payload` are integers.
   * In the result an integer is a Number when that is exact and a BigInt
   * otherwise (beyond 2^53 - 1). Use `callExact` to keep every integer exact
   * and distinct from floats. */
  call(op, payload) {
    let p;
    try {
      p = toInternal(payload);
    } catch (e) {
      return toPlain(errorResult(e instanceof RangeError ? e : new EngineError('invalid_input', `the request is not JSON: ${e?.message ?? e}`)));
    }
    return toPlain(this.callExact(op, p));
  }

  /** `call` in the exact JSON model of lib/json.mjs: integers are BigInt
   * (always), non-integer numbers are Number, objects have a null prototype.
   * This is what `parse` produces and `write` prints. Never throws. */
  callExact(op, payload) {
    try {
      this._acquire();
      try {
        if (!isObj(payload)) throw new EngineError('invalid_input', 'the request body must be a JSON object');
        this.state.refresh();
        const out = this._dispatch(op, payload);
        out.ok = true;
        return out;
      } finally {
        this._release();
      }
    } catch (e) {
      return errorResult(e);
    }
  }

  _dispatch(op, i) {
    switch (op) {
      case 'authorize': return this._decide(i, false);
      case 'filter': return this._decide(i, true);
      case 'explain': {
        const j = O(i);
        j.explain = true;
        j.dry_run = true;
        return this._decide(j, has(i, 'data'));
      }
      case 'issue_token': return this._issueToken(i);
      case 'exchange_token': return this._exchangeToken(i);
      case 'inspect_token': return this._inspectToken(i);
      case 'apply_obligations': return this._applyObligations(i);
      case 'revoke': return this._revoke(i);
      case 'approve': return this._approve(i);
      case 'approvals': return O({ pending: this.state.data.pending, granted: this.state.data.approvals });
      case 'audit_verify': {
        if (this.audit === null) throw new EngineError('no_audit', 'this engine has no audit log (no state_dir, or audit is off)');
        if (!existsSync(this.audit.path)) return O({ records: 0n, head: audit.GENESIS });
        const v = audit.verify(this.audit.path);
        return O({ ok: true, records: v.records, head: v.head });
      }
      case 'audit_tail':
        if (this.audit === null) throw new EngineError('no_audit', 'this engine has no audit log');
        return O({ records: audit.tail(this.audit.path, intOf(i, 'n', 20n)) });
      case 'info': return this.infoDict();
      case 'reload': {
        // a bundle that fails to load leaves the old one in force
        const next = new bundle.Bundle(this.bundleDir, this.bundlePublicKey);
        // the provider's signing keys are re-read too, so a key rotation needs
        // a reload, not a restart; a file that fails to load leaves the old
        // keys (and the old bundle) in force
        if (this.idp && this.idp.jwksFile) this.idp.jwks = readJwks(this.idp.jwksFile, true);
        this.bundle = next;
        this._audit(O({ event: 'bundle_reloaded', policy_version: this.bundle.version }), this._clock());
        return this.infoDict();
      }
      default:
        throw new EngineError('unknown_op', `no operation named '${op}'`);
    }
  }

  infoDict() {
    return O({ version: VERSION, implementation: IMPLEMENTATION, policy_version: this.bundle.version,
      bundle_signed_by: this.bundle.signedBy, policies: BigInt(this.bundle.policies.size),
      resources: [...this.bundle.catalog.keys()].sort(cmpCodePoint), roles: [...this.bundle.roles.keys()].sort(cmpCodePoint),
      mode: this.shadow ? 'shadow' : 'enforce', issuer: this.issuer, key_id: this.keys.kid, public_key: this.keys.publicB64,
      can_issue: this.keys.canSign(), oidc: this.idp ? this.idp.issuer : null });
  }

  _clock() {
    return BigInt(Math.floor(Date.now() / 1000));
  }

  _now(i) {
    return this.allowTestClock && isInt(i.now) ? i.now : this._clock();
  }

  /** Fail closed: when the decision cannot be recorded, the operation fails
   * and the caller gets an error instead of an allow. */
  _audit(record, ts) {
    if (this.audit !== null) {
      try {
        this.audit.append(record, ts);
      } catch (e) {
        if (!(e instanceof EngineError)) throw e;
        throw new EngineError('audit_io', `the decision could not be recorded, so it is refused: ${e.detail}`);
      }
    }
  }

  // -- tokens ----------------------------------------------------------------
  /** Throws Deny; `claims` is attached when the signature was good, so an
   * expired or revoked token's denial can still be attributed. */
  _verifyToken(token, now) {
    let claims;
    try {
      claims = this.keys.verify(token, this.issuer);
    } catch (e) {
      if (!(e instanceof tokens.TokenError)) throw e;
      throw new Deny('token_invalid', e.message);
    }
    if (!tokens.chainOf(claims).length) throw new Deny('token_invalid', 'the token names no agent');
    let d = null;
    if (claims.exp <= now) d = new Deny('token_expired', 'the capability token has expired');
    else if (claims.iat > now + 60n) d = new Deny('token_invalid', 'the capability token is dated in the future');
    else {
      for (const tid of [...claims.anc, claims.jti]) {
        if (has(this.state.data.revoked, tid)) {
          d = new Deny('token_revoked', `token ${tid} in the delegation chain was revoked`);
          break;
        }
      }
      // offboarding: every token of this user issued up to the cut-off is dead
      const users = this.state.data.revoked_users, user = tokens.userOf(claims);
      const cutoff = has(users, user) ? users[user] : null;
      if (d === null && isInt(cutoff) && claims.iat <= cutoff) {
        d = new Deny('token_revoked', 'every token issued for this user up to the cut-off was revoked');
      }
    }
    if (d !== null) {
      d.claims = claims;
      throw d;
    }
    return claims;
  }

  _iamContext(p) {
    return O({
      user_attrs: this.bundle.attrs.get(`User::${p.user}`) ?? obj(),
      user: O({ __entity: O({ type: 'User', id: p.user }) }),
      user_id: p.user,
      chain: [...p.chain],
      depth: BigInt(p.chain.length),
      root_agent: O({ __entity: O({ type: 'Agent', id: p.chain.length ? p.chain[0] : '' }) }),
      tenant: truthy(p.tenant) ? p.tenant : '',
      task: truthy(p.task) ? p.task : '',
      role: truthy(p.role) ? p.role : '',
    });
  }

  /** The entity store this principal is judged against. A token that carries
   * live group membership replaces what entities.json says about that user;
   * everything else is unchanged. */
  _storeFor(p) {
    if (p.groups === null) return this.bundle.store;
    return this.bundle.store.withParents(new cedar.Entity('User', p.user), p.groups.map((g) => new cedar.Entity(g.type, g.id)));
  }

  /** Normalise group membership supplied at issuance: names or {type, id}.
   * Groups that entities.json does not define are dropped; the result is
   * sorted and free of duplicates, so every port writes the same claim. */
  _groups(raw, defaultType, mapping) {
    const bad = () => new EngineError('invalid_input', 'groups must be a list of group names or {type, id}');
    if (typeof raw === 'string') raw = [raw];
    if (!Array.isArray(raw)) throw bad();
    const seen = new Map();
    for (let g of raw) {
      let t, n;
      if (typeof g === 'string') {
        if (mapping !== null) {
          if (!has(mapping, g)) continue;
          g = mapping[g];
        }
        t = defaultType;
        n = g;
      } else if (isObj(g) && typeof g.type === 'string' && typeof g.id === 'string') {
        t = g.type;
        n = g.id;
      } else throw bad();
      if (cedar.validType(t)) {
        const e = new cedar.Entity(t, n);
        if (this.bundle.store.has(e)) seen.set(e.k, e);
      }
    }
    return [...seen.values()].sort((a, b) => cmpCodePoint(a.type, b.type) || cmpCodePoint(a.id, b.id)).map((e) => O({ type: e.type, id: e.id }));
  }

  /** The human lends the agent one of their roles for this task. Returns the
   * capability and lifetime the token gets; throws when the human does not
   * hold the role or asks for more than the role allows. */
  _applyRole(name, p, cap, ttl) {
    const role = this.bundle.roles.get(name);
    if (role === undefined) throw new EngineError('unknown_role', `roles.json defines no role named '${name}'`);
    const user = new cedar.Entity('User', p.user);
    const held = this._storeFor(p).ancestors(user);
    if (!role.members.some((m) => m.k === user.k || held.has(m.k))) {
      throw new EngineError('role_not_held', `user '${p.user}' does not hold the role '${name}'`);
    }
    if (role.agents !== null && !role.agents.some((a) => tokens.matches(a, p.leaf))) {
      throw new EngineError('role_exceeded', `agent '${p.leaf}' may not be started in the role '${name}'`);
    }
    if (role.tasks !== null && !(truthy(p.task) && role.tasks.some((t) => tokens.matches(t, p.task)))) {
      throw new EngineError('role_exceeded', `the role '${name}' covers only tasks matching: ${role.tasks.join(', ')}`);
    }
    if (cap === null) {
      cap = Cap.fromJson(role.cap.toJson());
    } else {
      // what the role never sees, the token never sees
      cap.denyLabels = [...new Set([...cap.denyLabels, ...role.cap.denyLabels])].sort(cmpCodePoint);
      cap.denyFields = [...new Set([...cap.denyFields, ...role.cap.denyFields])].sort(cmpCodePoint);
      try {
        cap.checkNarrowerThan(role.cap);
      } catch (e) {
        if (!(e instanceof EngineError)) throw e;
        throw new EngineError('role_exceeded', `more than the role '${name}' allows: ${e.detail}`);
      }
    }
    return [cap, role.maxTtl !== null && ttl > role.maxTtl ? role.maxTtl : ttl];
  }

  _evaluate(principal, action, resource, ctx, store) {
    const r = cedar.isAuthorized(this.bundle.policies, new cedar.Env(principal, entity('Action', action), resource, ctx, store));
    const errors = [];
    let forbidError = false;
    for (const [pid, msg] of r.errors) {
      const isForbid = !this.bundle.policies.get(pid).permit;
      forbidError = forbidError || isForbid;
      errors.push(O({ policy: pid, effect: isForbid ? 'forbid' : 'permit', error: msg }));
    }
    return { allow: r.decision === 'allow' && !forbidError, policies: r.reasons, errors, forbidError };
  }

  /** Is `delegator` allowed to hand `cap` to `agent`? Governed by the same
   * policies as everything else: action "delegate" on the Agent. */
  _checkDelegation(delegator, agent, p, cap, ttl) {
    const agentUid = entity('Agent', agent);
    if (!this.bundle.store.has(agentUid)) throw new EngineError('unknown_agent', `agent '${agent}' is not registered in entities.json`);
    let ctx;
    try {
      ctx = cedar.fromJson(O({ iam: this._iamContext(p),
        requested: O({ actions: cap.actions, resources: cap.resources, ttl, budget: cap.budget }) }));
    } catch (e) {
      if (!(e instanceof cedar.ValueError)) throw e;
      throw new EngineError('invalid_input', e.message);
    }
    const v = this._evaluate(delegator, 'delegate', agentUid, ctx, this._storeFor(p));
    if (!v.allow) {
      const why = v.policies.length ? 'forbidden by ' + v.policies.join(', ') : 'no policy permits it';
      throw new EngineError('delegation_denied', `${delegator} may not delegate to agent '${agent}': ${why}`);
    }
  }

  static _parseCap(i) {
    if (!has(i, 'cap') || i.cap === null) return null;
    const cap = Cap.fromJson(i.cap);
    cap.validate();
    return cap;
  }

  _mint(claims, event, now) {
    claims.jti = randomBytes(12).toString('hex');
    const token = this.keys.sign(claims);
    const cap = claims.cap;
    if (truthy(cap.budget)) {
      this.state.data.limits[claims.jti] = O(cap.budget);
      this.state.prune(now);
      this.state.save();
    }
    const user = tokens.userOf(claims), chain = tokens.chainOf(claims);
    const opt = (k) => (has(claims, k) ? claims[k] : null);
    this._audit(O({ event, token_id: claims.jti, user, chain, tenant: opt('tnt'), task: opt('task'), role: opt('role'),
      ancestors: claims.anc, exp: claims.exp, cap, policy_version: this.bundle.version }), now);
    return O({ token, token_type: 'Bearer', issued_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      token_id: claims.jti, expires_at: claims.exp, expires_in: claims.exp - now,
      user, chain, role: opt('role'), task: opt('task'), cap });
  }

  _ttl(i) {
    let t = intOf(i, 'ttl', this.defaultTtl);
    if (t > this.maxTtl) t = this.maxTtl;
    return t < 1n ? 1n : t;
  }

  _issueToken(i) {
    const now = this._now(i);
    const idt = s(i, 'id_token');
    let user, groups = null;
    if (idt) {
      if (!this.idp) throw new EngineError('no_idp', 'no OIDC provider is configured');
      const claims = tokens.verifyIdToken(idt, this.idp.jwks, this.idp.issuer, this.idp.audience, now);
      user = has(claims, this.idp.userClaim) ? claims[this.idp.userClaim] : null;
      if (typeof user !== 'string' || user === '') throw new EngineError('id_token_invalid', `ID token has no '${this.idp.userClaim}' claim`);
      if (s(i, 'user') && i.user !== user) throw new EngineError('id_token_invalid', 'the ID token belongs to a different user');
      // Offboarding also covers sign-ins that happened before it: an ID token
      // issued at or before the user's revoke cut-off cannot start a new
      // agent, however long the provider says it lives.
      const users = this.state.data.revoked_users;
      const cutoff = has(users, user) ? users[user] : null;
      if (isInt(cutoff) && !(isInt(claims.iat) && claims.iat > cutoff)) {
        throw new EngineError('id_token_invalid', 'the ID token was issued before this user was revoked; sign in again');
      }
      if (this.idp.groupsClaim) {
        // the identity provider is the authority on what this human is a
        // member of right now; a missing claim means "of nothing". A dotted
        // name reads a nested claim (Keycloak: realm_access.roles).
        const name = this.idp.groupsClaim;
        let raw = has(claims, name) ? claims[name] : null;
        if (raw === null && name.includes('.')) {
          const [v, found] = lookup(claims, name);
          raw = found ? v : null;
        }
        try {
          groups = this._groups(raw === null ? [] : raw, this.idp.groupType, this.idp.groupMap);
        } catch (e) {
          if (!(e instanceof EngineError)) throw e;
          throw new EngineError('id_token_invalid', `the '${this.idp.groupsClaim}' claim is not a list of group names`);
        }
      }
    } else {
      user = req(i, 'user');
      groups = has(i, 'groups') && i.groups !== null ? this._groups(i.groups, 'Group', null) : null;
    }
    const agent = req(i, 'agent');
    let cap = EngineCore._parseCap(i);
    const role = s(i, 'role');
    if (role === null && this.requireRole) throw new EngineError('role_required', 'this engine issues tokens only for a named role');
    if (cap === null && role === null) throw new EngineError('invalid_cap', "'cap' is required: a root token must state what it may do");
    let ttl = this._ttl(i);
    const p = new Principal(user, [agent], s(i, 'tenant'), s(i, 'task'), null, [], cap, now + ttl, role, groups);
    if (role !== null) {
      [cap, ttl] = this._applyRole(role, p, cap, ttl);
      p.cap = cap;
      p.exp = now + ttl;
    }
    this._checkDelegation(entity('User', user), agent, p, cap, ttl);
    const claims = O({ iss: this.issuer, aud: tokens.AUDIENCE, sub: `user:${user}`, iat: now, exp: now + ttl, jti: '',
      act: tokens.actFor(p.chain), anc: [], cap: cap.toJson() });
    if (p.tenant) claims.tnt = p.tenant;
    if (p.task) claims.task = p.task;
    if (role !== null) claims.role = role;
    if (groups !== null) claims.grp = groups;
    return this._mint(claims, 'token_issued', now);
  }

  _exchangeToken(i) {
    const now = this._now(i);
    let parent;
    try {
      parent = this._verifyToken(req(i, 'subject_token'), now);
    } catch (d) {
      if (!(d instanceof Deny)) throw d;
      throw new EngineError(d.code, d.detail);
    }
    const pp = Principal.of(parent);
    const actor = req(i, 'actor');
    if (BigInt(pp.chain.length) >= this.maxDepth) throw new EngineError('depth_exceeded', `delegation chains are limited to ${this.maxDepth} agents`);
    const cap = EngineCore._parseCap(i) ?? pp.cap;
    cap.checkNarrowerThan(pp.cap);
    const wanted = now + this._ttl(i);
    const exp = wanted < parent.exp ? wanted : parent.exp;
    if (s(i, 'task') && truthy(pp.task) && i.task !== pp.task) throw new EngineError('widening', 'a sub-agent token cannot change the task it was issued for');
    if (s(i, 'role') && i.role !== pp.role) throw new EngineError('widening', 'a sub-agent token cannot change the role it was issued for');
    this._checkDelegation(entity('Agent', pp.leaf), actor, pp, cap, exp - now);
    const chain = [...pp.chain, actor];
    const claims = O({ iss: this.issuer, aud: tokens.AUDIENCE, sub: parent.sub, iat: now, exp, jti: '',
      act: tokens.actFor(chain), anc: [...parent.anc, parent.jti], cap: cap.toJson() });
    if (has(parent, 'tnt') && truthy(parent.tnt)) claims.tnt = parent.tnt;
    const task = truthy(pp.task) ? pp.task : s(i, 'task');
    if (truthy(task)) claims.task = task;
    if (pp.role !== null) claims.role = pp.role;
    if (pp.groups !== null) claims.grp = pp.groups;
    // every ancestor's budget travels with the token (see the budget check)
    const lim = O(pp.lim);
    if (truthy(pp.cap.budget)) lim[parent.jti] = O(pp.cap.budget);
    if (truthy(lim)) claims.lim = lim;
    return this._mint(claims, 'token_exchanged', now);
  }

  _inspectToken(i) {
    const now = this._now(i);
    let c;
    try {
      c = this._verifyToken(req(i, 'token'), now);
    } catch (d) {
      if (!(d instanceof Deny)) throw d;
      return O({ valid: false, reason: d.code, detail: d.detail });
    }
    return O({ valid: true, claims: c, chain: tokens.chainOf(c), user: tokens.userOf(c), expires_in: c.exp - now });
  }

  _revoke(i) {
    const now = this._now(i);
    if (has(i, 'user')) {
      // Offboarding, or a human who lost a role: one call ends every token
      // already issued for them, sub-agents included. New tokens are a matter
      // of role membership, not of this list.
      const user = i.user;
      if (typeof user !== 'string' || user === '') throw new EngineError('invalid_input', "'user' must be a non-empty string");
      // the cut-off only ever moves forward: a clock that steps back (or a
      // second machine with a slower clock) must not revive dead tokens
      const users = this.state.data.revoked_users;
      const prev = has(users, user) ? users[user] : null;
      const cutoff = isInt(prev) && prev > now ? prev : now;
      users[user] = cutoff;
      this.state.save();
      this._audit(O({ event: 'user_revoked', user, issued_up_to: cutoff, by: s(i, 'by') }), now);
      return O({ revoked_user: user, issued_up_to: cutoff });
    }
    const t = s(i, 'token');
    let tid, exp;
    if (t) {
      let c;
      try {
        c = this.keys.verify(t, this.issuer);
      } catch (e) {
        if (!(e instanceof tokens.TokenError)) throw e;
        throw new EngineError('token_invalid', e.message);
      }
      tid = c.jti;
      exp = c.exp;
    } else {
      tid = req(i, 'token_id');
      exp = now + this.maxTtl;
    }
    this.state.data.revoked[tid] = exp;
    this.state.save();
    this._audit(O({ event: 'token_revoked', token_id: tid, by: s(i, 'by') }), now);
    return O({ revoked: tid });
  }

  _approve(i) {
    const now = this._now(i);
    const aid = req(i, 'approval_id'), by = req(i, 'by');
    const pending = has(this.state.data.pending, aid) ? this.state.data.pending[aid] : null;
    if (pending === null) throw new EngineError('unknown_approval', 'no pending request with that approval id');
    if (!isObj(pending)) throw new EngineError('state_io', 'state.json is corrupt: a pending approval is not an object');
    for (const k of ['user', 'label', 'agent', 'action', 'resource']) {
      if (!has(pending, k)) throw new EngineError('state_io', `state.json is corrupt: a pending approval has no '${k}'`);
    }
    if (pending.user === by) throw new EngineError('self_approval', "the user an agent acts for cannot approve that agent's request");
    // who may approve is itself policy: action "approve" on the agent
    const ctx = cedar.fromJson(O({ label: pending.label, for_user: pending.user, action: pending.action }));
    const v = this._evaluate(entity('User', by), 'approve', entity('Agent', pending.agent), ctx, this.bundle.store);
    if (!v.allow) throw new EngineError('approval_denied', `no policy lets '${by}' approve this request`);
    delete this.state.data.pending[aid];
    const exp = now + intOf(i, 'ttl', this.approvalTtl);
    this.state.data.approvals[aid] = O({ by, exp });
    this.state.save();
    this._audit(O({ event: 'approval_granted', approval_id: aid, by, label: pending.label, for_user: pending.user,
      agent: pending.agent, action: pending.action, resource: pending.resource }), now);
    return O({ approved: aid, by, expires_at: exp });
  }

  /** Apply the obligations of an earlier decision to data that arrived later.
   * Pure: it authorises nothing by itself. */
  _applyObligations(i) {
    const ob = i.obligations;
    if (!isObj(ob)) throw new EngineError('invalid_input', "'obligations' from a decision is required");
    if (!has(i, 'data')) throw new EngineError('invalid_input', "'data' is required");
    const f = ob.fields;
    if (!isObj(f)) throw new EngineError('invalid_input', 'obligations.fields is missing; only an allow decision carries a field mask');
    const names = (k) => (Array.isArray(f[k]) ? f[k].filter((x) => typeof x === 'string') : []);
    const status = new Map();
    for (const n of names('allow')) status.set(n, fields.ALLOW);
    for (const n of names('deny')) status.set(n, fields.DENY);
    for (const n of names('redact')) status.set(n, fields.REDACT);
    const rf = Array.isArray(ob.row_filter) ? ob.row_filter.filter(isObj) : [];
    const [data, masked, dropped] = fields.apply(i.data, new fields.Mask(status), rf);
    const did = s(i, 'decision_id');
    if (did) this._audit(O({ event: 'obligations_applied', decision_id: did, masked, rows_dropped: BigInt(dropped) }), this._now(i));
    return O({ data, masked, rows_dropped: BigInt(dropped) });
  }

  // -- decisions ---------------------------------------------------------------
  _evaluateRequest(i, now, dryRun) {
    const o = new Outcome();
    try {
      this._steps(o, i, now, dryRun);
    } catch (d) {
      if (!(d instanceof Deny)) throw d;
      o.reason = d.code;
      o.detail = d.detail;
      o.trace.push(O({ check: d.code, result: 'deny', detail: d.detail }));
    }
    return o;
  }

  _steps(o, i, now, dryRun) {
    const passed = (check, msg) => o.trace.push(O({ check, result: 'pass', detail: msg }));

    const action = req(i, 'action');
    const res = i.resource;
    if (!isObj(res)) throw new EngineError('invalid_input', "'resource' must be an object with a 'path'");
    const path = req(res, 'path');
    const rid = s(res, 'id') ?? 'any';
    let callerCtx = has(i, 'context') ? i.context : null;
    if (callerCtx === null) callerCtx = obj();
    if (!isObj(callerCtx)) throw new EngineError('invalid_context', "'context' must be an object");
    if (has(callerCtx, 'iam')) throw new EngineError('invalid_context', "'iam' is reserved: identity comes from the token, not from the caller");

    // 1. principal
    const token = s(i, 'token');
    const chain = has(i, 'chain') ? i.chain : null;
    let principal;
    if (token) {
      try {
        principal = Principal.of(this._verifyToken(token, now));
      } catch (d) {
        if (d instanceof Deny && d.claims) o.principal = Principal.of(d.claims);
        throw d;
      }
    } else if (chain !== null && this.trustCallerChain && isObj(chain)) {
      const agents = Array.isArray(chain.agents) ? chain.agents.filter((a) => typeof a === 'string') : [];
      if (!agents.length) throw new EngineError('invalid_input', 'chain.agents must list at least one agent');
      principal = new Principal(req(chain, 'user'), agents, s(chain, 'tenant'), s(chain, 'task'), null, [], Cap.unrestricted(), now,
        s(chain, 'role'), has(chain, 'groups') && chain.groups !== null ? this._groups(chain.groups, 'Group', null) : null);
    } else if (chain !== null) {
      throw new Deny('token_invalid', 'this engine does not trust caller-supplied chains; send a capability token');
    } else {
      throw new Deny('token_invalid', 'no capability token was presented');
    }
    o.principal = principal;
    passed('token', `user ${principal.user} via ${principal.chain.join(' -> ')}`);

    // 2. catalog
    const rdef = this.bundle.catalog.get(path);
    if (rdef === undefined) throw new Deny('unknown_resource', `'${path}' is not in the catalog`);

    // 3. tenant
    let attrs = has(res, 'attrs') ? res.attrs : null;
    if (attrs === null) attrs = obj();
    if (!isObj(attrs)) throw new EngineError('invalid_input', 'resource.attrs must be an object');
    const rt = attrs.tenant;
    if (truthy(principal.tenant) && typeof rt === 'string' && principal.tenant !== rt) {
      throw new Deny('tenant_mismatch', `token tenant '${principal.tenant}' cannot touch a resource of tenant '${rt}'`);
    }

    // 4. capability
    if (!principal.cap.allowsAction(action)) throw new Deny('capability_action', `the token does not carry action '${action}'`);
    if (!principal.cap.allowsResource(path, rid)) throw new Deny('capability_resource', `the token does not cover ${path}/${rid}`);
    passed('capability', 'token covers the action and the resource');

    // 5. policy
    const etype = rdef.entityType;
    const rUid = entity(etype, rid);
    let fieldNames;
    if (Array.isArray(i.fields)) {
      fieldNames = [];
      for (const f of i.fields) {
        if (typeof f !== 'string' || !rdef.fields.has(f)) throw new Deny('unknown_field', `'${path}.${typeof f === 'string' ? f : '?'}' is not in the catalog`);
        fieldNames.push(f);
      }
    } else {
      fieldNames = [...rdef.fields.keys()].sort(cmpCodePoint);
    }
    const extra = [];
    if (!this.bundle.store.has(rUid)) {
      extra.push(O({ uid: O({ type: etype, id: rid }), attrs, parents: [] }));
    } else if (truthy(attrs)) {
      throw new EngineError('invalid_input', `${rUid} is defined in entities.json; do not send attrs for it`);
    }
    for (const n of fieldNames) {
      const fid = `${path}.${n}`;
      extra.push(O({ uid: O({ type: 'Field', id: fid }),
        attrs: O({ path: fid, name: n, resource: path, labels: rdef.fields.get(n).labels, of: O({ __entity: O({ type: etype, id: rid }) }) }),
        parents: [O({ type: etype, id: rid })] }));
    }
    let store;
    try {
      store = this._storeFor(principal).overlay(extra);
    } catch (e) {
      if (!(e instanceof cedar.ValueError)) throw e;
      throw new EngineError('invalid_input', `resource entity: ${e.message}`);
    }
    const fullCtx = O(callerCtx);
    fullCtx.iam = this._iamContext(principal);
    let ctx;
    try {
      ctx = cedar.fromJson(fullCtx);
    } catch (e) {
      if (!(e instanceof cedar.ValueError)) throw e;
      throw new EngineError('invalid_context', `${e.message} (use integers, strings, booleans, lists and objects; no floats or nulls)`);
    }
    const pUid = entity('Agent', principal.leaf);
    const v = this._evaluate(pUid, action, rUid, ctx, store);
    o.errors.push(...v.errors);
    o.policies = v.policies;
    if (!v.allow) {
      if (v.forbidError) throw new Deny('policy_error', 'a forbid policy failed to evaluate, so the request is denied');
      if (!v.policies.length) throw new Deny('no_matching_permit', 'no policy permits this request');
      throw new Deny('policy_forbid', 'forbidden by ' + v.policies.join(', '));
    }
    passed('policy', 'permitted by ' + v.policies.join(', '));

    // 6. obligations carried by the permits that decided
    let approvalLabel = null;
    for (const pid of v.policies) {
      const ann = this.bundle.policies.get(pid).annotations;
      if (has(ann, 'row_filter')) {
        try {
          o.rowFilter.push(...parseRowFilter(ann.row_filter, fullCtx));
        } catch (d) {
          if (!(d instanceof Deny)) throw d;
          throw new Deny(d.code, `${pid}: ${d.detail}`);
        }
      }
      if (has(ann, 'rate_limit')) {
        const rate = parseRate(ann.rate_limit);
        if (rate === null) throw new Deny('policy_error', `${pid}: rate_limit must be "<count>/<seconds>"`);
        o.rate.push([`${pid}|${principal.leaf}|${principal.user}`, rate[0], rate[1]]);
      }
      if (has(ann, 'require_approval')) approvalLabel = ann.require_approval;
    }
    for (const [key, n, w] of o.rate) {
      let q = this._rate.get(key);
      if (q === undefined) this._rate.set(key, q = []);
      while (q.length && q[0] <= now - w) q.shift();
      o.rateLimit = O({ limit: n, window_seconds: w, used: BigInt(q.length) });
      if (BigInt(q.length) >= n) throw new Deny('rate_limited', `more than ${n} calls in ${w} seconds`);
    }

    // 7. budget
    if (has(callerCtx, 'spend')) {
      const sp = callerCtx.spend;
      const cur = isObj(sp) ? sp.currency : undefined;
      const amount = isObj(sp) ? sp.amount : undefined;
      if (typeof cur !== 'string' || !isInt(amount) || amount < 0n) {
        throw new EngineError('invalid_context', 'context.spend must be {currency: string, amount: non-negative integer in minor units}');
      }
      if (principal.jti === null) throw new Deny('budget_exceeded', 'spending needs a capability token with a budget');
      if (!has(principal.cap.budget, cur)) throw new Deny('budget_exceeded', `the token carries no ${cur} budget`);
      const ledger = this.state.data.ledger, limits = this.state.data.limits;
      const amountOf = (table, tid) => {
        if (!has(table, tid)) return null;
        const b = table[tid];
        if (!isObj(b)) throw new EngineError('state_io', 'state.json is corrupt: a budget entry is not an object');
        return has(b, cur) ? stateInt(b[cur]) : null;
      };
      const spent = (tid) => amountOf(ledger, tid) ?? 0n;
      const own = principal.cap.budget[cur];
      if (spent(principal.jti) + amount > own) {
        throw new Deny('budget_exceeded', `${amount} ${cur} would exceed this token's budget of ${own} (already spent ${spent(principal.jti)})`);
      }
      for (const a of principal.anc) {
        // An ancestor's budget is in this engine's state when it issued the
        // ancestor, and in the token's `lim` claim always: a verify-only
        // engine elsewhere must enforce it too.
        const limit = amountOf(limits, a) ?? amountOf(principal.lim, a);
        if (limit !== null && spent(a) + amount > limit) throw new Deny('budget_exceeded', `${amount} ${cur} would exceed the budget of ancestor token ${a}`);
      }
      o.spend = [cur, amount];
      passed('budget', 'within the budget of every token in the chain');
    }

    // 8. human approval
    if (approvalLabel !== null) {
      const aid = hashInternal(O({ user: principal.user, chain: principal.chain, tenant: principal.tenant, action,
        resource: `${path}/${rid}`, attrs, context: callerCtx, label: approvalLabel })).slice(0, 24);
      const grant = has(this.state.data.approvals, aid) ? this.state.data.approvals[aid] : null;
      if (truthy(grant) && stateInt(isObj(grant) ? grant.exp : undefined) > now) {
        if (!has(grant, 'by')) throw new EngineError('state_io', "state.json is corrupt: an approval has no 'by'");
        o.approved = [aid, grant.by];
        passed('approval', `approved by ${grant.by}`);
      } else {
        if (!dryRun) {
          this.state.data.pending[aid] = O({ label: approvalLabel, user: principal.user, agent: principal.leaf, action,
            resource: `${path}/${rid}`, requested_at: now });
          this.state.save();
        }
        o.approval = O({ id: aid, label: approvalLabel });
        throw new Deny('approval_required', `a human must approve this (${approvalLabel})`);
      }
    }

    // 9. fields
    const status = new Map(), fieldTrace = [];
    for (const n of fieldNames) {
      const fid = `${path}.${n}`;
      const fdef = rdef.fields.get(n);
      let allowed, by;
      if (principal.cap.denyFields.includes(fid) || fdef.labels.some((l) => principal.cap.denyLabels.includes(l))) {
        allowed = false;
        by = 'capability';
      } else {
        const fv = this._evaluate(pUid, action, new cedar.Entity('Field', fid), ctx, store);
        o.errors.push(...fv.errors);
        allowed = fv.allow;
        by = fv.policies.length ? fv.policies : 'no_matching_permit';
      }
      if (allowed) {
        o.fieldAllow.push(n);
        status.set(n, fields.ALLOW);
      } else {
        o.fieldDeny.push(n);
        if (fdef.mask === 'redact') {
          o.fieldRedact.push(n);
          status.set(n, fields.REDACT);
        } else status.set(n, fields.DENY);
      }
      fieldTrace.push(O({ field: n, effect: allowed ? 'allow' : 'deny', by }));
    }
    o.trace.push(O({ check: 'fields', result: 'pass', fields: fieldTrace }));
    o.mask = new fields.Mask(status);
    o.allow = true;
    o.reason = 'policy_permit';
  }

  _decide(i, withData) {
    const now = this._now(i);
    const dryRun = i.dry_run === true;
    const strict = i.strict === true;
    if (withData && !has(i, 'data')) throw new EngineError('invalid_input', "'data' is required for filter");
    const data = withData ? i.data : null;
    const o = this._evaluateRequest(i, now, dryRun);

    // 10. strict mode: for tool *inputs*, where silently dropping a field
    // would change what the agent asked for
    if (o.allow && strict && withData) {
      const denied = fields.apply(data, o.mask, [])[1];
      if (denied.length) {
        o.allow = false;
        o.reason = 'field_denied';
        o.detail = 'the input contains fields this principal may not use: ' + denied.join(', ');
        o.trace.push(O({ check: 'field_denied', result: 'deny', detail: o.detail }));
      }
    }

    // commit the side effects of an allowed call
    if (o.allow && !dryRun) {
      for (const [key] of o.rate) {
        let q = this._rate.get(key);
        if (q === undefined) this._rate.set(key, q = []);
        q.push(now);
      }
      let dirty = false;
      if (o.spend && o.principal) {
        const [cur, amount] = o.spend;
        const ledger = this.state.data.ledger;
        for (const tid of [...o.principal.anc, o.principal.jti]) {
          if (!has(ledger, tid)) ledger[tid] = obj();
          const bucket = ledger[tid];
          if (!isObj(bucket)) throw new EngineError('state_io', 'state.json is corrupt: a ledger entry is not an object');
          bucket[cur] = (has(bucket, cur) ? stateInt(bucket[cur]) : 0n) + amount;
        }
        dirty = true;
      }
      if (o.approved) {
        // an approval is good for one call
        delete this.state.data.approvals[o.approved[0]];
        dirty = true;
      }
      if (dirty) this.state.save();
    }

    const wouldDeny = !o.allow;
    const shadowed = this.shadow && wouldDeny;
    const out = obj();
    out.effect = o.allow || shadowed ? 'allow' : 'deny';
    out.reason = shadowed ? 'shadow_allow' : o.reason;
    out.rule = ruleId(out.reason);
    if (o.detail && !shadowed) out.detail = o.detail;
    out.policies = o.policies;
    out.policy_version = this.bundle.version;
    out.principal = o.principal ? o.principal.toJson() : null;
    if (this.shadow) {
      out.shadow = true;
      if (wouldDeny) out.would_deny = O({ reason: o.reason, detail: o.detail });
    }
    if (o.approval) out.approval = o.approval;

    const obligations = obj();
    let masked = [], rowsDropped = 0n;
    if (o.allow) {
      obligations.fields = O({ allow: o.fieldAllow, deny: o.fieldDeny, redact: o.fieldRedact });
      if (o.rowFilter.length) obligations.row_filter = o.rowFilter;
      if (o.rateLimit) obligations.rate_limit = o.rateLimit;
      if (o.approved) obligations.approved = O({ id: o.approved[0], by: o.approved[1] });
    }
    if (withData) {
      if (o.allow) {
        const [filtered, m, dropped] = fields.apply(data, o.mask, o.rowFilter);
        masked = m;
        rowsDropped = BigInt(dropped);
        if (this.shadow) {
          // shadow mode never changes data; it reports what it would do
          out.data = data;
          out.would_mask = masked;
          out.would_drop_rows = rowsDropped;
        } else {
          out.data = filtered;
          out.masked = masked;
          out.rows_dropped = rowsDropped;
        }
      } else {
        out.data = shadowed ? data : null;
      }
    }
    out.obligations = obligations;
    if (o.errors.length) out.policy_errors = o.errors;
    if (i.explain === true) out.explain = o.trace;

    this._counter += 1;
    const opt = (k) => (has(i, k) ? i[k] : null);
    const p = o.principal;
    const requestHash = hashInternal(O({ action: opt('action'), resource: opt('resource'), context: opt('context'), token_id: p ? p.jti : null }));
    const decisionId = 'd-' + sha256Hex(`${requestHash}${now}${this._counter}${process.pid}`).slice(0, 16);
    out.decision_id = decisionId;

    if (!dryRun) {
      const res = isObj(i.resource) ? i.resource : obj();
      this._audit(O({
        event: 'decision', decision_id: decisionId, op: withData ? 'filter' : 'authorize',
        effect: o.allow ? 'allow' : 'deny', reason: o.reason, detail: o.detail,
        enforced: !this.shadow, policies: o.policies, policy_version: this.bundle.version,
        user: p ? p.user : null, chain: p ? p.chain : null, role: p ? p.role : null, tenant: p ? p.tenant : null,
        task: p ? p.task : null, token_id: p ? p.jti : null, token_exp: p ? p.exp : null,
        action: opt('action'),
        resource: `${s(res, 'path') ?? '?'}/${s(res, 'id') ?? 'any'}`,
        obligations, masked, rows_dropped: rowsDropped, approval: o.approval,
        spend: o.spend ? O({ currency: o.spend[0], amount: o.spend[1] }) : null,
        request_hash: requestHash,
      }), now);
    }
    return out;
  }
}

/** The engine, with the same convenience methods as the REST `Client`
 * (authorize, filter, issueToken, ...; synchronous here). */
export class Engine extends withOperations(EngineCore) {}
