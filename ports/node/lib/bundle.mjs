// Policy bundle: compiled policies, entity store, field catalog, signature.
//
//   bundle/
//     policies.json     Cedar's JSON policy form, keyed by policy id. This is
//                       what the engine evaluates.
//     policies/*.cedar  the human-written source policies.json is compiled from
//                       (`smartdelegate bundle compile`, in the Rust port)
//     entities.json     users, groups, agents
//     catalog.json      resources, fields, classification labels
//     roles.json        roles a human can act in (optional)
//     tests/*.json      policy unit tests (not part of the version)
//     bundle.sig.json   file hashes + Ed25519 signature
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonInternal, decodeUtf8, sha256Hex, utf8 } from './canon.mjs';
import * as cedar from './cedar.mjs';
import { EngineError } from './errors.mjs';
import { cmpCodePoint, has, isInt, isObj, jsonEq, obj, parse, truthy, write } from './json.mjs';
import { Cap } from './tokens.mjs';

function read(path) {
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch (e) {
    throw new EngineError('bundle_io', `${path}: ${e.code ?? e.message}`);
  }
  try {
    return decodeUtf8(bytes);
  } catch {
    throw new EngineError('bundle_io', `${path}: not UTF-8`);
  }
}

const digest = (path) => sha256Hex(utf8(read(path).replaceAll('\r\n', '\n')));

/** Relative path -> sha256 for every file that defines behaviour. Line endings
 * are normalised so a Windows checkout has the same version. */
export function manifest(dir) {
  const files = obj();
  const policies = join(dir, 'policies.json');
  if (!existsSync(policies)) {
    throw new EngineError('bundle_io', `${policies}: missing. This port loads compiled policies; run \`smartdelegate bundle compile\` (Rust port) on the .cedar sources`);
  }
  files['policies.json'] = digest(policies);
  for (const name of ['entities.json', 'catalog.json', 'roles.json']) {
    if (existsSync(join(dir, name))) files[name] = digest(join(dir, name));
  }
  return files;
}

export function versionOf(files) {
  return sha256Hex(canonInternal(files));
}

// ---- keys ------------------------------------------------------------------
// Private keys are base64 of the PKCS#8 DER encoding; public keys are base64 of
// the 32 raw bytes. The key id is the first 16 hex characters of sha256(public).

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const B64_STRICT = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function b64Strict(text) {
  if (typeof text !== 'string' || !B64_STRICT.test(text)) throw new Error('not base64');
  return Buffer.from(text, 'base64');
}

/** -> [private key b64, public key b64] */
export function keygen() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const der = privateKey.export({ format: 'der', type: 'pkcs8' });
  return [der.toString('base64'), publicRaw(privateKey).toString('base64')];
}

/** The 32 raw public bytes of an Ed25519 private or public KeyObject. */
export function publicRaw(key) {
  const pub = key.type === 'private' ? createPublicKey(key) : key;
  return pub.export({ format: 'der', type: 'spki' }).subarray(-32);
}

export function publicFromRaw(raw) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function loadPrivate(b64) {
  let key;
  try {
    key = createPrivateKey({ key: b64Strict(String(b64).trim()), format: 'der', type: 'pkcs8' });
  } catch {
    throw new EngineError('crypto', 'private key is not base64 Ed25519 PKCS#8');
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new EngineError('crypto', 'private key is not Ed25519');
  return key;
}

/** -> [KeyObject, raw 32 bytes] */
export function loadPublic(b64) {
  try {
    const raw = b64Strict(String(b64).trim());
    if (raw.length !== 32) throw new Error('wrong length');
    return [publicFromRaw(raw), raw];
  } catch {
    throw new EngineError('crypto', 'public key is not base64 of 32 raw Ed25519 bytes');
  }
}

export function keyId(publicB64) {
  return sha256Hex(loadPublic(publicB64)[1]).slice(0, 16);
}

export function signRaw(privateKey, bytes) {
  return cryptoSign(null, bytes, privateKey);
}

/** Sign the bundle in `dir`; writes bundle.sig.json and returns its content
 * (plain object). */
export function sign(dir, privateB64) {
  const key = loadPrivate(privateB64);
  const files = manifest(dir);
  const version = versionOf(files);
  const pub = publicRaw(key).toString('base64');
  const payload = obj();
  payload.files = files;
  payload.version = version;
  const out = obj();
  out.files = files;
  out.version = version;
  out.key_id = keyId(pub);
  out.alg = 'Ed25519';
  out.signature = signRaw(key, utf8(canonInternal(payload))).toString('base64');
  writeFileSync(join(dir, 'bundle.sig.json'), write(out, { indent: 2, ascii: true }), 'utf8');
  return { files: { ...files }, version, key_id: out.key_id, alg: out.alg, signature: out.signature };
}

function verifySignature(dir, files, publicB64) {
  const p = join(dir, 'bundle.sig.json');
  if (!existsSync(p)) throw new EngineError('bundle_unsigned', 'a signed bundle is required, but bundle.sig.json is missing');
  let sig, rawSig;
  try {
    sig = parse(read(p));
    if (!isObj(sig)) throw new Error('not an object');
    rawSig = b64Strict(has(sig, 'signature') ? sig.signature : '');
  } catch {
    throw new EngineError('bundle_signature', 'bundle.sig.json is malformed');
  }
  const payload = obj();
  payload.files = has(sig, 'files') ? sig.files : null;
  payload.version = has(sig, 'version') ? sig.version : null;
  const key = loadPublic(publicB64)[0];
  let good = false;
  try {
    good = cryptoVerify(null, utf8(canonInternal(payload)), key, rawSig);
  } catch {
    good = false;
  }
  if (!good) throw new EngineError('bundle_signature', 'bundle signature does not verify with the configured key');
  if (!jsonEq(files, payload.files)) throw new EngineError('bundle_signature', 'bundle files changed after signing');
}

function isDir(p) {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

export class Bundle {
  /** `publicKey`: when set, the bundle must carry a valid signature by that
   * key or loading fails. */
  constructor(dir, publicKey = null) {
    this.dir = dir;
    const files = manifest(dir);
    this.version = versionOf(files);
    this.signedBy = null;
    if (publicKey) {
      verifySignature(dir, files, publicKey);
      this.signedBy = keyId(publicKey);
    }

    let doc, compiled;
    const text = read(join(dir, 'policies.json'));
    try {
      doc = parse(text);
      if (!isObj(doc) || !has(doc, 'policies')) throw new Error("no 'policies'");
      compiled = doc.policies;
      if (!isObj(compiled)) throw new Error("'policies' must be an object");
    } catch (e) {
      throw new EngineError('policy_parse', `policies.json: ${e.message}`);
    }
    // policies.json records the hash of each .cedar file it was compiled from.
    // This port cannot parse Cedar text, but it can tell when a source was
    // edited (or added) without recompiling, so the policy a reviewer reads is
    // the policy that runs.
    const sources = isObj(doc.sources) ? doc.sources : obj();
    const onDisk = obj();
    const pdir = join(dir, 'policies');
    if (isDir(pdir)) {
      let names;
      try {
        names = readdirSync(pdir).filter((n) => n.endsWith('.cedar')).sort(cmpCodePoint);
      } catch (e) {
        throw new EngineError('bundle_io', `${pdir}: ${e.code ?? e.message}`);
      }
      for (const n of names) onDisk[`policies/${n}`] = digest(join(pdir, n));
    }
    if (Object.keys(onDisk).length && !jsonEq(onDisk, sources)) {
      const all = new Set([...Object.keys(onDisk), ...Object.keys(sources)]);
      const changed = [...all].filter((k) => !(has(onDisk, k) && has(sources, k) && jsonEq(onDisk[k], sources[k]))).sort(cmpCodePoint);
      throw new EngineError('bundle_stale', `policies.json does not match the .cedar sources (${changed.join(', ')}); run \`smartdelegate bundle compile\` from the Rust port`);
    }
    /** Map of policy id -> cedar.Policy */
    this.policies = new Map();
    for (const pid of Object.keys(compiled)) {
      try {
        this.policies.set(pid, new cedar.Policy(pid, compiled[pid]));
      } catch (e) {
        if (!(e instanceof cedar.Unsupported)) throw e;
        throw new EngineError('policy_parse', `policies.json: ${pid}: ${e.message}`);
      }
    }

    this.entitiesJson = [];
    /** "Type::id" -> attrs exactly as written in entities.json */
    this.attrs = new Map();
    if (existsSync(join(dir, 'entities.json'))) {
      const etext = read(join(dir, 'entities.json'));
      try {
        const list = parse(etext);
        if (!Array.isArray(list) || !list.every(isObj)) throw new Error('expected a list of entities');
        this.entitiesJson = list;
        this.store = new cedar.Store(this.entitiesJson);
        for (const e of this.entitiesJson) {
          const uid = cedar.Store.uid(e.uid);
          this.attrs.set(`${uid.type}::${uid.id}`, truthy(e.attrs) ? e.attrs : obj());
        }
      } catch (e) {
        throw new EngineError('entities_parse', `entities.json: ${e.message}`);
      }
    } else {
      this.store = new cedar.Store();
    }

    /** Map of resource path -> {entityType, fields: Map name -> {labels, mask}} */
    this.catalog = new Map();
    if (existsSync(join(dir, 'catalog.json'))) {
      const ctext = read(join(dir, 'catalog.json'));
      try {
        const cat = parse(ctext);
        if (!isObj(cat)) throw new Error('catalog.json must be an object');
        const resources = truthy(cat.resources) ? cat.resources : obj();
        if (!isObj(resources)) throw new Error('resources must be an object');
        for (const path of Object.keys(resources)) {
          const rdef = resources[path];
          if (!isObj(rdef) || !cedar.validType(rdef.entity_type)) throw new Error(`${path}: entity_type is missing or malformed`);
          const fields = new Map();
          const fdefs = truthy(rdef.fields) ? rdef.fields : obj();
          if (!isObj(fdefs)) throw new Error(`${path}: fields must be an object`);
          for (const name of Object.keys(fdefs)) {
            const fdef = fdefs[name];
            if (!isObj(fdef)) throw new Error(`${path}.${name}: must be an object`);
            const mask = has(fdef, 'mask') ? fdef.mask : null;
            if (mask !== null && mask !== 'drop' && mask !== 'redact') throw new Error(`${path}.${name}: mask must be 'drop' or 'redact'`);
            let labels = [];
            if (truthy(fdef.labels)) {
              const l = fdef.labels;
              if (Array.isArray(l)) labels = [...l];
              else if (typeof l === 'string') labels = Array.from(l);
              else if (isObj(l)) labels = Object.keys(l);
              else throw new Error(`${path}.${name}: labels must be a list`);
            }
            fields.set(name, { labels, mask });
          }
          this.catalog.set(path, { entityType: rdef.entity_type, fields });
        }
      } catch (e) {
        throw new EngineError('catalog_parse', e.message);
      }
    }

    /** Map of role name -> Role */
    this.roles = new Map();
    if (existsSync(join(dir, 'roles.json'))) {
      const rtext = read(join(dir, 'roles.json'));
      try {
        const rdoc = parse(rtext);
        if (!isObj(rdoc) || !isObj(rdoc.roles)) throw new Error('expected {"roles": {...}}');
        for (const name of Object.keys(rdoc.roles)) this.roles.set(name, new Role(name, rdoc.roles[name]));
      } catch (e) {
        throw new EngineError('roles_parse', `roles.json: ${e instanceof EngineError ? e.detail : e.message}`);
      }
    }
  }
}

const ROLE_KEYS = new Set(['description', 'members', 'cap', 'max_ttl', 'tasks', 'agents', 'bindings']);

function patternList(v, what) {
  if (!Array.isArray(v) || !v.length || !v.every((x) => typeof x === 'string' && x !== '' && !x.slice(0, -1).includes('*'))) {
    throw new Error(`${what} must be a non-empty list of names, each with at most one trailing *`);
  }
  return [...v];
}

/** A role a human holds and can lend to an agent for one task.
 *
 *   members   entities whose members hold the role (the user itself, or any
 *             group the user is in)
 *   cap       the ceiling: the most a token issued under this role can carry
 *   maxTtl    tokens under this role live at most this many seconds (BigInt)
 *   tasks     when set, the token must name a task matching one pattern
 *   agents    when set, only these agents may be started in this role
 *   bindings  free-form, for bridges; ignored by the engine */
export class Role {
  constructor(name, v) {
    if (!name || !isObj(v)) throw new Error(`role '${name}' must be an object`);
    const unknown = Object.keys(v).filter((k) => !ROLE_KEYS.has(k));
    // a misspelt key must not silently loosen a role
    if (unknown.length) throw new Error(`role '${name}': unknown field(s): ${unknown.sort().join(', ')}`);
    this.name = name;
    const members = v.members;
    if (!Array.isArray(members) || !members.length) throw new Error(`role '${name}': members must be a non-empty list of {type, id}`);
    this.members = [];
    for (const m of members) {
      if (!isObj(m) || !cedar.validType(m.type) || typeof m.id !== 'string') throw new Error(`role '${name}': each member must be {type, id}`);
      this.members.push(new cedar.Entity(m.type, m.id));
    }
    if (!has(v, 'cap')) throw new Error(`role '${name}': cap is required`);
    this.cap = Cap.fromJson(v.cap);
    this.cap.validate();
    this.maxTtl = null;
    if (has(v, 'max_ttl')) {
      const t = v.max_ttl;
      if (!isInt(t) || t <= 0n) throw new Error(`role '${name}': max_ttl must be a positive integer`);
      this.maxTtl = t;
    }
    this.tasks = has(v, 'tasks') ? patternList(v.tasks, `role '${name}': tasks`) : null;
    this.agents = has(v, 'agents') ? patternList(v.agents, `role '${name}': agents`) : null;
    if (has(v, 'bindings') && !isObj(v.bindings)) throw new Error(`role '${name}': bindings must be an object`);
    this.bindings = truthy(v.bindings) ? v.bindings : obj();
  }
}
