// Shared helpers for the tests in ../test. Not part of the package.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stringify } from '../lib/json.mjs';

export const HERE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const ROOT = resolve(HERE, '..', '..');
export const SPEC = join(ROOT, 'spec');
export const BUNDLE = join(SPEC, 'conformance', 'bundle');
export const VECTORS = join(SPEC, 'conformance', 'vectors');
export const EVAL = join(SPEC, 'conformance', 'eval', 'cases.json');
export const OIDC = join(SPEC, 'conformance', 'oidc');
export const CLI = join(HERE, 'bin', 'cli.mjs');
export const T = 1700000000;
export const FULL_CAP = { actions: ['read', 'create', 'update'], resources: ['crm.customer/*', 'billing.refund/*'], budget: { EUR: 20000 } };
export const ADMIN = 'admin-key-for-tests-0123456789';
export const PEP = 'pep-key-for-tests-0123456789';

/** A temp directory that is removed when the test (or suite) `t` ends. */
export function tempDir(t, prefix = 'smartdelegate-node-') {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

export function config(stateDir, extra = {}) {
  return { bundle_dir: BUNDLE, state_dir: stateDir, allow_test_clock: true, max_depth: 3, ...extra };
}

/** Run this port's CLI to completion. -> {status, stdout, stderr} */
export function cli(args, { env = {}, input, cwd } = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, ...env }, input, cwd, timeout: 60000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** `cli.mjs serve` on a free port with its own state directory, removed on stop(). */
export async function startDaemon(extra = {}, { args = [], env = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'smartdelegate-node-d-'));
  const cfgPath = join(dir, 'smartdelegate.json');
  writeFileSync(cfgPath, stringify({ ...config(join(dir, 'state')), admin_key: ADMIN, pep_key: PEP, ...extra }));
  const proc = spawn(process.execPath, [CLI, 'serve', '--config', cfgPath, '--listen', '127.0.0.1:0', ...args],
    { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, ...env } });
  let exited = false;
  const gone = new Promise((done) => proc.once('exit', () => { exited = true; done(); }));
  const stop = async () => {
    if (!exited) proc.kill('SIGKILL');
    await gone;
    rmSync(dir, { recursive: true, force: true });
  };
  try {
    const url = await new Promise((ok, fail) => {
      let buf = '';
      const timer = setTimeout(() => fail(new Error(`daemon did not start in time: ${buf}`)), 20000);
      proc.stderr.on('data', (d) => {
        buf += d;
        // wait for the whole line: the chunk can end in the middle of the URL
        const m = buf.match(/(http:\/\/\S+)\r?\n/);
        if (m) {
          clearTimeout(timer);
          ok(m[1]);
        }
      });
      proc.once('exit', (code) => { clearTimeout(timer); fail(new Error(`daemon exited with ${code}: ${buf}`)); });
      proc.once('error', (e) => { clearTimeout(timer); fail(e); });
    });
    return { url, dir, config: cfgPath, proc, stop };
  } catch (e) {
    await stop();
    throw e;
  }
}

// ---- the Python reference ---------------------------------------------------

export const PYTHON = process.env.PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
const PY_ENV = { ...process.env, PYTHONDONTWRITEBYTECODE: '1',
  PYTHONPATH: join(ROOT, 'src') + (process.env.PYTHONPATH ? delimiter + process.env.PYTHONPATH : '') };

let pythonState;
/** null when the reference can run here, else the reason it cannot. */
export function referenceUnavailable() {
  if (pythonState === undefined) {
    const r = spawnSync(PYTHON, ['-c', 'import cryptography, smartdelegate'], { encoding: 'utf8', env: PY_ENV, timeout: 60000 });
    if (r.error) pythonState = `interoperability with the Python reference was NOT tested: ${PYTHON} is not installed (${r.error.code ?? r.error.message})`;
    else if (r.status !== 0) pythonState = `interoperability with the Python reference was NOT tested: ${PYTHON} cannot import the reference or the 'cryptography' package (${(r.stderr || '').trim().split('\n').pop()})`;
    else pythonState = null;
  }
  return pythonState;
}

/** Run the reference CLI. -> {status, stdout, stderr} */
export function py(args, { input } = {}) {
  const r = spawnSync(PYTHON, ['-m', 'sf_smartdelegate', ...args], { encoding: 'utf8', env: PY_ENV, input, timeout: 60000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

/** Run a Python snippet with the reference on the path. */
export function pyCode(code, { input } = {}) {
  const r = spawnSync(PYTHON, ['-c', code], { encoding: 'utf8', env: PY_ENV, input, timeout: 60000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

// ---- OIDC fixtures made on the fly --------------------------------------------

import { constants, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

export const IDP = { issuer: 'https://idp.example.test', audience: 'smartdelegate-demo' };

/** A JWKS with one key per supported algorithm, and ID tokens signed with
 * them: {jwks, tokens: {name: {token, valid}}}. Nothing is written to disk. */
export function makeIdTokens() {
  const b64u = (x) => Buffer.from(x).toString('base64url');
  const keys = [];
  const signers = {};
  const add = (kid, alg, pair, signer) => {
    keys.push({ ...pair.publicKey.export({ format: 'jwk' }), kid, alg, use: 'sig' });
    signers[kid] = { alg, sign: (data) => signer(pair.privateKey, data) };
  };
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  for (const bits of ['256', '384', '512']) {
    add(`rsa-${bits}`, `RS${bits}`, rsa, (key, data) => cryptoSign(`sha${bits}`, data, { key, padding: constants.RSA_PKCS1_PADDING }));
  }
  add('ec-256', 'ES256', generateKeyPairSync('ec', { namedCurve: 'P-256' }), (key, data) => cryptoSign('sha256', data, { key, dsaEncoding: 'ieee-p1363' }));
  add('ec-384', 'ES384', generateKeyPairSync('ec', { namedCurve: 'P-384' }), (key, data) => cryptoSign('sha384', data, { key, dsaEncoding: 'ieee-p1363' }));
  add('ed', 'EdDSA', generateKeyPairSync('ed25519'), (key, data) => cryptoSign(null, data, key));
  const claims = { iss: IDP.issuer, aud: [IDP.audience, 'other'], azp: IDP.audience, iat: T, exp: 4102444800, sub: 'alice' };
  const make = (kid, { header = {}, body = claims, signWith = kid } = {}) => {
    const head = b64u(JSON.stringify({ alg: signers[kid].alg, typ: 'JWT', kid, ...header }));
    const payload = b64u(JSON.stringify(body));
    return `${head}.${payload}.${b64u(signers[signWith].sign(Buffer.from(`${head}.${payload}`)))}`;
  };
  const tokens = {};
  for (const kid of Object.keys(signers)) {
    tokens[`${kid} good`] = { token: make(kid), valid: true };
    const [h, p, s] = make(kid).split('.');
    const forged = b64u(JSON.stringify({ ...claims, sub: 'bob' }));
    tokens[`${kid} altered payload`] = { token: `${h}.${forged}.${s}`, valid: false };
    tokens[`${kid} truncated signature`] = { token: `${h}.${p}.${s.slice(0, -8)}`, valid: false };
  }
  // the algorithm in the header must fit the key it names
  tokens['RS256 header, EC key'] = { token: make('ec-256', { header: { alg: 'RS256' } }), valid: false };
  tokens['ES256 header, RSA key'] = { token: make('rsa-256', { header: { alg: 'ES256' } }), valid: false };
  tokens['ES256 header, P-384 key'] = { token: make('ec-384', { header: { alg: 'ES256' } }), valid: false };
  tokens['HS256'] = { token: make('rsa-256', { header: { alg: 'HS256' } }), valid: false };
  tokens.none = { token: make('rsa-256', { header: { alg: 'none' } }).split('.').slice(0, 2).join('.') + '.', valid: false };
  tokens.ES512 = { token: make('ec-256', { header: { alg: 'ES512' } }), valid: false };
  tokens['unknown kid'] = { token: make('ed', { header: { kid: 'nobody' } }), valid: false };
  tokens['no kid, several keys'] = { token: make('ed', { header: { kid: undefined } }), valid: false };
  tokens['signed by another key'] = { token: make('rsa-256', { signWith: 'rsa-384' }), valid: false };
  // ECDSA signatures in a JWS are r||s, not DER
  const der = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  keys.push({ ...der.publicKey.export({ format: 'jwk' }), kid: 'ec-der', alg: 'ES256' });
  signers['ec-der'] = { alg: 'ES256', sign: (data) => cryptoSign('sha256', data, der.privateKey) };
  tokens['ES256 with a DER signature'] = { token: make('ec-der'), valid: false };
  tokens['expired'] = { token: make('ed', { body: { ...claims, exp: T - 1 } }), valid: false };
  tokens['not yet valid'] = { token: make('ed', { body: { ...claims, nbf: T + 3600 } }), valid: false };
  tokens['nbf within the allowed skew'] = { token: make('ed', { body: { ...claims, nbf: T + 30 } }), valid: true };
  tokens['wrong audience'] = { token: make('ed', { body: { ...claims, aud: ['x', 'y'] } }), valid: false };
  tokens['no exp'] = { token: make('ed', { body: { iss: claims.iss, aud: IDP.audience, sub: 'alice' } }), valid: false };
  tokens['exp is a float'] = { token: `${b64u(JSON.stringify({ alg: 'EdDSA', kid: 'ed' }))}.${b64u(`{"iss":"${claims.iss}","aud":"${IDP.audience}","sub":"alice","exp":4102444800.0}`)}.`, valid: false };
  // authorised party (OIDC Core 3.1.3.7)
  const { azp: _azp, ...noAzp } = claims;
  tokens['several audiences, no azp'] = { token: make('ed', { body: noAzp }), valid: false };
  tokens['several audiences, azp is another client'] = { token: make('ed', { body: { ...claims, azp: 'other' } }), valid: false };
  tokens['one audience, azp is another client'] = { token: make('ed', { body: { ...claims, aud: IDP.audience, azp: 'other' } }), valid: false };
  tokens['azp is not a string'] = { token: make('ed', { body: { ...claims, azp: [IDP.audience] } }), valid: false };
  tokens['azp is null'] = { token: make('ed', { body: { ...claims, azp: null } }), valid: false };
  tokens['one audience as a string, no azp'] = { token: make('ed', { body: { ...noAzp, aud: IDP.audience } }), valid: true };
  tokens['one audience as a list, no azp'] = { token: make('ed', { body: { ...noAzp, aud: [IDP.audience] } }), valid: true };
  tokens['one audience, azp ours'] = { token: make('ed', { body: { ...claims, aud: IDP.audience } }), valid: true };
  tokens['empty audience list'] = { token: make('ed', { body: { ...noAzp, aud: [] } }), valid: false };

  /** An EdDSA ID token for alice with these claims added or replaced (undefined removes one). */
  const idToken = (extra = {}) => {
    const body = { ...noAzp, aud: IDP.audience, ...extra };
    for (const k of Object.keys(body)) if (body[k] === undefined) delete body[k];
    return make('ed', { body });
  };
  return { jwks: { keys }, tokens, idToken };
}

/** Requests that exercise the 0.3 ID-token rules beyond the signature: the
 * revoked-user cut-off against `iat`, and group claims (flat and nested).
 * Each is {name, idp (extra idp config), revokeAt (revoke alice at this time
 * first, or null), input (for issue_token), ok, code (the error when refused),
 * grp (expected claim, when ok)}. */
export function oidcScenarios(idToken) {
  const base = { agent: 'support-bot', now: T + 100 };
  const cap = { cap: FULL_CAP };
  const role = { role: 'support-agent' };
  const support = [{ type: 'Group', id: 'support' }];
  const out = [];
  const add = (name, idp, revokeAt, claims, extra, ok, grp) => out.push({ name, idp, revokeAt, input: { ...base, ...extra, id_token: idToken(claims) }, ok, grp });
  // the cut-off of a revoked user: the ID token must have been issued after it
  for (const [name, iat, ok] of [['iat before the cut-off', T + 10, false], ['iat equal to the cut-off', T + 50, false], ['iat after the cut-off', T + 51, true],
    ['no iat', undefined, false], ['iat is a float', T + 60.5, false], ['iat is a string', String(T + 60), false], ['iat is true', true, false]]) {
    add(`revoked user, ${name}`, {}, T + 50, { iat }, cap, ok, undefined);
  }
  add('another user was revoked', {}, null, { iat: T }, cap, true, undefined);
  add('not revoked, no iat', {}, null, { iat: undefined }, cap, true, undefined);
  // flat group claim
  add('groups claim, list', { groups_claim: 'groups' }, null, { groups: ['support', 'nope'] }, role, true, support);
  add('groups claim, one name', { groups_claim: 'groups' }, null, { groups: 'support' }, role, true, support);
  add('groups claim, objects', { groups_claim: 'groups' }, null, { groups: [{ type: 'Group', id: 'support' }, 'supervisors'] }, role, true,
    [{ type: 'Group', id: 'supervisors' }, { type: 'Group', id: 'support' }]);
  add('groups claim missing: member of nothing', { groups_claim: 'groups' }, null, {}, role, false, undefined);
  add('groups claim missing, no role asked', { groups_claim: 'groups' }, null, {}, cap, false, undefined);
  add('groups claim malformed', { groups_claim: 'groups' }, null, { groups: [1] }, role, false, undefined);
  add('groups claim is a number', { groups_claim: 'groups' }, null, { groups: 5 }, role, false, undefined);
  // nested group claim
  const nested = { groups_claim: 'realm_access.roles' };
  add('nested claim', nested, null, { realm_access: { roles: ['support'] } }, role, true, support);
  add('nested claim, one name', nested, null, { realm_access: { roles: 'support' } }, role, true, support);
  add('nested claim, the exact top-level name wins', nested, null, { 'realm_access.roles': ['support'], realm_access: { roles: ['compliance'] } }, role, true, support);
  add('nested claim, the exact top-level name wins (and denies)', nested, null, { 'realm_access.roles': [], realm_access: { roles: ['support'] } }, role, false, undefined);
  add('nested claim, top-level null falls through to the path', nested, null, { 'realm_access.roles': null, realm_access: { roles: ['support'] } }, role, true, support);
  add('nested claim missing', nested, null, { realm_access: {} }, role, false, undefined);
  add('nested claim, parent missing', nested, null, {}, role, false, undefined);
  add('nested claim, parent is not an object', nested, null, { realm_access: ['roles'] }, role, false, undefined);
  add('nested claim, parent is a string', nested, null, { realm_access: 'roles' }, role, false, undefined);
  add('nested claim is null', nested, null, { realm_access: { roles: null } }, role, false, undefined);
  add('nested claim malformed', nested, null, { realm_access: { roles: [[1]] } }, role, false, undefined);
  add('nested claim is an object', nested, null, { realm_access: { roles: { a: 1 } } }, role, false, undefined);
  const deep = { groups_claim: 'a.b.c', group_map: { 'kc-support': 'support' } };
  add('three levels, mapped names', deep, null, { a: { b: { c: ['kc-support', 'support'] } } }, role, true, support);
  add('three levels, stops short', deep, null, { a: { b: ['kc-support'] } }, role, false, undefined);
  add('dotted name with an empty part', { groups_claim: 'a..b' }, null, { a: { '': { b: ['support'] } } }, role, true, support);
  // the error each refused scenario ends in: a token that is not acceptable,
  // or an acceptable token whose (empty) membership does not hold the role
  const notHeld = new Set(['groups claim missing: member of nothing', 'nested claim, the exact top-level name wins (and denies)', 'nested claim missing',
    'nested claim, parent missing', 'nested claim, parent is not an object', 'nested claim, parent is a string', 'nested claim is null', 'three levels, stops short']);
  for (const sc of out) {
    if (sc.ok) sc.code = null;
    else if (notHeld.has(sc.name)) sc.code = 'role_not_held';
    else if (sc.name === 'groups claim missing, no role asked') sc.code = 'delegation_denied';
    else sc.code = 'id_token_invalid';
  }
  return out;
}

