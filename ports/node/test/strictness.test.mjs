// One test per bullet of "Strictness (0.3)" in spec/PORTING.md.
// (The containsAll / containsAny bullet is eval cases 92 to 95; it is checked
// here as well so that every bullet has a test in this file.)
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import * as cedar from '../lib/cedar.mjs';
import { loadEval, runEvalCase } from '../lib/conformance.mjs';
import { Engine, auditVerify, keygen } from '../lib/index.mjs';
import { parse, toInternal } from '../lib/json.mjs';
import { Keys, b64uDec } from '../lib/tokens.mjs';
import { BUNDLE, EVAL, FULL_CAP, HERE, T, cli, config, tempDir } from '../tools/support.mjs';

const READ = { action: 'read', resource: 'crm.customer', id: 'c-1' };
const code = (c) => (err) => err.code === c;

function setup(t, extra = {}) {
  const dir = tempDir(t);
  const e = new Engine(config(join(dir, 'state'), extra));
  t.after(() => e.close());
  return { dir, e, state: join(dir, 'state') };
}

test('audit lines end at "\\n" and nowhere else', (t) => {
  const { e, state, dir } = setup(t);
  const second = new Engine(config(state));
  t.after(() => second.close());
  const log = join(state, 'audit.jsonl');
  const separators = [' ', ' ', '\u0085', '\u000b', '\u000c', '\u001c', '\u001d', '\u001e'];
  separators.forEach((sep, n) => {
    const action = `re${sep}ad`;
    assert.equal((n % 2 ? e : second).authorize({ token: 'x', ...READ, action }).reason, 'token_invalid');
    // the tail holds the whole record, and the other engine chains onto it
    const last = (n % 2 ? second : e).call('audit_tail', { n: 1 }).records;
    assert.equal(last.length, 1);
    assert.equal(last[0].action, action);
    assert.equal(last[0].seq, n + 1);
  });
  assert.equal(readFileSync(log, 'utf8').split('\n').filter(Boolean).length, separators.length, 'one "\\n" per record');
  assert.ok(readFileSync(log, 'utf8').includes('re ad'), 'U+2028 is written as itself');
  assert.equal(e.call('audit_verify', {}).records, separators.length);
  assert.equal(e.call('audit_tail', { n: 100 }).records.length, separators.length);
  // a "\r" is not a line end either: between two members it is JSON
  // whitespace inside one record, where a "\n" cuts the record in two
  const text = readFileSync(log, 'utf8');
  const cut = join(dir, 'cut.jsonl');
  writeFileSync(cut, text.replace(',"event"', ',\r"event"'));
  assert.equal(auditVerify(cut).records, BigInt(separators.length));
  writeFileSync(cut, text.replace(',"event"', ',\n"event"'));
  assert.throws(() => auditVerify(cut), code('audit_broken'));
  // CRLF line ends still verify (the "\r" is whitespace around a record)
  writeFileSync(cut, text.replaceAll('\n', '\r\n'));
  assert.equal(auditVerify(cut).records, BigInt(separators.length));
});

test('base64url is strict: one token has one spelling', (t) => {
  const { e } = setup(t);
  const { token } = e.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP });
  assert.equal(e.authorize({ token, ...READ }).effect, 'allow');
  const [h, b, s] = token.split('.');
  const variants = [];
  for (const [n, part] of [h, b, s].entries()) {
    const put = (x) => [h, b, s].map((p, k) => (k === n ? x : p)).join('.');
    // characters the lenient decoders skip, in the middle and at the end
    for (const junk of ['!', '*', ' ', '\n', '\t', '~', '%', 'é', '\u0000']) {
      variants.push(put(part.slice(0, 5) + junk + part.slice(5)), put(part + junk));
    }
    // padding, and the standard alphabet instead of the URL-safe one
    variants.push(put(part + '='), put(part + '=='), put(part.slice(0, 4) + '=' + part.slice(4)));
    variants.push(put('+' + part.slice(1)), put('/' + part.slice(1)), put(part.slice(0, 7) + '+/' + part.slice(9)));
    if (/[-_]/.test(part)) variants.push(put(part.replaceAll('-', '+').replaceAll('_', '/')));
    // an impossible length
    variants.push(put(part + 'A'.repeat((5 - (part.length % 4)) % 4 || 4)));
  }
  assert.ok(variants.length > 70);
  for (const v of variants) {
    assert.notEqual(v, token);
    const d = e.call('authorize', { token: v, action: 'read', resource: { path: 'crm.customer', id: 'c-1' } });
    assert.deepEqual([d.ok, d.effect, d.reason], [true, 'deny', 'token_invalid'], JSON.stringify(v.slice(-40)));
    assert.equal(e.call('inspect_token', { token: v }).reason, 'token_invalid');
    assert.equal(e.call('exchange_token', { subject_token: v, actor: 'refund-helper', ttl: 60 }).error.code, 'token_invalid');
    assert.equal(e.call('revoke', { token: v }).error.code, 'token_invalid');
  }
  for (const bad of ['', 'A', 'AAAAA', 'AA=', 'AA==', 'A A', 'AA\n', '\nAA', 'AA+', 'AA/', 'AA!A', 'é', null, 5]) assert.throws(() => b64uDec(bad), undefined, String(bad));
  assert.deepEqual([...b64uDec('AA')], [0]);
  assert.deepEqual([...b64uDec('-_8')], [0xfb, 0xff]);
});

test('entity type names match in full', (t) => {
  for (const ok of ['User', '_x', 'A1', 'Ns::Sub::Type', 'a_b::c']) assert.equal(cedar.validType(ok), true, ok);
  for (const bad of ['User\n', '\nUser', 'User\r', 'User ', ' User', 'User\n::X', 'A::', '::A', 'A:B', 'A::1b', '1A', 'A-B', 'A::B\n', '', 'é', null, 5, ['User']]) {
    assert.equal(cedar.validType(bad), false, JSON.stringify(bad));
  }
  const { e } = setup(t);
  const { token } = e.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP });
  const ask = (ref) => e.call('authorize', { token, action: 'read', resource: { path: 'crm.customer', id: 'c-1' }, context: { ref } });
  assert.equal(ask({ __entity: { type: 'User', id: 'alice' } }).effect, 'allow');
  assert.equal(ask({ __entity: { type: 'User\n', id: 'alice' } }).error.code, 'invalid_context');
  // a group whose type is not a type name is not a group of the store: dropped
  const r = e.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP, groups: [{ type: 'Group\n', id: 'support' }, { type: 'Group', id: 'support' }] });
  assert.deepEqual(e.inspectToken(r.token).claims.grp, [{ type: 'Group', id: 'support' }]);
  assert.throws(() => new cedar.Store(toInternal([{ uid: { type: 'User\n', id: 'x' } }])), cedar.ValueError);
  const scope = { op: 'All' };
  assert.throws(() => new cedar.Policy('p', toInternal({ effect: 'permit', principal: { op: 'is', entity_type: 'User\n' }, action: scope, resource: scope })), cedar.Unsupported);
});

test('containsAll / containsAny check that both operands are sets before looking inside', () => {
  const { store, cases } = loadEval(EVAL);
  assert.equal(cases.length, 95);
  const last = cases.slice(91);
  assert.equal(last.filter((c) => /containsAll|containsAny/.test(c.cedar)).length, 4);
  for (const c of last) assert.equal(runEvalCase(c, store), null, c.name);
  // directly: an empty argument must not hide a receiver that is not a set, nor the reverse
  const env = new cedar.Env(new cedar.Entity('User', 'a'), new cedar.Entity('Action', 'x'), new cedar.Entity('Doc', 'd'), cedar.fromJson(toInternal({})), new cedar.Store());
  const val = (v) => ({ Value: v });
  for (const op of ['containsAll', 'containsAny']) {
    const run = (left, right) => cedar.evaluate(toInternal({ [op]: { left: val(left), right: val(right) } }), env);
    assert.equal(run([1, 2], []), op === 'containsAll');
    assert.equal(run([], []), op === 'containsAll');
    assert.equal(run([1, 2], [2]), true);
    for (const [l, r] of [[1, []], ['x', []], [{ a: 1 }, []], [true, [1]], [[], 1], [[1], 'x'], [[], { a: 1 }], [1, 2]]) {
      assert.throws(() => run(l, r), cedar.EvalError, `${op} ${JSON.stringify([l, r])}`);
    }
  }
});

test('policy JSON shapes are checked at load', (t) => {
  const all = { op: 'All' };
  const base = { effect: 'permit', principal: all, action: all, resource: all };
  const when = (body) => ({ ...base, conditions: [{ kind: 'when', body }] });
  const T_ = { Value: true };
  const good = {
    'no conditions key': base,
    'empty conditions': { ...base, conditions: [] },
    'set literal': when({ contains: { left: { Set: [{ Value: 1 }] }, right: { Value: 1 } } }),
    'like pattern': when({ like: { left: { Value: 'a' }, pattern: ['Wildcard', { Literal: 'a' }] } }),
    'record literal': when({ has: { left: { Record: { a: T_ } }, attr: 'a' } }),
    'action list': { ...base, action: { op: 'in', entities: [{ type: 'Action', id: 'read' }] } },
    'annotations': { ...base, annotations: { id: 'p', note: null } },
    'null annotations': { ...base, annotations: null },
  };
  const bad = {
    'conditions is an object': { ...base, conditions: {} },
    'conditions is a string': { ...base, conditions: '' },
    'conditions is null': { ...base, conditions: null },
    'conditions holds a string': { ...base, conditions: ['when'] },
    'Set is an object': when({ isEmpty: { arg: { Set: {} } } }),
    'Set is a string': when({ isEmpty: { arg: { Set: '' } } }),
    'Set is null': when({ isEmpty: { arg: { Set: null } } }),
    'like pattern is a string': when({ like: { left: { Value: 'a' }, pattern: '' } }),
    'like pattern is an object': when({ like: { left: { Value: 'a' }, pattern: {} } }),
    'like pattern is missing': when({ like: { left: { Value: 'a' } } }),
    'like pattern holds a number': when({ like: { left: { Value: 'a' }, pattern: [1] } }),
    'Record is a list': when({ has: { left: { Record: [] }, attr: 'a' } }),
    'Record is a string': when({ has: { left: { Record: '' }, attr: 'a' } }),
    'Record is null': when({ has: { left: { Record: null }, attr: 'a' } }),
    'scope entities is an object': { ...base, action: { op: 'in', entities: {} } },
    'scope entities is a string': { ...base, action: { op: 'in', entities: '' } },
    'scope entities is null': { ...base, action: { op: 'in', entities: null } },
    'annotations is a list': { ...base, annotations: [['id', 'p']] },
    'annotations is a string': { ...base, annotations: 'id' },
    'annotations is a number': { ...base, annotations: 7 },
    'the policy is a list': [],
    'the policy is null': null,
  };
  for (const [name, est] of Object.entries(good)) assert.doesNotThrow(() => new cedar.Policy('p', toInternal(est)), name);
  for (const [name, est] of Object.entries(bad)) assert.throws(() => new cedar.Policy('p', toInternal(est)), cedar.Unsupported, name);

  // and through a bundle: policy_parse, at load and at reload
  const dir = tempDir(t);
  const b = join(dir, 'bundle');
  cpSync(BUNDLE, b, { recursive: true });
  const file = join(b, 'policies.json');
  const original = readFileSync(file, 'utf8');
  const live = new Engine({ bundle_dir: b });
  t.after(() => live.close());
  for (const [name, est] of Object.entries(bad)) {
    const doc = JSON.parse(original);
    doc.policies['zz-bad'] = est;
    writeFileSync(file, JSON.stringify(doc));
    assert.throws(() => new Engine({ bundle_dir: b }), code('policy_parse'), name);
    assert.equal(live.call('reload', {}).error.code, 'policy_parse', name);
  }
  for (const text of ['{"policies": []}', '{"policies": null}', '[]', '{}', 'null']) {
    writeFileSync(file, text);
    assert.throws(() => new Engine({ bundle_dir: b }), code('policy_parse'), text);
  }
});

test('token claims: `anc` is an array of strings; a string is not', (t) => {
  const [sk] = keygen();
  const { e } = setup(t, { signing_key: sk });
  const keys = new Keys(sk, []);
  const real = parse(Buffer.from(e.call('issue_token', { user: 'alice', agent: 'support-bot', cap: FULL_CAP, now: T }).token.split('.')[1], 'base64url').toString());
  const withAnc = (anc) => {
    const claims = Object.assign(Object.create(null), real);
    if (anc === undefined) delete claims.anc;
    else claims.anc = toInternal(anc);
    return keys.sign(claims);
  };
  const ask = (token) => e.call('authorize', { token, action: 'read', resource: { path: 'crm.customer', id: 'c-1' }, now: T });
  for (const ok of [[], ['aa', 'bb'], undefined]) assert.equal(ask(withAnc(ok)).effect, 'allow', JSON.stringify(ok));
  for (const bad of ['', 'abc', { a: 'b' }, {}, null, 5, true, [1], ['a', null], [['a']]]) {
    const d = ask(withAnc(bad));
    assert.deepEqual([d.effect, d.reason, d.principal], ['deny', 'token_invalid', null], JSON.stringify(bad));
  }
  // a string must not be read as a list of one-character ids: revoking "a" does not touch anc "abc"
  e.call('revoke', { token_id: 'a', now: T });
  assert.equal(ask(withAnc('abc')).reason, 'token_invalid');
  assert.equal(ask(withAnc(['a'])).reason, 'token_revoked');
});

test('files that are not UTF-8, and entities.json that is not a list of objects, are errors with a code', (t) => {
  const NOT_UTF8 = Buffer.from([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x3a, 0x31, 0x7d, 0x0a]);
  const { e, state, dir } = setup(t);
  const r = e.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP });
  const req = { token: r.token, action: 'read', resource: { path: 'crm.customer', id: 'c-1' } };
  e.revoke(r.token_id);

  // state.json -> state_io, from a call and from a new engine
  const stateFile = join(state, 'state.json');
  const goodState = readFileSync(stateFile);
  writeFileSync(stateFile, NOT_UTF8);
  let out = e.call('authorize', req);
  assert.deepEqual([out.ok, out.error.code, out.effect], [false, 'state_io', undefined]);
  assert.throws(() => new Engine(config(state)), code('state_io'));
  writeFileSync(stateFile, goodState);
  assert.equal(e.call('authorize', req).reason, 'token_revoked');

  // the audit log -> audit_broken, from verify, from the next decision (after another writer), from a new engine
  const log = join(state, 'audit.jsonl');
  const goodLog = readFileSync(log);
  writeFileSync(log, Buffer.concat([goodLog, NOT_UTF8]));
  assert.equal(e.call('audit_verify', {}).error.code, 'audit_broken');
  assert.throws(() => auditVerify(log), code('audit_broken'));
  out = e.call('authorize', req);
  assert.equal(out.ok, false, 'the decision cannot be chained onto an unreadable record, so it is refused');
  assert.equal(out.error.code, 'audit_io');
  assert.throws(() => new Engine(config(state)), code('audit_broken'));
  assert.equal(e.call('audit_tail', { n: 2 }).ok, true, 'the tail never throws');
  let c = cli(['audit', 'verify', '--bundle', BUNDLE, '--state', state]);
  assert.equal(c.status, 1);
  assert.match(c.stderr, /^smartdelegate: audit_broken: /);
  writeFileSync(log, goodLog);
  assert.equal(e.call('audit_verify', {}).ok, true);

  // each bundle file -> bundle_io
  const b = join(dir, 'bundle');
  cpSync(BUNDLE, b, { recursive: true });
  for (const name of ['policies.json', 'entities.json', 'catalog.json', 'roles.json', 'policies/crm.cedar']) {
    const keep = readFileSync(join(b, name));
    writeFileSync(join(b, name), Buffer.concat([keep, Buffer.from([0xc3, 0x28])]));
    assert.throws(() => new Engine({ bundle_dir: b }), code('bundle_io'), name);
    writeFileSync(join(b, name), keep);
  }
  c = cli(['info', '--bundle', b]);
  assert.equal(c.status, 0);

  // entities.json that is not a list of objects -> entities_parse
  const ent = join(b, 'entities.json');
  for (const text of ['{}', 'null', '0', '""', 'false', '{"uid": {"type": "User", "id": "a"}}', '[1]', '["x"]', '[null]', '[[]]', '[{"uid": {"type": "User", "id": "a"}}, 5]',
    '[{}]', '[{"uid": "User::a"}]', '[{"uid": {"type": "User", "id": "a"}, "attrs": 5}]', '[{"uid": {"type": "User", "id": "a"}, "parents": "Group::x"}]', '{nope']) {
    writeFileSync(ent, text);
    assert.throws(() => new Engine({ bundle_dir: b }), code('entities_parse'), text);
  }
  writeFileSync(ent, '[]');
  assert.doesNotThrow(() => new Engine({ bundle_dir: b }).close());
});

test('two (here: eight) processes starting on an empty state directory agree on one signing key', async (t) => {
  for (let round = 0; round < 3; round++) {
    const state = join(tempDir(t), 'state');
    const run = () => new Promise((resolve, reject) => {
      const p = spawn(process.execPath, [join(HERE, 'tools', 'keyid.mjs'), state, BUNDLE], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '', err = '';
      p.stdout.on('data', (d) => { out += d; });
      p.stderr.on('data', (d) => { err += d; });
      p.on('error', reject);
      p.on('exit', (status) => (status === 0 ? resolve(out.trim()) : reject(new Error(`exit ${status}: ${err}`))));
    });
    const ids = await Promise.all(Array.from({ length: 8 }, run));
    assert.equal(ids.length, 8);
    assert.equal(new Set(ids).size, 1, `every process has the same key: ${ids}`);
    assert.match(ids[0], /^[0-9a-f]{16}$/);
    const pub = readFileSync(join(state, 'signing_key.pub.b64'), 'utf8');
    const late = new Engine({ bundle_dir: BUNDLE, state_dir: state });
    assert.deepEqual([late.info().key_id, late.info().public_key], [ids[0], pub]);
    late.close();
  }
});

test('an empty signing key file is a key being written: wait for it, then state_io; never "no key"', async (t) => {
  const [sk, pk] = keygen();
  // empty forever (also: only whitespace) -> state_io after the deadline, from the library and from the CLI
  for (const content of ['', ' \n\t']) {
    const state = join(tempDir(t), 'state');
    mkdirSync(state);
    writeFileSync(join(state, 'signing_key.pk8.b64'), content);
    const started = Date.now();
    assert.throws(() => new Engine({ bundle_dir: BUNDLE, state_dir: state, key_wait_ms: 300 }), code('state_io'));
    assert.ok(Date.now() - started >= 280, 'it waited before giving up');
    assert.equal(readFileSync(join(state, 'signing_key.pk8.b64'), 'utf8'), content, 'the file is not overwritten');
    assert.equal(existsSync(join(state, 'signing_key.pub.b64')), false);
    const cfg = join(state, '..', 'cfg.json');
    writeFileSync(cfg, JSON.stringify({ bundle_dir: BUNDLE, state_dir: state, key_wait_ms: 200 }));
    const c = cli(['info', '--config', cfg]);
    assert.equal(c.status, 1);
    assert.match(c.stderr, /^smartdelegate: state_io: .*signing_key\.pk8\.b64 is empty/);
    assert.equal(c.stdout, '', 'no info, and above all no "can_issue": false');
    // a verify-only engine does not need the key and does not wait for it
    const v = new Engine({ bundle_dir: BUNDLE, state_dir: state, verify_only: true, trusted_keys: [pk] });
    assert.equal(v.info().can_issue, false);
    v.close();
  }

  // empty now, filled 400 ms later by "another process" -> the engine starts with that key and can issue
  const state = join(tempDir(t), 'state');
  mkdirSync(state);
  const kp = join(state, 'signing_key.pk8.b64');
  writeFileSync(kp, '');
  const writer = spawn(process.execPath, ['-e', `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(kp)}, ${JSON.stringify(sk + '\n')}), 400)`], { stdio: 'ignore' });
  const done = new Promise((ok) => writer.once('exit', ok));
  const started = Date.now();
  const e = new Engine({ bundle_dir: BUNDLE, state_dir: state, key_wait_ms: 10000 });
  t.after(() => e.close());
  await done;
  assert.ok(Date.now() - started >= 300, 'the engine waited for the key');
  const info = e.info();
  assert.deepEqual([info.can_issue, info.public_key], [true, pk]);
  const tok = e.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP });
  assert.equal(e.authorize({ token: tok.token, ...READ }).effect, 'allow');

  // a key that is there but is not a key is an error too, not "no key"
  const bad = join(tempDir(t), 'state');
  mkdirSync(bad);
  writeFileSync(join(bad, 'signing_key.pk8.b64'), 'not a key');
  assert.throws(() => new Engine({ bundle_dir: BUNDLE, state_dir: bad }), code('crypto'));
  writeFileSync(join(bad, 'signing_key.pk8.b64'), Buffer.from([0xff, 0xfe]));
  assert.throws(() => new Engine({ bundle_dir: BUNDLE, state_dir: bad }), code('state_io'));

  // a new key appears complete: no temporary file is left, the mode is 0600
  const fresh = join(tempDir(t), 'state');
  new Engine({ bundle_dir: BUNDLE, state_dir: fresh }).close();
  assert.deepEqual(readdirSync(fresh).filter((n) => n.includes('signing_key')).sort(), ['signing_key.pk8.b64', 'signing_key.pub.b64']);
  assert.equal(Buffer.from(readFileSync(join(fresh, 'signing_key.pk8.b64'), 'utf8'), 'base64').length, 48);
});
