// (4) Interoperability with the Python reference: tokens, signed bundles,
// audit logs and canonical JSON, in both directions.
//
// Skipped, with the reason, when python3 or its `cryptography` package is not
// available. Set PYTHON to use another interpreter.
import assert from 'node:assert/strict';
import { cpSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { canonInternal } from '../lib/canon.mjs';
import { Engine, auditVerify, bundleManifest, bundleVersion, keygen, signBundle } from '../lib/index.mjs';
import { parse, stringify, write } from '../lib/json.mjs';
import { differential } from '../tools/differential.mjs';
import { BUNDLE, FULL_CAP, IDP, PYTHON, T, cli, config, makeIdTokens, oidcScenarios, py, pyCode, referenceUnavailable, tempDir } from '../tools/support.mjs';

const skip = referenceUnavailable() ?? false;
if (skip) console.error(`SKIPPED: ${skip}`);

function setup(t) {
  const dir = tempDir(t);
  const write = (name, value) => {
    const p = join(dir, name);
    writeFileSync(p, typeof value === 'string' ? value : stringify(value));
    return p;
  };
  /** The reference CLI with a config; returns status and parsed stdout. */
  const python = (cfg, ...args) => {
    const r = py([...args, '--config', cfg]);
    let json = null;
    try { json = JSON.parse(r.stdout); } catch { /* --raw or an error */ }
    return { ...r, json, text: r.stdout.trim() };
  };
  const node = (cfg, ...args) => {
    const r = cli([...args, '--config', cfg]);
    let json = null;
    try { json = JSON.parse(r.stdout); } catch { /* --raw or an error */ }
    return { ...r, json, text: r.stdout.trim() };
  };
  const engines = [];
  t.after(() => engines.forEach((e) => e.close()));
  const engine = (cfg) => {
    const e = new Engine(cfg);
    engines.push(e);
    return e;
  };
  return { dir, write, python, node, engine };
}

const READ = ['authorize', '--action', 'read', '--resource', 'crm.customer/c-1'];

test('both ports report the same version of the spec bundle', { skip }, (t) => {
  const { write, python } = setup(t);
  const info = python(write('p.json', { bundle_dir: BUNDLE }), 'info');
  assert.equal(info.status, 0, info.stderr);
  assert.equal(info.json.policy_version, bundleVersion(bundleManifest(BUNDLE)));
  const mine = new Engine({ bundle_dir: BUNDLE });
  t.after(() => mine.close());
  assert.equal(mine.info().policy_version, info.json.policy_version);
  assert.deepEqual(mine.info().roles, info.json.roles);
  assert.deepEqual(mine.info().resources, info.json.resources);
  assert.equal(mine.info().policies, info.json.policies);
});

test('a token issued by this port is accepted by the reference (trusted_keys, verify_only)', { skip }, (t) => {
  const { dir, write, python, engine } = setup(t);
  const mine = engine(config(join(dir, 'node-state')));
  const pcfg = write('p.json', config(join(dir, 'py-state'), { verify_only: true, trusted_keys: [mine.info().public_key] }));

  const plain = mine.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP, tenant: 'acme', task: 'ticket-1' });
  let r = python(pcfg, ...READ, '--token', plain.token);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.deepEqual([r.json.effect, r.json.principal.user, r.json.principal.tenant, r.json.principal.task, r.json.principal.token_id],
    ['allow', 'alice', 'acme', 'ticket-1', plain.token_id]);

  // a role token with live membership (`grp`)
  const role = mine.issueToken({ user: 'bob', agent: 'support-bot', role: 'support-agent', groups: ['supervisors', 'support', 'no-such-group'] });
  r = python(pcfg, 'token', 'inspect', '--token', role.token);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(r.json.valid, true);
  assert.equal(r.json.claims.role, 'support-agent');
  assert.deepEqual(r.json.claims.grp, [{ type: 'Group', id: 'supervisors' }, { type: 'Group', id: 'support' }]);
  assert.deepEqual(r.json.claims, mine.inspectToken(role.token).claims, 'both ports read the same claims');
  r = python(pcfg, ...READ, '--token', role.token);
  assert.deepEqual([r.status, r.json.effect, r.json.principal.role], [0, 'allow', 'support-agent']);

  // the same decisions, field by field, for a set of requests
  const requests = [
    ['read', 'crm.customer/c-1', null],
    ['update', 'crm.customer/c-1', null],
    ['delete', 'crm.customer/c-1', null],
    ['read', 'hr.salary/s-1', null],
    ['create', 'billing.refund/r-1', { spend: { currency: 'EUR', amount: 5000 } }],
    ['create', 'billing.refund/r-2', { spend: { currency: 'EUR', amount: 15000 } }],
    ['create', 'billing.refund/r-3', { spend: { currency: 'USD', amount: 1 } }],
    ['read', 'nothing.here/x', null],
  ];
  for (const [action, resource, context] of requests) {
    const args = ['authorize', '--action', action, '--resource', resource, '--token', role.token, '--dry-run'];
    if (context) args.push('--context', stringify(context));
    const theirs = python(pcfg, ...args).json;
    const [path, id] = resource.split('/');
    const ours = mine.call('authorize', { token: role.token, action, resource: { path, id }, context: context ?? undefined, dry_run: true });
    for (const k of ['ok', 'effect', 'reason', 'rule', 'policies', 'policy_version', 'principal', 'obligations', 'approval']) {
      assert.deepEqual(ours[k], theirs[k], `${action} ${resource}: ${k}`);
    }
  }

  // a token signed by a key the reference was not told about is refused
  const stranger = engine(config(join(dir, 'other-state')));
  const foreign = stranger.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP });
  r = python(pcfg, ...READ, '--token', foreign.token);
  assert.deepEqual([r.status, r.json.reason], [2, 'token_invalid']);
});

test('a token issued by the reference is accepted by this port (trusted_keys, verify_only)', { skip }, (t) => {
  const { dir, write, python, engine } = setup(t);
  const pcfg = write('p.json', config(join(dir, 'py-state')));
  const cap = write('cap.json', FULL_CAP);
  let r = python(pcfg, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + cap, '--tenant', 'acme', '--raw');
  assert.equal(r.status, 0, r.stderr);
  const plain = r.text;
  r = python(pcfg, 'token', 'issue', '--user', 'bob', '--agent', 'support-bot', '--role', 'supervisor', '--groups', 'supervisors,support', '--task', 'escalation-9', '--raw');
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const role = r.text;
  const pub = python(pcfg, 'info').json.public_key;

  const mine = engine(config(join(dir, 'node-state'), { verify_only: true, trusted_keys: [pub] }));
  let d = mine.authorize({ token: plain, action: 'read', resource: 'crm.customer', id: 'c-1' });
  assert.deepEqual([d.effect, d.principal.user, d.principal.tenant], ['allow', 'alice', 'acme']);
  const i = mine.inspectToken(role);
  assert.equal(i.valid, true);
  assert.deepEqual([i.claims.role, i.claims.task, i.user], ['supervisor', 'escalation-9', 'bob']);
  assert.deepEqual(i.claims.grp, [{ type: 'Group', id: 'supervisors' }, { type: 'Group', id: 'support' }]);
  assert.deepEqual(i.claims, python(pcfg, 'token', 'inspect', '--token', role).json.claims);
  d = mine.authorize({ token: role, action: 'create', resource: 'billing.refund', id: 'r-1', context: { spend: { currency: 'EUR', amount: 30000 } }, dry_run: true });
  const theirs = python(pcfg, 'authorize', '--action', 'create', '--resource', 'billing.refund/r-1', '--context', '{"spend":{"currency":"EUR","amount":30000}}', '--token', role, '--dry-run').json;
  for (const k of ['effect', 'reason', 'rule', 'policies', 'principal', 'obligations']) assert.deepEqual(d[k], theirs[k], k);
  assert.equal(d.principal.role, 'supervisor');
  assert.throws(() => mine.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP }), { code: 'no_signing_key' });
  // an engine that does not trust the reference's key refuses its tokens
  const untrusting = engine(config(join(dir, 'node-state-2')));
  assert.equal(untrusting.authorize({ token: plain, action: 'read', resource: 'crm.customer', id: 'c-1' }).reason, 'token_invalid');
});

test('one state directory used in turn: shared signing key, delegation, revocation, spend', { skip }, (t) => {
  const { dir, write, python, node } = setup(t);
  const cap = write('cap.json', FULL_CAP);
  const narrow = write('narrow.json', { actions: ['read'], resources: ['crm.customer/c-1'], deny_labels: ['pii'] });
  const spend = write('spend.json', { spend: { currency: 'EUR', amount: 8000 } });
  const state = join(dir, 'state');
  const cfg = write('shared.json', config(state));
  for (const [issuer, verifier, name] of [[python, node, 'reference issues'], [node, python, 'this port issues']]) {
    rmSync(state, { recursive: true, force: true });     // a fresh signing key, written by the issuer's port
    let r = issuer(cfg, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + cap, '--raw');
    assert.equal(r.status, 0, name + r.stderr);
    const token = r.text;
    r = verifier(cfg, ...READ, '--token', token);
    assert.equal(r.status, 0, name + r.stdout + r.stderr);
    assert.deepEqual([r.json.effect, r.json.principal.user], ['allow', 'alice'], name);
    assert.equal(issuer(cfg, 'info').json.key_id, verifier(cfg, 'info').json.key_id, 'both read the same key file');
    // the other port can delegate from it and revoke it
    r = verifier(cfg, 'token', 'exchange', '--token', token, '--actor', 'refund-helper', '--cap', '@' + narrow, '--ttl', '300', '--raw');
    assert.equal(r.status, 0, name + r.stdout + r.stderr);
    const child = r.text;
    assert.deepEqual(issuer(cfg, ...READ, '--token', child).json.principal.chain, ['support-bot', 'refund-helper'], name);
    // spend recorded by one port counts in the other: 3 x 8000 > 20000
    const refund = ['authorize', '--action', 'create', '--resource', 'billing.refund/r-1', '--context', '@' + spend, '--token', token];
    assert.equal(verifier(cfg, ...refund).status, 0, name);
    assert.equal(issuer(cfg, ...refund).status, 0, name);
    assert.equal(verifier(cfg, ...refund).json.reason, 'budget_exceeded', name);
    assert.equal(issuer(cfg, ...refund).json.reason, 'budget_exceeded', name);
    assert.equal(verifier(cfg, 'token', 'revoke', '--token', token).status, 0, name);
    assert.equal(issuer(cfg, ...READ, '--token', child).json.reason, 'token_revoked', name);
    assert.equal(verifier(cfg, ...READ, '--token', token).json.reason, 'token_revoked', name);
    // one audit chain, written by both, valid for both
    for (const port of [python, node]) {
      r = port(cfg, 'audit', 'verify');
      assert.equal(r.status, 0, name + r.stdout + r.stderr);
      assert.equal(r.json.records, 11, name);
    }
    assert.equal(python(cfg, 'audit', 'verify').json.head, node(cfg, 'audit', 'verify').json.head);
  }
});

test('a user revoked in one port is revoked in the other', { skip }, (t) => {
  const { dir, write, python, node } = setup(t);
  const cap = write('cap.json', FULL_CAP);
  for (const [first, second, name] of [[python, node, 'reference revokes'], [node, python, 'this port revokes']]) {
    const cfg = write(`s-${name.replace(' ', '-')}.json`, config(join(dir, name.replace(' ', '-'))));
    const issue = (port, user) => port(cfg, 'token', 'issue', '--user', user, '--agent', 'support-bot', '--cap', '@' + cap, '--task', 'ticket-9').json;
    const a = issue(second, 'alice'), b = issue(first, 'bob');
    assert.deepEqual([a.task, b.task], ['ticket-9', 'ticket-9'], name);
    const child = second(cfg, 'token', 'exchange', '--token', a.token, '--actor', 'refund-helper', '--ttl', '300').json;
    assert.equal(child.task, 'ticket-9', name);
    const r = first(cfg, 'token', 'revoke', '--user', 'alice');
    assert.equal(r.status, 0, name + r.stderr);
    assert.deepEqual(Object.keys(r.json), ['revoked_user', 'issued_up_to', 'ok'], name);
    for (const port of [first, second]) {
      assert.equal(port(cfg, ...READ, '--token', a.token).json.reason, 'token_revoked', name);
      assert.equal(port(cfg, ...READ, '--token', child.token).json.reason, 'token_revoked', name);
      assert.equal(port(cfg, ...READ, '--token', b.token).json.effect, 'allow', name);
    }
    assert.deepEqual(JSON.parse(readFileSync(join(dir, name.replace(' ', '-'), 'state.json'), 'utf8')).revoked_users, { alice: r.json.issued_up_to }, name);
    assert.equal(python(cfg, 'audit', 'verify').json.head, node(cfg, 'audit', 'verify').json.head, name);
    assert.equal(python(cfg, 'audit', 'tail', '-n', '8').stdout, node(cfg, 'audit', 'tail', '-n', '8').stdout, name);
  }
});

test('an ancestor budget is enforced by a verify-only engine of the other port with its own state (`lim`)', { skip }, (t) => {
  const { dir, write, python, node } = setup(t);
  const cap = (EUR) => ({ actions: ['create'], resources: ['billing.refund/*'], budget: { EUR } });
  const parentCap = write('parent.json', cap(10000)), kidCap = write('kid.json', cap(6000));
  const spend = write('spend.json', { spend: { currency: 'EUR', amount: 5000 } });
  for (const [issuer, verifier, name] of [[node, python, 'this port issues, the reference verifies'], [python, node, 'the reference issues, this port verifies']]) {
    const tag = issuer === node ? 'n' : 'p';
    const icfg = write(`issuer-${tag}.json`, config(join(dir, `issuer-${tag}`)));
    const parent = issuer(icfg, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + parentCap).json;
    assert.equal(parent.ok, true, name);
    const kids = [1, 2, 3].map(() => issuer(icfg, 'token', 'exchange', '--token', parent.token, '--actor', 'refund-helper', '--cap', '@' + kidCap, '--ttl', '300').json);
    const vcfg = write(`verifier-${tag}.json`, config(join(dir, `verifier-${tag}`), { verify_only: true, trusted_keys: [issuer(icfg, 'info').json.public_key] }));
    // both ports read the same `lim` out of the token
    for (const port of [issuer, verifier]) {
      assert.deepEqual(port(port === issuer ? icfg : vcfg, 'token', 'inspect', '--token', kids[0].token).json.claims.lim, { [parent.token_id]: { EUR: 10000 } }, name);
    }
    const ask = (k) => verifier(vcfg, 'authorize', '--action', 'create', '--resource', 'billing.refund/r', '--context', '@' + spend, '--token', k.token);
    assert.equal(ask(kids[0]).json.effect, 'allow', name);
    assert.equal(ask(kids[1]).json.effect, 'allow', name);
    const third = ask(kids[2]);
    assert.deepEqual([third.status, third.json.effect, third.json.reason], [2, 'deny', 'budget_exceeded'], name);
    // the verifier's state knows the spend but not the limit: it came from the token
    const state = JSON.parse(readFileSync(join(dir, `verifier-${tag}`, 'state.json'), 'utf8'));
    assert.equal(state.ledger[parent.token_id].EUR, 10000, name);
    assert.deepEqual(state.limits, {}, name);
  }
});

test('an approval id is the same in both ports (canonical JSON of the request)', { skip }, (t) => {
  const { dir, write, python, node } = setup(t);
  const cfg = write('shared.json', config(join(dir, 'state')));
  const cap = write('cap.json', { ...FULL_CAP, budget: { EUR: 100000 } });
  const token = node(cfg, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + cap, '--tenant', 'ącme', '--raw').text;
  // key order, a 64-bit integer, non-ASCII, a line separator, a control character, an astral key that sorts last
  const context = write('ctx.json', '{"zeta": [3, 1, 2], "spend": {"currency": "EUR", "amount": 15000}, "big": 9223372036854775807, '
    + '"neg": -9223372036854775808, "note": "Zażółć \\u2028 \\u0001\\t\\" \\\\ 😀", "\\ud83d\\ude00": true, "\\uff5e": {"b": "", "a": []}, "10": 1, "9": 2}');
  const args = ['authorize', '--action', 'create', '--resource', 'billing.refund/r-ü', '--context', '@' + context, '--token', token];
  const ours = node(cfg, ...args, '--dry-run');
  const theirs = python(cfg, ...args, '--dry-run');
  assert.deepEqual([ours.status, ours.json.reason], [2, 'approval_required'], ours.stdout);
  assert.deepEqual([theirs.status, theirs.json.reason], [2, 'approval_required'], theirs.stdout + theirs.stderr);
  assert.match(ours.json.approval.id, /^[0-9a-f]{24}$/);
  assert.equal(ours.json.approval.id, theirs.json.approval.id);
  // requested in one port, approved in the other, consumed in the first
  assert.equal(node(cfg, ...args).json.approval.id, ours.json.approval.id);
  assert.equal(python(cfg, 'approve', ours.json.approval.id, '--by', 'bob').status, 0);
  const done = node(cfg, ...args);
  assert.deepEqual([done.status, done.json.obligations.approved], [0, { id: ours.json.approval.id, by: 'bob' }]);
  assert.equal(python(cfg, ...args).json.reason, 'approval_required', 'the approval was used up');
  assert.equal(python(cfg, 'audit', 'verify').json.records, 5);
});

test('an approval id covers resource.attrs and is the same in both ports', { skip }, (t) => {
  const { dir, write, python, node } = setup(t);
  const cfg = write('shared.json', config(join(dir, 'state')));
  const token = node(cfg, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + write('cap.json', { ...FULL_CAP, budget: { EUR: 1000000 } }), '--raw').text;
  const context = write('ctx.json', { spend: { currency: 'EUR', amount: 15000 } });
  const id = (port, attrs) => {
    const args = ['authorize', '--action', 'create', '--resource', 'billing.refund/r-1', '--context', '@' + context, '--token', token, '--dry-run'];
    if (attrs !== undefined) args.push('--attrs', '@' + write('attrs.json', attrs));
    const r = port(cfg, ...args);
    assert.deepEqual([r.status, r.json?.reason], [2, 'approval_required'], r.stdout + r.stderr);
    assert.match(r.json.approval.id, /^[0-9a-f]{24}$/);
    return r.json.approval.id;
  };
  // nested object, non-ASCII, a line separator, integers beyond 2^53 and at the i64 edges, sets, an astral key
  const rich = '{"employee": "emp-1", "owner": {"name": "Zażółć 😀 \u2028", "tags": ["b", "a", "b"], "deep": {"z": 1, "a": {"n": -9223372036854775808}}}, '
    + '"big": 9223372036854775807, "past53": 9007199254740993, "flag": true, "\ud83d\ude00": "astral key", "\uff5e": "bmp key", "10": "x", "9": "y"}';
  // the same attributes with every object's members in another order
  const shuffled = '{"9": "y", "\uff5e": "bmp key", "flag": true, "10": "x", "past53": 9007199254740993, "\ud83d\ude00": "astral key", "big": 9223372036854775807, '
    + '"owner": {"deep": {"a": {"n": -9223372036854775808}, "z": 1}, "tags": ["b", "a", "b"], "name": "Zażółć 😀 \u2028"}, "employee": "emp-1"}';
  const variants = {
    'no attrs': undefined,
    'empty attrs': '{}',
    rich,
    shuffled,
    'another employee': rich.replace('emp-1', 'emp-2'),
    'another nested value': rich.replace('"z": 1', '"z": 2'),
    'big integer off by one': rich.replace('9007199254740993', '9007199254740992'),
    'list order': rich.replace('["b", "a", "b"]', '["a", "b", "b"]'),
    'one attribute': '{"employee": "emp-1"}',
  };
  const ids = {};
  for (const [name, attrs] of Object.entries(variants)) {
    const ours = id(node, attrs), theirs = id(python, attrs);
    assert.equal(ours, theirs, `both ports compute the same approval id: ${name}`);
    ids[name] = ours;
  }
  assert.equal(ids['no attrs'], ids['empty attrs'], 'absent attrs are {}');
  assert.match(ids.rich, /^[0-9a-f]{24}$/);
  assert.equal(ids.rich, ids.shuffled, 'member order does not matter');
  const distinct = Object.entries(ids).filter(([name]) => name !== 'empty attrs' && name !== 'shuffled').map(([, v]) => v);
  assert.equal(new Set(distinct).size, distinct.length, 'every other difference in the attributes is a different approval');

  // an approval given (by the reference) for emp-1 is not consumed by the same request about emp-2
  const refund = (port, attrs) => port(cfg, 'authorize', '--action', 'create', '--resource', 'billing.refund/r-1', '--context', '@' + context, '--token', token,
    '--attrs', '@' + write('attrs.json', attrs));
  const pending = refund(node, variants['one attribute']).json.approval.id;
  assert.equal(pending, ids['one attribute']);
  assert.equal(python(cfg, 'approve', pending, '--by', 'bob').status, 0);
  for (const port of [node, python]) assert.equal(refund(port, '{"employee": "emp-2"}').json.reason, 'approval_required');
  const used = refund(python, variants['one attribute']);
  assert.deepEqual([used.status, used.json.obligations.approved], [0, { id: pending, by: 'bob' }]);
  assert.equal(refund(node, variants['one attribute']).json.reason, 'approval_required', 'and it was good for one call');
});

test('filtering gives the same data in both ports', { skip }, (t) => {
  const { dir, write, python, node } = setup(t);
  const cfg = write('shared.json', config(join(dir, 'state')));
  const cap = write('cap.json', FULL_CAP);
  const token = python(cfg, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + cap, '--raw').text;
  const data = write('data.json', [
    { id: 'c-1', name: 'Ada', email: 'ada@example.com', ssn: '123-45-6789', region: 'EU', tier: 'gold', notes: 'vip', unlisted: 1,
      addresses: [{ city: 'Wien', geo: { lat: 48 }, big: 12345678901234567890n, ratio: 0.25 }, 'loose', 7], card: { last4: '4242', number: '4242424242424242', extra: true }, score: 1.5 },
    { id: 'c-2', region: 'US', name: 'Bob' },
    { id: 'c-3', region: 'EU', card: 'not an object', addresses: 'nor a list' },
    'not a record', 42, null, [],
  ]);
  for (const extra of [[], ['--strict']]) {
    const args = ['authorize', '--action', 'read', '--resource', 'crm.customer/c-1', '--token', token, '--data', '@' + data, '--dry-run', ...extra];
    const ours = node(cfg, ...args), theirs = python(cfg, ...args);
    assert.equal(ours.status, theirs.status, ours.stdout + theirs.stderr);
    // compared as text, so integers beyond 2^53 and floats are compared exactly
    const view = (r) => {
      const v = parse(r.stdout);
      return canonInternal({ data: v.data, masked: v.masked ?? null, rows_dropped: v.rows_dropped ?? null, obligations: v.obligations, effect: v.effect, reason: v.reason });
    };
    assert.equal(view(ours), view(theirs));
    if (!extra.length) assert.ok(view(ours).includes('"big":12345678901234567890,"city":"Wien","ratio":0.25'), view(ours));
  }
});

test('echoed data keeps its member order in both ports, also for integer-like keys', { skip }, (t) => {
  const { dir, write, python, node } = setup(t);
  const cfg = write('shared.json', config(join(dir, 'state')));
  const token = python(cfg, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + write('cap.json', FULL_CAP), '--raw').text;
  const data = write('data.json', '[{"region":"EU","id":"c","10":0,"addresses":[{"b":1,"10":2,"9":3,"geo":{"x":1},"a":{"3":1,"k":2,"1":3}},{"2":1,"1":2}],"email":"e"}]');
  const args = ['authorize', '--action', 'read', '--resource', 'crm.customer/c-1', '--token', token, '--data', '@' + data, '--dry-run'];
  const slice = (r) => r.stdout.slice(r.stdout.indexOf('"data"'), r.stdout.indexOf('"masked"')).replace(/\s+/g, '');
  const ours = slice(node(cfg, ...args)), theirs = slice(python(cfg, ...args));
  assert.equal(ours, '"data":[{"region":"EU","id":"c","addresses":[{"b":1,"10":2,"9":3,"a":{"3":1,"k":2,"1":3}},{"2":1,"1":2}],"email":"e"}],');
  assert.equal(ours, theirs);
  const ob = write('ob.json', '{"obligations":{"fields":{"allow":["b","10","9","a"],"redact":["5"]}},"data":{"b":1,"10":2,"5":0,"9":3,"zz":0,"a":4}}');
  const a = node(cfg, 'call', 'apply_obligations', '--input', '@' + ob), b = python(cfg, 'call', 'apply_obligations', '--input', '@' + ob);
  assert.equal(a.stdout, b.stdout);
  assert.ok(a.stdout.replace(/\s+/g, '').includes('"data":{"b":1,"10":2,"5":"[REDACTED]","9":3,"a":4}'), a.stdout);
});

test('the audit tail is the same in both ports when records hold U+2028 and friends', { skip }, (t) => {
  const { dir, write, python, node, engine } = setup(t);
  const state = join(dir, 'state');
  const cfg = write('shared.json', config(state));
  const mine = engine(config(state));
  for (const sep of ['\u2028', '\u2029', '\u0085', '\u000b', '\u001c']) mine.call('authorize', { token: 'x', action: `re${sep}ad`, resource: { path: 'crm.customer', id: 'c-1' } });
  const theirs = python(cfg, 'audit', 'tail', '-n', '3');
  assert.equal(theirs.status, 0, theirs.stderr);
  assert.equal(theirs.stdout.trim().split('\n').length, 3);
  assert.equal(node(cfg, 'audit', 'tail', '-n', '3').stdout, theirs.stdout);
  // the reference appends after such a record, and this port's open engine chains onto that
  assert.equal(python(cfg, 'authorize', '--action', 're\u2028ad', '--resource', 'crm.customer/c-1', '--token', 'x').status, 2);
  assert.equal(mine.call('authorize', { token: 'x', action: 'read', resource: { path: 'crm.customer', id: 'c-1' } }).reason, 'token_invalid');
  assert.deepEqual([python(cfg, 'audit', 'verify').json.records, node(cfg, 'audit', 'verify').json.records], [7, 7]);
});

test('a bundle signed by this port loads in the reference, and the reverse; tampering is caught', { skip }, (t) => {
  const { dir, write, python, node } = setup(t);
  for (const [signer, loader, name] of [[node, python, 'node signs'], [python, node, 'reference signs']]) {
    const b = join(dir, `bundle-${name.replace(' ', '-')}`);
    cpSync(BUNDLE, b, { recursive: true });
    const prefix = join(dir, `key-${name.replace(' ', '-')}`);
    const signerCli = signer === node ? cli : py;
    assert.equal(signerCli(['bundle', 'keygen', prefix]).status, 0, name);
    let r = signerCli(['bundle', 'sign', '--key', prefix + '.key', '--bundle', b]);
    assert.equal(r.status, 0, name + r.stderr);
    const pub = readFileSync(prefix + '.pub', 'utf8');
    const cfg = write(`signed-${name.replace(' ', '-')}.json`, { bundle_dir: b, bundle_public_key: pub });
    for (const port of [loader, signer]) {
      r = port(cfg, 'info');
      assert.equal(r.status, 0, name + r.stdout + r.stderr);
      assert.match(r.json.bundle_signed_by, /^[0-9a-f]{16}$/);
    }
    assert.equal(loader(cfg, 'info').json.policy_version, signer(cfg, 'info').json.policy_version, name);
    assert.equal(loader(cfg, 'info').json.bundle_signed_by, signer(cfg, 'info').json.bundle_signed_by, name);

    // Ed25519 is deterministic: signing the same bundle with the same key in
    // the other port must give byte-identical signature data
    const first = JSON.parse(readFileSync(join(b, 'bundle.sig.json'), 'utf8'));
    const loaderCli = loader === node ? cli : py;
    assert.equal(loaderCli(['bundle', 'sign', '--key', prefix + '.key', '--bundle', b]).status, 0, name);
    assert.deepEqual(JSON.parse(readFileSync(join(b, 'bundle.sig.json'), 'utf8')), first, name);

    const entities = join(b, 'entities.json');
    writeFileSync(entities, readFileSync(entities, 'utf8').replace('"region": "EU"', '"region": "US"'));
    for (const port of [loader, signer]) {
      r = port(cfg, 'info');
      assert.notEqual(r.status, 0, name);
      assert.match(r.stdout + r.stderr, /bundle_signature/, name);
    }
  }
  // a key pair made by one port works in the other
  const [sk, pk] = keygen();
  const b = join(dir, 'bundle-lib');
  cpSync(BUNDLE, b, { recursive: true });
  const sig = signBundle(b, sk);
  const r = python(write('lib.json', { bundle_dir: b, bundle_public_key: pk }), 'info');
  assert.deepEqual([r.status, r.json.bundle_signed_by, r.json.policy_version], [0, sig.key_id, sig.version]);
});

test('an audit log written by this port verifies in the reference, and the reverse; tampering is detected', { skip }, (t) => {
  const { dir, write, python, node, engine } = setup(t);
  const state = join(dir, 'state');
  const log = join(state, 'audit.jsonl');
  const cfg = write('shared.json', config(state));
  const mine = engine(config(state));
  const { token, token_id } = mine.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP, task: 'tâche ✓' });
  const call = (action, id, context) => mine.call('authorize', { token, action, resource: { path: 'crm.customer', id }, context });
  // records with text that exercises the canonical form
  call('read', 'c-1', { n: 9223372036854775807n, s: 'ünï \u2028 \u0007 "q" \\ 😀', l: [true, false, -1] });
  call('lés\n\t\u0001\u2029😀', 'c-\u00e9', undefined);
  call('read', 'c-1', { f: 1.5 });                       // an error: not recorded
  mine.call('filter', { token, action: 'read', resource: { path: 'crm.customer', id: 'c-1' }, data: { id: 'c-1', ssn: 'x' } });
  mine.call('authorize', { token: 'garbage', action: 'read', resource: { path: 'crm.customer', id: 'c-1', attrs: { x: 1.5, y: 1e300 } }, context: { z: 0.1 } });
  mine.revoke(token_id);
  let r = python(cfg, 'audit', 'verify');
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(r.json.records, 6);
  assert.equal(r.json.head, mine.call('audit_verify', {}).head);

  // the reference appends; this port's open engine chains onto it, and so on
  assert.equal(python(cfg, ...READ, '--token', token).json.reason, 'token_revoked');
  assert.equal(mine.call('audit_verify', {}).records, 7);
  mine.call('authorize', { token, action: 'read', resource: { path: 'crm.customer', id: 'c-2' } });
  r = python(cfg, 'token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + write('cap.json', FULL_CAP), '--task', 'zadanie-ł', '--raw');
  assert.equal(r.status, 0, r.stderr);
  mine.call('authorize', { token: r.text, action: 'read', resource: { path: 'crm.customer', id: 'c-3' } });
  const theirs = python(cfg, 'audit', 'verify');
  assert.deepEqual([theirs.status, theirs.json.records], [0, 10], theirs.stdout + theirs.stderr);
  const ours = node(cfg, 'audit', 'verify');
  assert.deepEqual([ours.status, ours.json.records, ours.json.head], [0, 10, theirs.json.head]);
  assert.equal(auditVerify(log).head, theirs.json.head);
  // both print the same last records
  assert.equal(node(cfg, 'audit', 'tail', '-n', '4').stdout, python(cfg, 'audit', 'tail', '-n', '4').stdout);

  // tampering with a record either port wrote is detected by both
  const original = readFileSync(log, 'utf8');
  const lines = original.split('\n').filter(Boolean);
  assert.equal(lines.length, 10);
  const variants = {
    'edit a node record': lines.map((l, n) => (n === 1 ? l.replace('"effect":"allow"', '"effect":"deny"') : l)),
    'edit a reference record': lines.map((l, n) => (n === 6 ? l.replace('"reason":"token_revoked"', '"reason":"policy_permit"') : l)),
    'delete a record': lines.filter((_, n) => n !== 4),
    'swap two records': [...lines.slice(0, 7), lines[8], lines[7], lines[9]],
    'drop the first record': lines.slice(1),
  };
  for (const [name, changed] of Object.entries(variants)) {
    assert.notDeepEqual(changed, lines, name);
    writeFileSync(log, changed.join('\n') + '\n');
    r = python(cfg, 'audit', 'verify');
    assert.equal(r.status, 1, name);
    assert.match(r.stdout + r.stderr, /audit_broken/, name);
    r = node(cfg, 'audit', 'verify');
    assert.equal(r.status, 1, name);
    assert.match(r.stdout + r.stderr, /audit_broken/, name);
    assert.equal(mine.call('audit_verify', {}).error.code, 'audit_broken', name);
  }
  writeFileSync(log, original);
  assert.equal(python(cfg, 'audit', 'verify').status, 0);
  assert.equal(mine.call('audit_verify', {}).records, 10);
});

test('OIDC ID tokens of every algorithm are judged the same by both ports', { skip }, (t) => {
  const { dir, write, python, engine } = setup(t);
  const { jwks, tokens } = makeIdTokens();
  const jwksFile = write('jwks.json', jwks);
  const pcfg = write('p.json', config(join(dir, 'py-state'), { idp: { ...IDP, jwks_file: jwksFile } }));
  const mine = engine(config(join(dir, 'node-state'), { idp: { ...IDP, jwks_file: jwksFile } }));
  for (const [name, { token, valid }] of Object.entries(tokens)) {
    const input = write('in.json', { id_token: token, agent: 'support-bot', cap: FULL_CAP, now: T });
    const theirs = python(pcfg, 'call', 'issue_token', '--input', '@' + input).json;
    const ours = mine.call('issue_token', { id_token: token, agent: 'support-bot', cap: FULL_CAP, now: T });
    assert.equal(theirs.ok, valid, `reference: ${name}`);
    assert.equal(ours.ok, valid, `this port: ${name}`);
    if (valid) assert.equal(ours.user, theirs.user, name);
    else assert.deepEqual([ours.error.code, ours.error.rule], [theirs.error.code, theirs.error.rule], name);
  }
});

test('OIDC rules beyond the signature (azp, several audiences, iat against the revoke cut-off, nested group claims) are the same in both ports', { skip }, (t) => {
  const { dir, write, python, engine } = setup(t);
  const { jwks, idToken } = makeIdTokens();
  const jwksFile = write('jwks.json', jwks);
  const scenarios = oidcScenarios(idToken);
  // the reference runs every scenario in one process: one config and state per scenario, a script of calls on stdin
  const script = scenarios.map((sc, n) => ({ config: config(join(dir, `py-${n}`), { idp: { ...IDP, jwks_file: jwksFile, ...sc.idp } }),
    calls: [...(sc.revokeAt === null ? [] : [['revoke', { user: 'alice', now: sc.revokeAt }]]), ['issue_token', sc.input]] }));
  const code = ['import json, sys', 'from smartdelegate import Engine', 'out = []', 'for s in json.load(sys.stdin):',
    '    e = Engine(s["config"])', '    r = None', '    for op, i in s["calls"]:', '        r = e.call(op, i)',
    '    grp = e.call("inspect_token", {"token": r["token"], "now": i["now"]})["claims"].get("grp") if r.get("ok") else None',
    '    out.append({"ok": r.get("ok"), "code": (r.get("error") or {}).get("code"), "user": r.get("user"), "role": r.get("role"), "grp": grp})',
    '    e.close()', 'print(json.dumps(out))'].join('\n');
  const ran = pyCode(code, { input: JSON.stringify(script) });
  assert.equal(ran.status, 0, ran.stderr);
  const theirs = JSON.parse(ran.stdout);
  assert.equal(theirs.length, scenarios.length);
  scenarios.forEach((sc, n) => {
    const mine = engine(config(join(dir, `node-${n}`), { idp: { ...IDP, jwks_file: jwksFile, ...sc.idp } }));
    if (sc.revokeAt !== null) mine.call('revoke', { user: 'alice', now: sc.revokeAt });
    const r = mine.call('issue_token', sc.input);
    const ours = { ok: r.ok, code: r.error?.code ?? null, user: r.user ?? null, role: r.role ?? null,
      grp: r.ok ? mine.call('inspect_token', { token: r.token, now: sc.input.now }).claims.grp ?? null : null };
    assert.deepEqual(ours, theirs[n], sc.name);
    assert.deepEqual([ours.ok, ours.code], [sc.ok, sc.code], sc.name);
  });
  assert.ok(theirs.filter((x) => x.ok).length >= 10 && theirs.filter((x) => !x.ok).length >= 15);
});

test('reload re-reads idp.jwks_file in both ports (key rotation)', { skip }, (t) => {
  const { dir, write, engine } = setup(t);
  const oldKeys = makeIdTokens(), newKeys = makeIdTokens();
  const file = write('jwks.json', oldKeys.jwks);
  const input = (keys) => ({ id_token: keys.idToken(), agent: 'support-bot', cap: FULL_CAP, now: T });
  const steps = [['old', 'issue'], ['new', 'issue'], ['write', 'new'], ['old', 'issue'], ['reload'], ['old', 'issue'], ['new', 'issue'],
    ['write', 'broken'], ['reload'], ['new', 'issue'], ['old', 'issue']];
  const files = { new: JSON.stringify(newKeys.jwks), broken: '{"keys": 5}' };
  const code = ['import json, sys', 'from smartdelegate import Engine', 'd = json.load(sys.stdin)', 'e = Engine(d["config"])', 'out = []',
    'for s in d["steps"]:',
    '    if s[0] == "write":', '        open(d["file"], "w").write(d["files"][s[1]]); continue',
    '    r = e.call("reload", {}) if s[0] == "reload" else e.call("issue_token", d["inputs"][s[0]])',
    '    out.append([r.get("ok"), (r.get("error") or {}).get("code")])', 'e.close()', 'print(json.dumps(out))'].join('\n');
  const pfile = write('py-jwks.json', oldKeys.jwks);
  const ran = pyCode(code, { input: JSON.stringify({ config: config(join(dir, 'py'), { idp: { ...IDP, jwks_file: pfile } }), steps, files, file: pfile,
    inputs: { old: input(oldKeys), new: input(newKeys) } }) });
  assert.equal(ran.status, 0, ran.stderr);
  const mine = engine(config(join(dir, 'node'), { idp: { ...IDP, jwks_file: file } }));
  const ours = [];
  for (const s of steps) {
    if (s[0] === 'write') { writeFileSync(file, files[s[1]]); continue; }
    const r = s[0] === 'reload' ? mine.call('reload', {}) : mine.call('issue_token', input(s[0] === 'old' ? oldKeys : newKeys));
    ours.push([r.ok, r.error?.code ?? null]);
  }
  const expected = [[true, null], [false, 'id_token_invalid'], [true, null], [true, null], [false, 'id_token_invalid'], [true, null],
    [false, 'invalid_config'], [true, null], [false, 'id_token_invalid']];
  assert.deepEqual(ours, expected);
  assert.deepEqual(JSON.parse(ran.stdout), expected);
});

test('canonical JSON and the JSON parser agree with the reference byte for byte', { skip }, () => {
  const docs = [
    '{"b": 1, "a": {"y": [1, 2, {"k": null}], "x": true}, "": false}',
    '{"\\ud83d\\ude00": 1, "\\uff5e": 2, "\\ue000": 3, "z": 4, "Z": 5, "10": 6, "9": 7, "é": 8, "\\u007f": 9}',
    '["\\u0000\\u0001\\u0008\\u0009\\u000a\\u000b\\u000c\\u000d\\u001f \\" \\\\ \\/ \\u007f \\u0080 \\u2028 \\u2029 \\ufeff 😀 日本"]',
    '[9223372036854775807, -9223372036854775808, 18446744073709551616, 123456789012345678901234567890, 0, -0]',
    '[1.0, 1.5, -0.0, 1e16, 1e15, 123456789012345.6, 1.5e-7, 0.0001, 0.00001, 1e300, 5e-324, 0.1, 100.0, 2.5e+20, 1E5, 1e-5]',
    '[NaN, Infinity, -Infinity]',
    '{"a": 1, "a": 2, "__proto__": {"x": 1}, "constructor": "c"}',
    '  [ ]  ',
  ];
  const code = 'import json,sys\nfor d in json.load(sys.stdin):\n    sys.stdout.write(json.dumps(json.loads(d), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\\n")\n';
  const r = pyCode(code, { input: JSON.stringify(docs) });
  assert.equal(r.status, 0, r.stderr);
  const theirs = r.stdout.split('\n').slice(0, docs.length);
  docs.forEach((d, n) => assert.equal(canonInternal(parse(d)), theirs[n], d));
  // ... and the two non-canonical forms the ports write: the state file and the signature file
  const code2 = 'import json,sys\nfor d in json.load(sys.stdin):\n    v = json.loads(d)\n    sys.stdout.write(json.dumps(v, separators=(",", ":")) + "\\n" + json.dumps(v, indent=2).replace("\\n", "\\\\n") + "\\n")\n';
  const r2 = pyCode(code2, { input: JSON.stringify(docs.slice(0, 5)) });
  assert.equal(r2.status, 0, r2.stderr);
  const out = r2.stdout.split('\n');
  docs.slice(0, 5).forEach((d, n) => {
    // Python keeps the order of the text; so does this port, except for integer-like keys (documented)
    if (d.includes('"10"')) return;
    assert.equal(write(parse(d), { ascii: true }), out[2 * n], d);
    assert.equal(write(parse(d), { ascii: true, indent: 2 }).replaceAll('\n', '\\n'), out[2 * n + 1], d);
  });
});

// The same random script of operations through both engines, every result
// compared. SMARTDELEGATE_DIFF_COUNT sets the number of operations per seed
// (default 1500); SMARTDELEGATE_DIFF_SEEDS the seeds (default "1,2,3").
const DIFF_COUNT = Number(process.env.SMARTDELEGATE_DIFF_COUNT ?? 1500);
for (const seed of (process.env.SMARTDELEGATE_DIFF_SEEDS ?? '1,2,3').split(',').map(Number)) {
  test(`differential: ${DIFF_COUNT} random operations give the same results in both engines (seed ${seed})`, { skip }, async () => {
    const s = await differential({ seed, count: DIFF_COUNT, python: PYTHON });
    assert.deepEqual(s.mismatches, []);
    assert.equal(s.compared, DIFF_COUNT);
    assert.equal(s.auditSame, true, 'both audit logs hold the same events in the same order');
    if (DIFF_COUNT >= 1500) {
      // the script must really reach the interesting paths, not only the early refusals
      assert.ok(s.allows >= 100, `allows: ${s.allows}`);
      for (const reason of ['approval_required', 'rate_limited', 'budget_exceeded', 'field_denied', 'policy_forbid', 'no_matching_permit', 'widening',
        'role_not_held', 'delegation_denied', 'token_expired', 'token_revoked', 'invalid_context', 'invalid_cap']) {
        assert.ok((s.reasons[reason] ?? 0) > 0, `the script never produced ${reason}`);
      }
      assert.ok(s.auditRecords >= 400);
    }
  });
}
