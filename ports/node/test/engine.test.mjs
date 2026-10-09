// Engine behaviour beyond the shared vectors: integers, shadow mode, signed
// bundles, audit tampering, verify-only engines, state shared by two engines,
// failing closed. (Mirrors tests/test_engine.py of the reference.)
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { Engine, SmartDelegateError, guardTool, keygen, signBundle } from '../lib/index.mjs';
import { parse, toInternal } from '../lib/json.mjs';
import { Keys } from '../lib/tokens.mjs';
import { BUNDLE, FULL_CAP, IDP, T, config, makeIdTokens, oidcScenarios, tempDir } from '../tools/support.mjs';

function setup(t) {
  const dir = tempDir(t);
  const engines = [];
  t.after(() => engines.forEach((e) => e.close()));
  const engine = (extra = {}) => {
    const { state = 'state', ...rest } = extra;
    const e = new Engine(config(join(dir, state), rest));
    engines.push(e);
    return e;
  };
  return { dir, engine };
}

const issue = (e, extra = {}) => e.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP, ...extra });
const READ = { action: 'read', resource: 'crm.customer', id: 'c-1' };
const code = (c) => (err) => err instanceof SmartDelegateError && err.code === c;

test('call never throws, whatever it is given', (t) => {
  const { engine } = setup(t);
  const e = engine();
  const cyclic = {};
  cyclic.self = cyclic;
  let deep = {};
  for (let i = 0; i < 50000; i++) deep = { d: deep };
  const inputs = [undefined, null, 1, 'x', [], cyclic, deep, { token: 1n << 70n }, { context: new Map() }, { f() {} }, Symbol('s'), { a: NaN },
    { action: 'read', resource: { path: 'crm.customer' }, context: { x: Infinity } }];
  for (const op of ['authorize', 'filter', 'explain', 'issue_token', 'exchange_token', 'inspect_token', 'apply_obligations', 'revoke', 'approve', 'nope', undefined, 7]) {
    for (const input of inputs) {
      const r = e.call(op, input);
      // an error, or (for a well-formed request without a token) a deny; never an allow
      assert.notEqual(r.effect, 'allow', String(op));
      if (r.ok !== true) {
        assert.equal(r.ok, false);
        assert.equal(typeof r.error.code, 'string');
        assert.match(r.error.rule, /^DELEGATE-[A-Z-]+$/);
      } else {
        assert.equal(r.effect, 'deny');
        assert.equal(r.reason, 'token_invalid');
      }
    }
  }
  assert.equal(e.call('authorize', deep).error.code, 'invalid_input');
  assert.equal(e.call('nope', {}).error.code, 'unknown_op');
});

test('64-bit integers: exact in context, budgets and results; overflow and floats are refused', (t) => {
  const { engine } = setup(t);
  const e = engine();
  const max = 9223372036854775807n;
  const tok = e.issueToken({ user: 'alice', agent: 'support-bot', cap: { actions: ['read'], resources: ['crm.customer/*'], budget: { EUR: max } } });
  assert.equal(tok.cap.budget.EUR, max, 'a budget beyond 2^53 comes back as the same BigInt');
  assert.equal(e.inspectToken(tok.token).claims.cap.budget.EUR, max);
  const ask = (context) => e.call('authorize', { token: tok.token, action: 'read', resource: { path: 'crm.customer', id: 'c-1' }, context });
  const now = { token: tok.token, ...READ };
  assert.equal(e.authorize({ ...now, context: { big: max, small: -(2n ** 63n) } }).effect, 'allow');
  assert.equal(ask({ big: max + 1n }).error.code, 'invalid_context');
  assert.equal(ask({ nested: [{ deep: -(2n ** 63n) - 1n }] }).error.code, 'invalid_context');
  assert.equal(ask({ score: 1.5 }).error.code, 'invalid_context');
  assert.equal(ask({ n: null }).error.code, 'invalid_context');
  // spend is exact arithmetic on the ledger, far beyond what a double can count
  const spend = (amount) => e.authorize({ ...now, context: { spend: { currency: 'EUR', amount } } });
  assert.equal(spend(max - 1n).effect, 'allow');
  assert.equal(spend(2n).reason, 'budget_exceeded');
  assert.equal(spend(1n).effect, 'allow');
  assert.equal(spend(1n).reason, 'budget_exceeded');
  assert.throws(() => spend(1.5), code('invalid_context'));
  assert.equal(e.call('authorize', { token: tok.token, action: 'read', resource: { path: 'crm.customer' }, context: { spend: { currency: 'EUR', amount: 1.5 } } }).error.code, 'invalid_context');
  assert.equal(e.call('issue_token', { user: 'alice', agent: 'support-bot', cap: { actions: ['read'], resources: ['*'], budget: { EUR: 1.5 } } }).error.code, 'invalid_cap');
  // ordinary integers are ordinary Numbers in results
  assert.equal(typeof tok.expires_in, 'number');
  assert.equal(e.info().policies, 21);
});

test('the engine has the convenience methods of the REST client, and guardTool works on it', async (t) => {
  const { engine } = setup(t);
  const e = engine();
  const { token } = issue(e);
  const getCustomer = guardTool(e, () => token, { action: 'read', resource: 'crm.customer', id: (a) => a.id },
    async ({ id }) => ({ id, email: 'ada@example.com', ssn: '123-45-6789', region: 'EU' }));
  assert.deepEqual(await getCustomer({ id: 'c-1' }), { id: 'c-1', email: 'ada@example.com', region: 'EU' });
  let ran = false;
  const drop = guardTool(e, token, { action: 'delete', resource: 'crm.customer' }, async () => { ran = true; });
  await assert.rejects(drop({}), (err) => err.reason === 'capability_action');
  assert.equal(ran, false);
  assert.throws(() => e.issueToken({ user: 'alice', agent: 'nobody', cap: FULL_CAP }), code('unknown_agent'));
});

test('a role token: held, bounded by the ceiling, inherited by sub-agents', (t) => {
  const { engine } = setup(t);
  const e = engine();
  const r = e.issueToken({ user: 'alice', agent: 'support-bot', role: 'support-agent', groups: ['support'], ttl: 5000 });
  assert.equal(r.role, 'support-agent');
  assert.equal(r.expires_in, 600);
  assert.deepEqual(e.inspectToken(r.token).claims.grp, [{ type: 'Group', id: 'support' }]);
  const d = e.authorize({ token: r.token, ...READ });
  assert.equal(d.effect, 'allow');
  assert.equal(d.rule, 'DELEGATE-POLICY-PERMIT');
  assert.equal(d.principal.role, 'support-agent');
  assert.throws(() => e.issueToken({ user: 'dave', agent: 'support-bot', role: 'support-agent' }), code('role_not_held'));
  assert.throws(() => e.issueToken({ user: 'alice', agent: 'support-bot', role: 'support-agent', groups: [] }), code('role_not_held'));
  assert.throws(() => e.issueToken({ user: 'alice', agent: 'support-bot', role: 'support-agent', cap: { actions: ['delete'], resources: ['crm.customer/*'] } }), code('role_exceeded'));
  const child = e.exchangeToken({ subjectToken: r.token, actor: 'refund-helper', ttl: 300 });
  assert.equal(child.role, 'support-agent');
  assert.throws(() => e.exchangeToken({ subjectToken: r.token, actor: 'refund-helper', ttl: 300, role: 'auditor' }), code('widening'));
});

test('revoking a user ends every token already issued for them, sub-agents included; later tokens are unaffected', (t) => {
  const { dir, engine } = setup(t);
  const e = engine();
  const at = (now) => ({ now });
  const issueAt = (user, now, extra = {}) => e.call('issue_token', { user, agent: 'support-bot', cap: FULL_CAP, now, ...extra });
  const ask = (token, now) => e.call('authorize', { token, action: 'read', resource: { path: 'crm.customer', id: 'c-1' }, now });
  const alice = issueAt('alice', T, { task: 'ticket-1' });
  assert.equal(alice.task, 'ticket-1', 'token results carry the task');
  assert.equal(issueAt('alice', T).task, null);
  assert.deepEqual(Object.keys(alice), ['token', 'token_type', 'issued_token_type', 'token_id', 'expires_at', 'expires_in', 'user', 'chain', 'role', 'task', 'cap', 'ok']);
  const child = e.call('exchange_token', { subject_token: alice.token, actor: 'refund-helper', ttl: 300, now: T + 5 });
  assert.equal(child.task, 'ticket-1');
  const bob = issueAt('bob', T);
  const sameSecond = issueAt('alice', T + 10);

  const r = e.call('revoke', { user: 'alice', by: 'hr', now: T + 10, token_id: bob.token_id, token: bob.token });
  assert.deepEqual(r, { revoked_user: 'alice', issued_up_to: T + 10, ok: true }, '`user` takes precedence over token and token_id');
  for (const tok of [alice, child, sameSecond]) {
    const d = ask(tok.token, T + 20);
    assert.deepEqual([d.effect, d.reason, d.rule, d.principal.user], ['deny', 'token_revoked', 'DELEGATE-TOKEN-REVOKED', 'alice']);
    assert.equal(e.call('inspect_token', { token: tok.token, now: T + 20 }).reason, 'token_revoked');
    assert.equal(e.call('exchange_token', { subject_token: tok.token, actor: 'refund-helper', ttl: 60, now: T + 20 }).error.code, 'token_revoked');
  }
  assert.equal(ask(bob.token, T + 20).effect, 'allow', 'other users are untouched');
  const later = issueAt('alice', T + 11);
  assert.equal(later.ok, true, 'whether the user can get a new token is a matter of membership, not of this list');
  assert.equal(ask(later.token, T + 20).effect, 'allow');
  // an expired token is reported as expired, a token-id revocation is checked first
  assert.equal(ask(alice.token, T + 5000).reason, 'token_expired');
  const tail = e.call('audit_tail', { n: 200 }).records;
  const rec = tail.find((x) => x.event === 'user_revoked');
  assert.deepEqual([rec.user, rec.issued_up_to, rec.by, rec.ts], ['alice', T + 10, 'hr', T + 10]);
  const state = JSON.parse(readFileSync(join(dir, 'state', 'state.json'), 'utf8'));
  assert.deepEqual(state.revoked_users, { alice: T + 10 });

  // invalid input
  for (const user of ['', null, 5, ['alice'], { id: 'alice' }, true]) {
    assert.equal(e.call('revoke', { user, token_id: 'x', ...at(T) }).error.code, 'invalid_input', JSON.stringify(user));
  }
  // entries are never pruned, and a state file without the key is read as empty
  const big = issueAt('bob', T + 10 * 86400 * 365, { cap: { ...FULL_CAP, budget: { EUR: 5 } } });   // minting with a budget prunes the state
  assert.equal(big.ok, true);
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'state', 'state.json'), 'utf8')).revoked_users, { alice: T + 10 });
  const old = JSON.parse(readFileSync(join(dir, 'state', 'state.json'), 'utf8'));
  delete old.revoked_users;
  writeFileSync(join(dir, 'state', 'state.json'), JSON.stringify(old));
  assert.equal(ask(later.token, T + 20).effect, 'allow');
  assert.equal(ask(alice.token, T + 20).effect, 'allow', 'with the entry gone the cut-off is gone');
  writeFileSync(join(dir, 'state', 'state.json'), JSON.stringify({ ...old, revoked_users: [] }));
  assert.equal(ask(later.token, T + 20).error.code, 'state_io');
  writeFileSync(join(dir, 'state', 'state.json'), JSON.stringify(old));
  // the convenience method
  const viaMethod = e.revokeUser('bob', 'admin');
  assert.equal(viaMethod.revoked_user, 'bob');
  assert.equal(typeof viaMethod.issued_up_to, 'number');
  assert.throws(() => e.revokeUser(''), code('invalid_input'));
});

test('an ancestor budget travels in the `lim` claim: a verify-only engine with its own state enforces it', (t) => {
  const { dir, engine } = setup(t);
  const [sk] = keygen();
  const issuer = engine({ signing_key: sk });
  const capOf = (EUR) => ({ actions: ['create'], resources: ['billing.refund/*'], budget: { EUR } });
  const parent = issuer.call('issue_token', { user: 'alice', agent: 'support-bot', now: T, cap: capOf(10000) });
  assert.equal(issuer.call('inspect_token', { token: parent.token, now: T }).claims.lim, undefined, 'a root token has no lim');
  const kid = () => issuer.call('exchange_token', { subject_token: parent.token, actor: 'refund-helper', ttl: 300, now: T, cap: capOf(6000) });
  const kids = [kid(), kid(), kid()];
  assert.deepEqual(issuer.call('inspect_token', { token: kids[0].token, now: T }).claims.lim, { [parent.token_id]: { EUR: 10000 } });
  // a grandchild carries both ancestors; a chain without budgets carries none
  const grand = issuer.call('exchange_token', { subject_token: kids[0].token, actor: 'summarizer', ttl: 200, now: T, cap: capOf(100) });
  assert.deepEqual(issuer.call('inspect_token', { token: grand.token, now: T }).claims.lim,
    { [parent.token_id]: { EUR: 10000 }, [kids[0].token_id]: { EUR: 6000 } });
  const plain = issuer.call('issue_token', { user: 'alice', agent: 'support-bot', now: T, cap: { actions: ['read'], resources: ['crm.customer/*'] } });
  const plainKid = issuer.call('exchange_token', { subject_token: plain.token, actor: 'refund-helper', ttl: 300, now: T });
  assert.equal('lim' in issuer.call('inspect_token', { token: plainKid.token, now: T }).claims, false);

  const verifier = new Engine({ bundle_dir: BUNDLE, state_dir: join(dir, 'verifier'), allow_test_clock: true, verify_only: true, trusted_keys: [issuer.info().public_key] });
  t.after(() => verifier.close());
  const spend = (e, k, amount = 5000) => e.call('authorize', { token: k.token, action: 'create', resource: { path: 'billing.refund', id: 'r' }, now: T,
    context: { spend: { currency: 'EUR', amount } } });
  assert.equal(spend(verifier, kids[0]).effect, 'allow');
  assert.equal(spend(verifier, kids[1]).effect, 'allow');
  const third = spend(verifier, kids[2]);
  assert.deepEqual([third.effect, third.reason], ['deny', 'budget_exceeded'], 'the parent has 10000 in all');
  // the grandchild is bound by its own 100, and by the ancestors the verifier never saw being issued
  assert.equal(spend(verifier, grand, 101).reason, 'budget_exceeded');
  assert.equal(spend(verifier, grand, 1).reason, 'budget_exceeded', 'the parent is already used up');
  // the issuer itself still decides from its own state
  assert.equal(spend(issuer, kids[2]).effect, 'allow');
  assert.equal(spend(issuer, kids[1]).effect, 'allow');
  assert.equal(spend(issuer, kids[0]).reason, 'budget_exceeded');

  // a forged or malformed lim is not a token
  const keys = new Keys(sk, []);
  const claims = parse(Buffer.from(kids[0].token.split('.')[1], 'base64url').toString());
  const withLim = (lim) => {
    const c = Object.assign(Object.create(null), claims);
    c.lim = toInternal(lim);
    return keys.sign(c);
  };
  for (const ok of [{}, { a: {} }, { a: { EUR: 0 } }, { a: { EUR: 2n ** 70n, USD: 1 }, b: {} }]) {
    assert.equal(issuer.call('inspect_token', { token: withLim(ok), now: T }).valid, true, JSON.stringify(ok, (k, v) => (typeof v === 'bigint' ? String(v) : v)));
  }
  for (const bad of ['x', [], null, 5, true, { a: 5 }, { a: null }, { a: [] }, { a: 'EUR' }, { a: { EUR: -1 } }, { a: { EUR: '9' } }, { a: { EUR: 1.5 } },
    { a: { EUR: true } }, { a: { EUR: null } }, { a: { EUR: 1 }, b: { EUR: -1 } }, { a: { EUR: { n: 1 } } }]) {
    const r = issuer.call('inspect_token', { token: withLim(bad), now: T });
    assert.deepEqual([r.valid, r.reason], [false, 'token_invalid'], JSON.stringify(bad));
    assert.equal(spend(verifier, { token: withLim(bad) }).reason, 'token_invalid');
  }
  // a lower limit in the token does not override what this engine's own state says, and a higher one cannot raise it
  const raised = withLim({ [parent.token_id]: { EUR: 999999 } });
  assert.equal(spend(issuer, { token: raised }).reason, 'budget_exceeded');
});

test('revoking a user again with an earlier clock does not move the cut-off back', (t) => {
  const { dir, engine } = setup(t);
  const e = engine();
  const tok = e.call('issue_token', { user: 'alice', agent: 'support-bot', cap: FULL_CAP, now: T + 50 });
  assert.deepEqual(e.call('revoke', { user: 'alice', now: T + 100 }), { revoked_user: 'alice', issued_up_to: T + 100, ok: true });
  assert.deepEqual(e.call('revoke', { user: 'alice', now: T + 10, by: 'slow-clock' }), { revoked_user: 'alice', issued_up_to: T + 100, ok: true });
  assert.equal(e.call('authorize', { token: tok.token, action: 'read', resource: { path: 'crm.customer', id: 'c-1' }, now: T + 60 }).reason, 'token_revoked');
  const rec = e.call('audit_tail', { n: 2 }).records[0];
  assert.deepEqual([rec.event, rec.issued_up_to, rec.ts, rec.by], ['user_revoked', T + 100, T + 10, 'slow-clock']);
  assert.deepEqual(e.call('revoke', { user: 'alice', now: T + 200 }).issued_up_to, T + 200);
  assert.deepEqual(e.call('revoke', { user: 'bob', now: T + 5 }).issued_up_to, T + 5);
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'state', 'state.json'), 'utf8')).revoked_users, { alice: T + 200, bob: T + 5 });
});

test('an approval is bound to the resource attributes of the request it was given for', (t) => {
  const { engine } = setup(t);
  const e = engine();
  const token = e.call('issue_token', { user: 'alice', agent: 'support-bot', cap: { ...FULL_CAP, budget: { EUR: 1000000 } }, now: T }).token;
  const refund = (attrs, extra = {}) => e.call('authorize', { token, action: 'create', now: T, context: { spend: { currency: 'EUR', amount: 15000 } },
    resource: attrs === undefined ? { path: 'billing.refund', id: 'r-1' } : { path: 'billing.refund', id: 'r-1', attrs }, ...extra });
  const one = refund({ employee: 'emp-1', meta: { n: 1, list: ['a'] } });
  assert.equal(one.reason, 'approval_required');
  assert.equal(e.call('approve', { approval_id: one.approval.id, by: 'bob', now: T }).ok, true);
  // the same request about someone else, with a changed nested value, with no attrs, with a null: each needs its own approval
  const others = [{ employee: 'emp-2', meta: { n: 1, list: ['a'] } }, { employee: 'emp-1', meta: { n: 2, list: ['a'] } }, { employee: 'emp-1', meta: { n: 1, list: ['b'] } },
    { employee: 'emp-1' }, {}, undefined, null];
  const ids = others.map((attrs) => {
    const d = refund(attrs);
    assert.deepEqual([d.effect, d.reason], ['deny', 'approval_required'], JSON.stringify(attrs));
    assert.notEqual(d.approval.id, one.approval.id);
    return d.approval.id;
  });
  assert.equal(new Set(ids.slice(0, 5)).size, 5);
  assert.deepEqual([ids[4], ids[4]], [ids[5], ids[6]], 'absent, null and {} are the same request');
  // the member order of the attributes is not part of the request
  assert.equal(refund({ meta: { list: ['a'], n: 1 }, employee: 'emp-1' }, { dry_run: true }).obligations.approved.id, one.approval.id);
  const used = refund({ employee: 'emp-1', meta: { n: 1, list: ['a'] } });
  assert.deepEqual([used.effect, used.obligations.approved], ['allow', { id: one.approval.id, by: 'bob' }]);
  assert.equal(refund({ employee: 'emp-1', meta: { n: 1, list: ['a'] } }).reason, 'approval_required');
});

test('shadow mode allows but reports and logs, and never changes data', (t) => {
  const { engine } = setup(t);
  const e = engine({ mode: 'shadow' });
  const { token } = issue(e);
  const d = e.authorize({ token, action: 'delete', resource: 'crm.customer', id: 'c-1' });
  assert.equal(d.effect, 'allow');
  assert.equal(d.shadow, true);
  assert.equal(d.would_deny.reason, 'capability_action');
  const rec = e.call('audit_tail', { n: 1 }).records[0];
  assert.deepEqual([rec.effect, rec.enforced], ['deny', false]);
  const data = { id: 'c-1', ssn: '123-45-6789', region: 'EU' };
  const f = e.filter({ token, ...READ, data });
  assert.deepEqual(f.data, data);
  assert.deepEqual(f.would_mask, ['ssn']);
  const bad = e.authorize({ token: 'not.a.token', ...READ });
  assert.deepEqual([bad.effect, bad.would_deny.reason], ['allow', 'token_invalid']);
});

test('signed bundles: unsigned, tampered, wrong key, stale sources, unsupported Cedar', (t) => {
  const dir = tempDir(t);
  const b = join(dir, 'bundle');
  cpSync(BUNDLE, b, { recursive: true });
  const [sk, pk] = keygen();
  const load = (key = pk) => new Engine({ bundle_dir: b, bundle_public_key: key }).close();
  assert.throws(load, code('bundle_unsigned'));
  const sig = signBundle(b, sk);
  assert.equal(sig.alg, 'Ed25519');
  const e = new Engine({ bundle_dir: b, bundle_public_key: pk });
  assert.equal(e.info().bundle_signed_by, sig.key_id);
  assert.equal(e.info().policy_version, sig.version);
  e.close();
  assert.throws(() => load(keygen()[1]), code('bundle_signature'));
  assert.throws(() => load('not base64!'), code('crypto'));

  const ent = join(b, 'entities.json');
  const original = readFileSync(ent, 'utf8');
  writeFileSync(ent, original.replace('"region": "EU"', '"region": "US"'));
  assert.throws(load, code('bundle_signature'));
  writeFileSync(ent, original.replaceAll('\n', '\r\n'));
  assert.doesNotThrow(load, 'line endings do not change the version');
  writeFileSync(ent, original);

  const sigFile = join(b, 'bundle.sig.json');
  const doc = JSON.parse(readFileSync(sigFile, 'utf8'));
  writeFileSync(sigFile, JSON.stringify({ ...doc, version: '0'.repeat(64) }));
  assert.throws(load, code('bundle_signature'));
  writeFileSync(sigFile, '{not json');
  assert.throws(load, code('bundle_signature'));
  rmSync(sigFile);

  const cedarFile = join(b, 'policies', 'crm.cedar');
  const source = readFileSync(cedarFile, 'utf8');
  writeFileSync(cedarFile, source + '\npermit(principal, action, resource);\n');
  assert.throws(() => new Engine({ bundle_dir: b }), code('bundle_stale'));
  writeFileSync(cedarFile, source);
  writeFileSync(join(b, 'policies', 'zz_new.cedar'), 'permit(principal, action, resource);');
  assert.throws(() => new Engine({ bundle_dir: b }), code('bundle_stale'));
  rmSync(join(b, 'policies', 'zz_new.cedar'));

  const pfile = join(b, 'policies.json');
  const good = readFileSync(pfile, 'utf8');
  const live = new Engine({ bundle_dir: b, allow_test_clock: true });
  t.after(() => live.close());
  const before = live.info().policy_version;
  const pdoc = JSON.parse(good);
  pdoc.policies['uses-ip'] = { effect: 'forbid', principal: { op: 'All' }, action: { op: 'All' }, resource: { op: 'All' },
    conditions: [{ kind: 'when', body: { isLoopback: [{ ip: [{ Value: '10.0.0.1' }] }] } }] };
  writeFileSync(pfile, JSON.stringify(pdoc));
  assert.throws(() => new Engine({ bundle_dir: b }), code('policy_parse'));
  // a bundle that fails to load leaves the old one in force
  assert.equal(live.call('reload', {}).error.code, 'policy_parse');
  writeFileSync(pfile, good.slice(0, -40));
  assert.equal(live.call('reload', {}).error.code, 'policy_parse');
  assert.equal(live.info().policy_version, before);
  const { token } = live.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP });
  assert.equal(live.authorize({ token, ...READ }).effect, 'allow');
  for (const [file, err] of [['roles.json', 'roles_parse'], ['catalog.json', 'catalog_parse'], ['entities.json', 'entities_parse']]) {
    const keep = readFileSync(join(b, file), 'utf8');
    writeFileSync(pfile, good);
    writeFileSync(join(b, file), '{"roles": {"x": {"members": [{"type": "Group", "id": "g"}], "cap": {}, "max_tll": 5}}, "resources": {"r": {}}}');
    assert.throws(() => new Engine({ bundle_dir: b }), code(err), file);
    writeFileSync(join(b, file), keep);
  }
  assert.throws(() => new Engine({ bundle_dir: join(dir, 'missing') }), code('bundle_io'));
});

test('audit: the chain verifies; edit, delete and reorder are detected; values are not logged', (t) => {
  const { dir, engine } = setup(t);
  const log = join(dir, 'state', 'audit.jsonl');
  const e = engine();
  const { token } = issue(e);
  for (let i = 0; i < 5; i++) e.authorize({ token, action: 'read', resource: 'crm.customer', id: `c-${i}` });
  const v = e.call('audit_verify', {});
  assert.equal(v.records, 6);
  assert.match(v.head, /^[0-9a-f]{64}$/);
  const original = readFileSync(log, 'utf8').split('\n').filter(Boolean);
  const edited = [...original];
  edited[2] = edited[2].replace('"effect":"allow"', '"effect":"deny"');
  assert.notEqual(edited[2], original[2]);
  const variants = { edit: edited, delete: [...original.slice(0, 2), ...original.slice(3)],
    reorder: [...original.slice(0, 2), original[3], original[2], ...original.slice(4)] };
  for (const [name, lines] of Object.entries(variants)) {
    writeFileSync(log, lines.join('\n') + '\n');
    assert.equal(e.call('audit_verify', {}).error?.code, 'audit_broken', name);
  }
  writeFileSync(log, original.join('\n') + '\n');
  assert.equal(e.call('audit_verify', {}).records, 6);

  e.filter({ token, ...READ, data: { id: 'c-1', ssn: '123-45-6789', email: 'ada@example.com', region: 'EU' } });
  const text = readFileSync(log, 'utf8');
  assert.ok(text.includes('"masked":["ssn"]'));
  assert.ok(!text.includes('123-45-6789') && !text.includes('ada@example.com') && !text.includes(token));
});

test('audit: denials on revoked tokens are attributed; a reopened log continues; a broken log stops the engine', (t) => {
  const { dir, engine } = setup(t);
  const e = engine();
  const r = issue(e);
  e.revoke(r.token_id);
  const d = e.authorize({ token: r.token, ...READ });
  assert.deepEqual([d.effect, d.reason, d.principal.user], ['deny', 'token_revoked', 'alice']);
  const rec = e.call('audit_tail', { n: 1 }).records[0];
  assert.deepEqual([rec.user, rec.chain, rec.effect], ['alice', ['support-bot'], 'deny']);
  assert.equal(e.authorize({ token: 'abc.def.ghi', ...READ }).principal, null);
  assert.equal(e.call('audit_verify', {}).records, 4);
  assert.equal(e.call('audit_tail', { n: 0 }).records.length, 0);
  assert.equal(e.call('audit_tail', { n: 2 }).records.length, 2);
  assert.equal(e.call('audit_tail', {}).records.length, 4);
  e.close();
  const e2 = engine();
  e2.authorize({ token: 'x', ...READ });
  assert.equal(e2.call('audit_verify', {}).records, 5);
  e2.close();
  const log = join(dir, 'state', 'audit.jsonl');
  const lines = readFileSync(log, 'utf8').split('\n').filter(Boolean);
  writeFileSync(log, lines.slice(1).join('\n') + '\n');
  assert.throws(() => engine(), code('audit_broken'));
});

test('keys: verify-only engines, unknown issuers, altered tokens, the test clock, caller chains', (t) => {
  const { engine } = setup(t);
  const issuer = engine();
  const { token } = issue(issuer);
  const pub = issuer.info().public_key;
  const verifier = engine({ state: 'state2', verify_only: true, trusted_keys: [pub] });
  assert.equal(verifier.authorize({ token, ...READ }).effect, 'allow');
  assert.equal(verifier.info().can_issue, false);
  assert.throws(() => issue(verifier), code('no_signing_key'));
  assert.equal(engine({ state: 'state3' }).authorize({ token, ...READ }).reason, 'token_invalid');
  const other = engine({ state: 'state4', verify_only: true, trusted_keys: [pub], issuer: 'smartdelegate://other' });
  assert.equal(other.authorize({ token, ...READ }).reason, 'token_invalid');

  const narrow = issue(issuer, { cap: { actions: ['read'], resources: ['crm.customer/c-1'] } }).token;
  const [head, body, sig] = narrow.split('.');
  const claims = JSON.parse(Buffer.from(body, 'base64url').toString());
  claims.cap.actions = ['*'];
  const forged = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const update = { action: 'update', resource: 'crm.customer', id: 'c-1' };
  assert.equal(issuer.authorize({ token: `${head}.${forged}.${sig}`, ...update }).reason, 'token_invalid');
  const none = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url');
  assert.equal(issuer.authorize({ token: `${none}.${forged}.`, ...update }).reason, 'token_invalid');
  for (const bad of [`${head}.${body}`, `${head}.${body}.${sig}.x`, `${head}.${body}.${sig}=`, `${head}.${body}.${sig.slice(0, -2)}`, `${head}.${body} .${sig}`, '..', `é.${body}.${sig}`]) {
    assert.equal(issuer.authorize({ token: bad, ...READ }).reason, 'token_invalid', bad.slice(-12));
  }

  const real = new Engine({ bundle_dir: BUNDLE });
  t.after(() => real.close());
  const short = real.issueToken({ user: 'alice', agent: 'support-bot', cap: FULL_CAP, ttl: 60 }).token;
  assert.equal(real.call('authorize', { token: short, action: 'read', resource: { path: 'crm.customer', id: 'c-1' }, now: T + 10 ** 9 }).effect, 'allow');

  const req = { chain: { user: 'alice', agents: ['support-bot'] }, action: 'read', resource: { path: 'crm.customer', id: 'c-1' } };
  assert.equal(issuer.call('authorize', req).reason, 'token_invalid');
  assert.equal(engine({ state: 's5', trust_caller_chain: true }).call('authorize', req).effect, 'allow');
});

test('two engines on one state directory: revocation, one audit chain, shared spend', (t) => {
  const { engine } = setup(t);
  const a = engine();
  const r = issue(a, { cap: { ...FULL_CAP, budget: { EUR: 1000 } } });
  const b = engine({ verify_only: true, trusted_keys: [a.info().public_key] });   // same state directory
  for (let i = 0; i < 6; i++) (i % 2 ? a : b).authorize({ token: r.token, action: 'read', resource: 'crm.customer', id: `c-${i}` });
  assert.equal(a.call('audit_verify', {}).records, 7);
  assert.equal(b.call('audit_verify', {}).records, 7);
  const spend = { context: { spend: { currency: 'EUR', amount: 600 } }, action: 'create', resource: 'billing.refund' };
  assert.equal(a.authorize({ token: r.token, ...spend, id: 'r-1' }).effect, 'allow');
  assert.equal(b.authorize({ token: r.token, ...spend, id: 'r-2' }).reason, 'budget_exceeded');
  assert.equal(b.authorize({ token: r.token, ...READ }).effect, 'allow');
  a.revoke(r.token_id);
  assert.equal(b.authorize({ token: r.token, ...READ }).reason, 'token_revoked');
  assert.equal(a.call('audit_verify', {}).records, 12);
});

test('audit: a record holding U+2028 does not break the tail or a second engine on the same log', (t) => {
  const { engine } = setup(t);
  const a = engine(), b = engine();
  const odd = { token: 'x', action: 're\u2028ad \u2029 \u0085 \u000b\u000c\u001c', resource: 'crm.customer', id: 'c-1' };
  assert.equal(a.authorize(odd).reason, 'token_invalid');
  assert.equal(a.call('audit_tail', { n: 5 }).records.length, 1);
  assert.equal(a.call('audit_tail', { n: 5 }).records[0].action, odd.action);
  assert.equal(b.authorize({ ...odd, action: 'read' }).reason, 'token_invalid', 'the second engine chains onto it');
  assert.equal(a.authorize(odd).reason, 'token_invalid');
  assert.equal(b.call('audit_verify', {}).records, 3);
});

test('failing closed: an unwritable audit log, a corrupt state file', (t) => {
  const { dir, engine } = setup(t);
  const e = engine();
  const r = issue(e);
  const req = { token: r.token, action: 'read', resource: { path: 'crm.customer', id: 'c-1' } };
  const log = join(dir, 'state', 'audit.jsonl');
  const saved = readFileSync(log);
  rmSync(log);
  mkdirSync(log);
  const out = e.call('authorize', req);
  assert.equal(out.error?.code, 'audit_io');
  assert.equal(out.effect, undefined);
  rmSync(log, { recursive: true });
  writeFileSync(log, saved);
  assert.equal(e.call('authorize', req).effect, 'allow');

  e.revoke(r.token_id);
  writeFileSync(join(dir, 'state', 'state.json'), '{not json');
  const bad = e.call('authorize', req);
  assert.equal(bad.ok, false);
  assert.equal(bad.error.code, 'state_io');
  writeFileSync(join(dir, 'state', 'state.json'), '{"revoked": []}');
  assert.equal(e.call('authorize', req).error.code, 'state_io');
});

test('OIDC ID tokens: RS256/384/512, ES256/384 and EdDSA verify; everything else is id_token_invalid', (t) => {
  const { engine } = setup(t);
  const { jwks, tokens } = makeIdTokens();
  const e = engine({ idp: { ...IDP, jwks } });
  assert.equal(Object.values(tokens).filter((x) => x.valid).length, 10);
  for (const [name, { token, valid }] of Object.entries(tokens)) {
    const r = e.call('issue_token', { id_token: token, agent: 'support-bot', cap: FULL_CAP, now: T });
    if (valid) assert.deepEqual([r.ok, r.user], [true, 'alice'], name);
    else assert.deepEqual([r.ok, r.error?.code], [false, 'id_token_invalid'], name);
  }
  // with exactly one key in the JWKS a token needs no kid
  const one = engine({ state: 'one', idp: { ...IDP, jwks: { keys: [jwks.keys.find((k) => k.kid === 'ed')] } } });
  assert.equal(one.call('issue_token', { id_token: tokens['no kid, several keys'].token, agent: 'support-bot', cap: FULL_CAP, now: T }).user, 'alice');
});

test('OIDC: the revoked-user cut-off against iat, and flat and nested group claims', (t) => {
  const { dir } = setup(t);
  const { jwks, idToken } = makeIdTokens();
  const scenarios = oidcScenarios(idToken);
  assert.ok(scenarios.length >= 30);
  scenarios.forEach((sc, n) => {
    const e = new Engine(config(join(dir, `s${n}`), { idp: { ...IDP, jwks, ...sc.idp } }));
    try {
      e.call('revoke', { user: 'bob', now: T + 500 });
      if (sc.revokeAt !== null) assert.equal(e.call('revoke', { user: 'alice', now: sc.revokeAt }).ok, true);
      const r = e.call('issue_token', sc.input);
      assert.equal(r.ok, sc.ok, `${sc.name}: ${JSON.stringify(r.error ?? null)}`);
      if (!sc.ok) {
        assert.equal(r.error.code, sc.code, sc.name);
      } else {
        assert.equal(r.user, 'alice', sc.name);
        assert.deepEqual(e.call('inspect_token', { token: r.token, now: T + 100 }).claims.grp, sc.grp, sc.name);
      }
    } finally {
      e.close();
    }
  });
});

test('reload re-reads idp.jwks_file: key rotation without a restart; a broken file leaves the old keys and the old bundle', (t) => {
  const { dir } = setup(t);
  const oldKeys = makeIdTokens(), newKeys = makeIdTokens();
  const file = join(dir, 'jwks.json');
  writeFileSync(file, JSON.stringify(oldKeys.jwks));
  const b = join(dir, 'bundle');
  cpSync(BUNDLE, b, { recursive: true });
  const e = new Engine({ ...config(join(dir, 'rot')), bundle_dir: b, idp: { ...IDP, jwks_file: file } });
  t.after(() => e.close());
  const issue = (keys) => e.call('issue_token', { id_token: keys.idToken(), agent: 'support-bot', cap: FULL_CAP, now: T });
  assert.equal(issue(oldKeys).ok, true);
  assert.equal(issue(newKeys).error.code, 'id_token_invalid');

  // the provider rotates its keys: nothing changes until reload
  writeFileSync(file, JSON.stringify(newKeys.jwks));
  assert.equal(issue(oldKeys).ok, true);
  assert.equal(issue(newKeys).error.code, 'id_token_invalid');
  const version = e.info().policy_version;
  const reloaded = e.call('reload', {});
  assert.deepEqual([reloaded.ok, reloaded.policy_version], [true, version]);
  assert.equal(issue(oldKeys).error.code, 'id_token_invalid', 'old-key tokens are refused after the reload');
  assert.equal(issue(newKeys).ok, true, 'new-key tokens are accepted');

  // a broken JWKS file: the error is returned, the keys in force stay, and so does the bundle
  const records = e.call('audit_verify', {}).records;
  const roles = join(b, 'roles.json');
  const goodRoles = readFileSync(roles, 'utf8');
  writeFileSync(roles, goodRoles.replace('"max_ttl": 600', '"max_ttl": 60'));   // a bundle change that must NOT take effect either
  for (const broken of ['{not json', '[]', '"x"', '{"keys": {}}', '{"keys": "x"}', '{}', 'null', Buffer.from([0xff, 0xfe])]) {
    writeFileSync(file, broken);
    const r = e.call('reload', {});
    assert.deepEqual([r.ok, r.error.code, r.error.rule], [false, 'invalid_config', 'DELEGATE-INVALID-CONFIG'], String(broken));
    assert.equal(issue(newKeys).ok, true, 'the keys in force before the failed reload still work');
    assert.equal(issue(oldKeys).error.code, 'id_token_invalid');
    assert.equal(e.info().policy_version, version, 'the bundle was not replaced either');
  }
  assert.equal(e.call('issue_token', { user: 'alice', agent: 'support-bot', role: 'support-agent', now: T }).expires_in, 600);
  rmSync(file);
  assert.equal(e.call('reload', {}).error.code, 'invalid_config');
  assert.equal(issue(newKeys).ok, true);
  assert.equal(e.call('audit_tail', { n: 1000 }).records.filter((x) => x.event === 'bundle_reloaded').length, 1, 'a failed reload is not recorded as a reload');
  assert.ok(e.call('audit_verify', {}).records > records);

  // a failing bundle leaves the old keys too
  writeFileSync(file, JSON.stringify(oldKeys.jwks));
  writeFileSync(roles, '{nope');
  assert.equal(e.call('reload', {}).error.code, 'roles_parse');
  assert.equal(issue(newKeys).ok, true);
  assert.equal(issue(oldKeys).error.code, 'id_token_invalid');
  // both good again: both replaced
  writeFileSync(roles, goodRoles.replace('"max_ttl": 600', '"max_ttl": 60'));
  const again = e.call('reload', {});
  assert.equal(again.ok, true);
  assert.notEqual(again.policy_version, version);
  assert.equal(issue(oldKeys).ok, true);
  assert.equal(issue(newKeys).error.code, 'id_token_invalid');
  assert.equal(e.call('issue_token', { user: 'alice', agent: 'support-bot', role: 'support-agent', now: T }).expires_in, 60);

  // inline keys are not re-read from anywhere
  const inline = new Engine({ ...config(join(dir, 'inline')), idp: { ...IDP, jwks: oldKeys.jwks, jwks_file: join(dir, 'missing.json') } });
  t.after(() => inline.close());
  assert.equal(inline.call('reload', {}).ok, true);
  assert.equal(inline.call('issue_token', { id_token: oldKeys.idToken(), agent: 'support-bot', cap: FULL_CAP, now: T }).ok, true);
});

test('configuration errors are EngineErrors', () => {
  assert.throws(() => new Engine(null), code('invalid_input'));
  assert.throws(() => new Engine({}), code('invalid_input'));
  assert.throws(() => new Engine({ bundle_dir: BUNDLE, mode: 'observe' }), code('invalid_config'));
  assert.throws(() => new Engine({ bundle_dir: BUNDLE, idp: { issuer: 'x', audience: 'y', jwks_file: '/nonexistent/jwks.json' } }), code('invalid_config'));
  assert.throws(() => new Engine({ bundle_dir: BUNDLE, signing_key: 'AAAA' }), code('crypto'));
  assert.throws(() => new Engine({ bundle_dir: BUNDLE, trusted_keys: ['AAAA'] }), code('crypto'));
});
