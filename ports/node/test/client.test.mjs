// The REST client against this port's daemon: API keys, tool middleware,
// failure modes, raw HTTP behaviour of the daemon. (The first three tests are
// those of ports/js, whose public API this client keeps.)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { Client, Denied, SmartDelegateError, guardTool } from '../lib/index.mjs';
import { parse } from '../lib/json.mjs';
import { ADMIN, OIDC, PEP, startDaemon } from '../tools/support.mjs';

const CAP = { actions: ['read', 'create', 'update'], resources: ['crm.customer/*', 'billing.refund/*'], budget: { EUR: 20000 } };

test('daemon keys separate enforcement points from administrators', async () => {
  const d = await startDaemon();
  try {
    const admin = new Client({ url: d.url, adminKey: ADMIN });
    const pep = new Client({ url: d.url, pepKey: PEP });
    const nobody = new Client({ url: d.url });
    const { token, token_id } = await admin.issueToken({ user: 'alice', agent: 'support-bot', cap: CAP });

    await assert.rejects(pep.issueToken({ user: 'carol', agent: 'support-bot', cap: CAP }), { code: 'unauthorized' });
    await assert.rejects(pep.revoke(token_id), { code: 'unauthorized' });
    await assert.rejects(nobody.authorize({ token, action: 'read', resource: 'crm.customer', id: 'c-1' }), { code: 'unauthorized' });
    await assert.rejects(new Client({ url: d.url, pepKey: 'wrong-key-wrong-key-wrong' }).info(), { code: 'unauthorized' });

    assert.equal((await pep.authorize({ token, action: 'read', resource: 'crm.customer', id: 'c-1' })).effect, 'allow');
    // exchanging needs no key: holding the parent token is the authority
    const child = await nobody.exchangeToken({ subjectToken: token, actor: 'refund-helper', cap: { actions: ['read'], resources: ['crm.customer/c-1'] }, ttl: 300 });
    assert.deepEqual(child.chain, ['support-bot', 'refund-helper']);
    await assert.rejects(nobody.exchangeToken({ subjectToken: token, actor: 'refund-helper', cap: { actions: ['*'], resources: ['*'] }, ttl: 300 }), { code: 'widening' });
    // a role token over REST
    const role = await admin.issueToken({ user: 'alice', agent: 'support-bot', role: 'support-agent', groups: ['support'] });
    assert.equal(role.role, 'support-agent');
    assert.equal((await pep.info()).implementation, 'node');
    assert.equal(role.task, null);
    // offboarding needs the admin key
    await assert.rejects(pep.revokeUser('alice', 'hr'), { code: 'unauthorized' });
    const gone = await admin.revokeUser('alice', 'hr');
    assert.equal(gone.revoked_user, 'alice');
    assert.equal((await pep.authorize({ token: role.token, action: 'read', resource: 'crm.customer', id: 'c-1' })).reason, 'token_revoked');
  } finally {
    await d.stop();
  }
});

test('guardTool decides first, checks input strictly and masks output', async () => {
  const d = await startDaemon();
  try {
    const client = new Client({ url: d.url, pepKey: PEP, adminKey: ADMIN });
    const { token } = await client.issueToken({ user: 'alice', agent: 'support-bot', cap: CAP });
    const ran = [];

    const getCustomer = guardTool(client, () => token, { action: 'read', resource: 'crm.customer', id: (a) => a.id },
      async ({ id }) => { ran.push(id); return { id, email: 'ada@example.com', ssn: '123-45-6789', region: 'EU' }; });
    assert.deepEqual(await getCustomer({ id: 'c-1' }), { id: 'c-1', email: 'ada@example.com', region: 'EU' });

    const dropAll = guardTool(client, token, { action: 'delete', resource: 'crm.customer', id: (a) => a.id }, async ({ id }) => { ran.push(`deleted ${id}`); });
    await assert.rejects(dropAll({ id: 'c-1' }), (e) => e instanceof Denied && e.reason === 'capability_action');

    const update = guardTool(client, token, { action: 'update', resource: 'crm.customer', id: (a) => a.id, input: (a) => a.changes },
      async ({ id, changes }) => { ran.push(changes); return { id, ...changes }; });
    await assert.rejects(update({ id: 'c-1', changes: { tier: 'platinum' } }), (e) => e.reason === 'field_denied');
    assert.deepEqual(await update({ id: 'c-1', changes: { email: 'new@example.com' } }), { email: 'new@example.com' });

    const refund = guardTool(client, token, { action: 'create', resource: 'billing.refund', spend: (a) => ['EUR', a.amount] },
      async ({ amount }) => { ran.push(amount); return { amount, currency: 'EUR', internal_note: 'x' }; });
    assert.deepEqual(await refund({ amount: 5000 }), { amount: 5000, currency: 'EUR' });
    const held = await refund({ amount: 15000 }).catch((e) => e);
    assert.equal(held.reason, 'approval_required');
    await client.approve(held.approvalId, 'bob');
    assert.equal((await refund({ amount: 15000 })).amount, 15000);

    assert.deepEqual(ran, ['c-1', { email: 'new@example.com' }, 5000, 15000]);
  } finally {
    await d.stop();
  }
});

test('an unreachable daemon is an error, never an allow', async () => {
  const client = new Client({ url: 'http://127.0.0.1:9', pepKey: PEP, timeoutMs: 2000 });
  await assert.rejects(client.authorize({ token: 'x', action: 'read', resource: 'crm.customer' }), (e) => e instanceof SmartDelegateError && e.code === 'daemon_unreachable');
  let ran = false;
  const tool = guardTool(client, 'x', { action: 'read', resource: 'crm.customer' }, async () => { ran = true; });
  await assert.rejects(tool({}));
  assert.equal(ran, false);
  assert.equal((await client.call('no_such_op', {})).error.code, 'unknown_op');
  assert.equal((await client.call('constructor', {})).error.code, 'unknown_op');
});

test('daemon: routes, status codes, body rules, exact integers', async () => {
  const d = await startDaemon();
  try {
    const http = async (method, path, { key, body, headers = {} } = {}) => {
      const h = { ...headers };
      if (key) h.Authorization = `Bearer ${key}`;
      const res = await fetch(d.url + path, { method, headers: h, body });
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* not JSON */ }
      return { status: res.status, text, json, type: res.headers.get('content-type') };
    };
    const post = (path, obj, key) => http('POST', path, { key, body: typeof obj === 'string' || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj) });

    let r = await http('GET', '/healthz');
    assert.deepEqual([r.status, r.json, r.type], [200, { ok: true }, 'application/json']);
    assert.equal((await http('GET', '/healthz?x=1')).status, 200);
    assert.equal((await http('POST', '/healthz', { body: 'garbage' })).status, 200);

    r = await http('GET', '/v1/nope', { key: ADMIN });
    assert.deepEqual([r.status, r.json.error.code], [404, 'not_found']);
    assert.equal((await http('GET', '/v1/info/', { key: ADMIN })).status, 404);
    assert.equal((await http('GET', '/v1/authorize', { key: ADMIN })).status, 404, 'the method is part of the route');
    assert.equal((await http('POST', '/v1/info', { key: ADMIN, body: '{}' })).status, 404);
    assert.equal((await http('DELETE', '/v1/info', { key: ADMIN })).status, 501);

    // 401: no key, wrong key, pep key on an admin route, wrong scheme
    for (const key of [undefined, 'x', PEP + 'x', ADMIN.slice(0, -1)]) {
      r = await http('GET', '/v1/info', { key });
      assert.deepEqual([r.status, r.json.error.code], [401, 'unauthorized'], String(key));
    }
    assert.equal((await http('GET', '/v1/admin/approvals', { key: PEP })).status, 401);
    assert.equal((await http('GET', '/v1/info', { headers: { Authorization: `Basic ${PEP}` } })).status, 401);
    assert.equal((await http('GET', '/v1/info', { headers: { Authorization: `bearer ${PEP}` } })).status, 401);
    assert.equal((await http('GET', '/v1/info', { headers: { Authorization: `Bearer   ${PEP}  ` } })).status, 200);
    assert.equal((await http('GET', '/v1/info', { key: ADMIN })).status, 200, 'the admin key is also a pep key');
    assert.equal((await post('/v1/token', { user: 'alice', agent: 'support-bot', cap: CAP }, PEP)).status, 401);
    assert.equal((await post('/v1/token', [1, 2], undefined)).status, 401);

    // 400 before authentication for a body that is not JSON; engine errors are 400 too
    r = await post('/v1/authorize', '{not json', undefined);
    assert.deepEqual([r.status, r.json.error], [400, { code: 'invalid_input', message: 'body is not JSON' }]);
    assert.equal((await post('/v1/authorize', Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x7d]), PEP)).json.error.message, 'body is not JSON');
    assert.equal((await post('/v1/authorize', '['.repeat(200000), PEP)).json.error.message, 'body is not JSON');
    r = await post('/v1/authorize', '[1]', PEP);
    assert.deepEqual([r.status, r.json.error.code, r.json.error.rule], [400, 'invalid_input', 'DELEGATE-INVALID-INPUT']);
    r = await post('/v1/authorize', '   ', PEP);
    assert.deepEqual([r.status, r.json.error.code], [400, 'invalid_input'], 'an empty body is {}');
    r = await post('/v1/token', { user: 'alice', agent: 'support-bot' }, ADMIN);
    assert.deepEqual([r.status, r.json.error.code], [400, 'invalid_cap']);

    // the body limit: 8 MiB
    r = await post('/v1/authorize', JSON.stringify({ pad: 'x'.repeat(8 * 1024 * 1024) }), PEP);
    assert.deepEqual([r.status, r.json.error.message], [400, 'request body is too large']);
    r = await post('/v1/authorize', JSON.stringify({ pad: 'x'.repeat(8 * 1024 * 1024 - 100) }), PEP);
    assert.deepEqual([r.status, r.json.error.code], [400, 'invalid_input'], 'just under the limit reaches the engine');
    assert.equal((await http('GET', '/healthz')).status, 200, 'the daemon is still up');

    // token exchange and a decision
    const tok = (await post('/v1/token', { user: 'alice', agent: 'support-bot', cap: CAP }, ADMIN)).json;
    assert.equal(tok.ok, true);
    r = await post('/v1/token', { subject_token: tok.token, actor: 'refund-helper', ttl: 300 }, undefined);
    assert.deepEqual([r.status, r.json.chain], [200, ['support-bot', 'refund-helper']]);
    r = await post('/v1/authorize', { token: tok.token, action: 'delete', resource: { path: 'crm.customer', id: 'c-1' } }, PEP);
    assert.deepEqual([r.status, r.json.effect, r.json.rule], [200, 'deny', 'DELEGATE-CAPABILITY-ACTION'], 'a deny is 200');

    // integers and floats are exact on the wire, in both directions
    const big = '123456789012345678901234567890';
    r = await post('/v1/obligations/apply', `{"obligations":{"fields":{"allow":["n","f","s"]}},"data":{"n":${big},"f":1.0,"s":"é\\u2028😀","dropped":1}}`, PEP);
    assert.equal(r.status, 200);
    assert.ok(r.text.includes(`"n":${big}`), r.text);
    assert.ok(r.text.includes('"f":1.0'), r.text);
    assert.ok(r.text.includes('"s":"\\u00e9\\u2028\\ud83d\\ude00"'), r.text);
    const exact = parse(r.text);
    assert.equal(exact.data.n, BigInt(big));
    assert.deepEqual(exact.masked, ['dropped']);
    const client = new Client({ url: d.url, pepKey: PEP });
    const viaClient = await client.call('apply_obligations', { obligations: { fields: { allow: ['n'] } }, data: { n: BigInt(big), m: 7 } });
    assert.deepEqual(viaClient.data, { n: BigInt(big) });
    assert.equal(viaClient.rows_dropped, 0);
    r = await post('/v1/authorize', `{"token":"${tok.token}","action":"read","resource":{"path":"crm.customer","id":"c-1"},"context":{"n":9223372036854775808}}`, PEP);
    assert.deepEqual([r.status, r.json.error.code], [400, 'invalid_context']);
    r = await post('/v1/authorize', `{"token":"${tok.token}","action":"read","resource":{"path":"crm.customer","id":"c-1"},"context":{"n":9223372036854775807}}`, PEP);
    assert.deepEqual([r.status, r.json.effect], [200, 'allow']);
    r = await post('/v1/authorize', `{"token":"${tok.token}","action":"read","resource":{"path":"crm.customer","id":"c-1"},"context":{"n":1.0}}`, PEP);
    assert.deepEqual([r.status, r.json.error.code], [400, 'invalid_context'], '1.0 is a float, not the integer 1');

    // member order of echoed data is the order in which it was sent, also for integer-like keys
    r = await post('/v1/obligations/apply', '{"obligations":{"fields":{"allow":["m","b","10","9","a"]}},"data":[{"b":1,"10":2,"9":3,"zz":0,"a":4,"m":{"z":1,"2":2,"1":3}}]}', PEP);
    assert.ok(r.text.includes('"data":[{"b":1,"10":2,"9":3,"a":4,"m":{"z":1,"2":2,"1":3}}]'), r.text);
    r = await post('/v1/filter', `{"token":"${tok.token}","action":"read","resource":{"path":"crm.customer","id":"c-1"},"dry_run":true,`
      + '"data":{"region":"EU","id":"c","addresses":[{"b":1,"10":2,"9":3,"geo":0,"a":4}]}}', PEP);
    assert.ok(r.text.includes('"data":{"region":"EU","id":"c","addresses":[{"b":1,"10":2,"9":3,"a":4}]}'), r.text);

    // audit tail: ?n=
    assert.equal((await http('GET', '/v1/admin/audit/tail?n=2', { key: ADMIN })).json.records.length, 2);
    assert.equal((await http('GET', '/v1/admin/audit/tail?x=1&n=1', { key: ADMIN })).json.records.length, 1);
    assert.equal((await http('GET', '/v1/admin/audit/tail?n=abc', { key: ADMIN })).json.records.length, 4);
    assert.equal((await http('GET', '/v1/admin/audit/tail', { key: ADMIN })).json.records.length, 4);
    assert.equal((await client.call('audit_tail', { n: 3 })).error.code, 'unauthorized');
    r = await http('GET', '/v1/admin/audit/verify', { key: ADMIN });
    assert.deepEqual([r.status, r.json.records], [200, 4]);
    r = await http('POST', '/v1/admin/reload', { key: ADMIN });
    assert.deepEqual([r.status, r.json.implementation, r.json.version], [200, 'node', '0.3.0']);
  } finally {
    await d.stop();
  }
});

test('daemon: an ID token is the credential, and `user` in the body is ignored', async () => {
  const idTokens = JSON.parse(readFileSync(join(OIDC, 'id_tokens.json'), 'utf8'));
  const jwks = JSON.parse(readFileSync(join(OIDC, 'jwks.json'), 'utf8'));
  const d = await startDaemon({ idp: { issuer: 'https://idp.example.test', audience: 'smartdelegate-demo', jwks } });
  try {
    const post = async (body, key) => {
      const res = await fetch(d.url + '/v1/token', { method: 'POST', headers: key ? { Authorization: `Bearer ${key}` } : {}, body: JSON.stringify(body) });
      return { status: res.status, json: await res.json() };
    };
    // no key needed; the body names bob, the ID token says alice: the token is for alice
    let r = await post({ id_token: idTokens.alice, user: 'bob', agent: 'support-bot', cap: CAP });
    assert.deepEqual([r.status, r.json.user], [200, 'alice']);
    r = await post({ id_token: idTokens.forged, agent: 'support-bot', cap: CAP });
    assert.deepEqual([r.status, r.json.error.code], [400, 'id_token_invalid']);
    r = await post({ id_token: idTokens.expired, agent: 'support-bot', cap: CAP }, ADMIN);
    assert.deepEqual([r.status, r.json.error.code], [400, 'id_token_invalid']);
    // without an ID token the admin key is required
    assert.equal((await post({ user: 'alice', agent: 'support-bot', cap: CAP })).status, 401);
    // the client sends no key with an ID token
    const client = new Client({ url: d.url, adminKey: ADMIN });
    assert.equal((await client.issueToken({ idToken: idTokens.alice, agent: 'support-bot', cap: CAP })).user, 'alice');
  } finally {
    await d.stop();
  }
});
