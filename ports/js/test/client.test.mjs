// Client behaviour: API keys, tool middleware, failure modes.
import assert from 'node:assert/strict';
import test from 'node:test';
import { SmartDelegateError, Client, Denied, guardTool } from '../index.mjs';
import { ADMIN, PEP, startDaemon } from './support.mjs';

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
  } finally {
    d.stop();
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
    d.stop();
  }
});

test('an unreachable daemon is an error, never an allow', async () => {
  const client = new Client({ url: 'http://127.0.0.1:9', pepKey: PEP, timeoutMs: 2000 });
  await assert.rejects(client.authorize({ token: 'x', action: 'read', resource: 'crm.customer' }), (e) => e instanceof SmartDelegateError && e.code === 'daemon_unreachable');
  let ran = false;
  const tool = guardTool(client, 'x', { action: 'read', resource: 'crm.customer' }, async () => { ran = true; });
  await assert.rejects(tool({}));
  assert.equal(ran, false);
});

test('role tokens, live groups and revoking a user', async () => {
  const d = await startDaemon();
  try {
    const admin = new Client({ url: d.url, adminKey: ADMIN, pepKey: PEP });
    const g = await admin.issueToken({ user: 'dave', agent: 'support-bot', role: 'support-agent', groups: ['support'], task: 'ticket-1' });
    assert.equal(g.role, 'support-agent');
    assert.equal(g.task, 'ticket-1');
    assert.deepEqual(g.cap.deny_labels, ['secret']);
    await assert.rejects(admin.issueToken({ user: 'dave', agent: 'support-bot', role: 'support-agent' }), { code: 'role_not_held' });
    await assert.rejects(admin.issueToken({ user: 'alice', agent: 'support-bot', role: 'support-agent', cap: { actions: ['read'], resources: ['hr.salary/*'] } }), { code: 'role_exceeded' });
    const before = await admin.authorize({ token: g.token, action: 'read', resource: 'crm.customer', id: 'c-1' });
    assert.equal(before.effect, 'allow');
    assert.equal(before.rule, 'DELEGATE-POLICY-PERMIT');
    assert.equal(before.principal.role, 'support-agent');
    await new Promise((r) => setTimeout(r, 1100)); // the cut-off is inclusive to the second
    assert.equal((await admin.revokeUser('dave', 'test')).revoked_user, 'dave');
    const after = await admin.authorize({ token: g.token, action: 'read', resource: 'crm.customer', id: 'c-1' });
    assert.equal(after.reason, 'token_revoked');
    await assert.rejects(new Client({ url: d.url, pepKey: PEP }).revokeUser('alice'), { code: 'unauthorized' });
  } finally {
    d.stop();
  }
});
