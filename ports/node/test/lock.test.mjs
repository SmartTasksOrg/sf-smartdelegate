// (5b) The state-directory lock between Node.js processes.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { Engine, auditVerify } from '../lib/index.mjs';
import { DirLock } from '../lib/lock.mjs';
import { BUNDLE, HERE, tempDir } from '../tools/support.mjs';

function run(script, args) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [join(HERE, 'tools', script), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', reject);
    p.on('exit', (code) => (code === 0 ? resolve(out) : reject(new Error(`${script} exited with ${code}: ${err}`))));
  });
}

test('four processes hammering one state directory keep one valid audit chain and one ledger', async (t) => {
  const dir = tempDir(t);
  const state = join(dir, 'state');
  const PROCS = 4, COUNT = 60, BUDGET = 1000, AMOUNT = 10;
  const parent = new Engine({ bundle_dir: BUNDLE, state_dir: state, max_depth: 3 });
  t.after(() => parent.close());
  const shared = parent.issueToken({ user: 'alice', agent: 'support-bot', cap: { actions: ['read'], resources: ['crm.customer/*'], budget: { EUR: BUDGET } } });

  const results = (await Promise.all(Array.from({ length: PROCS }, () => run('hammer.mjs', [state, BUNDLE, String(COUNT), shared.token]))))
    .map((line) => JSON.parse(line));
  for (const r of results) {
    assert.deepEqual(r.errors, [], 'no call failed (no lock timeout, no state or audit error)');
    assert.equal(r.issued, 1);
    assert.equal(r.allowed, COUNT);
    assert.equal(r.spent + r.refused, COUNT);
  }
  // the budget was spent exactly once over, however the processes interleaved
  assert.equal(results.reduce((n, r) => n + r.spent, 0), BUDGET / AMOUNT);
  assert.ok(results.filter((r) => r.spent > 0).length >= 2, 'the processes really did interleave');
  const ledger = JSON.parse(readFileSync(join(state, 'state.json'), 'utf8')).ledger;
  assert.equal(ledger[shared.token_id].EUR, BUDGET);

  // 1 issue by the parent, then per process 1 issue + 2 decisions per round
  const expected = 1 + PROCS * (1 + 2 * COUNT);
  const direct = auditVerify(join(state, 'audit.jsonl'));
  assert.equal(direct.records, BigInt(expected));
  const v = parent.call('audit_verify', {});
  assert.equal(v.ok, true);
  assert.equal(v.records, expected);
  assert.equal(v.head, direct.head);
  // the parent engine, open all along, chains onto what the others wrote
  assert.equal(parent.authorize({ token: shared.token, action: 'read', resource: 'crm.customer', id: 'c-1' }).effect, 'allow');
  assert.equal(parent.call('audit_verify', {}).records, expected + 1);
  assert.deepEqual(readdirSync(state).filter((f) => f.startsWith('lock')), [], 'no lock file is left behind');
});

test('a lock left by a dead process is taken over; a held lock times out as state_io', async (t) => {
  const dir = tempDir(t);
  const state = join(dir, 'state');
  mkdirSync(state);
  // a lock whose holder (a pid that does not exist) is gone
  writeFileSync(join(state, 'lock.node'), '4194399 12345 abcdef\n');
  const e = new Engine({ bundle_dir: BUNDLE, state_dir: state, lock_timeout_ms: 400 });
  t.after(() => e.close());
  assert.equal(e.call('info', {}).ok, true);
  assert.equal(existsSync(join(state, 'lock.node')), false);

  const holder = spawn(process.execPath, [join(HERE, 'tools', 'hold_lock.mjs'), state], { stdio: ['ignore', 'pipe', 'inherit'] });
  const exited = new Promise((done) => holder.once('exit', done));
  t.after(() => { holder.kill('SIGKILL'); return exited; });
  await new Promise((ok, fail) => {
    holder.stdout.once('data', ok);
    holder.once('exit', () => fail(new Error('the lock holder exited')));
  });
  const started = Date.now();
  const refused = e.call('info', {});
  assert.equal(refused.ok, false);
  assert.equal(refused.error.code, 'state_io');
  assert.ok(Date.now() - started >= 350, 'it waited for the lock before giving up');
  assert.throws(() => new Engine({ bundle_dir: BUNDLE, state_dir: state, lock_timeout_ms: 100 }), (err) => err.code === 'state_io');

  // the holder dies without releasing: its lock file is still there, and is recognised as stale
  holder.kill('SIGKILL');
  await exited;
  assert.equal(existsSync(join(state, 'lock.node')), true);
  assert.equal(e.call('info', {}).ok, true);
  assert.equal(existsSync(join(state, 'lock.node')), false);
});

test('the lock excludes: a second lock object cannot take it until it is released', (t) => {
  const dir = tempDir(t);
  const a = new DirLock(dir), b = new DirLock(dir, { timeoutMs: 100 });
  a.acquire();
  assert.throws(() => b.acquire(), (err) => err.code === 'state_io');
  a.release();
  b.acquire();
  b.release();
  a.release();   // releasing twice is harmless and does not remove someone else's lock
  b.acquire();
  a.release();
  assert.equal(existsSync(join(dir, 'lock.node')), true);
  b.release();
});
