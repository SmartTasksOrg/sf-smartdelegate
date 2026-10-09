// The shared conformance vectors, through the JavaScript client and the daemon.
import assert from 'node:assert/strict';
import test from 'node:test';
import { Client } from '../index.mjs';
import { ADMIN, PEP, cases, runCase, startDaemon } from './support.mjs';

test('shared conformance vectors', async () => {
  const all = cases();
  assert.ok(all.length >= 65);
  for (const c of all) {
    const d = await startDaemon(c.config); // a suite may add settings, e.g. an identity provider
    try {
      const client = new Client({ url: d.url, pepKey: PEP, adminKey: ADMIN });
      const failures = await runCase((op, input) => client.call(op, input), c);
      assert.deepEqual(failures, [], `${c.suite}: ${c.name}`);
    } finally {
      d.stop();
    }
  }
});
