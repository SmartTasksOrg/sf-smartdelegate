// (3) The shared conformance vectors over REST: this port's daemon
// (`cli.mjs serve`, one per case) driven by this port's client.
import assert from 'node:assert/strict';
import test from 'node:test';
import { loadVectors, runCaseAsync } from '../lib/conformance.mjs';
import { Client } from '../lib/index.mjs';
import { toPlain } from '../lib/json.mjs';
import { ADMIN, PEP, VECTORS, startDaemon } from '../tools/support.mjs';

const suites = loadVectors(VECTORS);

for (const s of suites) {
  for (const c of s.cases) {
    test(`REST ${s.suite}: ${c.name}`, async () => {
      const d = await startDaemon(s.config ? toPlain(s.config) : {});
      try {
        const client = new Client({ url: d.url, pepKey: PEP, adminKey: ADMIN });
        const r = await runCaseAsync((op, input) => client.call(op, input), c);
        assert.deepEqual(r.failures, []);
        assert.equal(r.steps, c.steps.length);
      } finally {
        await d.stop();
      }
    });
  }
}
