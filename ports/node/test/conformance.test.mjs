// (2) The shared conformance vectors, in-process: a fresh engine and state
// directory per case.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { conformanceConfig, loadVectors, runCase } from '../lib/conformance.mjs';
import { Engine } from '../lib/index.mjs';
import { BUNDLE, VECTORS } from '../tools/support.mjs';

const suites = loadVectors(VECTORS);

test('the vector files hold the 78 cases and 327 steps of the spec', () => {
  assert.equal(suites.reduce((n, s) => n + s.cases.length, 0), 78);
  assert.equal(suites.reduce((n, s) => n + s.cases.reduce((m, c) => m + c.steps.length, 0), 0), 327);
});

for (const s of suites) {
  for (const c of s.cases) {
    test(`in-process ${s.suite}: ${c.name}`, () => {
      const state = mkdtempSync(join(tmpdir(), 'smartdelegate-node-conf-'));
      let engine = null;
      try {
        engine = new Engine(conformanceConfig(BUNDLE, state, s.config));
        const r = runCase((op, input) => engine.call(op, input), c);
        assert.deepEqual(r.failures, []);
        assert.equal(r.steps, c.steps.length);
      } finally {
        engine?.close();
        rmSync(state, { recursive: true, force: true });
      }
    });
  }
}
