// (1) The policy evaluator against answers recorded from the real Cedar engine.
import assert from 'node:assert/strict';
import test from 'node:test';
import { loadEval, runEvalCase } from '../lib/conformance.mjs';
import { EVAL } from '../tools/support.mjs';

const { store, cases } = loadEval(EVAL);

test('the eval file holds the 95 cases of the spec', () => {
  assert.equal(cases.length, 95);
  assert.ok(cases.filter((c) => c.expect.load_error === true).length >= 3, 'load_error cases are present');
  assert.ok(cases.filter((c) => /overflow/.test(c.name)).length >= 3, 'overflow cases are present');
});

cases.forEach((c, n) => {
  test(`eval ${String(n + 1).padStart(2, '0')}: ${c.name}`, () => {
    assert.equal(runEvalCase(c, store), null);
  });
});
