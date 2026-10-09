// Runner for the policy evaluation cases, the shared conformance vectors and
// a bundle's own tests.
//
// A case is a list of steps; each step names an operation, its input and a
// partial expected result. `save` stores a value from a result and "$name" in
// a later input is replaced by it.
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeUtf8 } from './canon.mjs';
import * as cedar from './cedar.mjs';
import { Engine } from './engine.mjs';
import { cmpCodePoint, has, isObj, jsonEq, parse, stringify, toInternal } from './json.mjs';

export function readJson(path) {
  let text = decodeUtf8(readFileSync(path));
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return parse(text);
}

export function substitute(v, variables) {
  if (typeof v === 'string' && v.startsWith('$')) return variables.has(v.slice(1)) ? variables.get(v.slice(1)) : v;
  if (Array.isArray(v)) return v.map((x) => substitute(x, variables));
  if (isObj(v)) {
    const out = Object.create(null);
    for (const k of Object.keys(v)) out[k] = substitute(v[k], variables);
    return out;
  }
  return v;
}

/** Every key in `expect` must be present and equal in `actual`; objects
 * recursively, everything else exactly. An expected null also matches a
 * missing key. Returns a mismatch or null. */
export function subset(expect, actual, path = '') {
  if (isObj(expect) && isObj(actual)) {
    for (const k of Object.keys(expect)) {
      const p = path ? `${path}.${k}` : k;
      if (!has(actual, k)) {
        if (expect[k] === null) continue;
        return `${p}: missing, expected ${stringify(expect[k])}`;
      }
      const m = subset(expect[k], actual[k], p);
      if (m) return m;
    }
    return null;
  }
  if (!jsonEq(expect, actual)) return `${path}: expected ${stringify(expect)}, got ${stringify(actual === undefined ? null : actual)}`;
  return null;
}

function finishStep(step, n, result, variables, failures) {
  const save = isObj(step.save) ? step.save : {};
  for (const name of Object.keys(save)) {
    let cur = result;
    for (const part of String(save[name]).split('.')) cur = isObj(cur) && has(cur, part) ? cur[part] : null;
    variables.set(name, cur);
  }
  const m = subset(isObj(step.expect) ? step.expect : {}, result);
  if (m) failures.push({ step: n, op: step.op ?? null, mismatch: m });
}

const stepsOf = (c) => (Array.isArray(c.steps) ? c.steps : []);
const inputOf = (step, variables) => substitute(has(step, 'input') ? step.input : null, variables);

/** `call(op, input) -> result`, synchronous (an Engine). */
export function runCase(call, c) {
  const variables = new Map(), failures = [];
  stepsOf(c).forEach((step, n) => finishStep(step, n, call(step.op ?? '', inputOf(step, variables)), variables, failures));
  return { name: c.name ?? null, steps: stepsOf(c).length, passed: failures.length === 0, failures };
}

/** `call(op, input) -> Promise<result>` (a REST Client). */
export async function runCaseAsync(call, c) {
  const variables = new Map(), failures = [];
  let n = 0;
  for (const step of stepsOf(c)) finishStep(step, n++, await call(step.op ?? '', inputOf(step, variables)), variables, failures);
  return { name: c.name ?? null, steps: stepsOf(c).length, passed: failures.length === 0, failures };
}

/** The configuration every port uses for the shared vectors, plus the suite's
 * own `config` when it has one. */
export function conformanceConfig(bundleDir, stateDir, extra, maxDepth = 3) {
  return { bundle_dir: bundleDir, state_dir: stateDir, allow_test_clock: true, max_depth: maxDepth, ...(isObj(extra) ? extra : {}) };
}

/** [{file, suite, config, cases}] for every *.json in the directory, in name order. */
export function loadVectors(vectorsDir) {
  return readdirSync(vectorsDir).filter((f) => f.endsWith('.json')).sort(cmpCodePoint).map((f) => {
    const doc = readJson(join(vectorsDir, f));
    return { file: f, suite: typeof doc.suite === 'string' ? doc.suite : f.replace(/\.json$/, ''),
      config: isObj(doc.config) ? doc.config : null, cases: Array.isArray(doc.cases) ? doc.cases : [] };
  });
}

/** Every case against a fresh engine with its own state directory. */
export function runVectors(vectorsDir, bundleDir, maxDepth = 3) {
  const results = [], suites = [];
  for (const v of loadVectors(vectorsDir)) {
    const suite = { file: v.file, suite: v.suite, total: 0, failed: 0, steps: 0 };
    for (const c of v.cases) {
      const state = mkdtempSync(join(tmpdir(), 'smartdelegate-conf-'));
      let engine = null, r;
      try {
        engine = new Engine(conformanceConfig(bundleDir, state, v.config, maxDepth));
        r = runCase((op, input) => engine.call(op, input), c);
      } finally {
        engine?.close();
        rmSync(state, { recursive: true, force: true });
      }
      r.suite = v.suite;
      results.push(r);
      suite.total++;
      suite.steps += r.steps;
      if (!r.passed) suite.failed++;
    }
    suites.push(suite);
  }
  return { total: results.length, failed: results.filter((r) => !r.passed).length, steps: results.reduce((n, r) => n + r.steps, 0), suites, results };
}

/** `<bundle>/tests/*.json` against a throwaway engine per case: no state
 * directory, no audit log, test clock on, caller-supplied chains trusted. */
export function runBundleTests(bundleDir) {
  const results = [];
  const dir = join(bundleDir, 'tests');
  const files = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.json')).sort(cmpCodePoint) : [];
  for (const f of files) {
    const doc = readJson(join(dir, f));
    for (const c of Array.isArray(doc.cases) ? doc.cases : []) {
      const engine = new Engine({ bundle_dir: bundleDir, allow_test_clock: true, trust_caller_chain: true, audit: false });
      try {
        results.push(runCase((op, input) => engine.call(op, input), c));
      } finally {
        engine.close();
      }
    }
  }
  return { total: results.length, failed: results.filter((r) => !r.passed).length, results };
}

/** One policy evaluation case (spec/conformance/eval/cases.json) against the
 * evaluator. `store` is a cedar.Store of the file's entities. Returns a
 * mismatch or null. */
export function runEvalCase(c, store) {
  const expect = c.expect;
  let policies;
  try {
    policies = new Map(Object.keys(c.policies).map((pid) => [pid, new cedar.Policy(pid, c.policies[pid])]));
  } catch (e) {
    if (!(e instanceof cedar.Unsupported)) throw e;
    return expect.load_error === true ? null : `load failed: ${e.message}`;
  }
  if (expect.load_error === true) return 'expected the policy to be refused at load, but it loaded';
  const r = c.request;
  const env = new cedar.Env(new cedar.Entity(r.principal[0], r.principal[1]), new cedar.Entity('Action', r.action),
    new cedar.Entity(r.resource[0], r.resource[1]), cedar.fromJson(r.context), store);
  const got = cedar.isAuthorized(policies, env);
  const actual = toInternal({ decision: got.decision, reasons: got.reasons, errors: got.errors.map((e) => e[0]).sort(cmpCodePoint) });
  return jsonEq(actual, expect) ? null : `expected ${stringify(expect)}, got ${stringify(actual)}`;
}

/** {entities, cases} of an eval file, with the store built. */
export function loadEval(casesFile) {
  const doc = readJson(casesFile);
  return { store: new cedar.Store(doc.entities), cases: doc.cases };
}

export function runEval(casesFile) {
  const { store, cases } = loadEval(casesFile);
  const results = cases.map((c) => {
    let mismatch;
    try {
      mismatch = runEvalCase(c, store);
    } catch (e) {
      mismatch = `threw ${e?.name}: ${e?.message}`;
    }
    return { name: c.name, passed: mismatch === null, failures: mismatch === null ? [] : [{ mismatch }] };
  });
  return { total: results.length, failed: results.filter((r) => !r.passed).length, results };
}
