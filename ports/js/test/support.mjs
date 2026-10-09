import { spawn } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
// The daemon under test. Default: the Python reference implementation.
// Set SMARTDELEGATE_CLI to a JSON array to use another port, e.g.
//   SMARTDELEGATE_CLI='["/repo/ports/rust/target/release/smartdelegate"]'
const python = process.env.PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
export const CLI = process.env.SMARTDELEGATE_CLI ? JSON.parse(process.env.SMARTDELEGATE_CLI) : [python, '-m', 'sf_smartdelegate'];
const ENV = { ...process.env, PYTHONPATH: join(ROOT, 'src') + (process.env.PYTHONPATH ? (process.platform === 'win32' ? ';' : ':') + process.env.PYTHONPATH : '') };
export const ADMIN = 'admin-key-for-tests-0123456789';
export const PEP = 'pep-key-for-tests-0123456789';

export function cases() {
  const dir = join(ROOT, 'spec', 'conformance', 'vectors');
  return readdirSync(dir).filter((f) => f.endsWith('.json')).sort().flatMap((f) => {
    const doc = JSON.parse(readFileSync(join(dir, f), 'utf8'));
    return doc.cases.map((c) => ({ suite: doc.suite, config: doc.config ?? {}, ...c }));
  });
}

/** `smartdelegate serve` on a free port with its own state directory. */
export async function startDaemon(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'smartdelegate-js-'));
  const config = join(dir, 'smartdelegate.json');
  writeFileSync(config, JSON.stringify({
    bundle_dir: join(ROOT, 'spec', 'conformance', 'bundle'), state_dir: join(dir, 'state'),
    allow_test_clock: true, max_depth: 3, admin_key: ADMIN, pep_key: PEP, ...extra,
  }));
  const proc = spawn(CLI[0], [...CLI.slice(1), 'serve', '--config', config, '--listen', '127.0.0.1:0'], { stdio: ['ignore', 'ignore', 'pipe'], env: ENV });
  const url = await new Promise((ok, fail) => {
    let buf = '';
    proc.stderr.on('data', (d) => {
      buf += d;
      // wait for the whole line: the chunk can end in the middle of the URL
      const m = buf.match(/(http:\/\/\S+)\r?\n/);
      if (m) ok(m[1]);
    });
    proc.on('exit', () => fail(new Error(`daemon exited: ${buf}`)));
    proc.on('error', fail);
  });
  return { url, stop: () => { proc.kill(); rmSync(dir, { recursive: true, force: true }); } };
}

export function substitute(v, vars) {
  if (typeof v === 'string' && v.startsWith('$')) return v.slice(1) in vars ? vars[v.slice(1)] : v;
  if (Array.isArray(v)) return v.map((x) => substitute(x, vars));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, substitute(x, vars)]));
  return v;
}

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

/** Every key in `expect` must be present and equal in `actual`. */
export function subset(expect, actual, path = '') {
  if (isObj(expect) && isObj(actual)) {
    for (const [k, ev] of Object.entries(expect)) {
      const p = path ? `${path}.${k}` : k;
      if (!(k in actual)) {
        if (ev === null) continue;
        return `${p}: missing, expected ${JSON.stringify(ev)}`;
      }
      const m = subset(ev, actual[k], p);
      if (m) return m;
    }
    return null;
  }
  if (Array.isArray(expect) && Array.isArray(actual) && expect.length === actual.length) {
    for (let i = 0; i < expect.length; i++) {
      // arrays are compared exactly, element by element
      if (JSON.stringify(sortKeys(expect[i])) !== JSON.stringify(sortKeys(actual[i]))) return `${path}[${i}]: expected ${JSON.stringify(expect[i])}, got ${JSON.stringify(actual[i])}`;
    }
    return null;
  }
  return JSON.stringify(expect) === JSON.stringify(actual) ? null : `${path}: expected ${JSON.stringify(expect)}, got ${JSON.stringify(actual)}`;
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (isObj(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}

export async function runCase(call, c) {
  const vars = {};
  const failures = [];
  for (const [i, step] of c.steps.entries()) {
    const result = await call(step.op, substitute(step.input, vars));
    for (const [name, key] of Object.entries(step.save ?? {})) {
      vars[name] = key.split('.').reduce((cur, part) => (isObj(cur) ? cur[part] : undefined), result);
    }
    const m = subset(step.expect ?? {}, result);
    if (m) failures.push(`step ${i} (${step.op}): ${m}`);
  }
  return failures;
}
