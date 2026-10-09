// Differential test against the Python reference: one random script of
// operations is run by both engines and every result is compared.
//
//   node tools/differential.mjs [seed] [count]
//
// Each engine has its own state directory and the same signing key. Results
// are compared exactly (integers vs floats included) after replacing what
// legitimately differs: token ids, tokens, decision ids, hashes, and the
// human-readable messages. Used by test/interop.test.mjs.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonInternal } from '../lib/canon.mjs';
import { Engine, keygen } from '../lib/index.mjs';
import { isObj, obj, parse, toInternal, write } from '../lib/json.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolvePath(HERE, '..', '..', '..');
const BUNDLE = join(ROOT, 'spec', 'conformance', 'bundle');
const T = 1700000000;

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A script of [op, input] pairs. Inputs are plain values; BigInt marks a 64-bit integer. */
export function script(seed, count) {
  const r = rng(seed);
  const int = (n) => Math.floor(r() * n);
  const pick = (a) => a[int(a.length)];
  const chance = (p) => r() < p;
  const some = (a, p = 0.5) => a.filter(() => chance(p));
  const now = () => T + (chance(0.9) ? int(120) : pick([200, 400, 700, 1000, 4000, -100]));

  const users = ['alice', 'alice', 'alice', 'bob', 'bob', 'carol', 'carol', 'dave', 'erin', 'nobody', 'ünï'];
  const agents = ['support-bot', 'support-bot', 'support-bot', 'refund-helper', 'summarizer', 'rogue-bot', 'ghost'];
  const actions = ['read', 'read', 'read', 'read', 'create', 'create', 'create', 'update', 'update', 'delete', 'approve', 'export'];
  const paths = ['crm.customer', 'crm.customer', 'crm.customer', 'crm.customer', 'billing.refund', 'billing.refund', 'billing.refund', 'hr.salary', 'nope.thing'];
  const ids = ['c-1', 'c-2', 'r-1', 's-1', 'any', 'é'];
  const patterns = ['*', 'read', 'create', 'update', 'delete', 'rea*', 're*d', '**', '', 'crm.customer/*', 'crm.customer/c-1', 'crm.customer/c-*',
    'billing.refund/*', 'billing.*', 'hr.salary/*', 'crm.*'];
  const labels = ['pii', 'secret', 'internal', 'financial', 'other'];
  const fieldIds = ['crm.customer.email', 'crm.customer.name', 'crm.customer.card.last4', 'billing.refund.amount', 'crm.customer.addresses'];
  const roles = ['support-agent', 'support-agent', 'supervisor', 'auditor', 'break-glass', 'nope'];
  const groupNames = ['support', 'supervisors', 'compliance', 'ghosts', 'support'];
  const tasks = ['ticket-1', 'escalation-2', 'incident-3', 'other'];
  const weird = () => pick([null, true, false, 0, 1, -1, 2.5, 'x', '', [], {}, [1], { a: 1 }, 9007199254740993n, 2n ** 63n, -(2n ** 63n), 1e300]);

  const cap = () => {
    if (chance(0.04)) return weird();
    const c = {};
    if (chance(0.95)) c.actions = chance(0.6) ? ['read', 'create', 'update'] : some(patterns.slice(0, 9), 0.3);
    if (chance(0.95)) c.resources = chance(0.6) ? ['crm.customer/*', 'billing.refund/*'] : some(patterns.slice(9).concat(['*']), 0.35);
    if (chance(0.3)) c.deny_labels = some(labels, 0.35);
    if (chance(0.2)) c.deny_fields = some(fieldIds, 0.35);
    if (chance(0.5)) {
      c.budget = {};
      if (chance(0.9)) c.budget.EUR = pick([0, 100, 5000, 10000, 20000, 50000, 2n ** 62n, -5]);
      if (chance(0.15)) c.budget.USD = pick([1000, 2.5, '5', true]);
    }
    if (chance(0.02)) c.actoins = ['read'];
    if (chance(0.02)) c.actions = pick(['read', [1], null]);
    if (chance(0.02)) c.budget = weird();
    return c;
  };
  const groups = () => pick([['support'], ['supervisors', 'support'], [], some(groupNames), 'support', [{ type: 'Group', id: 'support' }],
    [{ type: 'User', id: 'carol' }], [{ type: 'bad type', id: 'x' }], [1], { type: 'Group', id: 'support' }, 7, null,
    [{ type: 'Group', id: 'compliance' }, 'supervisors', 'supervisors']]);
  const tok = () => {
    if (chance(0.05)) return pick(['', 'garbage', 'a.b.c', 'a.b', '..', 5, null, 'é.é.é']);
    // mostly one of the latest well-formed tokens (see `fresh` below)
    const t = chance(0.7) ? { $tok: int(6), good: true } : { $tok: int(1000) };
    // damage that does not depend on the (random) signature bytes: the last
    // base64 character of a signature has unused bits, so replacing it may or
    // may not change the signature
    const m = r();
    if (m < 0.04) t.cut = 1 + int(3);
    else if (m < 0.07) t.append = pick(['x', '=', ' ', '.x', '\n']);
    else if (m < 0.11) t.flip = 40 + int(200);
    if (chance(0.04)) t.sig_of = int(1000);
    return t;
  };
  const spend = () => pick([{ currency: 'EUR', amount: pick([0, 1, 100, 4000, 5000, 9000, 10000, 10001, 15000, 20000, 20001, 2n ** 62n]) },
    { currency: 'EUR', amount: 5000 }, { currency: 'USD', amount: 10 }, { currency: 'EUR', amount: -1 }, { currency: 'EUR', amount: 1.5 },
    { currency: 5, amount: 5 }, { amount: 5 }, 'EUR', null, { currency: 'EUR', amount: true }]);
  const context = () => {
    if (chance(0.4)) return undefined;
    if (chance(0.03)) return weird();
    const c = {};
    if (chance(0.6)) c.spend = spend();
    if (chance(0.15)) c.note = pick(['x', 'Zażółć   😀', '']);
    if (chance(0.1)) c.n = pick([1, -1, 2n ** 63n - 1n, 2n ** 63n, 1.5, null]);
    if (chance(0.08)) c.list = pick([[1, 2, 2, 1], [[1], [1]], [{ a: 1 }, { a: 1 }], [1, 'a', true], [null], [1.0]]);
    if (chance(0.05)) c.ref = pick([{ __entity: { type: 'User', id: 'alice' } }, { __entity: { type: 'User' } }, { __extn: { fn: 'ip', arg: '1.1.1.1' } },
      { __entity: { type: 'User', id: 'alice' }, more: 1 }]);
    if (chance(0.03)) c.iam = { user_id: 'carol' };
    if (chance(0.05)) c.region = pick(['EU', 'US']);
    return c;
  };
  const attrs = () => {
    if (chance(0.7)) return undefined;
    if (chance(0.06)) return weird();
    const a = {};
    if (chance(0.5)) a.tenant = pick(['acme', 'other', 5]);
    if (chance(0.5)) a.customer_owner = pick(['alice', 'bob', 5, ['alice']]);
    if (chance(0.15)) a.x = pick([1.5, null, [1], { y: 1 }, 2n ** 64n]);
    return a;
  };
  const leaf = () => pick(['v', 'EU', 'US', 1, 0, true, false, null, 2.5, 1.0, '', 12345678901234567890n, -3]);
  const address = () => pick([leaf(), { city: 'Wien', geo: pick([{ lat: 48, lon: 16 }, 'x', [1]]), zip: leaf() }, { geo: null }, [leaf()], [], {}]);
  const record = () => {
    if (chance(0.06)) return pick([leaf(), [], [leaf()], {}]);
    const d = {};
    for (const k of ['id', 'name', 'email', 'phone', 'ssn', 'region', 'tier', 'notes', 'unlisted', 'order_id', 'amount', 'currency', 'reason', 'internal_note', 'employee']) {
      if (chance(0.3)) d[k] = chance(0.1) ? pick([{ nested: leaf() }, [leaf(), { a: leaf() }]]) : leaf();
    }
    if (chance(0.5)) d.region = pick(['EU', 'EU', 'US']);
    if (chance(0.35)) d.addresses = chance(0.15) ? leaf() : Array.from({ length: int(4) }, address);
    if (chance(0.35)) d.card = pick([{ last4: '4242', number: '4242424242424242' }, { last4: leaf(), number: leaf(), extra: leaf() }, { number: { deep: 1 } }, 'card', ['4242'], {}, { last4: ['4', '2'] }]);
    if (chance(0.05)) d['card.last4'] = 'flat';
    if (chance(0.05)) d['addresses[]'] = 'flat';
    if (chance(0.05)) d['10'] = leaf();
    return d;
  };
  const data = () => (chance(0.3) ? Array.from({ length: int(5) }, record) : record());
  // requests that are likely to be allowed, so the allow path (obligations,
  // spend, rate limits, approvals, masking) is compared as much as the denials
  const happy = (withData) => {
    const i = { token: { $tok: int(6), good: true }, now: T + int(100) };
    const kind = int(4);
    if (kind === 0) Object.assign(i, { action: 'read', resource: { path: 'crm.customer', id: pick(ids) } });
    else if (kind === 1) Object.assign(i, { action: 'update', resource: { path: 'crm.customer', id: 'c-1' } });
    else Object.assign(i, { action: 'create', resource: { path: 'billing.refund', id: pick(ids) },
      context: { spend: { currency: 'EUR', amount: pick([1, 100, 2500, 9999, 10000, 10001, 12000, 15000]) } } });
    if (chance(0.2)) i.resource.attrs = pick([{ customer_owner: 'alice' }, { customer_owner: 'bob' }, { tenant: 'acme' }, { vip: true, score: 7 }]);
    if (chance(0.15)) i.fields = pick([['email'], ['id', 'region'], ['ssn', 'card.number'], ['amount', 'currency'], ['addresses', 'addresses[].geo']]);
    if (chance(0.15)) i.explain = true;
    if (chance(0.1)) i.dry_run = true;
    if (withData) {
      i.data = data();
      if (chance(0.25)) i.strict = true;
    }
    return i;
  };
  const decision = (withData) => {
    if (chance(0.45)) return happy(withData);
    const i = { token: tok(), action: pick(actions), resource: { path: pick(paths) }, now: now() };
    if (chance(0.85)) i.resource.id = pick(ids);
    const a = attrs();
    if (a !== undefined) i.resource.attrs = a;
    const c = context();
    if (c !== undefined) i.context = c;
    if (chance(0.12)) i.fields = pick([['email'], ['id', 'region'], ['ssn', 'card.number'], ['nope'], [], ['email', 'email'], [5], 'email', ['amount', 'currency'], ['addresses[].geo']]);
    if (chance(0.1)) i.dry_run = pick([true, true, 1, 'yes']);
    if (chance(0.1)) i.explain = true;
    if (withData) {
      if (chance(0.97)) i.data = data();
      if (chance(0.3)) i.strict = true;
    }
    if (chance(0.02)) delete i.action;
    if (chance(0.02)) i.resource = pick(['crm.customer/c-1', null, { id: 'c-1' }, { path: '' }]);
    if (chance(0.02)) i.chain = { user: 'alice', agents: ['support-bot'] };
    if (chance(0.02)) delete i.token;
    return i;
  };
  const obligations = () => {
    if (chance(0.06)) return weird();
    const names = ['id', 'name', 'email', 'ssn', 'region', 'addresses', 'addresses[]', 'addresses[].geo', 'addresses[].geo.lat', 'card', 'card.last4', 'card.number',
      'amount', 'notes', 'unlisted', '10'];
    const o = { fields: { allow: some(names, 0.4), deny: some(names, 0.2), redact: some(names, 0.12) } };
    if (chance(0.05)) o.fields = pick([null, {}, { allow: 'id' }, { allow: [1, 'id', null] }, []]);
    if (chance(0.3)) {
      o.row_filter = pick([[{ column: 'region', op: 'eq', value: 'EU' }], [{ column: 'region', op: 'eq', value: 'EU' }, { column: 'tier', op: 'eq', value: 'v' }],
        [{ column: 'amount', op: 'eq', value: 1 }], [{ column: 'amount', op: 'eq', value: 1.0 }], [{ column: 'tier', op: 'eq', value: true }],
        [{ column: 'name', op: 'eq', value: null }], [{ column: 'name' }], [{ value: 'EU' }], ['x', { column: 'region', value: 'US' }], 'region',
        [{ column: 'card', op: 'eq', value: { last4: '4242', number: '4242424242424242' } }], [{ column: 'addresses', value: [] }], [{ column: 5, value: 1 }]]);
    }
    return o;
  };

  const out = [];
  // Well-formed tokens, issued again every so often because budgets run out
  // and tokens expire. `_good` is not an engine input (unknown keys are
  // ignored); it tells both sides to remember the token as a good one, and
  // good tokens are never picked for revocation.
  const fresh = () => {
    for (const [user, role] of [['alice', null], ['bob', null], ['alice', 'support-agent'], ['bob', 'supervisor'], ['carol', 'auditor']]) {
      const i = { user, agent: 'support-bot', now: T, _good: true };
      if (role) Object.assign(i, { role, task: 'escalation-1' });
      else i.cap = { actions: ['read', 'create', 'update'], resources: ['crm.customer/*', 'billing.refund/*'], budget: { EUR: 20000 } };
      out.push(['issue_token', i]);
    }
    out.push(['exchange_token', { subject_token: { $tok: 4, good: true }, actor: 'refund-helper', ttl: 300, now: T, _good: true }]);
  };
  while (out.length < count) {
    if (out.length % 250 === 0) fresh();
    const x = r();
    if (x < 0.14) {
      const i = { user: pick(users), agent: pick(agents), now: now() };
      if (chance(0.8)) i.cap = cap();
      if (chance(0.35)) i.role = pick(roles);
      if (chance(0.25)) i.groups = groups();
      if (chance(0.4)) i.ttl = pick([60, 300, 600, 601, 3600, 99999, 0, -5, 1.5, '300', 2n ** 62n]);
      if (chance(0.2)) i.tenant = pick(['acme', 'other', '', 5]);
      if (chance(0.35)) i.task = pick(tasks);
      if (chance(0.03)) i.id_token = 'a.b.c';
      if (chance(0.03)) delete i.user;
      if (chance(0.03)) delete i.agent;
      out.push(['issue_token', i]);
    } else if (x < 0.26) {
      const i = { subject_token: tok(), actor: pick(agents), now: now() };
      if (chance(0.55)) i.cap = cap();
      if (chance(0.6)) i.ttl = pick([60, 300, 600, 601, 3600, 0, -1]);
      if (chance(0.2)) i.task = pick(tasks);
      if (chance(0.15)) i.role = pick(roles);
      out.push(['exchange_token', i]);
    } else if (x < 0.5) out.push(['authorize', decision(false)]);
    else if (x < 0.72) out.push(['filter', decision(true)]);
    else if (x < 0.78) out.push(['explain', decision(chance(0.5))]);
    else if (x < 0.88) {
      const i = { obligations: obligations(), now: now() };
      if (chance(0.97)) i.data = data();
      if (chance(0.1)) i.decision_id = 'd-fixed';
      out.push(['apply_obligations', i]);
    } else if (x < 0.91) out.push(['inspect_token', { token: tok(), now: now() }]);
    else if (x < 0.914) {
      // offboarding: mostly users the well-formed tokens do not belong to, so the rest of the script stays interesting
      out.push(['revoke', { user: pick(['carol', 'dave', 'erin', 'nobody', 'ünï', 'carol', '', 5, null, ['alice'], chance(0.15) ? 'bob' : 'erin']), by: 'fuzz',
        now: chance(0.5) ? T - 1 - int(50) : now(), ...(chance(0.3) ? { token_id: 'abc' } : {}) }]);
    } else if (x < 0.918) out.push(['revoke', chance(0.7) ? { token: { $tok: int(1000), other: true }, now: now(), by: 'fuzz' } : { token_id: pick(['abc', '', 5]), now: now() }]);
    else if (x < 0.96) out.push(['approve', { approval_id: { $approval: int(1000) }, by: pick(['bob', 'bob', 'alice', 'carol', 'nobody', '']), now: now(), ...(chance(0.2) ? { ttl: pick([1, 100, -1]) } : {}) }]);
    else if (x < 0.975) out.push(['approvals', {}]);
    else if (x < 0.985) out.push(['audit_verify', {}]);
    else if (x < 0.99) out.push(['audit_tail', { n: pick([1, 3, 0, -1, 2.5, '2']) }]);
    else if (x < 0.995) out.push(['info', {}]);
    else out.push([pick(['reload', 'nope', '']), {}]);
  }
  return out;
}

const DROP = new Set(['message', 'detail', 'decision_id', 'request_hash', 'hash', 'prev', 'head', 'version', 'implementation', 'ts']);

/** Replace what legitimately differs between two engines. `names` maps a
 * token or token id to the order in which this engine produced it. */
function normalise(v, names, key = null) {
  if (typeof v === 'string') {
    if (names.has(v)) return names.get(v);
    // "T is the 24-hex id of a token": also inside policy errors and rate keys there are none; messages are dropped
    return v;
  }
  if (Array.isArray(v)) return v.map((x) => normalise(x, names, key));
  if (isObj(v)) {
    const out = obj();
    for (const k of Object.keys(v)) {
      if (DROP.has(k)) continue;
      if (k === 'error' && typeof v[k] === 'string') continue;       // the text of a policy evaluation error
      out[names.has(k) ? names.get(k) : k] = normalise(v[k], names, k);
    }
    return out;
  }
  return v;
}

class Side {
  constructor(call) {
    this.call = call;
    this.tokens = { all: [], good: [], other: [] };
    this.names = new Map();
  }

  learn(result, input) {
    if (isObj(result) && result.ok === true && typeof result.token === 'string') {
      const n = this.tokens.all.length;
      this.tokens.all.push(result.token);
      (isObj(input) && input._good === true ? this.tokens.good : this.tokens.other).push(result.token);
      this.names.set(result.token, `<token ${n}>`);
      this.names.set(result.token_id, `<id ${n}>`);
    }
  }
}

/** {"$tok": n} is the n-th token this engine issued; with "good", the n-th
 * latest of the well-formed ones; with "other", the n-th of the rest. */
function pickToken(v, tokens) {
  const list = v.good === true ? tokens.good : v.other === true ? tokens.other : tokens.all;
  if (!list.length) return null;
  const n = Number(v.$tok);
  return v.good === true ? list[Math.max(0, list.length - 1 - n)] : list[n % list.length];
}

function resolveTokens(v, tokens) {
  if (isObj(v)) {
    if ('$tok' in v) {
      let t = pickToken(v, tokens);
      if (t === null) return 'no-token-yet';
      if ('sig_of' in v) {
        const other = tokens.all[Number(v.sig_of) % tokens.all.length];
        t = [...t.split('.').slice(0, 2), other.split('.')[2]].join('.');
      }
      if ('flip' in v) {
        const at = Number(v.flip) % t.length;
        t = t.slice(0, at) + (t[at] === 'A' ? 'B' : 'A') + t.slice(at + 1);
      }
      if ('cut' in v) t = t.slice(0, -Number(v.cut));
      return t + ('append' in v ? v.append : '');
    }
    const out = obj();
    for (const k of Object.keys(v)) out[k] = resolveTokens(v[k], tokens);
    return out;
  }
  if (Array.isArray(v)) return v.map((x) => resolveTokens(x, tokens));
  return v;
}

/** Run `count` operations from `seed` through both engines.
 * -> {count, compared, mismatches: [{n, op, input, node, reference}], ops: {op: count}, allows, denies, errors} */
export async function differential({ seed = 1, count = 1000, python = 'python3', maxMismatches = 5 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'smartdelegate-node-diff-'));
  const [signingKey] = keygen();
  const cfg = (state) => ({ bundle_dir: BUNDLE, state_dir: join(dir, state), allow_test_clock: true, max_depth: 3, signing_key: signingKey });
  const engine = new Engine(cfg('node'));
  const proc = spawn(python, [join(HERE, 'differential_driver.py')], { stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', PYTHONPATH: join(ROOT, 'src') + (process.env.PYTHONPATH ? delimiter + process.env.PYTHONPATH : '') } });
  let stderr = '';
  proc.stderr.on('data', (d) => { stderr += d; });
  const lines = [];
  let waiting = null, buf = '', ended = false;
  const wake = () => { if (waiting) { const w = waiting; waiting = null; w(); } };
  proc.stdout.setEncoding('utf8');
  proc.stdout.on('data', (d) => {
    buf += d;
    let at;
    while ((at = buf.indexOf('\n')) >= 0) {
      lines.push(buf.slice(0, at));
      buf = buf.slice(at + 1);
    }
    wake();
  });
  proc.on('exit', () => { ended = true; wake(); });
  proc.stdin.on('error', () => {});
  const ask = async (text) => {
    proc.stdin.write(text + '\n');
    while (!lines.length) {
      if (ended) throw new Error(`the reference driver stopped: ${stderr}`);
      await new Promise((ok) => { waiting = ok; });
    }
    return lines.shift();
  };

  const summary = { seed, count, compared: 0, mismatches: [], ops: {}, allows: 0, denies: 0, errors: 0, reasons: {} };
  try {
    proc.stdin.write(JSON.stringify(cfg('python')) + '\n');
    const node = new Side((op, input) => engine.callExact(op, input));
    const ref = new Side(null);
    const approvals = [];
    for (const [n, [op, plain]] of script(seed, count).entries()) {
      // approval ids are the same in both engines (a hash of the request); pick from those seen so far
      const withApproval = (v) => (isObj(v) && '$approval' in v ? (approvals.length ? approvals[Number(v.$approval) % approvals.length] : 'none-yet') : v);
      const input = toInternal(plain);
      if (isObj(input)) for (const k of Object.keys(input)) input[k] = withApproval(input[k]);
      const ours = node.call(op, resolveTokens(input, node.tokens));
      // the reference resolves {"$tok": n} against its own tokens
      const theirs = parse(await ask(write([op, input], { ascii: true })));
      node.learn(ours, input);
      ref.learn(theirs, input);
      if (isObj(ours.approval) && typeof ours.approval.id === 'string' && !approvals.includes(ours.approval.id)) approvals.push(ours.approval.id);
      const a = canonInternal(normalise(ours, node.names)), b = canonInternal(normalise(theirs, ref.names));
      summary.compared++;
      summary.ops[op] = (summary.ops[op] ?? 0) + 1;
      if (ours.ok !== true) {
        summary.errors++;
        const c = ours.error?.code;
        summary.reasons[c] = (summary.reasons[c] ?? 0) + 1;
      } else if (ours.effect === 'allow') summary.allows++;
      else if (ours.effect === 'deny') {
        summary.denies++;
        summary.reasons[ours.reason] = (summary.reasons[ours.reason] ?? 0) + 1;
      }
      if (a !== b) {
        summary.mismatches.push({ n, op, input: write(input), node: a, reference: b });
        if (summary.mismatches.length >= maxMismatches) break;
      }
    }
    // the two audit logs must hold the same events in the same order
    const tail = (records) => canonInternal(records.map((rec) => normalise(rec, new Map())).map((rec) => { delete rec.seq; return [rec.event, rec.effect ?? null, rec.reason ?? null, rec.op ?? null, rec.action ?? null, rec.resource ?? null]; }));
    const mine = engine.callExact('audit_tail', toInternal({ n: 1000000 }));
    const theirs = parse(await ask(write(toInternal(['audit_tail', { n: 1000000 }]), { ascii: true })));
    summary.auditRecords = mine.records.length;
    summary.auditSame = tail(mine.records) === tail(theirs.records);
  } finally {
    proc.stdin.end();
    if (!ended) await new Promise((ok) => { proc.once('exit', ok); setTimeout(() => proc.kill('SIGKILL'), 5000).unref(); });
    engine.close();
    rmSync(dir, { recursive: true, force: true });
  }
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const seed = Number(process.argv[2] ?? 1), count = Number(process.argv[3] ?? 2000);
  const s = await differential({ seed, count });
  for (const m of s.mismatches) console.log(`MISMATCH at ${m.n}: ${m.op} ${m.input}\n  node:      ${m.node}\n  reference: ${m.reference}`);
  console.log(JSON.stringify({ ...s, mismatches: s.mismatches.length }));
  process.exitCode = s.mismatches.length || !s.auditSame ? 1 : 0;
}
