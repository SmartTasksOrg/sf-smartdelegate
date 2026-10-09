// The command line: commands, flags, config resolution, exit codes.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import test from 'node:test';
import { ADMIN, BUNDLE, FULL_CAP, HERE, OIDC, PEP, VECTORS, cli, config, startDaemon, tempDir } from '../tools/support.mjs';

function setup(t) {
  const dir = tempDir(t);
  const cfg = join(dir, 'smartdelegate.json');
  writeFileSync(cfg, JSON.stringify(config(join(dir, 'state'))));
  const cap = join(dir, 'cap.json');
  writeFileSync(cap, JSON.stringify(FULL_CAP));
  const run = (...args) => cli([...args, '--config', cfg]);
  const json = (...args) => {
    const r = run(...args);
    return { ...r, json: JSON.parse(r.stdout) };
  };
  const token = (...extra) => {
    const r = run('token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + cap, '--raw', ...extra);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    return r.stdout.trim();
  };
  return { dir, cfg, cap, run, json, token };
}

test('help, version, unknown commands and missing flags', () => {
  let r = cli(['help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /smartdelegate-node/);
  assert.equal(cli(['--help']).status, 0);
  assert.equal(cli([]).status, 0);
  assert.equal(cli(['version']).stdout.trim(), 'smartdelegate 0.3.0 (node)');
  r = cli(['frobnicate']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /USAGE/);
  r = cli(['authorize', '--bundle', BUNDLE, '--action', 'read']);
  assert.deepEqual([r.status, r.stderr.trim()], [1, 'smartdelegate: --resource is required']);
  r = cli(['authorize', '--bundle', BUNDLE, '--action']);
  assert.deepEqual([r.status, r.stderr.trim()], [1, 'smartdelegate: --action needs a value']);
  r = cli(['mcp-proxy']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not part of the Node\.js port/);
});

test('exit codes: 0 allow, 2 deny, 1 error', (t) => {
  const { json, run, token, dir } = setup(t);
  const tok = token();
  const req = ['--token', tok, '--resource', 'crm.customer/c-1'];
  let r = json('authorize', '--action', 'read', ...req);
  assert.deepEqual([r.status, r.json.ok, r.json.effect, r.json.principal.user], [0, true, 'allow', 'alice']);
  assert.ok(r.stdout.startsWith('{\n  "effect": "allow",\n  "reason": "policy_permit",\n  "rule": "DELEGATE-POLICY-PERMIT",'), 'two-space indentation, engine key order');
  r = json('authorize', '--action', 'delete', ...req);
  assert.deepEqual([r.status, r.json.effect, r.json.reason], [2, 'deny', 'capability_action']);
  r = json('authorize', '--action', 'read', ...req, '--context', '{"score": 1.5}');
  assert.deepEqual([r.status, r.json.ok, r.json.error.code, r.json.error.rule], [1, false, 'invalid_context', 'DELEGATE-INVALID-CONTEXT']);
  r = json('authorize', '--action', 'read', ...req, '--context', '{"n": 9223372036854775808}');
  assert.deepEqual([r.status, r.json.error.code], [1, 'invalid_context']);
  assert.equal(run('authorize', '--action', 'read', ...req, '--context', '{"n": 9223372036854775807}').status, 0);
  r = run('authorize', '--action', 'read', ...req, '--context', '{oops');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /^smartdelegate: not valid JSON/);
  r = run('authorize', '--action', 'read', ...req, '--context', '@' + join(dir, 'missing.json'));
  assert.equal(r.status, 1);
  // --resource without an id means "any"; --dry-run writes no audit record
  const before = json('audit', 'verify').json.records;
  r = json('authorize', '--action', 'read', '--token', tok, '--resource', 'crm.customer', '--dry-run');
  assert.equal(r.status, 0);
  assert.equal(json('audit', 'verify').json.records, before);
});

test('filter, strict and explain', (t) => {
  const { json, token, dir } = setup(t);
  const tok = token();
  const data = join(dir, 'data.json');
  writeFileSync(data, '﻿' + JSON.stringify({ id: 'c-1', ssn: '123-45-6789', region: 'EU', name: 'Zoë 😀' }));
  let r = json('authorize', '--action', 'read', '--token', tok, '--resource', 'crm.customer/c-1', '--data', '@' + data);
  assert.equal(r.status, 0);
  assert.deepEqual(r.json.data, { id: 'c-1', region: 'EU', name: 'Zoë 😀' });
  assert.deepEqual(r.json.masked, ['ssn']);
  assert.ok(r.stdout.includes('Zoë 😀'), 'non-ASCII is printed as itself');
  r = json('authorize', '--action', 'update', '--token', tok, '--resource', 'crm.customer/c-1', '--data', '{"tier": "gold"}', '--strict');
  assert.deepEqual([r.status, r.json.reason], [2, 'field_denied']);
  r = json('explain', '--action', 'read', '--token', tok, '--resource', 'crm.customer/c-1');
  assert.equal(r.status, 0);
  assert.deepEqual(r.json.explain.map((s) => s.check), ['token', 'capability', 'policy', 'fields']);
  r = json('authorize', '--action', 'read', '--token', tok, '--resource', 'crm.customer/c-1', '--attrs', '{"tenant": "acme"}');
  assert.equal(r.status, 0);
});

test('tokens: issue (cap, role, groups, ttl, tenant, task), exchange, inspect, revoke', (t) => {
  const { json, run, token, cap, dir } = setup(t);
  let r = json('token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + cap, '--ttl', '120', '--tenant', 'acme', '--task', 'ticket-7');
  assert.equal(r.status, 0);
  assert.deepEqual([r.json.user, r.json.expires_in, r.json.role, r.json.token_type], ['alice', 120, null, 'Bearer']);
  let i = json('token', 'inspect', '--token', r.json.token);
  assert.deepEqual([i.status, i.json.valid, i.json.claims.tnt, i.json.claims.task], [0, true, 'acme', 'ticket-7']);

  r = json('token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--role', 'support-agent', '--groups', 'support,,nonexistent');
  assert.deepEqual([r.status, r.json.role, r.json.expires_in], [0, 'support-agent', 600]);
  i = json('token', 'inspect', '--token', r.json.token);
  assert.deepEqual(i.json.claims.grp, [{ type: 'Group', id: 'support' }]);
  assert.equal(i.json.claims.role, 'support-agent');
  r = json('token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--role', 'support-agent', '--groups', '');
  assert.deepEqual([r.status, r.json.error.code], [1, 'role_not_held'], '--groups "" is live membership of nothing');
  r = json('token', 'issue', '--user', 'dave', '--agent', 'support-bot', '--role', 'support-agent');
  assert.deepEqual([r.status, r.json.error.code, r.json.error.rule], [1, 'role_not_held', 'DELEGATE-ROLE-NOT-HELD']);
  r = run('token', 'issue', '--user', 'alice', '--agent', 'support-bot');
  assert.deepEqual([r.status, r.stderr.trim()], [1, 'smartdelegate: --cap JSON or --role NAME is required']);
  r = run('token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + cap, '--ttl', 'soon');
  assert.deepEqual([r.status, r.stderr.trim()], [1, 'smartdelegate: --ttl must be a number of seconds']);
  r = run('token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '{"actions":["read"],"resources":["*"],"budget":{"EUR":9223372036854775807}}');
  assert.equal(r.status, 0);
  assert.ok(r.stdout.includes('"EUR": 9223372036854775807'), 'a 64-bit budget is printed exactly');

  const parent = token();
  assert.match(parent, /^[\w-]+\.[\w-]+\.[\w-]+$/);
  const narrow = join(dir, 'narrow.json');
  writeFileSync(narrow, JSON.stringify({ actions: ['read'], resources: ['crm.customer/c-1'], deny_labels: ['pii'] }));
  r = run('token', 'exchange', '--token', parent, '--actor', 'refund-helper', '--cap', '@' + narrow, '--ttl', '300', '--raw');
  assert.equal(r.status, 0, r.stdout);
  const child = r.stdout.trim();
  const req = ['authorize', '--action', 'read', '--resource', 'crm.customer/c-1'];
  assert.deepEqual(json(...req, '--token', child).json.principal.chain, ['support-bot', 'refund-helper']);
  r = json('token', 'exchange', '--token', parent, '--actor', 'refund-helper', '--cap', '{"actions":["*"],"resources":["*"]}', '--ttl', '300');
  assert.deepEqual([r.status, r.json.error.code], [1, 'widening']);
  r = json('token', 'revoke', '--token', parent);
  assert.equal(r.status, 0);
  assert.deepEqual([json(...req, '--token', child).status, json(...req, '--token', child).json.reason], [2, 'token_revoked']);
  const other = json('token', 'issue', '--user', 'alice', '--agent', 'support-bot', '--cap', '@' + cap).json;
  assert.deepEqual(json('token', 'revoke', '--id', other.token_id).json, { revoked: other.token_id, ok: true });
  i = json('token', 'inspect', '--token', other.token);
  assert.deepEqual([i.status, i.json.valid, i.json.reason], [0, false, 'token_revoked']);
  assert.equal(json('audit', 'tail', '-n', '1').stdout.includes('"by":"cli"'), true);
  // offboarding
  const fresh = token();
  r = json('token', 'revoke', '--user', 'alice');
  assert.equal(r.status, 0);
  assert.deepEqual(Object.keys(r.json), ['revoked_user', 'issued_up_to', 'ok']);
  assert.equal(r.json.revoked_user, 'alice');
  assert.deepEqual([json(...req, '--token', fresh).status, json(...req, '--token', fresh).json.reason], [2, 'token_revoked']);
  assert.ok(run('audit', 'tail', '-n', '3').stdout.includes('"event":"user_revoked"'));
});

test('approvals, approve, call, audit verify and tail', (t) => {
  const { json, run, token, dir } = setup(t);
  const tok = token();
  const spend = join(dir, 'spend.json');
  writeFileSync(spend, JSON.stringify({ spend: { currency: 'EUR', amount: 15000 } }));
  const refund = ['authorize', '--action', 'create', '--resource', 'billing.refund/r-1', '--context', '@' + spend, '--token', tok];
  let r = json(...refund);
  assert.deepEqual([r.status, r.json.reason], [2, 'approval_required']);
  const id = r.json.approval.id;
  assert.deepEqual(Object.keys(json('approvals').json.pending), [id]);
  r = json('approve', id, '--by', 'alice');
  assert.deepEqual([r.status, r.json.error.code], [1, 'self_approval']);
  r = json('approve', id, '--by', 'carol');
  assert.deepEqual([r.status, r.json.error.code], [1, 'approval_denied']);
  assert.equal(json('approve', id, '--by', 'bob').status, 0);
  assert.deepEqual(Object.keys(json('approvals').json.granted), [id]);
  r = json(...refund);
  assert.deepEqual([r.status, r.json.obligations.approved], [0, { id, by: 'bob' }]);
  assert.equal(json(...refund).status, 2, 'an approval is good for one call');

  // call: input inline, from a file, from standard input
  const input = { token: tok, action: 'read', resource: { path: 'crm.customer', id: 'c-1' } };
  assert.equal(json('call', 'authorize', '--input', JSON.stringify(input)).json.effect, 'allow');
  const file = join(dir, 'in.json');
  writeFileSync(file, JSON.stringify(input));
  assert.equal(json('call', 'authorize', '--input', '@' + file).json.effect, 'allow');
  r = cli(['call', 'authorize', '--input', '-', '--config', join(dir, 'smartdelegate.json')], { input: JSON.stringify(input) });
  assert.deepEqual([r.status, JSON.parse(r.stdout).effect], [0, 'allow']);
  assert.equal(json('call', 'info').json.implementation, 'node');
  r = json('call', 'no_such_op');
  assert.deepEqual([r.status, r.json.error.code], [1, 'unknown_op']);
  r = json('call', 'authorize', '--input', '[1]');
  assert.deepEqual([r.status, r.json.error.code], [1, 'invalid_input']);

  r = json('audit', 'verify');
  assert.equal(r.status, 0);
  const total = r.json.records;
  assert.equal(total, 8);   // issue, deny, approval, allow, deny, three calls; errors are not decisions
  r = run('audit', 'tail', '-n', '3');
  assert.equal(r.status, 0);
  const lines = r.stdout.trim().split('\n');
  assert.equal(lines.length, 3);
  assert.deepEqual(lines.map((l) => JSON.parse(l).seq), [6, 7, 8]);
  const log = readFileSync(join(dir, 'state', 'audit.jsonl'), 'utf8').trim().split('\n');
  assert.deepEqual(lines, log.slice(-3), 'tail prints the records as they are stored');
  assert.equal(run('audit', 'tail').stdout.trim().split('\n').length, 8);
  writeFileSync(join(dir, 'state', 'audit.jsonl'), log.slice(1).join('\n') + '\n');
  r = run('audit', 'verify');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /^smartdelegate: audit_broken: /);
});

test('config resolution: --config, SMARTDELEGATE_CONFIG, ./smartdelegate.json, relative paths, overrides', (t) => {
  const dir = tempDir(t);
  const home = join(dir, 'home'), elsewhere = join(dir, 'elsewhere');
  mkdirSync(home);
  mkdirSync(elsewhere);
  cpSync(BUNDLE, join(home, 'bundle'), { recursive: true });
  cpSync(join(OIDC, 'jwks.json'), join(home, 'jwks.json'));
  const idTokens = JSON.parse(readFileSync(join(OIDC, 'id_tokens.json'), 'utf8'));
  // every path in the file is relative to the file, not to the working directory
  writeFileSync(join(home, 'smartdelegate.json'), '﻿' + JSON.stringify({ bundle_dir: 'bundle', state_dir: 'state', allow_test_clock: true,
    idp: { issuer: 'https://idp.example.test', audience: 'smartdelegate-demo', jwks_file: 'jwks.json' } }));
  const info = (args, opts) => {
    const r = cli(['info', ...args], opts);
    return r.status === 0 ? JSON.parse(r.stdout) : r;
  };
  const a = info(['--config', join(home, 'smartdelegate.json')], { cwd: elsewhere });
  assert.equal(a.oidc, 'https://idp.example.test');
  assert.ok(existsSync(join(home, 'state', 'signing_key.pk8.b64')), 'state_dir is next to the config file');
  assert.equal(existsSync(join(elsewhere, 'state')), false);
  if (process.platform !== 'win32') assert.equal(statSync(join(home, 'state', 'signing_key.pk8.b64')).mode & 0o777, 0o600);
  assert.equal(readFileSync(join(home, 'state', 'signing_key.pub.b64'), 'utf8'), a.public_key);
  const b = info(['--config', relative(elsewhere, join(home, 'smartdelegate.json'))], { cwd: elsewhere });
  assert.equal(b.key_id, a.key_id, 'a relative --config is relative to the working directory');
  assert.equal(info([], { cwd: elsewhere, env: { SMARTDELEGATE_CONFIG: join(home, 'smartdelegate.json') } }).key_id, a.key_id);
  assert.equal(info([], { cwd: home, env: { SMARTDELEGATE_CONFIG: '' } }).key_id, a.key_id, './smartdelegate.json is the default');
  let r = info([], { cwd: elsewhere, env: { SMARTDELEGATE_CONFIG: '' } });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /^smartdelegate: no bundle/);
  r = cli(['token', 'issue', '--agent', 'support-bot', '--id-token', idTokens.alice, '--cap', JSON.stringify(FULL_CAP), '--config', join(home, 'smartdelegate.json')], { cwd: elsewhere });
  assert.deepEqual([r.status, JSON.parse(r.stdout).user], [0, 'alice'], 'jwks_file was found next to the config file');

  // --state and --bundle override the file (and are relative to the working directory); --shadow sets the mode
  const c = info(['--config', join(home, 'smartdelegate.json'), '--state', 'other-state', '--shadow'], { cwd: elsewhere });
  assert.notEqual(c.key_id, a.key_id);
  assert.equal(c.mode, 'shadow');
  assert.ok(existsSync(join(elsewhere, 'other-state', 'signing_key.pk8.b64')));
  const d = info(['--bundle', relative(elsewhere, BUNDLE)], { cwd: elsewhere, env: { SMARTDELEGATE_CONFIG: '' } });
  assert.equal(d.policy_version, a.policy_version);
  assert.equal(d.mode, 'enforce');
  r = cli(['info', '--config', join(dir, 'missing.json')]);
  assert.equal(r.status, 1);
  writeFileSync(join(elsewhere, 'bad.json'), '{nope');
  assert.equal(cli(['info', '--config', join(elsewhere, 'bad.json')]).status, 1);
  r = cli(['info', '--bundle', join(dir, 'no-bundle')]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /^smartdelegate: bundle_io: /);
});

test('bundle keygen and sign; policy check and test', (t) => {
  const dir = tempDir(t);
  const b = join(dir, 'bundle');
  cpSync(BUNDLE, b, { recursive: true });
  const prefix = join(dir, 'k');
  let r = cli(['bundle', 'keygen', prefix]);
  assert.equal(r.status, 0);
  const sk = readFileSync(prefix + '.key', 'utf8'), pk = readFileSync(prefix + '.pub', 'utf8');
  const der = Buffer.from(sk, 'base64');
  assert.equal(der.length, 48, 'PKCS#8 version 1');
  assert.equal(der.subarray(0, 16).toString('hex'), '302e020100300506032b657004220420');
  assert.equal(Buffer.from(pk, 'base64').length, 32);
  if (process.platform !== 'win32') assert.equal(statSync(prefix + '.key').mode & 0o777, 0o600);
  assert.ok(r.stdout.includes(`"bundle_public_key": "${pk}"`));
  const cfg = join(dir, 'signed.json');
  writeFileSync(cfg, JSON.stringify({ bundle_dir: b, bundle_public_key: pk }));
  r = cli(['info', '--config', cfg]);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /bundle_unsigned/);
  r = cli(['bundle', 'sign', '--key', prefix + '.key', '--bundle', b]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^signed bundle version [0-9a-f]{64} with key [0-9a-f]{16}\n$/);
  const sig = JSON.parse(readFileSync(join(b, 'bundle.sig.json'), 'utf8'));
  assert.deepEqual(Object.keys(sig), ['files', 'version', 'key_id', 'alg', 'signature']);
  assert.deepEqual(Object.keys(sig.files), ['policies.json', 'entities.json', 'catalog.json', 'roles.json']);
  r = cli(['info', '--config', cfg]);
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).bundle_signed_by, sig.key_id);
  assert.equal(cli(['bundle', 'sign', '--bundle', b]).status, 1);
  assert.equal(cli(['bundle', 'sign', '--key', join(dir, 'missing.key'), '--bundle', b]).status, 1);
  assert.equal(cli(['bundle', 'keygen']).status, 1);

  r = cli(['policy', 'check', '--bundle', BUNDLE]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^bundle loads: 21 policies, version [0-9a-f]{64}\n$/);
  r = cli(['policy', 'test', '--bundle', BUNDLE]);
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /\n\d+ tests, 0 failed\n$/);
});

test('serve: keys from the config or the environment; short keys are refused', async (t) => {
  const dir = tempDir(t);
  const cfg = join(dir, 'smartdelegate.json');
  writeFileSync(cfg, JSON.stringify({ ...config(join(dir, 'state')), admin_key: 'short', pep_key: PEP }));
  let r = cli(['serve', '--config', cfg, '--listen', '127.0.0.1:0']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /^smartdelegate: serve needs admin_key and pep_key \(16\+ characters\)/);
  writeFileSync(cfg, JSON.stringify(config(join(dir, 'state'))));
  r = cli(['serve', '--config', cfg, '--listen', '127.0.0.1:0']);
  assert.equal(r.status, 1);

  // the environment overrides the file
  const d = await startDaemon({ admin_key: 'x'.repeat(20), pep_key: 'y'.repeat(20) }, { env: { SMARTDELEGATE_ADMIN_KEY: ADMIN, SMARTDELEGATE_PEP_KEY: PEP } });
  try {
    assert.match(d.url, /^http:\/\/127\.0\.0\.1:\d+$/);
    const get = (key) => fetch(d.url + '/v1/admin/approvals', { headers: { Authorization: `Bearer ${key}` } }).then((res) => res.status);
    assert.equal(await get(ADMIN), 200);
    assert.equal(await get('x'.repeat(20)), 401);
    // SIGTERM stops it cleanly
    const exited = new Promise((done) => d.proc.once('exit', (codeNow, signal) => done([codeNow, signal])));
    d.proc.kill('SIGTERM');
    assert.deepEqual(await exited, [0, null]);
  } finally {
    await d.stop();
  }
});

test('conformance command and run_conformance.sh', { skip: process.platform === 'win32' ? 'bash script' : false }, (t) => {
  let r = cli(['conformance']);
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /^eval: 95 cases, 0 failed$/m);
  assert.match(r.stdout, /^conformance: 78 cases, 327 steps, 0 failed$/m);
  r = cli(['conformance', VECTORS, BUNDLE]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^conformance: 78 cases, 327 steps, 0 failed$/m);

  r = spawnSync('bash', [join(HERE, 'run_conformance.sh')], { encoding: 'utf8', cwd: tempDir(t) });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^conformance: 78 cases, 327 steps, 0 failed$/m);

  // a failing vector is reported and makes the exit code 1
  const dir = tempDir(t);
  const vectors = join(dir, 'vectors');
  mkdirSync(vectors);
  writeFileSync(join(vectors, '01_bad.json'), JSON.stringify({ suite: 'bad', cases: [
    { name: 'passes', steps: [{ op: 'info', input: {}, expect: { ok: true, implementation: 'node' } }] },
    { name: 'this one fails', steps: [{ op: 'info', input: {}, expect: { ok: true, mode: 'shadow' } }] }] }));
  r = cli(['conformance', vectors, BUNDLE]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /FAIL bad: "this one fails"/);
  assert.match(r.stdout, /mode: expected \\"shadow\\", got \\"enforce\\"/);
  assert.match(r.stdout, /^conformance: 2 cases, 2 steps, 1 failed$/m);
  assert.match(r.stdout, /^eval: skipped/m);
  assert.equal(cli(['conformance', join(dir, 'empty-or-missing'), BUNDLE]).status, 1);
  mkdirSync(join(dir, 'empty'));
  assert.equal(cli(['conformance', join(dir, 'empty'), BUNDLE]).status, 1, 'no vectors is not a pass');
});
