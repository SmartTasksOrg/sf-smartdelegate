#!/usr/bin/env node
// `smartdelegate-node` command line. Same commands, flags, output and exit
// codes as the reference CLI (`python -m sf_smartdelegate`) for everything it
// implements; see HELP for what it does not.
import { closeSync, existsSync, openSync, readFileSync, writeFileSync, writeSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as bundle from '../lib/bundle.mjs';
import { canonInternal, decodeUtf8 } from '../lib/canon.mjs';
import * as conformance from '../lib/conformance.mjs';
import { Engine, VERSION } from '../lib/engine.mjs';
import { EngineError } from '../lib/errors.mjs';
import { has, isObj, obj, parse, toInternal, write } from '../lib/json.mjs';
import { serve } from '../lib/server.mjs';

const HELP = `smartdelegate-node - identity and access management for LLM agents (Node.js port)

USAGE
  smartdelegate-node <command> [options]     JSON options accept @file, e.g. --cap @cap.json

SETUP
  info                                  version, policy version, mode, key id
  policy check                          load the bundle and report problems
  policy test                           run the bundle's tests/*.json
  bundle keygen <prefix>                write <prefix>.key and <prefix>.pub (Ed25519)
  bundle sign --key <file>              sign the bundle (writes bundle.sig.json)

TOKENS
  token issue --user U --agent A (--cap JSON | --role R [--cap JSON]) [--groups g1,g2]
              [--ttl S] [--tenant T] [--task X] [--id-token JWT] [--raw]
                                        --role: lend the agent a role the user holds; the
                                        token can never carry more than the role allows
  token exchange --token T --actor A [--cap JSON] [--ttl S] [--raw]
  token inspect --token T
  token revoke --id TOKEN_ID | --token T | --user U     --user ends every token already
                                        issued for that user, sub-agents included

DECISIONS
  authorize --token T --action A --resource path/id [--attrs JSON] [--context JSON]
            [--data JSON] [--strict] [--dry-run]      exit code 0 allow, 2 deny, 1 error
  explain   (same options)              show every check and every field decision
  approvals                             list held requests
  approve <approval_id> --by USER

AUDIT
  audit verify                          recompute the hash chain
  audit tail [-n N]

SERVERS
  serve [--listen 127.0.0.1:8181]       REST decision daemon

OTHER
  call <op> [--input JSON|@file|-]      any operation of spec/API.md, JSON in, JSON out
  conformance [<vectors dir> <bundle dir>]
                                        policy evaluation cases and engine vectors; with no
                                        arguments, the repository's spec/conformance
  version

NOT IN THIS PORT
  init, bench, bundle compile, http-proxy, mcp-proxy (use the Python or Rust port)

CONFIG
  --config FILE (or SMARTDELEGATE_CONFIG, or ./smartdelegate.json); --bundle DIR and --state DIR override it.
  --shadow logs would-be denials without enforcing them.
`;

const SWITCHES = new Set(['raw', 'strict', 'dry-run', 'shadow', 'help']);

class Exit extends Error {
  constructor(code) {
    super(`exit ${code}`);
    this.exitCode = code;
  }
}

function die(msg) {
  process.stderr.write(`smartdelegate: ${msg}\n`);
  throw new Exit(1);
}

const out = (text) => { writeSync(1, text + '\n'); };

class Args {
  constructor(argv) {
    this.pos = [];
    this.flags = new Map();
    this.rest = [];
    for (let i = 0; i < argv.length; i++) {
      const x = argv[i];
      if (x === '--') {
        this.rest = argv.slice(i + 1);
        break;
      }
      const name = x.startsWith('--') ? x.slice(2) : (x.startsWith('-') && x.length === 2 ? x.slice(1) : null);
      if (name === null) this.pos.push(x);
      else if (SWITCHES.has(name)) this.flags.set(name, 'true');
      else if (name.includes('=')) {
        const at = name.indexOf('=');
        this.flags.set(name.slice(0, at), name.slice(at + 1));
      } else {
        i++;
        if (i >= argv.length) die(`--${name} needs a value`);
        this.flags.set(name, argv[i]);
      }
    }
    if (this.flags.has('help')) this.pos = ['help'];
  }

  /** the value, or null; an empty value counts as absent, as in the reference */
  flag(k) {
    return this.flags.get(k) || null;
  }

  has(k) {
    return this.flags.has(k);
  }

  req(k) {
    if (!this.flags.has(k)) die(`--${k} is required`);
    return this.flags.get(k);
  }

  at(n, usage) {
    if (this.pos.length <= n) die(usage);
    return this.pos[n];
  }
}

function readText(path) {
  let text = decodeUtf8(readFileSync(path));
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return text;
}

/** A JSON value given inline or as @file (friendlier in PowerShell and cmd). */
function jsonArg(s) {
  let text = s;
  if (s.startsWith('@')) {
    try {
      text = readText(s.slice(1));
    } catch (e) {
      die(`${s.slice(1)}: ${e.code ?? e.message}`);
    }
  }
  try {
    return parse(text);
  } catch (e) {
    return die(`not valid JSON (${e.message}): ${s}`);
  }
}

/** Config file + command-line overrides. Relative paths in the file are
 * relative to the file. Returns the internal JSON model. */
function loadConfig(args) {
  const path = args.flag('config') || process.env.SMARTDELEGATE_CONFIG || (existsSync('smartdelegate.json') ? 'smartdelegate.json' : null);
  let cfg = obj();
  if (path) {
    try {
      cfg = parse(readText(path));
    } catch (e) {
      die(`${path}: ${e.code ?? e.message}`);
    }
    if (!isObj(cfg)) die(`${path}: the configuration must be a JSON object`);
    const base = dirname(resolve(path));
    const fix = (p) => (isAbsolute(p) ? p : join(base, p));
    for (const k of ['bundle_dir', 'state_dir']) if (typeof cfg[k] === 'string') cfg[k] = fix(cfg[k]);
    if (isObj(cfg.idp) && typeof cfg.idp.jwks_file === 'string') cfg.idp.jwks_file = fix(cfg.idp.jwks_file);
  }
  if (args.flag('bundle')) cfg.bundle_dir = args.flag('bundle');
  if (args.flag('state')) cfg.state_dir = args.flag('state');
  if (args.has('shadow')) cfg.mode = 'shadow';
  for (const [k, env] of [['admin_key', 'SMARTDELEGATE_ADMIN_KEY'], ['pep_key', 'SMARTDELEGATE_PEP_KEY']]) {
    if (process.env[env]) cfg[k] = process.env[env];
  }
  if (!cfg.bundle_dir) die('no bundle: pass --config FILE or --bundle DIR');
  return cfg;
}

function engineFrom(args) {
  const cfg = loadConfig(args);
  try {
    return [new Engine(cfg), cfg];
  } catch (e) {
    if (e instanceof EngineError) return die(e.message);
    throw e;
  }
}

/** Run one operation on a fresh engine; `input` is a plain or internal value. */
function run(args, op, input) {
  const [engine] = engineFrom(args);
  try {
    return engine.callExact(op, toInternal(input));
  } finally {
    engine.close();
  }
}

function finish(v) {
  out(write(v, { indent: 2 }));
  return v.ok !== true ? 1 : (v.effect === 'deny' ? 2 : 0);
}

function decisionInput(args) {
  const res = args.req('resource');
  const at = res.indexOf('/');
  const path = at < 0 ? res : res.slice(0, at);
  const rid = at < 0 ? '' : res.slice(at + 1);
  const i = obj();
  i.action = args.req('action');
  i.resource = obj();
  i.resource.path = path;
  i.resource.id = rid || 'any';
  if (args.flag('token')) i.token = args.flag('token');
  if (args.flag('attrs')) i.resource.attrs = jsonArg(args.flag('attrs'));
  if (args.flag('context')) i.context = jsonArg(args.flag('context'));
  if (args.has('strict')) i.strict = true;
  if (args.has('dry-run')) i.dry_run = true;
  if (args.flag('data')) {
    i.data = jsonArg(args.flag('data'));
    return [i, 'filter'];
  }
  return [i, 'authorize'];
}

function integer(text, what) {
  if (!/^\s*[+-]?[0-9]+\s*$/.test(text)) die(what);
  return BigInt(text.trim());
}

function ttlOf(args, i) {
  if (args.flag('ttl')) i.ttl = integer(args.flag('ttl'), '--ttl must be a number of seconds');
}

function tokenOut(v, args) {
  if (args.has('raw') && v.ok === true) {
    out(v.token);
    return 0;
  }
  return finish(v);
}

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function conformanceCommand(args) {
  const vectors = args.pos[1] ?? join(ROOT, 'spec', 'conformance', 'vectors');
  const bundleDir = args.pos[2] ?? (args.pos[1] ? join('spec', 'conformance', 'bundle') : join(ROOT, 'spec', 'conformance', 'bundle'));
  const evalFile = args.flag('eval') ?? (args.pos[1] ? join(vectors, '..', 'eval', 'cases.json') : join(ROOT, 'spec', 'conformance', 'eval', 'cases.json'));
  const fail = (label, r) => {
    if (!r.passed) out(`FAIL ${label}${JSON.stringify(r.name)}\n${JSON.stringify(r.failures, null, 2)}`);
  };
  let failed = 0;
  try {
    if (existsSync(evalFile)) {
      const e = conformance.runEval(evalFile);
      for (const r of e.results) fail('eval: ', r);
      out(`eval: ${e.total} cases, ${e.failed} failed`);
      failed += e.failed;
    } else {
      out(`eval: skipped, ${evalFile} not found`);
    }
    const v = conformance.runVectors(vectors, bundleDir);
    for (const r of v.results) fail(`${r.suite}: `, r);
    for (const s of v.suites) out(`  ${s.file}: ${s.total} cases, ${s.steps} steps, ${s.failed} failed`);
    out(`conformance: ${v.total} cases, ${v.steps} steps, ${v.failed} failed`);
    failed += v.failed;
    if (v.total === 0) {
      out(`no vectors found in ${vectors}`);
      failed += 1;
    }
  } catch (e) {
    if (e instanceof EngineError) die(e.message);
    if (e && typeof e.syscall === 'string') die(e.message);
    throw e;
  }
  return failed === 0 ? 0 : 1;
}

async function main(argv) {
  const args = new Args(argv);
  const cmd = args.pos.length ? args.pos[0] : 'help';
  const sub = args.pos.length > 1 ? args.pos[1] : '';
  const is = (a, b) => cmd === a && sub === b;
  if (cmd === 'help' || cmd === '-h') {
    process.stdout.write(HELP);
    return 0;
  }
  if (cmd === 'version') {
    out(`smartdelegate ${VERSION} (node)`);
    return 0;
  }
  if (cmd === 'info') return finish(run(args, 'info', {}));
  if (is('policy', 'check')) {
    const info = run(args, 'info', {});
    out(`bundle loads: ${info.policies} policies, version ${info.policy_version}`);
    return 0;
  }
  if (is('policy', 'test')) {
    let r;
    try {
      r = conformance.runBundleTests(loadConfig(args).bundle_dir);
    } catch (e) {
      if (e instanceof EngineError) die(e.message);
      throw e;
    }
    for (const c of r.results) {
      out(`${c.passed ? 'ok  ' : 'FAIL'} ${c.name}`);
      if (!c.passed) out(JSON.stringify(c.failures, null, 2));
    }
    out(`${r.total} tests, ${r.failed} failed`);
    return r.failed === 0 ? 0 : 1;
  }
  if (is('bundle', 'keygen')) {
    const prefix = args.at(2, 'usage: smartdelegate-node bundle keygen <prefix>');
    const [sk, pk] = bundle.keygen();
    try {
      const fd = openSync(prefix + '.key', 'w', 0o600);
      try {
        writeSync(fd, sk);
      } finally {
        closeSync(fd);
      }
      writeFileSync(prefix + '.pub', pk, 'utf8');
    } catch (e) {
      die(e.message);
    }
    out(`wrote ${prefix}.key (keep secret) and ${prefix}.pub\nset "bundle_public_key": "${pk}" in smartdelegate.json to require signed bundles`);
    return 0;
  }
  if (is('bundle', 'sign')) {
    let v;
    try {
      v = bundle.sign(loadConfig(args).bundle_dir, readFileSync(args.req('key'), 'utf8'));
    } catch (e) {
      if (e instanceof Exit) throw e;
      die(e.message);
    }
    out(`signed bundle version ${v.version} with key ${v.key_id}`);
    return 0;
  }
  if (is('bundle', 'compile')) {
    die('compiling .cedar to policies.json needs the Cedar toolchain: run `smartdelegate bundle compile` from the Rust port (ports/rust)');
  }
  if (is('token', 'issue')) {
    const i = obj();
    i.agent = args.req('agent');
    if (args.flag('cap')) i.cap = jsonArg(args.flag('cap'));
    else if (!args.flag('role')) die('--cap JSON or --role NAME is required');
    for (const [k, f] of [['user', 'user'], ['tenant', 'tenant'], ['task', 'task'], ['id_token', 'id-token'], ['role', 'role']]) {
      if (args.flag(f)) i[k] = args.flag(f);
    }
    if (args.has('groups')) i.groups = args.flags.get('groups').split(',').filter((g) => g !== '');
    ttlOf(args, i);
    return tokenOut(run(args, 'issue_token', i), args);
  }
  if (is('token', 'exchange')) {
    const i = obj();
    i.subject_token = args.req('token');
    i.actor = args.req('actor');
    if (args.flag('cap')) i.cap = jsonArg(args.flag('cap'));
    ttlOf(args, i);
    return tokenOut(run(args, 'exchange_token', i), args);
  }
  if (is('token', 'inspect')) return finish(run(args, 'inspect_token', { token: args.req('token') }));
  if (is('token', 'revoke')) {
    let i;
    if (args.flag('user')) i = { user: args.flag('user'), by: 'cli' };
    else i = args.flag('id') ? { token_id: args.flag('id'), by: 'cli' } : { token: args.req('token'), by: 'cli' };
    return finish(run(args, 'revoke', i));
  }
  if (cmd === 'call' && sub) {
    // any operation, input as JSON: the form other ports and scripts use
    const raw = args.flag('input') || '{}';
    let input;
    if (raw === '-') {
      try {
        input = parse(decodeUtf8(readFileSync(0)));
      } catch (e) {
        die(`not valid JSON on standard input (${e.message})`);
      }
    } else input = jsonArg(raw);
    return finish(run(args, sub, input));
  }
  if (cmd === 'authorize') {
    const [i, op] = decisionInput(args);
    return finish(run(args, op, i));
  }
  if (cmd === 'explain') return finish(run(args, 'explain', decisionInput(args)[0]));
  if (cmd === 'approvals') return finish(run(args, 'approvals', {}));
  if (cmd === 'approve' && sub) return finish(run(args, 'approve', { approval_id: sub, by: args.req('by') }));
  if (is('audit', 'verify')) return finish(run(args, 'audit_verify', {}));
  if (is('audit', 'tail')) {
    const r = run(args, 'audit_tail', { n: integer(args.flag('n') || '20', '-n must be a number') });
    for (const rec of has(r, 'records') && Array.isArray(r.records) ? r.records : []) out(canonInternal(rec));
    return 0;
  }
  if (cmd === 'serve') {
    const [engine, cfg] = engineFrom(args);
    const str = (v) => (typeof v === 'string' ? v : '');
    let daemon;
    try {
      daemon = await serve(engine, args.flag('listen') || str(cfg.listen) || '127.0.0.1:8181', str(cfg.admin_key), str(cfg.pep_key));
    } catch (e) {
      engine.close();
      die(e.message);
    }
    await new Promise((done) => {
      const stop = () => daemon.close().then(done);
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
    });
    engine.close();
    return 0;
  }
  if (cmd === 'conformance') return conformanceCommand(args);
  if (['init', 'bench', 'http-proxy', 'mcp-proxy'].includes(cmd)) {
    die(`'${cmd}' is not part of the Node.js port; use the Python reference or the Rust port`);
  }
  process.stderr.write(HELP);
  return 1;
}

main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
}, (e) => {
  if (e instanceof Exit) {
    process.exitCode = e.exitCode;
  } else {
    process.stderr.write(`smartdelegate: ${e?.stack ?? e}\n`);
    process.exitCode = 1;
  }
});
