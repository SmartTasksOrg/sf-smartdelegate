// REST decision daemon (`smartdelegate-node serve`). See spec/openapi.yaml.
//
// Two keys guard it:
//   pep key    enforcement points: /v1/authorize, /v1/filter, /v1/explain,
//              /v1/obligations/apply, /v1/token/inspect, /v1/info
//   admin key  /v1/admin/* and issuing a root token without an OIDC ID token
// /v1/token needs no key for token exchange (holding the parent token is the
// authority) or for issuance backed by a verified OIDC ID token.
// TLS is not terminated here: bind to loopback or put it behind a mesh.
import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { decodeUtf8 } from './canon.mjs';
import { has, isObj, obj, parse, write } from './json.mjs';

export const MAX_BODY = 8 * 1024 * 1024;

const ROUTES = new Map([
  ['GET /v1/info', ['info', 'pep']],
  ['POST /v1/authorize', ['authorize', 'pep']],
  ['POST /v1/filter', ['filter', 'pep']],
  ['POST /v1/explain', ['explain', 'pep']],
  ['POST /v1/obligations/apply', ['apply_obligations', 'pep']],
  ['POST /v1/token/inspect', ['inspect_token', 'pep']],
  ['POST /v1/admin/revoke', ['revoke', 'admin']],
  ['POST /v1/admin/approve', ['approve', 'admin']],
  ['POST /v1/admin/reload', ['reload', 'admin']],
  ['GET /v1/admin/approvals', ['approvals', 'admin']],
  ['GET /v1/admin/audit/verify', ['audit_verify', 'admin']],
  ['GET /v1/admin/audit/tail', ['audit_tail', 'admin']],
]);

const digest = (s) => createHash('sha256').update(String(s), 'utf8').digest();
/** Constant-time comparison of two strings of any length. */
export const same = (a, b) => timingSafeEqual(digest(a), digest(b));

const error = (code, message) => ({ ok: false, error: { code, message } });

function sendJson(res, status, text, close = false) {
  const raw = Buffer.from(text, 'utf8');
  const headers = { 'Content-Type': 'application/json', 'Content-Length': String(raw.length) };
  if (close) headers.Connection = 'close';
  res.writeHead(status, headers);
  res.end(raw);
}

function bearer(req) {
  const h = req.headers.authorization ?? '';
  return h.startsWith('Bearer ') ? h.slice(7).trim() : null;
}

const TOO_LARGE = 'request body is too large';
const DISCARD_LIMIT = 4 * MAX_BODY, DISCARD_MS = 10000;

/** Reads the request body. Resolves to [Buffer, null] or [null, message].
 *
 * A body over the limit is never buffered. It is read and thrown away (up to
 * DISCARD_LIMIT bytes or DISCARD_MS) so that the client, which is still
 * sending, gets to read the 400 instead of a connection reset; past that the
 * connection is simply closed after the answer. */
function readBody(req) {
  return new Promise((resolve) => {
    const declared = req.headers['content-length'];
    let failure = null;
    if (declared !== undefined) {
      if (!/^\s*[+-]?[0-9]+\s*$/.test(declared)) {
        resolve([null, 'bad Content-Length']);
        return;
      }
      if (Number(declared) > MAX_BODY) failure = TOO_LARGE;
    }
    let chunks = [], size = 0, done = false, timer = null;
    const finish = (v) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      resolve(v);
    };
    const giveUp = () => {
      if (failure === null) failure = TOO_LARGE;
      chunks = [];
      if (timer === null) timer = setTimeout(() => finish([null, failure]), DISCARD_MS);
    };
    if (failure !== null) giveUp();
    req.on('data', (c) => {
      size += c.length;
      if (failure === null && size > MAX_BODY) giveUp();
      if (failure === null) chunks.push(c);
      else if (size > DISCARD_LIMIT) finish([null, failure]);
    });
    req.on('end', () => finish(failure === null ? [Buffer.concat(chunks), null] : [null, failure]));
    req.on('error', () => finish([null, failure ?? 'request body could not be read']));
    req.on('aborted', () => finish([null, failure ?? 'request body could not be read']));
  });
}

/** The request handler for an engine. `engine` needs `callExact(op, payload)`. */
export function handler(engine, adminKey, pepKey) {
  return async (req, res) => {
    try {
      const method = req.method;
      if (method !== 'GET' && method !== 'POST') {
        return sendJson(res, 501, JSON.stringify(error('unsupported_method', `unsupported method ${method}`)), true);
      }
      const url = req.url ?? '';
      const q = url.indexOf('?');
      const path = q < 0 ? url : url.slice(0, q);
      const query = q < 0 ? '' : url.slice(q + 1);
      if (path === '/healthz') {
        req.resume();
        return sendJson(res, 200, '{"ok":true}');
      }
      let body = obj();
      if (method === 'POST') {
        let [raw, err] = await readBody(req);
        if (err === null && raw.length) {
          try {
            const text = decodeUtf8(raw);
            // a BOM is tolerated, as in the reference; other leading/trailing whitespace is JSON whitespace
            const t = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
            if (t.trim() !== '') body = parse(t);
          } catch {
            err = 'body is not JSON';
          }
        }
        if (err) {
          // after an oversized body the connection is not reused
          return sendJson(res, 400, JSON.stringify(error('invalid_input', err)), err === TOO_LARGE);
        }
      } else {
        req.resume();
      }
      const key = bearer(req) ?? '';
      const isAdmin = same(key, adminKey);
      const isPep = isAdmin || same(key, pepKey);
      let op, allowed;
      const route = ROUTES.get(`${method} ${path}`);
      if (method === 'POST' && path === '/v1/token') {
        if (isObj(body) && has(body, 'subject_token')) {
          op = 'exchange_token';
          allowed = true;
        } else if (isObj(body) && has(body, 'id_token')) {
          // identity comes from the ID token alone
          const b = obj();
          for (const k of Object.keys(body)) if (k !== 'user') b[k] = body[k];
          body = b;
          op = 'issue_token';
          allowed = true;
        } else {
          op = 'issue_token';
          allowed = isAdmin;
        }
      } else if (route) {
        op = route[0];
        allowed = route[1] === 'admin' ? isAdmin : isPep;
        if (op === 'audit_tail') {
          const kv = query.split('&').find((x) => x.startsWith('n='));
          const n = kv === undefined ? '20' : kv.slice(2);
          body = obj();
          body.n = /^[0-9]+$/.test(n) ? BigInt(n) : 20n;
        }
      } else {
        return sendJson(res, 404, JSON.stringify(error('not_found', 'no such endpoint')));
      }
      if (!allowed) return sendJson(res, 401, JSON.stringify(error('unauthorized', 'missing or wrong API key')));
      const result = engine.callExact(op, body);
      return sendJson(res, result.ok === true ? 200 : 400, write(result, { ascii: true }));
    } catch (e) {
      // never an allow, never a crash
      try {
        return sendJson(res, 500, JSON.stringify(error('internal', String(e?.message ?? e))), true);
      } catch {
        res.destroy();
        return undefined;
      }
    }
  };
}

/** "host:port" -> [host, port] */
export function listenAddress(text) {
  const at = String(text).lastIndexOf(':');
  const host = at <= 0 ? '127.0.0.1' : text.slice(0, at).replace(/^\[(.*)\]$/, '$1');
  const port = Number(at < 0 ? text : text.slice(at + 1));
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`bad listen address '${text}'`);
  return [host, port];
}

/** Start the daemon. Resolves once it is listening, to
 * {server, url, host, port, close()}. Prints the startup line on stderr
 * unless `quiet`. Rejects when the keys are too short or the port is taken. */
export function serve(engine, listen = '127.0.0.1:8181', adminKey = '', pepKey = '', { quiet = false } = {}) {
  return new Promise((resolve, reject) => {
    if (String(adminKey ?? '').length < 16 || String(pepKey ?? '').length < 16) {
      reject(new Error('serve needs admin_key and pep_key (16+ characters) in the config or SMARTDELEGATE_ADMIN_KEY / SMARTDELEGATE_PEP_KEY'));
      return;
    }
    let host, port;
    try {
      [host, port] = listenAddress(listen);
    } catch (e) {
      reject(e);
      return;
    }
    const server = createServer({ noDelay: true, keepAlive: true }, handler(engine, String(adminKey), String(pepKey)));
    server.on('connection', (socket) => socket.setNoDelay(true));
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      const a = server.address();
      const shown = a.family === 'IPv6' ? `[${a.address}]` : a.address;
      const url = `http://${shown}:${a.port}`;
      if (!quiet) process.stderr.write(`smartdelegate daemon listening on ${url}\n`);
      resolve({ server, url, host: a.address, port: a.port,
        close: () => new Promise((done) => { server.close(() => done()); server.closeAllConnections?.(); }) });
    });
  });
}
