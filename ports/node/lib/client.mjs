// REST client for `smartdelegate serve` (any port's daemon), and middleware
// that puts a decision in front of an agent tool. Same public API as the
// REST-only client in ports/js, so code can switch between the two.
//
// In-process checks bind an agent that cooperates. The boundary an agent
// cannot skip is a proxy (`smartdelegate http-proxy`, `smartdelegate mcp-proxy`
// in the Python and Rust ports).
import { withOperations } from './api.mjs';
import { Denied, SmartDelegateError } from './errors.mjs';
import { parse, stringify, toPlain } from './json.mjs';

const ROUTES = {
  authorize: ['POST', '/v1/authorize', 'pep'],
  filter: ['POST', '/v1/filter', 'pep'],
  explain: ['POST', '/v1/explain', 'pep'],
  apply_obligations: ['POST', '/v1/obligations/apply', 'pep'],
  inspect_token: ['POST', '/v1/token/inspect', 'pep'],
  info: ['GET', '/v1/info', 'pep'],
  exchange_token: ['POST', '/v1/token', null],
  issue_token: ['POST', '/v1/token', 'admin'],
  revoke: ['POST', '/v1/admin/revoke', 'admin'],
  approve: ['POST', '/v1/admin/approve', 'admin'],
  reload: ['POST', '/v1/admin/reload', 'admin'],
  approvals: ['GET', '/v1/admin/approvals', 'admin'],
  audit_verify: ['GET', '/v1/admin/audit/verify', 'admin'],
  audit_tail: ['GET', '/v1/admin/audit/tail', 'admin'],
};

class ClientCore {
  constructor({ url, pepKey, adminKey, timeoutMs = 10000 }) {
    this.url = String(url).replace(/\/+$/, '');
    this.keys = { pep: pepKey ?? adminKey, admin: adminKey };
    this.timeoutMs = timeoutMs;
  }

  /** Raw operation: resolves to the engine's JSON result, including
   * {ok: false} errors. Integers beyond 2^53 - 1 come back as BigInt, and
   * BigInt values in `payload` are sent exactly. Rejects with
   * SmartDelegateError `daemon_unreachable` when there is no answer. */
  async call(op, payload = {}) {
    const route = Object.hasOwn(ROUTES, op) ? ROUTES[op] : undefined;
    if (!route) return { ok: false, error: { code: 'unknown_op', message: `no operation named '${op}'` } };
    let [method, path, kind] = route;   // eslint-disable-line prefer-const
    const p = payload ?? {};
    if (op === 'audit_tail' && p.n !== undefined && p.n !== null) path += `?n=${BigInt(p.n)}`;
    const headers = { 'Content-Type': 'application/json' };
    const key = op === 'issue_token' && p.id_token ? null : kind && this.keys[kind];
    if (key) headers.Authorization = `Bearer ${key}`;
    let res, text;
    try {
      res = await fetch(this.url + path, {
        method, headers, body: method === 'POST' ? stringify(p) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      text = await res.text();
    } catch (e) {
      // an unreachable decision point is never an allow
      throw new SmartDelegateError('daemon_unreachable', String(e?.cause?.message ?? e?.message ?? e));
    }
    try {
      return toPlain(parse(text));
    } catch {
      return { ok: false, error: { code: 'http_error', message: `HTTP ${res.status}: ${text.slice(0, 200)}` } };
    }
  }
}

/** Thin REST client. `call(op, payload)` plus authorize(), filter(), explain(),
 * applyObligations(), issueToken(), exchangeToken(), inspectToken(), revoke(),
 * approve(), info(); those reject with SmartDelegateError when ok is false. */
export class Client extends withOperations(ClientCore) {}

/**
 * Wrap a tool function. The decision happens first; record data in `input`
 * is checked strictly; the return value is masked before the caller (and so
 * the model) sees it. `client` is a Client or an in-process Engine.
 *
 *   const getCustomer = guardTool(client, () => taskToken,
 *     { action: 'read', resource: 'crm.customer', id: (a) => a.customerId },
 *     async ({ customerId }) => db.get(customerId));
 */
export function guardTool(client, token, spec, fn) {
  const tokenOf = typeof token === 'function' ? token : () => token;
  return async (args = {}) => {
    const req = { token: await tokenOf(), action: spec.action, resource: spec.resource, id: spec.id?.(args), attrs: spec.attrs?.(args) };
    if (spec.spend) {
      const [currency, amount] = spec.spend(args);
      req.context = { spend: { currency, amount } };
    }
    const input = spec.input?.(args);
    const d = input !== undefined ? await client.filter({ ...req, data: input, strict: true }) : await client.authorize(req);
    if (d.effect !== 'allow') throw new Denied(d);
    const result = await fn(args);
    if (spec.output === 'raw' || result === undefined || result === null) return result;
    return (await client.applyObligations(d, result)).data;
  };
}

export { Denied, SmartDelegateError };
