// SmartDelegate JavaScript SDK: a thin client for `smartdelegate serve`, and middleware
// that puts a decision in front of an agent tool. No dependencies.
//
// In-process checks bind an agent that cooperates. The boundary an agent
// cannot skip is a proxy (`smartdelegate http-proxy`, `smartdelegate mcp-proxy`).

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

/** The request was malformed or could not be processed. A deny is not an error. */
export class SmartDelegateError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

export class Denied extends Error {
  constructor(decision) {
    super(`denied by SmartDelegate (${decision.reason}): ${decision.detail ?? ''}`);
    this.decision = decision;
    this.reason = decision.reason;
    this.approvalId = decision.approval?.id;
  }
}

const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null));

export class Client {
  constructor({ url, pepKey, adminKey, timeoutMs = 10000 }) {
    this.url = url.replace(/\/+$/, '');
    this.keys = { pep: pepKey ?? adminKey, admin: adminKey };
    this.timeoutMs = timeoutMs;
  }

  /** Raw operation: returns the engine's JSON result, including {ok:false} errors. */
  async call(op, payload = {}) {
    const route = ROUTES[op];
    if (!route) return { ok: false, error: { code: 'unknown_op', message: `no operation named '${op}'` } };
    let [method, path, kind] = route;
    if (op === 'audit_tail' && payload.n !== undefined) path += `?n=${Number(payload.n)}`;
    const headers = { 'Content-Type': 'application/json' };
    const key = op === 'issue_token' && payload.id_token ? null : kind && this.keys[kind];
    if (key) headers.Authorization = `Bearer ${key}`;
    let res;
    try {
      res = await fetch(this.url + path, {
        method, headers, body: method === 'POST' ? JSON.stringify(payload) : undefined,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      // an unreachable decision point is never an allow
      throw new SmartDelegateError('daemon_unreachable', String(e.cause?.message ?? e.message));
    }
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      return { ok: false, error: { code: 'http_error', message: `HTTP ${res.status}: ${text.slice(0, 200)}` } };
    }
  }

  async #ok(op, payload) {
    const r = await this.call(op, payload);
    if (!r.ok) throw new SmartDelegateError(r.error?.code ?? 'error', r.error?.message ?? 'unknown error');
    return r;
  }

  #request({ token, action, resource, id, attrs, context, ...extra }) {
    return clean({ token, action, resource: clean({ path: resource, id: id ?? 'any', attrs }), context, ...extra });
  }

  authorize(req) { return this.#ok('authorize', this.#request(req)); }
  filter(req) { return this.#ok('filter', this.#request(req)); }
  explain(req) { return this.#ok('explain', this.#request(req)); }
  applyObligations(decision, data) {
    return this.#ok('apply_obligations', { obligations: decision.obligations, data, decision_id: decision.decision_id });
  }
  /** `role`: lend the agent a role the user holds; `cap` may then be omitted. `groups`: the user's live membership. */
  issueToken({ user, agent, cap, role, groups, idToken, ttl, tenant, task }) {
    return this.#ok('issue_token', clean({ user, agent, cap, role, groups, id_token: idToken, ttl, tenant, task }));
  }
  exchangeToken({ subjectToken, actor, cap, ttl, task }) {
    return this.#ok('exchange_token', clean({ subject_token: subjectToken, actor, cap, ttl, task }));
  }
  inspectToken(token) { return this.#ok('inspect_token', { token }); }
  revoke(tokenId) { return this.#ok('revoke', { token_id: tokenId }); }
  /** Offboarding: end every token already issued for this human, sub-agents included. */
  revokeUser(user, by) { return this.#ok('revoke', clean({ user, by })); }
  approve(approvalId, by) { return this.#ok('approve', { approval_id: approvalId, by }); }
  info() { return this.#ok('info', {}); }
}

/**
 * Wrap a tool function. The decision happens first; record data in `input`
 * is checked strictly; the return value is masked before the caller (and so
 * the model) sees it.
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
