// The convenience methods shared by the in-process Engine and the REST Client,
// so code written against one runs against the other. Each returns the
// operation's JSON result; a result with ok === false throws SmartDelegateError.
// (The Engine's are synchronous, the Client's return promises; `await` works
// with both.)
import { SmartDelegateError } from './errors.mjs';

export const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== null));

export function decisionRequest({ token, action, resource, id, attrs, context, ...extra }) {
  return clean({ token, action, resource: clean({ path: resource, id: id ?? 'any', attrs }), context, ...extra });
}

export function unwrap(r) {
  if (!r || r.ok !== true) throw new SmartDelegateError(r?.error?.code ?? 'error', r?.error?.message ?? 'unknown error');
  return r;
}

const then = (r, f) => (r && typeof r.then === 'function' ? r.then(f) : f(r));

/** Adds authorize(), filter(), ... to a class that has call(op, payload). */
export function withOperations(Base) {
  return class extends Base {
    #ok(op, payload) {
      return then(this.call(op, payload), unwrap);
    }

    authorize(req) { return this.#ok('authorize', decisionRequest(req)); }
    filter(req) { return this.#ok('filter', decisionRequest(req)); }
    explain(req) { return this.#ok('explain', decisionRequest(req)); }
    applyObligations(decision, data) {
      return this.#ok('apply_obligations', clean({ obligations: decision.obligations, data, decision_id: decision.decision_id }));
    }
    issueToken({ user, agent, cap, role, groups, idToken, ttl, tenant, task }) {
      return this.#ok('issue_token', clean({ user, agent, cap, role, groups, id_token: idToken, ttl, tenant, task }));
    }
    exchangeToken({ subjectToken, actor, cap, ttl, task, role }) {
      return this.#ok('exchange_token', clean({ subject_token: subjectToken, actor, cap, ttl, task, role }));
    }
    inspectToken(token) { return this.#ok('inspect_token', { token }); }
    revoke(tokenId) { return this.#ok('revoke', { token_id: tokenId }); }
    /** Offboarding: ends every token already issued for the user, sub-agents included. */
    revokeUser(user, by) { return this.#ok('revoke', clean({ user, by })); }
    approve(approvalId, by) { return this.#ok('approve', { approval_id: approvalId, by }); }
    info() { return this.#ok('info', {}); }
  };
}
