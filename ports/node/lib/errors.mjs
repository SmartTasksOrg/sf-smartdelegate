/** The rule id of a decision reason or error code: `policy_forbid` -> `DELEGATE-POLICY-FORBID`. */
export function ruleId(code) {
  return 'DELEGATE-' + String(code).toUpperCase().replaceAll('_', '-');
}

/** A request that could not be processed. Becomes
 * {"ok": false, "error": {"code", "message", "rule"}}; never an allow. */
export class EngineError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.name = 'EngineError';
    this.code = code;
    /** the message without the code prefix */
    this.detail = detail;
  }

  toResult() {
    return { ok: false, error: { code: this.code, message: this.detail, rule: ruleId(this.code) } };
  }
}

/** One error type for the engine and the REST client. A deny is not an error. */
export const SmartDelegateError = EngineError;

/** Thrown by `guardTool` when a decision is a deny. */
export class Denied extends Error {
  constructor(decision) {
    super(`denied by SmartDelegate (${decision.reason}): ${decision.detail ?? ''}`);
    this.name = 'Denied';
    this.decision = decision;
    this.reason = decision.reason;
    this.approvalId = decision.approval?.id;
  }
}
