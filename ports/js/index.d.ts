export interface Cap { actions: string[]; resources: string[]; deny_labels?: string[]; deny_fields?: string[]; budget?: Record<string, number>; }
export interface DecisionRequest { token: string; action: string; resource: string; id?: string; attrs?: Record<string, unknown>; context?: Record<string, unknown>; fields?: string[]; data?: unknown; strict?: boolean; dry_run?: boolean; }
export interface Obligations { fields?: { allow: string[]; deny: string[]; redact: string[] }; row_filter?: { column: string; op: 'eq'; value: unknown }[]; rate_limit?: { limit: number; window_seconds: number; used: number }; approved?: { id: string; by: string }; }
export interface Decision { ok: true; effect: 'allow' | 'deny'; reason: string; rule: string; detail?: string; policies: string[]; policy_version: string; decision_id: string; obligations: Obligations; principal: { user: string; agent: string; chain: string[]; tenant: string | null; task: string | null; role: string | null; token_id: string | null } | null; approval?: { id: string; label: string }; data?: unknown; masked?: string[]; rows_dropped?: number; shadow?: boolean; would_deny?: { reason: string; detail: string }; }
export interface TokenResult { ok: true; token: string; token_id: string; expires_at: number; expires_in: number; user: string; chain: string[]; role: string | null; task: string | null; cap: Cap; }
export class SmartDelegateError extends Error { code: string; rule?: string; }
export class Denied extends Error { decision: Decision; reason: string; approvalId?: string; }
export class Client {
  constructor(options: { url: string; pepKey?: string; adminKey?: string; timeoutMs?: number });
  call(op: string, payload?: Record<string, unknown>): Promise<any>;
  authorize(req: DecisionRequest): Promise<Decision>;
  filter(req: DecisionRequest): Promise<Decision>;
  explain(req: DecisionRequest): Promise<Decision & { explain: unknown[] }>;
  applyObligations(decision: Decision, data: unknown): Promise<{ data: unknown; masked: string[]; rows_dropped: number }>;
  issueToken(req: { user?: string; agent: string; cap?: Cap; role?: string; groups?: (string | { type: string; id: string })[]; idToken?: string; ttl?: number; tenant?: string; task?: string }): Promise<TokenResult>;
  exchangeToken(req: { subjectToken: string; actor: string; cap?: Cap; ttl?: number; task?: string }): Promise<TokenResult>;
  inspectToken(token: string): Promise<any>;
  revoke(tokenId: string): Promise<any>;
  revokeUser(user: string, by?: string): Promise<{ revoked_user: string; issued_up_to: number }>;
  approve(approvalId: string, by: string): Promise<any>;
  info(): Promise<any>;
}
export interface ToolSpec<A> { action: string; resource: string; id?: (args: A) => string | undefined; attrs?: (args: A) => Record<string, unknown>; input?: (args: A) => unknown; spend?: (args: A) => [string, number]; output?: 'filter' | 'raw'; }
export function guardTool<A, R>(client: Client, token: string | (() => string | Promise<string>), spec: ToolSpec<A>, fn: (args: A) => R | Promise<R>): (args: A) => Promise<R>;
