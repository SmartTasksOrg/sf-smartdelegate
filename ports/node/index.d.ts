// Type declarations for the SmartDelegate Node.js port. Hand-written.

/** A JSON integer: a Number when that is exact, a BigInt beyond 2^53 - 1. */
export type Int = number | bigint;
export type Json = null | boolean | number | bigint | string | Json[] | { [key: string]: Json };

export interface Cap {
  actions?: string[];
  resources?: string[];
  deny_labels?: string[];
  deny_fields?: string[];
  /** currency -> total spend in minor units */
  budget?: Record<string, Int>;
}

export interface GroupRef { type: string; id: string }

export interface IdpConfig {
  issuer: string;
  audience: string;
  jwks?: { keys: Record<string, unknown>[] };
  jwks_file?: string;
  user_claim?: string;
  groups_claim?: string;
  group_type?: string;
  group_map?: Record<string, string>;
}

/** Engine configuration; see spec/API.md. */
export interface EngineConfig {
  bundle_dir: string;
  /** Signing key, state.json, audit.jsonl, lock.node. Without it the engine is in-memory, has an ephemeral key and no audit log. */
  state_dir?: string;
  issuer?: string;
  mode?: 'enforce' | 'shadow';
  default_ttl?: number;
  max_ttl?: number;
  max_depth?: number;
  approval_ttl?: number;
  bundle_public_key?: string;
  idp?: IdpConfig;
  require_role?: boolean;
  trusted_keys?: string[];
  verify_only?: boolean;
  /** base64 Ed25519 PKCS#8; overrides the key in state_dir */
  signing_key?: string;
  trust_caller_chain?: boolean;
  allow_test_clock?: boolean;
  audit?: boolean;
  /** Node port only: how long to wait for a signing key file that another process is still writing (default 30000). */
  key_wait_ms?: number;
  /** Node port only: how long a call waits for the state-directory lock (default 30000). */
  lock_timeout_ms?: number;
  /** Node port only: age after which a lock is taken over even though its holder seems alive (default 600000). */
  lock_stale_ms?: number;
  [key: string]: unknown;
}

export interface ErrorResult { ok: false; error: { code: string; message: string; rule?: string } }

export interface DecisionRequest {
  token: string;
  action: string;
  /** catalog path, e.g. "crm.customer" */
  resource: string;
  id?: string;
  attrs?: Record<string, Json>;
  context?: Record<string, Json>;
  fields?: string[];
  data?: Json;
  strict?: boolean;
  dry_run?: boolean;
  explain?: boolean;
  now?: Int;
}

export interface Obligations {
  fields?: { allow: string[]; deny: string[]; redact: string[] };
  row_filter?: { column: string; op: 'eq'; value: Json }[];
  rate_limit?: { limit: Int; window_seconds: Int; used: Int };
  approved?: { id: string; by: string };
}

export interface Principal {
  user: string;
  agent: string;
  chain: string[];
  tenant: string | null;
  task: string | null;
  role: string | null;
  token_id: string | null;
}

export interface Decision {
  ok: true;
  effect: 'allow' | 'deny';
  reason: string;
  /** "DELEGATE-" + the reason in upper case with dashes */
  rule: string;
  detail?: string;
  policies: string[];
  policy_version: string;
  decision_id: string;
  obligations: Obligations;
  principal: Principal | null;
  approval?: { id: string; label: string };
  data?: Json;
  masked?: string[];
  rows_dropped?: number;
  shadow?: boolean;
  would_deny?: { reason: string; detail: string };
  would_mask?: string[];
  would_drop_rows?: number;
  policy_errors?: { policy: string; effect: 'permit' | 'forbid'; error: string }[];
  explain?: Record<string, Json>[];
}

export interface TokenResult {
  ok: true;
  token: string;
  token_type: 'Bearer';
  issued_token_type: string;
  token_id: string;
  expires_at: Int;
  expires_in: Int;
  user: string;
  chain: string[];
  role: string | null;
  task: string | null;
  cap: Required<Cap>;
}

export interface InspectResult {
  ok: true;
  valid: boolean;
  claims?: Record<string, Json>;
  chain?: string[];
  user?: string;
  expires_in?: Int;
  reason?: string;
  detail?: string;
}

export interface Info {
  ok: true;
  version: string;
  implementation: string;
  policy_version: string;
  bundle_signed_by: string | null;
  policies: number;
  resources: string[];
  roles: string[];
  mode: 'enforce' | 'shadow';
  issuer: string;
  key_id: string | null;
  public_key: string | null;
  can_issue: boolean;
  oidc: string | null;
}

export interface IssueRequest {
  user?: string;
  agent: string;
  cap?: Cap;
  /** lend the agent a role the user holds; see spec/ROLES.md */
  role?: string;
  groups?: string | (string | GroupRef)[];
  idToken?: string;
  ttl?: number;
  tenant?: string;
  task?: string;
}

export interface ExchangeRequest { subjectToken: string; actor: string; cap?: Cap; ttl?: number; task?: string; role?: string }

export type Operation = 'authorize' | 'filter' | 'explain' | 'apply_obligations' | 'issue_token' | 'exchange_token' | 'inspect_token'
  | 'revoke' | 'approve' | 'approvals' | 'audit_verify' | 'audit_tail' | 'info' | 'reload';

/** A request that could not be processed. `code` is the engine's error code; `detail` is the message without the code. */
export class EngineError extends Error {
  constructor(code: string, detail: string);
  code: string;
  detail: string;
  toResult(): ErrorResult;
}
/** The same class as EngineError. A deny is not an error. */
export class SmartDelegateError extends EngineError {}
/** Thrown by a guarded tool when the decision is a deny. */
export class Denied extends Error {
  constructor(decision: Decision);
  decision: Decision;
  reason: string;
  approvalId?: string;
}
export function ruleId(code: string): string;

/** The native engine. All methods are synchronous. */
export class Engine {
  /** Throws EngineError when the configuration or the bundle cannot be used. */
  constructor(config: EngineConfig);
  /** JSON in, JSON out. Never throws: failures are {ok: false, error}. A deny is {ok: true, effect: "deny"}. */
  call(op: Operation | string, payload?: unknown): any;
  /** `call` in the exact JSON model: every integer is a BigInt, every Number is a float, objects have a null prototype. */
  callExact(op: Operation | string, payload: unknown): any;
  /** Release what the engine holds. Idempotent. (This port holds nothing between calls.) */
  close(): void;
  authorize(req: DecisionRequest): Decision;
  filter(req: DecisionRequest): Decision;
  explain(req: DecisionRequest): Decision;
  applyObligations(decision: Pick<Decision, 'obligations'> & { decision_id?: string }, data: Json): { ok: true; data: Json; masked: string[]; rows_dropped: number };
  issueToken(req: IssueRequest): TokenResult;
  exchangeToken(req: ExchangeRequest): TokenResult;
  inspectToken(token: string): InspectResult;
  revoke(tokenId: string): { ok: true; revoked: string };
  /** Offboarding: every token of the user issued up to now is revoked, sub-agent tokens included. */
  revokeUser(user: string, by?: string): { ok: true; revoked_user: string; issued_up_to: Int };
  approve(approvalId: string, by: string): { ok: true; approved: string; by: string; expires_at: Int };
  info(): Info;
}

/** REST client for `smartdelegate serve` of any port. Same methods as Engine, returning promises. */
export class Client {
  constructor(options: { url: string; pepKey?: string; adminKey?: string; timeoutMs?: number });
  /** Resolves to the daemon's JSON result, including {ok: false}. Rejects with SmartDelegateError `daemon_unreachable`. */
  call(op: Operation | string, payload?: Record<string, unknown>): Promise<any>;
  authorize(req: DecisionRequest): Promise<Decision>;
  filter(req: DecisionRequest): Promise<Decision>;
  explain(req: DecisionRequest): Promise<Decision>;
  applyObligations(decision: Pick<Decision, 'obligations'> & { decision_id?: string }, data: Json): Promise<{ ok: true; data: Json; masked: string[]; rows_dropped: number }>;
  issueToken(req: IssueRequest): Promise<TokenResult>;
  exchangeToken(req: ExchangeRequest): Promise<TokenResult>;
  inspectToken(token: string): Promise<InspectResult>;
  revoke(tokenId: string): Promise<{ ok: true; revoked: string }>;
  revokeUser(user: string, by?: string): Promise<{ ok: true; revoked_user: string; issued_up_to: Int }>;
  approve(approvalId: string, by: string): Promise<{ ok: true; approved: string; by: string; expires_at: Int }>;
  info(): Promise<Info>;
}

export interface ToolSpec<A> {
  action: string;
  resource: string;
  id?: (args: A) => string | undefined;
  attrs?: (args: A) => Record<string, Json>;
  /** record data the tool is about to write; checked strictly */
  input?: (args: A) => unknown;
  /** [currency, amount in minor units] */
  spend?: (args: A) => [string, Int];
  /** "raw" skips masking of the return value */
  output?: 'filter' | 'raw';
}
/** Wrap a tool: decide first, check `input` strictly, mask the return value. `client` is a Client or an Engine. */
export function guardTool<A, R>(client: Client | Engine, token: string | (() => string | Promise<string>), spec: ToolSpec<A>,
  fn: (args: A) => R | Promise<R>): (args: A) => Promise<R>;

// ---- JSON with exact integers ------------------------------------------------
export class JSONError extends Error {}
export interface WriteOptions { sortKeys?: boolean; ascii?: boolean; indent?: number }
/** Text -> value in the exact model: integers are BigInt, numbers with a fraction or exponent are Number, objects have a null prototype. */
export function parse(text: string): any;
/** Like JSON.stringify, but BigInt and integer-valued Numbers are written as exact integers. */
export function stringify(value: unknown, options?: WriteOptions): string;
/** Ordinary value -> exact model (integer-valued Numbers become BigInt). */
export function toInternal(value: unknown): any;
/** Exact model -> ordinary value (integers become Numbers when exact, else stay BigInt). */
export function toPlain(value: unknown): any;
/** Canonical JSON: keys sorted by code point, compact, integers exact. */
export function canon(value: unknown): string;
/** sha256 of the canonical JSON, hex. */
export function hashValue(value: unknown): string;
export function sha256Hex(data: string | Uint8Array): string;

// ---- bundles and audit logs ---------------------------------------------------
/** -> [private key (base64 PKCS#8), public key (base64 of 32 raw bytes)] */
export function keygen(): [string, string];
export function keyId(publicKeyB64: string): string;
export interface BundleSignature { files: Record<string, string>; version: string; key_id: string; alg: 'Ed25519'; signature: string }
/** Sign the bundle in `dir`; writes bundle.sig.json. */
export function signBundle(dir: string, privateKeyB64: string): BundleSignature;
export function bundleManifest(dir: string): Record<string, string>;
export function bundleVersion(files: Record<string, string>): string;
export class Bundle {
  constructor(dir: string, publicKey?: string | null);
  version: string;
  signedBy: string | null;
}
export const GENESIS: string;
/** Recompute a hash chain. Throws EngineError `audit_broken` naming the first bad line. */
export function auditVerify(path: string): { ok: true; records: bigint; head: string };
export function auditTail(path: string, n: number | bigint): any[];

// ---- daemon -------------------------------------------------------------------
export interface Daemon { server: import('node:http').Server; url: string; host: string; port: number; close(): Promise<void> }
/** Start the REST daemon. Rejects when a key is shorter than 16 characters or the address cannot be bound. */
export function serve(engine: Engine, listen?: string, adminKey?: string, pepKey?: string, options?: { quiet?: boolean }): Promise<Daemon>;
export function requestHandler(engine: Engine, adminKey: string, pepKey: string): import('node:http').RequestListener;

// ---- conformance --------------------------------------------------------------
export interface CaseResult { name: string | null; steps?: number; suite?: string; passed: boolean; failures: { step?: number; op?: string | null; mismatch: string }[] }
export interface SuiteSummary { file: string; suite: string; total: number; failed: number; steps: number }
export function runVectors(vectorsDir: string, bundleDir: string, maxDepth?: number): { total: number; failed: number; steps: number; suites: SuiteSummary[]; results: CaseResult[] };
export function runEval(casesFile: string): { total: number; failed: number; results: CaseResult[] };
export function runBundleTests(bundleDir: string): { total: number; failed: number; results: CaseResult[] };
export function runCase(call: (op: string, input: unknown) => any, testCase: unknown): CaseResult;
export function runCaseAsync(call: (op: string, input: unknown) => Promise<any>, testCase: unknown): Promise<CaseResult>;
export function subset(expect: unknown, actual: unknown, path?: string): string | null;
export function substitute(value: unknown, variables: Map<string, unknown>): unknown;
export function conformanceConfig(bundleDir: string, stateDir: string, extra?: unknown, maxDepth?: number): EngineConfig;
export function loadVectors(vectorsDir: string): { file: string; suite: string; config: unknown; cases: any[] }[];

export const VERSION: string;
export const IMPLEMENTATION: string;
/** The policy evaluator (Cedar JSON subset): Policy, Store, Env, Entity, isAuthorized, fromJson, ... */
export const cedar: any;
