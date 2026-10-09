// Evaluator for Cedar's JSON policy form (the portable subset).
//
// What it must do is fixed by spec/conformance/eval/cases.json, whose expected
// answers come from the real Cedar engine. spec/POLICY_SUBSET.md lists what is
// in the subset; anything outside it is refused when the bundle loads.
//
// Values: boolean, long (BigInt, 64-bit, overflow is an error), string,
// Entity, CedarSet, record (an object with a null prototype).
import { cmpCodePoint, has, isObj, obj, truthy } from './json.mjs';

export const I64_MIN = -(2n ** 63n), I64_MAX = 2n ** 63n - 1n;
const TYPE = /^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$/;

const BINARY = new Set(['==', '!=', '<', '<=', '>', '>=', '&&', '||', '+', '-', '*', 'in', 'contains', 'containsAll', 'containsAny']);
const UNARY = new Set(['!', 'neg', 'isEmpty']);
const VARS = new Set(['principal', 'action', 'resource', 'context']);

/** A policy condition could not be evaluated. The policy is skipped. */
export class EvalError extends Error {}
/** The policy uses Cedar that is outside the portable subset. */
export class Unsupported extends Error {}
/** A JSON value that is not a Cedar value, or a malformed entity. */
export class ValueError extends Error {}

/** An entity reference: (type, id). */
export class Entity {
  constructor(type, id) {
    this.type = type;
    this.id = id;
    // types cannot contain a newline, so this is unambiguous
    this.k = type + '\n' + id;
  }

  toString() {
    return `${this.type}::"${this.id}"`;
  }
}

/** A Cedar set: unordered, no duplicates, any element types. */
export class CedarSet {
  constructor(values) {
    this.items = new Map();
    for (const v of values) this.items.set(key(v), v);
  }
}

const isRecord = (v) => isObj(v) && !(v instanceof Entity) && !(v instanceof CedarSet);

/** A string identity for a value; equal values have equal keys. */
export function key(v) {
  switch (typeof v) {
    case 'boolean': return v ? 'b1' : 'b0';
    case 'bigint': return 'l' + v;
    case 'string': return 's' + JSON.stringify(v);
    case 'object':
      if (v instanceof Entity) return 'e' + JSON.stringify([v.type, v.id]);
      if (v instanceof CedarSet) return 'S[' + [...v.items.keys()].sort().join(',') + ']';
      if (v !== null && !Array.isArray(v)) {
        return 'R{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + key(v[k])).join(',') + '}';
      }
    // fallthrough
    default: throw new EvalError('not a Cedar value');
  }
}

export function validType(name) {
  return typeof name === 'string' && TYPE.test(name);
}

/** JSON (internal model) -> Cedar value, for entity attributes, context and
 * literals. Lists are sets; {"__entity": {type, id}} is an entity reference. */
export function fromJson(v) {
  switch (typeof v) {
    case 'boolean': case 'string': return v;
    case 'bigint':
      if (v < I64_MIN || v > I64_MAX) throw new ValueError('integer does not fit in 64 bits');
      return v;
    case 'number': throw new ValueError('floating-point numbers are not Cedar values');
    case 'object': break;
    default: throw new ValueError(`not a JSON value: ${typeof v}`);
  }
  if (v === null) throw new ValueError('null is not a Cedar value');
  if (Array.isArray(v)) {
    const out = [];
    for (const x of v) out.push(fromJson(x));
    return new CedarSet(out);
  }
  if (has(v, '__entity')) {
    const e = v.__entity;
    if (Object.keys(v).length !== 1 || !isObj(e) || !validType(e.type) || typeof e.id !== 'string') throw new ValueError('malformed __entity reference');
    return new Entity(e.type, e.id);
  }
  if (has(v, '__extn')) throw new ValueError('extension values (decimal, ip, datetime) are outside the portable subset');
  const out = obj();
  for (const k of Object.keys(v)) out[k] = fromJson(v[k]);
  return out;
}

/** Entities: attributes and transitive ancestors. */
export class Store {
  constructor(entitiesJson) {
    this.attrs = new Map();     // entity key -> record
    this.parents = new Map();   // entity key -> Entity[]
    this._ancestors = new Map();
    for (const e of entitiesJson ?? []) this.add(e);
  }

  static uid(u) {
    if (isObj(u) && has(u, '__entity')) u = u.__entity;
    if (!isObj(u) || !validType(u.type) || typeof u.id !== 'string') throw new ValueError('malformed entity uid');
    return new Entity(u.type, u.id);
  }

  add(e) {
    if (!isObj(e)) throw new ValueError('an entity must be an object');
    const uid = Store.uid(e.uid);
    if (this.attrs.has(uid.k)) throw new ValueError(`duplicate entity ${uid}`);
    const attrs = truthy(e.attrs) ? e.attrs : obj();
    if (!isObj(attrs)) throw new ValueError(`${uid}: attrs must be an object`);
    const rec = obj();
    for (const k of Object.keys(attrs)) rec[k] = fromJson(attrs[k]);
    const parents = [];
    if (truthy(e.parents)) {
      if (!Array.isArray(e.parents)) throw new ValueError(`${uid}: parents must be a list`);
      for (const p of e.parents) parents.push(Store.uid(p));
    }
    this.attrs.set(uid.k, rec);
    this.parents.set(uid.k, parents);
    this._ancestors.clear();
    return uid;
  }

  /** A store with request-scoped entities added. The base is not changed. */
  overlay(extra) {
    const s = new Store();
    s.attrs = new Map(this.attrs);
    s.parents = new Map(this.parents);
    for (const e of extra) s.add(e);
    return s;
  }

  /** A store in which `uid` has exactly these parents (and its stored
   * attributes, if any). Used for live group membership carried by a token. */
  withParents(uid, parents) {
    const s = new Store();
    s.attrs = new Map(this.attrs);
    s.parents = new Map(this.parents);
    if (!s.attrs.has(uid.k)) s.attrs.set(uid.k, obj());
    s.parents.set(uid.k, [...parents]);
    return s;
  }

  has(uid) {
    return this.attrs.has(uid.k);
  }

  /** Set of entity keys. */
  ancestors(uid) {
    let got = this._ancestors.get(uid.k);
    if (got === undefined) {
      got = new Set();
      const stack = [...(this.parents.get(uid.k) ?? [])];
      while (stack.length) {
        const p = stack.pop();
        if (!got.has(p.k)) {
          got.add(p.k);
          const more = this.parents.get(p.k);
          if (more) stack.push(...more);
        }
      }
      this._ancestors.set(uid.k, got);
    }
    return got;
  }

  isIn(child, ancestor) {
    return child.k === ancestor.k || this.ancestors(child).has(ancestor.k);
  }
}

// ---- loading: reject anything outside the subset ---------------------------

function entityLit(e) {
  if (isObj(e) && has(e, '__entity')) e = e.__entity;
  if (!isObj(e) || !validType(e.type) || typeof e.id !== 'string') throw new Unsupported('malformed entity in policy scope');
  return new Entity(e.type, e.id);
}

function checkExpr(e, depth) {
  if (depth > 400) throw new Unsupported('expression is nested too deeply');
  if (!isObj(e) || Object.keys(e).length !== 1) throw new Unsupported('malformed expression');
  const op = Object.keys(e)[0];
  const arg = e[op];
  const d = depth + 1;
  if (op === 'Value') {
    try {
      fromJson(arg);
    } catch (err) {
      throw new Unsupported(err.message);
    }
    return;
  }
  if (op === 'Var') {
    if (typeof arg !== 'string' || !VARS.has(arg)) throw new Unsupported('unknown variable');
    return;
  }
  if (op === 'Set') {
    if (!Array.isArray(arg)) throw new Unsupported('malformed set literal');
    for (const x of arg) checkExpr(x, d);
    return;
  }
  if (!isObj(arg)) throw new Unsupported(BINARY.has(op) || UNARY.has(op) || ['.', 'has', 'is', 'like', 'if-then-else', 'Record'].includes(op)
    ? `malformed operand of \`${op}\`` : `\`${op}\` is outside the portable Cedar subset`);
  if (BINARY.has(op)) {
    checkExpr(arg.left, d);
    checkExpr(arg.right, d);
  } else if (UNARY.has(op)) {
    checkExpr(arg.arg, d);
  } else if (op === '.' || op === 'has') {
    checkExpr(arg.left, d);
    if (typeof arg.attr !== 'string') throw new Unsupported('attribute name must be a string');
  } else if (op === 'is') {
    checkExpr(arg.left, d);
    if (!validType(arg.entity_type)) throw new Unsupported('malformed entity type in `is`');
    if (has(arg, 'in')) checkExpr(arg.in, d);
  } else if (op === 'like') {
    checkExpr(arg.left, d);
    if (!Array.isArray(arg.pattern)) throw new Unsupported('malformed like pattern');
    for (const part of arg.pattern) {
      if (part !== 'Wildcard' && !(isObj(part) && typeof part.Literal === 'string')) throw new Unsupported('malformed like pattern');
    }
  } else if (op === 'if-then-else') {
    checkExpr(arg.if, d);
    checkExpr(arg.then, d);
    checkExpr(arg.else, d);
  } else if (op === 'Record') {
    for (const k of Object.keys(arg)) checkExpr(arg[k], d);
  } else {
    throw new Unsupported(`\`${op}\` is outside the portable Cedar subset`);
  }
}

function checkScope(scope, what) {
  if (!isObj(scope)) throw new Unsupported(`unsupported ${what} scope`);
  if (has(scope, 'slot')) throw new Unsupported('policy templates are not supported');
  const op = scope.op;
  if (op === 'All') return;
  if (op === '==') {
    entityLit(scope.entity);
  } else if (op === 'in') {
    if (has(scope, 'entities')) {
      if (what !== 'action') throw new Unsupported(`${what} scope cannot use a list`);
      if (!Array.isArray(scope.entities)) throw new Unsupported('malformed action list');
      for (const x of scope.entities) entityLit(x);
    } else entityLit(scope.entity);
  } else if (op === 'is' && what !== 'action') {
    if (!validType(scope.entity_type)) throw new Unsupported('malformed entity type in scope');
    if (has(scope, 'in')) {
      if (!isObj(scope.in)) throw new Unsupported('malformed `is ... in` scope');
      entityLit(scope.in.entity);
    }
  } else {
    throw new Unsupported(`unsupported ${what} scope`);
  }
}

/** One policy in Cedar's JSON form. The constructor throws Unsupported for
 * anything outside the portable subset. */
export class Policy {
  constructor(pid, est) {
    try {
      if (!isObj(est)) throw new Unsupported('a policy must be an object');
      if (est.effect !== 'permit' && est.effect !== 'forbid') throw new Unsupported('effect must be permit or forbid');
      for (const what of ['principal', 'action', 'resource']) checkScope(est[what], what);
      const conditions = has(est, 'conditions') ? est.conditions : [];
      if (!Array.isArray(conditions)) throw new Unsupported('conditions must be a list');
      for (const c of conditions) {
        if (!isObj(c) || (c.kind !== 'when' && c.kind !== 'unless')) throw new Unsupported('condition must be when or unless');
        checkExpr(c.body, 0);
      }
      const ann = truthy(est.annotations) ? est.annotations : obj();
      if (!isObj(ann)) throw new Unsupported('annotations must be an object');
      this.id = pid;
      this.permit = est.effect === 'permit';
      this.principal = est.principal;
      this.action = est.action;
      this.resource = est.resource;
      this.conditions = conditions;
      this.annotations = obj();
      for (const k of Object.keys(ann)) this.annotations[k] = ann[k] === null ? '' : ann[k];
    } catch (err) {
      if (err instanceof Unsupported) throw err;
      throw new Unsupported(`malformed policy JSON (${err.message})`);
    }
  }
}

// ---- evaluation ------------------------------------------------------------

export class Env {
  constructor(principal, action, resource, context, store) {
    this.principal = principal;
    this.action = action;
    this.resource = resource;
    this.context = context;
    this.store = store;
  }
}

function bool(v, what) {
  if (typeof v !== 'boolean') throw new EvalError(`${what} must be a boolean`);
  return v;
}

function long(v, what) {
  if (typeof v !== 'bigint') throw new EvalError(`${what} must be a long`);
  return v;
}

function checked(n) {
  if (n < I64_MIN || n > I64_MAX) throw new EvalError('integer overflow');
  return n;
}

function set(v, what) {
  if (!(v instanceof CedarSet)) throw new EvalError(`${what} must be a set`);
  return v;
}

function like(str, pattern) {
  // classic wildcard match with backtracking to the last star; by code point
  const s = Array.from(str);
  let i = 0, j = 0, star = -1, mark = -1;
  while (i < s.length) {
    if (j < pattern.length && pattern[j] !== 'Wildcard' && pattern[j].Literal === s[i]) {
      i++;
      j++;
    } else if (j < pattern.length && pattern[j] === 'Wildcard') {
      star = j;
      mark = i;
      j++;
    } else if (star !== -1) {
      j = star + 1;
      mark++;
      i = mark;
    } else return false;
  }
  while (j < pattern.length && pattern[j] === 'Wildcard') j++;
  return j === pattern.length;
}

export function evaluate(e, env) {
  const op = Object.keys(e)[0];
  const a = e[op];
  switch (op) {
    case 'Value': return fromJson(a);
    case 'Var': return env[a];
    case '&&':
      if (!bool(evaluate(a.left, env), 'left of &&')) return false;
      return bool(evaluate(a.right, env), 'right of &&');
    case '||':
      if (bool(evaluate(a.left, env), 'left of ||')) return true;
      return bool(evaluate(a.right, env), 'right of ||');
    case 'if-then-else':
      return evaluate(bool(evaluate(a.if, env), 'if condition') ? a.then : a.else, env);
    case '!': return !bool(evaluate(a.arg, env), 'operand of !');
    case 'neg': return checked(-long(evaluate(a.arg, env), 'operand of -'));
    case 'isEmpty': return set(evaluate(a.arg, env), 'isEmpty receiver').items.size === 0;
    case '.': {
      const left = evaluate(a.left, env);
      let rec;
      if (left instanceof Entity) {
        rec = env.store.attrs.get(left.k);
        if (rec === undefined) throw new EvalError(`entity ${left} does not exist`);
      } else if (isRecord(left)) rec = left;
      else throw new EvalError('attribute access needs an entity or a record');
      if (!has(rec, a.attr)) throw new EvalError(`no attribute \`${a.attr}\``);
      return rec[a.attr];
    }
    case 'has': {
      const left = evaluate(a.left, env);
      if (left instanceof Entity) {
        const rec = env.store.attrs.get(left.k);
        return rec !== undefined && has(rec, a.attr);
      }
      if (isRecord(left)) return has(left, a.attr);
      throw new EvalError('`has` needs an entity or a record');
    }
    case 'is': {
      const left = evaluate(a.left, env);
      if (!(left instanceof Entity)) throw new EvalError('`is` needs an entity');
      if (left.type !== a.entity_type) return false;
      if (has(a, 'in')) return isIn(left, evaluate(a.in, env), env);
      return true;
    }
    case 'like': {
      const left = evaluate(a.left, env);
      if (typeof left !== 'string') throw new EvalError('`like` needs a string');
      return like(left, a.pattern);
    }
    case 'Set': {
      const out = [];
      for (const x of a) out.push(evaluate(x, env));
      return new CedarSet(out);
    }
    case 'Record': {
      const out = obj();
      for (const k of Object.keys(a)) out[k] = evaluate(a[k], env);
      return out;
    }
    default:
  }
  const left = evaluate(a.left, env);
  const right = evaluate(a.right, env);
  switch (op) {
    case '==': return key(left) === key(right);
    case '!=': return key(left) !== key(right);
    case '<': case '<=': case '>': case '>=': {
      const x = long(left, `left of ${op}`), y = long(right, `right of ${op}`);
      return op === '<' ? x < y : op === '<=' ? x <= y : op === '>' ? x > y : x >= y;
    }
    case '+': case '-': case '*': {
      const x = long(left, `left of ${op}`), y = long(right, `right of ${op}`);
      return checked(op === '+' ? x + y : op === '-' ? x - y : x * y);
    }
    case 'in':
      if (!(left instanceof Entity)) throw new EvalError('left of `in` must be an entity');
      return isIn(left, right, env);
    case 'contains': return set(left, 'contains receiver').items.has(key(right));
    case 'containsAll': {
      const l = set(left, 'containsAll receiver').items;
      for (const k of set(right, 'containsAll argument').items.keys()) if (!l.has(k)) return false;
      return true;
    }
    case 'containsAny': {
      const l = set(left, 'containsAny receiver').items;
      for (const k of set(right, 'containsAny argument').items.keys()) if (l.has(k)) return true;
      return false;
    }
    default: throw new EvalError(`unsupported operator ${op}`);
  }
}

function isIn(left, right, env) {
  if (right instanceof Entity) return env.store.isIn(left, right);
  if (right instanceof CedarSet) {
    for (const x of right.items.values()) {
      if (!(x instanceof Entity)) throw new EvalError('right of `in` must be an entity or a set of entities');
    }
    for (const x of right.items.values()) if (env.store.isIn(left, x)) return true;
    return false;
  }
  throw new EvalError('right of `in` must be an entity or a set of entities');
}

function scopeMatches(scope, who, store) {
  const op = scope.op;
  if (op === 'All') return true;
  if (op === '==') return who.k === entityLit(scope.entity).k;
  if (op === 'in') {
    if (has(scope, 'entities')) {
      for (const x of scope.entities) if (store.isIn(who, entityLit(x))) return true;
      return false;
    }
    return store.isIn(who, entityLit(scope.entity));
  }
  if (who.type !== scope.entity_type) return false; // op === 'is'
  return !has(scope, 'in') || store.isIn(who, entityLit(scope.in.entity));
}

/** True when the policy's scope and every condition hold. Throws EvalError. */
export function applies(p, env) {
  if (!(scopeMatches(p.principal, env.principal, env.store) && scopeMatches(p.action, env.action, env.store)
        && scopeMatches(p.resource, env.resource, env.store))) return false;
  for (const c of p.conditions) {
    const v = bool(evaluate(c.body, env), `\`${c.kind}\` condition`);
    if (v !== (c.kind === 'when')) return false;
  }
  return true;
}

/** Cedar's authorization: {decision, reasons, errors: [[id, message]]}.
 * A satisfied forbid denies. Otherwise a satisfied permit allows. Otherwise deny.
 * `policies` is a Map of id -> Policy. */
export function isAuthorized(policies, env) {
  const permits = [], forbids = [], errors = [];
  for (const pid of [...policies.keys()].sort(cmpCodePoint)) {
    const p = policies.get(pid);
    try {
      if (applies(p, env)) (p.permit ? permits : forbids).push(pid);
    } catch (err) {
      if (!(err instanceof EvalError)) throw err;
      errors.push([pid, err.message]);
    }
  }
  if (forbids.length) return { decision: 'deny', reasons: forbids, errors };
  if (permits.length) return { decision: 'allow', reasons: permits, errors };
  return { decision: 'deny', reasons: [], errors };
}
