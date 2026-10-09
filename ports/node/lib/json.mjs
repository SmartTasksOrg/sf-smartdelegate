// JSON with exact integers.
//
// JavaScript numbers lose integer precision above 2^53, and SmartDelegate
// integers are 64-bit (Cedar longs, budgets, timestamps). Inside this port a
// JSON value is therefore modelled as:
//
//   integer            BigInt   (always; any size)
//   non-integer number Number   (a "float": 1.5, 1.0, 1e3, NaN, Infinity)
//   string / boolean / null     themselves
//   array              Array
//   object             an object with a null prototype (so "__proto__" and
//                      "constructor" are ordinary keys)
//
// `parse` produces that model from text; `write` prints it. `toInternal` and
// `toPlain` convert from and to ordinary JavaScript values at the public API.
// This file has no Node.js dependencies.

export class JSONError extends Error {}

export const MAX_DEPTH = 1000;

export const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
export const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
export const isInt = (v) => typeof v === 'bigint';
export const isStr = (v) => typeof v === 'string';
export const obj = () => Object.create(null);

// JavaScript lists integer-like keys ("10", "9") first, in numeric order,
// whatever order they were written in. `parse` remembers the written order of
// such objects under this symbol and `write` follows it, so that JSON which
// passes through (data echoed by `filter`, token claims) keeps its member
// order on the wire, as it does in the reference.
export const ORDER = Symbol('member order');
const INDEX_KEY = /^(?:0|[1-9][0-9]{0,9})$/;

/** The keys of an object of the internal model, in the order they were written. */
export function keysOf(o) {
  const order = o[ORDER];
  if (order === undefined) return Object.keys(o);
  const out = order.filter((k) => has(o, k));
  if (out.length !== Object.keys(o).length) {
    const seen = new Set(out);
    for (const k of Object.keys(o)) if (!seen.has(k)) out.push(k);
  }
  return out;
}

/** Record the member order of `o` when JavaScript would not keep it. */
export function setOrder(o, keys) {
  if (keys.some((k) => INDEX_KEY.test(k))) Object.defineProperty(o, ORDER, { value: keys, writable: true, configurable: true });
  return o;
}

/** Python truthiness of a JSON value: null, false, 0, "", [] and {} are false. */
export function truthy(v) {
  if (v === null || v === undefined || v === false || v === '' || v === 0n) return false;
  if (typeof v === 'number') return v !== 0;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') { for (const k in v) if (has(v, k)) return true; return false; }
  return true;
}

/** Compare two strings by Unicode code point (JavaScript's default is by UTF-16 unit). */
export function cmpCodePoint(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i), y = b.charCodeAt(i);
    if (x !== y) {
      // a surrogate stands for a code point above U+FFFF, which sorts after U+E000..U+FFFF
      const xs = x >= 0xd800 && x <= 0xdfff, ys = y >= 0xd800 && y <= 0xdfff;
      if (xs !== ys) {
        if (xs && y >= 0xe000) return 1;
        if (ys && x >= 0xe000) return -1;
      }
      return x - y;
    }
  }
  return a.length - b.length;
}

export const sortedKeys = (o) => Object.keys(o).sort(cmpCodePoint);

// ---- parse -------------------------------------------------------------------

const NUMBER = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;
const ESC = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
// eslint-disable-next-line no-control-regex
const NEEDS_SLOW = /[\u0000-\u001f\\]/;

/** Text -> value. Integers of any size become BigInt; numbers written with a
 * fraction or an exponent become Number. Throws JSONError. */
export function parse(text) {
  if (typeof text !== 'string') throw new JSONError('JSON text must be a string');
  const n = text.length;
  let i = 0;
  const fail = (m) => { throw new JSONError(`${m} at position ${i}`); };
  const ws = () => {
    for (; i < n; i++) {
      const c = text.charCodeAt(i);
      if (c !== 32 && c !== 9 && c !== 10 && c !== 13) break;
    }
  };
  const string = () => {
    // text[i] is the opening quote
    const start = i + 1;
    const end = text.indexOf('"', start);
    if (end < 0) fail('unterminated string');
    const fast = text.slice(start, end);
    if (!NEEDS_SLOW.test(fast)) { i = end + 1; return fast; }
    let out = '';
    i = start;
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 34) { i++; return out; }
      if (c < 32) fail('control character in string');
      if (c !== 92) {
        let j = i + 1;
        while (j < n) { const d = text.charCodeAt(j); if (d === 34 || d === 92 || d < 32) break; j++; }
        out += text.slice(i, j);
        i = j;
        continue;
      }
      const e = text[i + 1];
      if (e === 'u') {
        const hex = text.slice(i + 2, i + 6);
        if (!HEX4.test(hex)) fail('bad \\u escape');
        out += String.fromCharCode(parseInt(hex, 16));
        i += 6;
      } else if (e !== undefined && has(ESC, e)) {
        out += ESC[e];
        i += 2;
      } else fail('bad escape');
    }
  };
  const value = (depth) => {
    if (depth > MAX_DEPTH) fail('nested too deeply');
    ws();
    if (i >= n) fail('unexpected end of input');
    const c = text[i];
    if (c === '"') return string();
    if (c === '{') {
      i++;
      const o = obj();
      let order = null;
      ws();
      if (text[i] === '}') { i++; return o; }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('expected a string key');
        const k = string();
        if (order !== null) {
          if (!(k in o)) order.push(k);
        } else if (INDEX_KEY.test(k)) {
          order = Object.keys(o);
          if (!(k in o)) order.push(k);
        }
        ws();
        if (text[i] !== ':') fail("expected ':'");
        i++;
        o[k] = value(depth + 1);
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') {
          i++;
          if (order !== null) Object.defineProperty(o, ORDER, { value: order, writable: true, configurable: true });
          return o;
        }
        fail("expected ',' or '}'");
      }
    }
    if (c === '[') {
      i++;
      const a = [];
      ws();
      if (text[i] === ']') { i++; return a; }
      for (;;) {
        a.push(value(depth + 1));
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return a; }
        fail("expected ',' or ']'");
      }
    }
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    // the reference's parser (Python's json) accepts these three as well
    if (text.startsWith('NaN', i)) { i += 3; return NaN; }
    if (text.startsWith('Infinity', i)) { i += 8; return Infinity; }
    if (text.startsWith('-Infinity', i)) { i += 9; return -Infinity; }
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) fail('unexpected character');
    i = NUMBER.lastIndex;
    return m[1] === undefined && m[2] === undefined ? BigInt(m[0]) : Number(m[0]);
  };
  const v = value(0);
  ws();
  if (i < n) fail('unexpected data after the JSON value');
  return v;
}

// ---- write -------------------------------------------------------------------

// eslint-disable-next-line no-control-regex
const ESCAPE = /[\u0000-\u001f"\\]/g;
// eslint-disable-next-line no-control-regex
const ESCAPE_ASCII = /[\u0000-\u001f"\\]|[^\u0020-\u007e]/g;
const SHORT = { '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t' };
const esc = (c) => SHORT[c] ?? '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0');

export function quote(s, ascii = false) {
  const re = ascii ? ESCAPE_ASCII : ESCAPE;
  re.lastIndex = 0;
  return re.test(s) ? '"' + s.replace(re, esc) + '"' : '"' + s + '"';
}

/** A float the way Python's repr() prints it, so both ports hash the same text. */
export function floatRepr(x) {
  if (Number.isNaN(x)) return 'NaN';
  if (x === Infinity) return 'Infinity';
  if (x === -Infinity) return '-Infinity';
  if (x === 0) return Object.is(x, -0) ? '-0.0' : '0.0';
  const [mant, e] = x.toExponential().split('e');
  const exp = Number(e);
  const sign = mant[0] === '-' ? '-' : '';
  const digits = mant.replace('-', '').replace('.', '');
  if (exp < -4 || exp >= 16) {
    return sign + digits[0] + (digits.length > 1 ? '.' + digits.slice(1) : '') + 'e' + (exp < 0 ? '-' : '+') + String(Math.abs(exp)).padStart(2, '0');
  }
  if (exp < 0) return sign + '0.' + '0'.repeat(-exp - 1) + digits;
  if (digits.length <= exp + 1) return sign + digits.padEnd(exp + 1, '0') + '.0';
  return sign + digits.slice(0, exp + 1) + '.' + digits.slice(exp + 1);
}

/** Value (internal model) -> text.
 * options: sortKeys (by code point), ascii (escape non-ASCII as \uXXXX),
 * indent (spaces; 0 = compact with "," and ":"). */
export function write(value, { sortKeys = false, ascii = false, indent = 0 } = {}) {
  const pad = indent > 0 ? ' '.repeat(indent) : '';
  const colon = indent > 0 ? ': ' : ':';
  const go = (v, depth, cur) => {
    if (v === null) return 'null';
    switch (typeof v) {
      case 'string': return quote(v, ascii);
      case 'bigint': return v.toString();
      case 'boolean': return v ? 'true' : 'false';
      case 'number': return floatRepr(v);
      case 'object': break;
      default: throw new TypeError(`cannot write a ${typeof v} as JSON`);
    }
    if (depth > MAX_DEPTH) throw new RangeError('nested too deeply');
    const inner = cur + pad;
    const open = indent > 0 ? '\n' + inner : '';
    const sep = indent > 0 ? ',\n' + inner : ',';
    const close = indent > 0 ? '\n' + cur : '';
    if (Array.isArray(v)) {
      if (v.length === 0) return '[]';
      let out = '[' + open;
      for (let k = 0; k < v.length; k++) out += (k ? sep : '') + go(v[k], depth + 1, inner);
      return out + close + ']';
    }
    const keys = sortKeys ? sortedKeys(v) : keysOf(v);
    if (keys.length === 0) return '{}';
    let out = '{' + open;
    for (let k = 0; k < keys.length; k++) out += (k ? sep : '') + quote(keys[k], ascii) + colon + go(v[keys[k]], depth + 1, inner);
    return out + close + '}';
  };
  return go(value, 0, '');
}

// ---- conversion at the public API ---------------------------------------------

/** Ordinary JavaScript value -> internal model. Integer-valued Numbers become
 * BigInt (so `{ttl: 300}` means the integer 300); BigInt stays; `undefined`
 * object members are dropped as JSON.stringify would. Throws TypeError for
 * things JSON cannot carry and RangeError when nested too deeply. */
export function toInternal(v, depth = 0) {
  if (v === null || v === undefined) return null;
  switch (typeof v) {
    case 'string': case 'boolean': case 'bigint': return v;
    case 'number': return Number.isInteger(v) ? BigInt(v) : v;
    case 'object': break;
    default: throw new TypeError(`a ${typeof v} is not a JSON value`);
  }
  if (depth > MAX_DEPTH) throw new RangeError('nested too deeply');
  if (Array.isArray(v)) {
    const out = new Array(v.length);
    for (let k = 0; k < v.length; k++) out[k] = toInternal(v[k], depth + 1);
    return out;
  }
  const proto = Object.getPrototypeOf(v);
  if (proto !== null && proto !== Object.prototype) throw new TypeError(`a ${v.constructor?.name ?? 'non-plain'} object is not a JSON value`);
  const out = obj();
  const keys = keysOf(v);
  for (const k of keys) {
    if (v[k] !== undefined) out[k] = toInternal(v[k], depth + 1);
  }
  // a value that came from `parse` keeps its written member order
  if (v[ORDER] !== undefined) setOrder(out, keys.filter((k) => k in out));
  return out;
}

const SAFE_MAX = BigInt(Number.MAX_SAFE_INTEGER), SAFE_MIN = -SAFE_MAX;

/** Internal model -> ordinary JavaScript value: plain objects, and integers as
 * Number when that is exact (|n| <= 2^53 - 1), otherwise BigInt. */
export function toPlain(v) {
  if (typeof v === 'bigint') return v >= SAFE_MIN && v <= SAFE_MAX ? Number(v) : v;
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) {
    const out = new Array(v.length);
    for (let k = 0; k < v.length; k++) out[k] = toPlain(v[k]);
    return out;
  }
  const out = {};
  for (const k of Object.keys(v)) {
    if (k === '__proto__') Object.defineProperty(out, k, { value: toPlain(v[k]), enumerable: true, writable: true, configurable: true });
    else out[k] = toPlain(v[k]);
  }
  return out;
}

/** JSON.stringify for values that may hold BigInt: integer-valued Numbers and
 * BigInts are written as integers, exactly. Same options as `write`. */
export function stringify(value, options) {
  return write(toInternal(value), options);
}

/** Equality of two JSON values the way the reference compares them: numbers by
 * value (1 equals 1.0), everything else by type and content. Accepts the
 * internal model and plain values alike. */
export function jsonEq(a, b) {
  const ta = typeof a, tb = typeof b;
  if ((ta === 'bigint' || ta === 'number') && (tb === 'bigint' || tb === 'number')) {
    // eslint-disable-next-line eqeqeq
    return a == b;
  }
  if (ta !== tb) return false;
  if (a === null || b === null || ta !== 'object') return a === b;
  const aa = Array.isArray(a), ab = Array.isArray(b);
  if (aa !== ab) return false;
  if (aa) {
    if (a.length !== b.length) return false;
    for (let k = 0; k < a.length; k++) if (!jsonEq(a[k], b[k])) return false;
    return true;
  }
  const ka = Object.keys(a);
  if (ka.length !== Object.keys(b).length) return false;
  for (const k of ka) if (!has(b, k) || !jsonEq(a[k], b[k])) return false;
  return true;
}
