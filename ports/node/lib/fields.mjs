// Applying a field mask and a row filter to JSON data.
//
// Field paths are relative to the resource: `email`, `address.zip`,
// `orders[].total`. `[]` stands for "each element of this array".
//
// Rules (fail closed):
//   * a denied path is dropped, or replaced by "[REDACTED]" when the catalog
//     says `mask: redact`; its whole subtree goes with it
//   * an allowed path is kept; children that have their own catalog entry are
//     still checked one by one, other children are kept with the parent
//   * a path the catalog does not list, under no allowed parent, is dropped
import { ORDER, cmpCodePoint, has, isObj, jsonEq, keysOf, obj, setOrder } from './json.mjs';

export const REDACTED = '[REDACTED]';
export const ALLOW = 'allow', DENY = 'deny', REDACT = 'redact';

export class Mask {
  /** status: Map of path -> ALLOW | DENY | REDACT */
  constructor(status) {
    this.status = status;
  }

  hasChildren(path) {
    const a = path + '.', b = path + '[]';
    for (const k of this.status.keys()) if (k.startsWith(a) || k.startsWith(b)) return true;
    return false;
  }
}

const KEEP = 0, DROP = 1;
const container = (v) => v !== null && typeof v === 'object';

/** Returns [KEEP | DROP, value]. */
function walkValue(v, path, inherit, mask, masked) {
  if (isObj(v)) return [KEEP, walkObject(v, path, inherit, mask, masked)];
  if (Array.isArray(v)) {
    const p = path + '[]';
    const st = mask.status.get(p);
    const out = [];
    for (const el of v) {
      if (st === DENY) masked.add(p);
      else if (st === REDACT) {
        masked.add(p);
        out.push(REDACTED);
      } else if (st === ALLOW) {
        const [drop, x] = walkValue(el, p, true, mask, masked);
        if (!drop) out.push(x);
      } else if (container(el)) {
        const [drop, x] = walkValue(el, p, inherit, mask, masked);
        if (!drop) out.push(x);
      } else if (inherit) out.push(el);
      else masked.add(p);
    }
    return [KEEP, out];
  }
  return inherit ? [KEEP, v] : [DROP, null];
}

function walkObject(m, prefix, inherit, mask, masked) {
  const out = obj();
  const keys = keysOf(m);
  for (const k of keys) {
    const v = m[k];
    const p = prefix ? `${prefix}.${k}` : k;
    const st = mask.status.get(p);
    if (st === DENY) masked.add(p);
    else if (st === REDACT) {
      masked.add(p);
      out[k] = REDACTED;
    } else if (st === ALLOW) {
      if (mask.hasChildren(p)) {
        const [drop, x] = walkValue(v, p, true, mask, masked);
        if (!drop) out[k] = x;
      } else out[k] = v;
    } else if (inherit && !mask.hasChildren(p)) out[k] = v;
    else if (container(v) && mask.hasChildren(p)) {
      const [drop, x] = walkValue(v, p, inherit, mask, masked);
      if (!drop) out[k] = x;
    } else if (inherit) out[k] = v;
    else masked.add(p);
  }
  // keep the written member order where JavaScript would not (see json.mjs)
  if (m[ORDER] !== undefined) setOrder(out, keys.filter((k) => has(out, k)));
  return out;
}

function kind(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;   // bigint (integer), number (float), string, boolean, object
}

// JSON equality: true is not 1, and the integer 1 is not the float 1.0
const same = (a, b) => kind(a) === kind(b) && jsonEq(a, b);

function rowMatches(row, rowFilter) {
  for (const c of rowFilter) {
    const col = c.column;
    if (!(isObj(row) && typeof col === 'string' && has(row, col) && same(row[col], c.value === undefined ? null : c.value))) return false;
  }
  return true;
}

/** `data` is one record or a list of records. Returns [data, masked paths, rows dropped]. */
export function apply(data, mask, rowFilter) {
  const masked = new Set();
  let dropped = 0, out;
  if (Array.isArray(data)) {
    out = [];
    for (const r of data) {
      if (isObj(r) && rowMatches(r, rowFilter)) out.push(walkObject(r, '', false, mask, masked));
      else dropped++;
    }
  } else if (isObj(data)) {
    if (rowMatches(data, rowFilter)) out = walkObject(data, '', false, mask, masked);
    else {
      out = null;
      dropped = 1;
    }
  } else {
    // a bare scalar has no field identity, so nothing can authorise it
    out = null;
    dropped = 1;
  }
  return [out, [...masked].sort(cmpCodePoint), dropped];
}
