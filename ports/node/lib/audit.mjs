// Append-only, hash-chained decision log (JSON Lines).
//
// record.hash = sha256(prev_hash + canonical_json(record without "hash")).
// Editing, deleting or reordering any line breaks every hash after it.
// Truncating the tail is only detectable against a head hash kept elsewhere.
import { closeSync, existsSync, fstatSync, openSync, readFileSync, readSync, statSync, writeSync } from 'node:fs';
import { canonInternal, decodeUtf8, sha256Hex, utf8 } from './canon.mjs';
import { EngineError } from './errors.mjs';
import { has, isInt, isObj, obj, parse } from './json.mjs';

export const GENESIS = '0'.repeat(64);

const BLANK = /^\s*$/;

/** Recompute the whole chain. Throws audit_broken naming the first bad line.
 * Returns {ok, records (BigInt), head}. */
export function verify(path) {
  let text;
  try {
    text = readFileSync(path);
  } catch (e) {
    throw new EngineError('audit_io', `cannot read audit log: ${e.code ?? e.message}`);
  }
  try {
    text = decodeUtf8(text);
  } catch {
    throw new EngineError('audit_broken', 'the audit log is not UTF-8');
  }
  let prev = GENESIS, n = 0n, lineno = 0;
  // a record ends at "\n" and nowhere else: U+2028 and friends are data
  for (const line of text.split('\n')) {
    lineno++;
    if (BLANK.test(line)) continue;
    let rec;
    try {
      rec = parse(line);
      if (!isObj(rec)) throw new Error('not an object');
    } catch {
      throw new EngineError('audit_broken', `line ${lineno}: not JSON`);
    }
    const claimed = has(rec, 'hash') ? rec.hash : '';
    delete rec.hash;
    if (rec.prev !== prev) throw new EngineError('audit_broken', `line ${lineno}: prev hash does not match the line before`);
    // eslint-disable-next-line eqeqeq
    if (!((isInt(rec.seq) || typeof rec.seq === 'number') && rec.seq == n + 1n)) {
      throw new EngineError('audit_broken', `line ${lineno}: sequence number is not ${n + 1n}`);
    }
    if (sha256Hex(prev + canonInternal(rec)) !== claimed) throw new EngineError('audit_broken', `line ${lineno}: content does not match its hash`);
    prev = claimed;
    n += 1n;
  }
  return { ok: true, records: n, head: prev };
}

/** The last `n` records (internal model). Lines that are not JSON are skipped. */
export function tail(path, n) {
  if (!existsSync(path)) return [];
  const lines = readFileSync(path).toString('utf8').split('\n').filter((l) => !BLANK.test(l));
  const count = Number(n);
  const out = [];
  for (const l of lines.slice(Math.max(0, lines.length - count))) {
    try {
      out.push(parse(l));
    } catch {
      // skipped, as in the reference
    }
  }
  return out;
}

export class AuditLog {
  constructor(path) {
    this.path = path;
    this.seq = 0n;
    this.head = GENESIS;
    if (existsSync(path)) {
      const v = verify(path);
      this.seq = v.records;
      this.head = v.head;
    }
    this.len = existsSync(path) ? statSync(path).size : 0;
  }

  /** Chain onto the last record if another process appended. The engine holds
   * the state-directory lock while this runs. */
  _resync() {
    let size = 0;
    try {
      size = statSync(this.path).size;
    } catch {
      size = 0;
    }
    if (size === this.len) return;
    if (size === 0) throw new EngineError('audit_broken', 'the audit log was truncated while in use');
    let lines;
    try {
      const start = Math.max(0, size - (1 << 20));
      const buf = Buffer.alloc(size - start);
      const fd = openSync(this.path, 'r');
      let got = 0;
      try {
        while (got < buf.length) {
          const r = readSync(fd, buf, got, buf.length - got, start + got);
          if (r === 0) break;
          got += r;
        }
      } finally {
        closeSync(fd);
      }
      lines = buf.subarray(0, got).toString('utf8').split('\n').filter((l) => !BLANK.test(l));
    } catch (e) {
      throw new EngineError('audit_io', `cannot read audit log: ${e.code ?? e.message}`);
    }
    try {
      const last = parse(lines[lines.length - 1]);
      if (!isInt(last.seq) || typeof last.hash !== 'string') throw new Error('malformed');
      this.seq = last.seq;
      this.head = last.hash;
      this.len = size;
    } catch {
      throw new EngineError('audit_broken', 'the last audit record is unreadable');
    }
  }

  /** `record` is in the internal model; `ts` is a BigInt. Returns the hash. */
  append(record, ts) {
    this._resync();
    const rec = obj();
    for (const k of Object.keys(record)) if (k !== 'hash') rec[k] = record[k];
    rec.seq = this.seq + 1n;
    rec.ts = ts;
    rec.prev = this.head;
    const h = sha256Hex(this.head + canonInternal(rec));
    rec.hash = h;
    const line = utf8(canonInternal(rec) + '\n');
    try {
      const fd = openSync(this.path, 'a');
      try {
        let off = 0;
        while (off < line.length) off += writeSync(fd, line, off, line.length - off);
        this.len = fstatSync(fd).size;
      } finally {
        closeSync(fd);
      }
    } catch (e) {
      throw new EngineError('audit_io', `cannot write audit log: ${e.code ?? e.message}`);
    }
    this.seq += 1n;
    this.head = h;
    return h;
  }
}
