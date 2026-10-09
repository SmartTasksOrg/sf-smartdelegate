// Mutable engine state: revocations, approvals, spend ledger.
//
// One JSON file in the state directory. The engine holds the state-directory
// lock for every operation and re-reads the file at the start of each one, so
// processes sharing a directory see each other's changes on the next call.
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeUtf8 } from './canon.mjs';
import { EngineError } from './errors.mjs';
import { isInt, isObj, obj, parse, write } from './json.mjs';

const KEYS = ['revoked', 'approvals', 'pending', 'ledger', 'limits', 'revoked_users'];

function empty() {
  const d = obj();
  for (const k of KEYS) d[k] = obj();
  return d;
}

/** An integer read from the state file; anything else is a corrupt file. */
export function int(v) {
  if (!isInt(v)) throw new EngineError('state_io', 'state.json is corrupt: expected an integer');
  return v;
}

export class State {
  constructor(dir) {
    this.path = dir ? join(dir, 'state.json') : null;
    this.raw = '';
    this.data = empty();
    this.refresh();
  }

  refresh() {
    if (!this.path || !existsSync(this.path)) return;
    let text;
    try {
      text = decodeUtf8(readFileSync(this.path));
    } catch (e) {
      throw new EngineError('state_io', e.message);
    }
    if (text === this.raw) return;
    let data;
    try {
      data = parse(text);
      if (!isObj(data)) throw new Error('not an object');
      for (const k of KEYS) {
        if (!(k in data)) data[k] = obj();
        if (!isObj(data[k])) throw new Error('not an object');
      }
    } catch {
      // an unreadable state file must not silently drop revocations
      throw new EngineError('state_io', 'state.json is corrupt');
    }
    this.data = data;
    this.raw = text;
  }

  save() {
    if (!this.path) return;
    const text = write(this.data, { ascii: true });
    const tmp = this.path + '.tmp';
    try {
      writeFileSync(tmp, text, 'utf8');
      renameSync(tmp, this.path);
    } catch (e) {
      throw new EngineError('state_io', e.message);
    }
    this.raw = text;
  }

  prune(now) {
    const d = this.data;
    const keep = (m, pred) => {
      const out = obj();
      for (const k of Object.keys(m)) if (pred(m[k])) out[k] = m[k];
      return out;
    };
    d.revoked = keep(d.revoked, (v) => int(v) + 86400n > now);
    d.approvals = keep(d.approvals, (v) => int(isObj(v) ? v.exp : undefined) > now);
    d.pending = keep(d.pending, (v) => int(isObj(v) ? v.requested_at : undefined) + 86400n > now);
  }
}
