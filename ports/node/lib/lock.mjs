// Exclusive lock on a state directory, between Node.js processes.
//
// Node has no flock(), so this is NOT the lock the Python and Rust ports use:
// a state directory must not be used by this port and another port at the
// same time.
//
// The lock is the file `<state>/lock.node`, created with O_EXCL and removed on
// release. It holds "<pid> <process start time> <nonce>". A waiter that finds
// the holder gone (no such process, or a process with that pid but a
// different start time) removes the lock and takes it. Without /proc the
// start time is not available and only the pid is checked; a lock older than
// `staleMs` is then taken over as a last resort.
import { closeSync, mkdirSync, openSync, readFileSync, rmdirSync, statSync, unlinkSync, writeSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { EngineError } from './errors.mjs';

const SLEEP = new Int32Array(new SharedArrayBuffer(4));
/** Block this thread for `ms` milliseconds. */
export const sleep = (ms) => { Atomics.wait(SLEEP, 0, 0, ms); };

/** Start time of a process from /proc (Linux), null when there is no such
 * process, undefined when /proc is not available. */
function procStart(pid) {
  let stat;
  try {
    stat = readFileSync(`/proc/${pid}/stat`, 'latin1');
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ESRCH') return HAVE_PROC ? null : undefined;
    return undefined;
  }
  // "pid (comm) state ppid ... starttime ..."; comm may contain spaces and ')'
  const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  return rest[19] ?? undefined;
}

let HAVE_PROC = false;
try {
  readFileSync('/proc/self/stat');
  HAVE_PROC = true;
} catch {
  HAVE_PROC = false;
}
const MY_START = HAVE_PROC ? procStart(process.pid) ?? '-' : '-';

function alive(pid, start) {
  if (HAVE_PROC && start !== '-') {
    const s = procStart(pid);
    if (s === null) return false;
    if (s !== undefined) return s === start;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

export class DirLock {
  constructor(dir, { timeoutMs = 30000, staleMs = 600000 } = {}) {
    this.path = join(dir, 'lock.node');
    this.timeoutMs = timeoutMs;
    this.staleMs = staleMs;
    this.held = false;
  }

  acquire() {
    const deadline = Date.now() + this.timeoutMs;
    let delay = 1, nextCheck = 0;
    for (;;) {
      let fd;
      try {
        fd = openSync(this.path, 'wx', 0o600);
      } catch (e) {
        if (e.code !== 'EEXIST') throw new EngineError('state_io', `cannot lock the state directory: ${e.message}`);
        fd = -1;
      }
      if (fd >= 0) {
        try {
          writeSync(fd, `${process.pid} ${MY_START} ${randomBytes(6).toString('hex')}\n`);
        } finally {
          closeSync(fd);
        }
        this.held = true;
        return;
      }
      const now = Date.now();
      if (now >= nextCheck) {
        nextCheck = now + 50;
        const stale = this._stale();
        if (stale !== null) {
          this._remove(stale);
          continue;
        }
      }
      if (now > deadline) throw new EngineError('state_io', `cannot lock the state directory: ${this.path} is held by another process`);
      sleep(delay);
      delay = Math.min(delay * 2, 8) + Math.random();
    }
  }

  release() {
    if (!this.held) return;
    this.held = false;
    try {
      unlinkSync(this.path);
    } catch (e) {
      if (e.code !== 'ENOENT') throw new EngineError('state_io', `cannot unlock the state directory: ${e.message}`);
    }
  }

  /** The content of the lock file when its holder is gone, else null. */
  _stale() {
    let text, age;
    try {
      text = readFileSync(this.path, 'latin1');
      age = Date.now() - statSync(this.path).mtimeMs;
    } catch {
      return null;   // released in the meantime
    }
    const m = /^(\d+) (\S+) \S+\n$/.exec(text);
    // no content yet: the holder is between creating and writing, or died there
    if (!m) return age > 5000 ? text : null;
    if (!alive(Number(m[1]), m[2])) return text;
    return age > this.staleMs ? text : null;
  }

  /** Remove a stale lock. Stealers are serialised by a guard directory and
   * re-check under it, so a lock that was just taken by someone else is not
   * removed by mistake. */
  _remove(text) {
    const guard = this.path + '.steal';
    try {
      mkdirSync(guard);
    } catch (e) {
      if (e.code !== 'EEXIST') throw new EngineError('state_io', `cannot lock the state directory: ${e.message}`);
      try {
        if (Date.now() - statSync(guard).mtimeMs > 10000) rmdirSync(guard);
      } catch {
        // someone else cleaned up
      }
      sleep(1);
      return;
    }
    try {
      let cur;
      try {
        cur = readFileSync(this.path, 'latin1');
      } catch {
        return;
      }
      if (cur === text) {
        try {
          unlinkSync(this.path);
        } catch {
          // already gone
        }
      }
    } finally {
      try {
        rmdirSync(guard);
      } catch {
        // already gone
      }
    }
  }
}
