// Test helper: take the state-directory lock and keep it until killed.
//   node hold_lock.mjs <state dir>
import { DirLock } from '../lib/lock.mjs';

const lock = new DirLock(process.argv[2]);
lock.acquire();
process.stdout.write('held\n');
setInterval(() => {}, 1000);
