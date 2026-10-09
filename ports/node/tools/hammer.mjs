// Test helper: one process doing engine calls on a shared state directory.
//   node hammer.mjs <state dir> <bundle dir> <count> <shared token>
// Prints one JSON line: {issued, allowed, denied, errors}.
import { Engine } from '../lib/index.mjs';

const [stateDir, bundleDir, count, shared] = process.argv.slice(2);
const engine = new Engine({ bundle_dir: bundleDir, state_dir: stateDir, max_depth: 3 });
const out = { issued: 0, allowed: 0, denied: 0, spent: 0, refused: 0, errors: [] };
const t = engine.call('issue_token', { user: 'alice', agent: 'support-bot', cap: { actions: ['read'], resources: ['crm.customer/*'] } });
if (t.ok) out.issued++;
else out.errors.push(t.error);
for (let i = 0; i < Number(count); i++) {
  const d = engine.call('authorize', { token: t.token, action: 'read', resource: { path: 'crm.customer', id: `c-${i}` } });
  if (!d.ok) out.errors.push(d.error);
  else if (d.effect === 'allow') out.allowed++;
  else out.denied++;
  // every process draws on the same token's budget
  const s = engine.call('authorize', { token: shared, action: 'read', resource: { path: 'crm.customer', id: `s-${process.pid}-${i}` },
    context: { spend: { currency: 'EUR', amount: 10 } } });
  if (!s.ok) out.errors.push(s.error);
  else if (s.effect === 'allow') out.spent++;
  else if (s.reason === 'budget_exceeded') out.refused++;
  else out.errors.push({ code: 'unexpected', message: s.reason });
}
engine.close();
process.stdout.write(JSON.stringify(out) + '\n');
