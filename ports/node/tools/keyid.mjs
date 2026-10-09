// Test helper: open an engine on a state directory and print its key id.
//   node keyid.mjs <state dir> <bundle dir>
import { Engine } from '../lib/index.mjs';

const engine = new Engine({ bundle_dir: process.argv[3], state_dir: process.argv[2] });
process.stdout.write(engine.info().key_id + '\n');
engine.close();
