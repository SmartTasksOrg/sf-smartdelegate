// Makes `node --test test/` (the package's test script) work on every
// supported Node.js version.
//
// Node 18 and 20 take a directory and run every file in it, each in its own
// process; this file is then just one of them and does nothing. From Node 22
// on the argument is a path or a glob, and `test/` resolves to this file,
// which loads all the test files into one process.
// (`node --test test/*.test.mjs` runs one process per file on every version.)
import { readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const entry = process.argv[1] ? resolve(process.argv[1]) : '';
let asDirectory = false;
try {
  asDirectory = entry === here && statSync(entry).isDirectory();
} catch {
  asDirectory = false;
}
if (asDirectory) {
  for (const f of readdirSync(here).filter((n) => n.endsWith('.test.mjs')).sort()) {
    await import(pathToFileURL(join(here, f)).href);
  }
}
