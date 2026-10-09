#!/usr/bin/env bash
# Runs the policy evaluation cases and the engine conformance vectors of the
# repository against the Node.js port. Exits non-zero on any failure.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
if ! command -v node >/dev/null 2>&1; then
  echo "run_conformance.sh: node is not installed" >&2
  exit 1
fi
exec node "$HERE/bin/cli.mjs" conformance "$ROOT/spec/conformance/vectors" "$ROOT/spec/conformance/bundle"
