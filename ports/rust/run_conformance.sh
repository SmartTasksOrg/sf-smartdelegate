#!/usr/bin/env bash
# Runs the engine conformance vectors and the policy evaluation cases of this
# repository against the Rust port. No arguments.
#
#   1. cargo build --release                      (does nothing when up to date)
#   2. target/release/smartdelegate conformance <spec vectors> <spec bundle>
#   3. cargo test --release -p smartdelegate-core --test conformance
#      (the same vectors in-process, the eval cases re-checked against the
#      real Cedar engine, and policies.json is current with its .cedar sources)
#
# Exit status: 0 when everything passes, 3 when cargo is not installed,
# otherwise the status of the step that failed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "run_conformance.sh: cargo is not installed (the Rust port needs Rust 1.89 or newer)" >&2
  exit 3
fi

cd "$here"
cargo build --release
"$here/target/release/smartdelegate" conformance "$root/spec/conformance/vectors" "$root/spec/conformance/bundle"
cargo test --release -p smartdelegate-core --test conformance -- --nocapture --test-threads=1
echo "rust port: all suites passed"
