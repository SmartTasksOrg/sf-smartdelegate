#!/usr/bin/env bash
# Runs the policy-evaluation cases and the engine conformance vectors of this
# repository against the PHP port. No arguments. Exit status 0 only when
# every case passes.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

if ! command -v php >/dev/null 2>&1; then
    echo "run_conformance.sh: php is not installed" >&2
    exit 1
fi

exec php "$here/bin/smartdelegate-php" conformance "$root/spec/conformance/vectors" "$root/spec/conformance/bundle"
