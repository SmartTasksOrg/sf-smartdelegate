#!/usr/bin/env bash
# Runs the policy evaluation cases and the engine conformance vectors against
# the Go port. No arguments. Exit code 0 only when every case passes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$HERE"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"
exec go run ./cmd/smartdelegate-go conformance --root "$ROOT"
