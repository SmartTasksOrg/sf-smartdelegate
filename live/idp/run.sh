#!/usr/bin/env bash
# The whole live identity-provider run: start (or attach) -> provision -> tests -> stop.
#
#   live/idp/run.sh                 run everything
#   live/idp/run.sh --transcript    also rewrite live/idp/TRANSCRIPT.md
#   live/idp/run.sh -k PATTERN      only the tests matching PATTERN (unittest -k)
#
# Attach to an existing Keycloak instead of starting one:
#   SD_KEYCLOAK_URL=https://kc.example SD_KEYCLOAK_ADMIN=admin SD_KEYCLOAK_ADMIN_PASSWORD=... live/idp/run.sh
#
# Exit code: 0 all tests passed, 1 a test failed (or provisioning did),
#            3 skipped: Keycloak could not be obtained, started or reached (the reason is printed).
# The server is stopped at the end only if this script started it.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RUN_TIMEOUT="${SD_LIVE_TIMEOUT:-1800}"

args=()
for a in "$@"; do
  case "$a" in
    --transcript) export SD_LIVE_TRANSCRIPT=1 ;;
    *) args+=("$a") ;;
  esac
done

started=0
finish() {
  code=$?
  if [ "$started" = 1 ] && [ -z "${SD_KEYCLOAK_KEEP:-}" ]; then
    bash "$HERE/keycloak.sh" stop || code=1
  fi
  exit "$code"
}
trap finish EXIT
trap 'exit 1' INT TERM

command -v python3 >/dev/null 2>&1 || { echo "run.sh: SKIPPED: python3 is not installed" >&2; exit 3; }

if [ -n "${SD_KEYCLOAK_URL:-}" ]; then
  bash "$HERE/keycloak.sh" start || { echo "run.sh: SKIPPED: the Keycloak at SD_KEYCLOAK_URL does not answer" >&2; exit 3; }
elif bash "$HERE/keycloak.sh" status >/dev/null 2>&1; then
  echo "run.sh: using the Keycloak that is already running ($(bash "$HERE/keycloak.sh" url)); it will be left running" >&2
else
  bash "$HERE/keycloak.sh" start
  rc=$?
  if [ "$rc" != 0 ]; then
    echo "run.sh: SKIPPED: Keycloak could not be obtained or started (keycloak.sh start exited $rc; the reason is above)" >&2
    exit 3
  fi
  started=1
fi

cd "$ROOT" || exit 1
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

python3 "$HERE/provision.py"
rc=$?
if [ "$rc" = 3 ]; then echo "run.sh: SKIPPED: Keycloak is not reachable for provisioning" >&2; exit 3; fi
if [ "$rc" != 0 ]; then echo "run.sh: FAILED: provisioning the realm failed" >&2; exit 1; fi

# unittest itself reports a skipped module as success; tell the two apart here
timeout "$RUN_TIMEOUT" python3 - "${args[@]+"${args[@]}"}" <<'PY'
import sys
import unittest

argv = sys.argv[1:]
loader = unittest.TestLoader()
if "-k" in argv:
    loader.testNamePatterns = ["*" + argv[argv.index("-k") + 1] + "*"]
suite = loader.loadTestsFromName("live.idp.test_live_idp")
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful():
    sys.exit(1)
if result.testsRun == 0:
    print("run.sh: SKIPPED: " + (result.skipped[0][1] if result.skipped else "no test was selected"), file=sys.stderr)
    sys.exit(3)
print(f"run.sh: PASSED: {result.testsRun} tests against a real Keycloak, {len(result.skipped)} skipped", file=sys.stderr)
PY
rc=$?
if [ "$rc" = 124 ]; then echo "run.sh: FAILED: the tests did not finish within ${RUN_TIMEOUT}s" >&2; exit 1; fi
exit "$rc"
