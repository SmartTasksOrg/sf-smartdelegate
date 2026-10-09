#!/usr/bin/env bash
# Runs every test suite of the repository. A step whose toolchain is missing
# is reported as SKIP, never as PASS. Exit status 1 if any step failed.
#
#   ./test_all.sh              everything (several minutes)
#   ./test_all.sh --quick      only ports/conformance/run.sh: the two shared
#                              suites against every installed port
#   ./test_all.sh --verbose    print each step's whole output, not just its end
#   ./test_all.sh --logs DIR   keep each step's output in DIR
#   ./test_all.sh --live       also the live suites, when present: live/idp/run.sh
#                              (a real Keycloak) and live/run.sh all --quick
#                              (PostgreSQL, upstream services, network
#                              namespaces, load). They start services and may
#                              download; without --live the run is offline.
#                              A live suite that exits 3 could not run and is
#                              a SKIP with the reason it printed.
#
#   required: Python 3.10+ with `cryptography`  (src/sf_smartdelegate, the reference)
#   optional: JDK 17+ (ports/java), Node 18+ (ports/node, ports/js), Go 1.21+
#             (ports/go), PHP 8.1+ with sodium (ports/php), Rust 1.89+
#             (ports/rust) and a C compiler (its C ABI check)
#
# Build output goes to temporary directories or to a port's ignored build
# directory (ports/java/build, ports/rust/target); state and keys only to
# temporary directories.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(pwd)"

QUICK=0; VERBOSE=0; KEEP_LOGS=""; LIVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --verbose|-v) VERBOSE=1 ;;
    --live) LIVE=1 ;;
    --logs) shift; [ $# -gt 0 ] || { echo "test_all.sh: --logs needs a directory" >&2; exit 2; }; KEEP_LOGS="$1" ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "test_all.sh: unknown option '$1' (try --help)" >&2; exit 2 ;;
  esac
  shift
done

if [ "$QUICK" = 1 ]; then
  exec "$ROOT/ports/conformance/run.sh"
fi

PASS=(); FAIL=(); SKIP=()
have() { command -v "$1" >/dev/null 2>&1; }
PY=python3; have python3 || PY=python
have "$PY" || { echo "Python is required: it is the reference implementation."; exit 1; }
"$PY" -c "import cryptography" 2>/dev/null || { echo "Install the one dependency first (the cryptography package, with pip)."; exit 1; }
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export GOTOOLCHAIN="${GOTOOLCHAIN:-local}"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/smartdelegate-test-all.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
if [ -n "$KEEP_LOGS" ]; then mkdir -p "$KEEP_LOGS" && LOGS="$(cd "$KEEP_LOGS" && pwd)" || exit 2; else LOGS="$TMP/logs"; mkdir -p "$LOGS"; fi
STEP_LIMIT="${SMARTDELEGATE_STEP_TIMEOUT:-2400}"   # seconds per step
N=0

RUST_BIN="$ROOT/ports/rust/target/release/smartdelegate"
RUST_CLI="[\"$RUST_BIN\"]"
export ROOT PY TMP RUST_CLI

# The steps that are more than one command. They are exported so that a step
# can run in a child shell under `timeout`.
in_dir() { local dir="$1"; shift; cd "$ROOT/$dir" && "$@"; }   # in_dir <dir relative to the repository> <command...>
go_tests() { cd "$ROOT/ports/go" && go vet ./... && go test ./...; }
js_client() { cd "$ROOT/ports/js" && node --test test/*.test.mjs; }   # SMARTDELEGATE_CLI selects the daemon
rust_daemon_and_proxies() { cd "$ROOT/tests" && SMARTDELEGATE_TEST_CLI="$RUST_CLI" "$PY" -m unittest -v test_proxies test_conformance.DaemonConformance; }
c_abi() {
  cd "$ROOT/ports/rust" &&
  cc -Wall -Wextra -I core/include c/conformance.c -L target/release -lsmartdelegate_core -o "$TMP/c-abi-conformance" &&
  mkdir -p "$TMP/c-abi-scratch" &&
  LD_LIBRARY_PATH="$ROOT/ports/rust/target/release" DYLD_LIBRARY_PATH="$ROOT/ports/rust/target/release" "$TMP/c-abi-conformance" "$ROOT" "$TMP/c-abi-scratch"
}
# daemon_conformance <cli as a JSON array>: the reference's daemon test against another port's command line
daemon_conformance() { cd "$ROOT/tests" && SMARTDELEGATE_TEST_CLI="$1" "$PY" -m unittest test_conformance.DaemonConformance; }
go_daemon() {
  (cd "$ROOT/ports/go" && GOFLAGS="${GOFLAGS:--buildvcs=false}" go build -o "$TMP/smartdelegate-go" ./cmd/smartdelegate-go) &&
  daemon_conformance "[\"$TMP/smartdelegate-go\"]"
}
# the scenario harness (harness/README.md): the example company's policy tests, then every
# scenario four times on the reference engine
scenario_harness() {
  cd "$ROOT" &&
  "$PY" -m sf_smartdelegate policy test --bundle "$ROOT/examples/company" &&
  "$PY" -m harness run --scenarios all --instances 24 --seed 1 --out "$TMP/harness-report"
}
# the Java launcher needs build/smartdelegate.jar: build it again in case the Java port's own step did not get that far
java_daemon() { "$ROOT/ports/java/build.sh" && daemon_conformance "[\"$ROOT/ports/java/bin/smartdelegate-java\"]"; }
export -f in_dir go_tests js_client rust_daemon_and_proxies c_abi daemon_conformance go_daemon java_daemon scenario_harness

# run "<name>" <command...>: the command runs in a child shell, with a time
# limit where `timeout` exists; its output goes to a log, of which the end is
# shown (all of it with --verbose, the last 40 lines when it failed).
run() {
  local name="$1" log status; shift
  N=$((N + 1)); log="$LOGS/$(printf '%02d' "$N").log"
  echo; echo "=== $name"
  if have timeout; then timeout "$STEP_LIMIT" bash -c '"$@"' run "$@" > "$log" 2>&1
  else bash -c '"$@"' run "$@" > "$log" 2>&1; fi
  status=$?
  if [ "$status" = 0 ]; then
    PASS+=("$name")
    if [ "$VERBOSE" = 1 ]; then cat "$log"; else tail -n 6 "$log"; fi
  elif [ "$status" = 3 ] && [ "${EXIT_3_IS_SKIP:-0}" = 1 ]; then
    # the live runners exit 3 when nothing could run; the reason is what they printed
    local reason
    reason="$(grep -E 'SKIP' "$log" | sed -E 's/^[[:space:]]+//' | tr '\n' ' ' | cut -c1-400)"
    [ -n "$reason" ] || reason="$(tail -n 1 "$log")"
    SKIP+=("$name: exit 3, nothing ran: ${reason% }")
    if [ "$VERBOSE" = 1 ]; then cat "$log"; else tail -n 12 "$log"; fi
  else
    FAIL+=("$name (exit $status)")
    if [ "$VERBOSE" = 1 ]; then cat "$log"; else tail -n 40 "$log"; fi
  fi
}
skip() { SKIP+=("$1"); }
# Tests that a suite skipped by itself (an optional dependency is missing) are
# listed as SKIP lines too, so that a PASS does not hide them.
# unittest_skips <label>: reads the `unittest -v` output of the step that just ran
unittest_skips() {
  local line
  while IFS= read -r line; do
    [ -n "$line" ] && skip "$1: $line"
  done < <(sed -n -E "s/^.* \.\.\. skipped ['\"](.*)['\"]\$/\1/p" "$LOGS/$(printf '%02d' "$N").log" | sort | uniq -c | sed -E 's/^ *([0-9]+) (.*)$/\1 test(s) skipped by the suite: \2/')
}
# node_skips <label>: reads the `# skipped N` line of node --test
node_skips() {
  local n
  n="$(sed -n -E 's/^# skipped ([0-9]+)$/\1/p' "$LOGS/$(printf '%02d' "$N").log" | tail -n 1)"
  [ -n "$n" ] && [ "$n" != 0 ] && skip "$1: $n test(s) skipped by the suite (see its output with --verbose)"
  return 0
}

# ---- Rust first: the Python suite runs its cross-port tests (tests/test_interop.py) against the binary
if have cargo; then
  run "rust port: build" in_dir ports/rust cargo build --release
else
  skip "rust port (no cargo): build, cargo tests, daemon and proxy tests, C ABI check, JavaScript client against the Rust daemon"
  [ -x "$RUST_BIN" ] || skip "python: tests/test_interop.py, the reference against the Rust port (no Rust binary)"
fi

# ---- the reference
run "python (reference): unit tests: evaluator vs real Cedar's answers, conformance, engine, strictness, proxies, SQL guard, interop with Rust" \
  in_dir tests "$PY" -m unittest -v
unittest_skips "python (reference)"
run "python (reference): bundle policy tests" "$PY" -m sf_smartdelegate policy test --bundle "$ROOT/spec/conformance/bundle"
run "scenario harness (harness/): example company policy tests, 24 scenario instances on the reference engine" scenario_harness

# ---- each port's own full suite
if have javac && have java; then
  run "java port: eval, conformance, interop with the reference, strictness, REST client" env PYTHON="$PY" "$ROOT/ports/java/run_conformance.sh"
else skip "java port (no javac / java)"; fi

if have node; then
  if have npm; then run "node port: npm test" in_dir ports/node npm test
  else run "node port: node --test test/" in_dir ports/node node --test test/; fi
  node_skips "node port"
else skip "node port (no node)"; fi

if have go; then
  run "go port: go vet, go test" go_tests
else skip "go port (no go)"; fi

if have php; then
  run "php port: test/run.php" in_dir ports/php php test/run.php
else skip "php port (no php)"; fi

if have cargo && [ -x "$RUST_BIN" ]; then
  run "rust port: cargo test (conformance, eval cases re-checked against real Cedar, strictness)" in_dir ports/rust cargo test --release
  run "rust port: daemon, HTTP proxy and MCP proxy (the reference's tests against the Rust binary)" rust_daemon_and_proxies
  unittest_skips "rust port: daemon and proxies"
  if have cc; then run "rust port: C ABI" c_abi
  else skip "rust port: C ABI (no C compiler)"; fi
fi

# ---- the REST-only JavaScript client
if have node; then
  run "javascript client (ports/js) against the reference daemon" js_client
  node_skips "javascript client"
  if have cargo && [ -x "$RUST_BIN" ]; then
    run "javascript client (ports/js) against the rust daemon" env SMARTDELEGATE_CLI="$RUST_CLI" bash -c js_client
  fi
else skip "javascript client (no node)"; fi

# ---- the reference's daemon conformance test against the other daemons
if have node; then
  run "node daemon: the reference's DaemonConformance" daemon_conformance "[\"node\", \"$ROOT/ports/node/bin/cli.mjs\"]"
else skip "node daemon: the reference's DaemonConformance (no node)"; fi
if have go; then
  run "go daemon: the reference's DaemonConformance (binary built in a temporary directory)" go_daemon
else skip "go daemon: the reference's DaemonConformance (no go)"; fi
if have javac && have java && have jar; then
  run "java daemon: the reference's DaemonConformance" java_daemon
else skip "java daemon: the reference's DaemonConformance (no JDK)"; fi
if have php; then
  run "php daemon: the reference's DaemonConformance" daemon_conformance "[\"php\", \"$ROOT/ports/php/bin/smartdelegate-php\"]"
else skip "php daemon: the reference's DaemonConformance (no php)"; fi

# ---- all ports against each other
run "cross-port matrix (ports/conformance/matrix.py): tokens, sub-agents, tampering, signed bundles, audit logs, shared state directory" \
  "$PY" "$ROOT/ports/conformance/matrix.py"

# ---- live suites: real services, only with --live
if [ "$LIVE" = 1 ]; then
  if [ -f "$ROOT/live/idp/run.sh" ]; then
    EXIT_3_IS_SKIP=1 run "live: identity provider (live/idp/run.sh, a real Keycloak)" bash "$ROOT/live/idp/run.sh"
  else skip "live: identity provider (live/idp/run.sh is not in this checkout)"; fi
  if [ -f "$ROOT/live/run.sh" ]; then
    EXIT_3_IS_SKIP=1 run "live: upstream, boundary, load (live/run.sh all --quick)" bash "$ROOT/live/run.sh" all --quick
  else skip "live: upstream, boundary, load (live/run.sh is not in this checkout)"; fi
else
  skip "live suites (live/idp/run.sh, live/run.sh): not requested, pass --live"
fi

echo; echo "================ summary"
for n in "${PASS[@]:-}"; do [ -n "$n" ] && echo "  PASS  $n"; done
for n in "${SKIP[@]:-}"; do [ -n "$n" ] && echo "  SKIP  $n"; done
for n in "${FAIL[@]:-}"; do [ -n "$n" ] && echo "  FAIL  $n"; done
echo "  pass=${#PASS[@]} skip=${#SKIP[@]} fail=${#FAIL[@]}"
[ -n "$KEEP_LOGS" ] && echo "  logs: $LOGS"
[ ${#FAIL[@]} -eq 0 ]
