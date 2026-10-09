#!/usr/bin/env bash
# Run the live tests and print PASS / FAIL / SKIP per part with a reason.
#
#   live/run.sh [upstream|boundary|load|all] [--quick]
#
# Exit status:
#   0   at least one part ran, and nothing failed
#   1   a part failed
#   3   nothing ran: every part was skipped (each reason is printed)
# A part in which no test ran prints SKIP, never PASS.
#
# A test tied to an open finding (live/FINDINGS.md) is an expected failure. When one starts to
# pass, the line "FIXED? finding L-n no longer reproduces" is printed and the part still PASSes,
# as long as every other test passed (see live/runner.py).
#
# --quick keeps the whole thing under ~3 minutes (short load, no 75 s upstream-timeout case).
#
# The last thing the script does is check that no process started by the run is still alive (the test
# code records every pid it starts); if one is, it is listed, stopped, and the run exits 1.
#
# Everything this script starts is stopped by PID when it ends, when a part fails and on Ctrl-C:
# the test processes stop their own daemons, company-api and MCP servers, and this script stops
# the private PostgreSQL cluster it started (never one it attached to with SD_PG_DSN, and never
# one that was already running when it began).
#
# Attaching to services someone else started (docker-compose, CI): set any of
#   SD_PG_DSN
#   SD_UPSTREAM_URL  SD_UPSTREAM_KEY
#   SD_DAEMON_URL    SD_ADMIN_KEY   SD_PEP_KEY   (and SD_PROXY_URL for the proxy)
# The boundary part needs root and working network namespaces, and SKIPs otherwise.
# A real Keycloak is tested by live/idp/ (its own run.sh); this script does not drive it.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"
PART="all"
QUICK=""
for a in "$@"; do
  case "$a" in
    --quick) QUICK=1 ;;
    upstream|boundary|load|all) PART="$a" ;;
    *) echo "usage: run.sh [upstream|boundary|load|all] [--quick]" >&2; exit 2 ;;
  esac
done
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
[ -n "$QUICK" ] || export SD_LIVE_FULL=1
FAILED=0; RAN=0
CHILD=""; PG_OURS=""
OUT="$(mktemp -t smartdelegate-live-run.XXXXXX)"
# every process the test code starts writes "pid starttime" here (live/upstream/stack.py, record_pid)
export SD_LIVE_PIDFILE="$(mktemp -t smartdelegate-live-pids.XXXXXX)"

# still_alive: print (and stop) what this run started and is still running. The start time from
# /proc/<pid>/stat tells the process we started from another one that got the same pid later.
still_alive() {
  local pid start now found=1
  while read -r pid start; do
    [ -r "/proc/$pid/stat" ] || continue
    now="$(sed 's/^.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f20)"
    [ "$now" = "$start" ] || continue
    grep -q '^State:[[:space:]]*Z' "/proc/$pid/status" 2>/dev/null && continue      # exited, not yet reaped
    echo "run.sh: LEFT RUNNING pid $pid: $(tr '\0' ' ' <"/proc/$pid/cmdline" | cut -c1-160)"
    kill -TERM "$pid" 2>/dev/null
    found=0
  done <"$SD_LIVE_PIDFILE"
  return $found
}

cleanup() {
  trap - EXIT INT TERM HUP
  if [ -n "$CHILD" ] && kill -0 "$CHILD" 2>/dev/null; then
    kill -TERM "$CHILD" 2>/dev/null          # the test process stops what it started (live/upstream/stack.py)
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do kill -0 "$CHILD" 2>/dev/null || break; sleep 0.5; done
    kill -KILL "$CHILD" 2>/dev/null
  fi
  [ -n "$PG_OURS" ] && "$HERE/upstream/pg.sh" stop >/dev/null 2>&1
  LEFT=0
  if still_alive; then LEFT=1; fi
  if [ -n "$PG_OURS" ] && "$HERE/upstream/pg.sh" status >/dev/null 2>&1; then echo "run.sh: LEFT RUNNING the private PostgreSQL cluster"; LEFT=1; fi
  rm -f "$OUT" "$SD_LIVE_PIDFILE"
}
trap 'cleanup' EXIT
LEFT=0
trap 'echo "run.sh: interrupted" >&2; cleanup; exit 130' INT TERM HUP

line() { printf '%-9s %-4s %s\n' "$1" "$2" "$3"; }

# run <part> <seconds> <command...>: in the background, so a signal reaches the trap at once
run() {
  local part="$1" limit="$2"; shift 2
  timeout --signal=TERM --kill-after=30 "$limit" "$@" >"$OUT" 2>&1 &
  CHILD=$!
  wait "$CHILD"; local rc=$?
  CHILD=""
  grep -E '^FIXED\? ' "$OUT"
  local summary; summary="$(grep -E '^(RESULT|Ran [0-9]+ tests|thresholds:)' "$OUT" | tr '\n' ' ')"
  case $rc in
    0) RAN=1; line "$part" PASS "$summary" ;;
    3) line "$part" SKIP "$(grep -E '^SKIPPED: ' "$OUT" | sed 's/^SKIPPED: //' | tr '\n' ';' | cut -c1-300)" ;;
    124|137) FAILED=1; RAN=1; line "$part" FAIL "did not finish within $limit s"; tail -15 "$OUT" ;;
    *) FAILED=1; RAN=1; line "$part" FAIL "$summary(exit $rc)"; tail -40 "$OUT" ;;
  esac
}

start_pg() {
  [ -n "${SD_PG_DSN:-}" ] && return 0
  "$HERE/upstream/pg.sh" status >/dev/null 2>&1 && return 0     # somebody else's run: not ours to stop
  if "$HERE/upstream/pg.sh" start >/dev/null 2>"$OUT"; then PG_OURS=1; else return 1; fi
}

run_upstream() {
  if ! start_pg; then line upstream SKIP "no PostgreSQL: $(tr '\n' ' ' <"$OUT" | cut -c1-200)"; return; fi
  run upstream 1500 python3 -m live.runner live.upstream.test_live_upstream
}
run_boundary() {
  if [ "$(id -u)" != "0" ]; then line boundary SKIP "needs root (it creates a network namespace and drops to an unprivileged uid)"; return; fi
  if ! start_pg; then line boundary SKIP "no PostgreSQL: $(tr '\n' ' ' <"$OUT" | cut -c1-200)"; return; fi
  run boundary 600 python3 -m live.runner live.boundary.test_boundary
}
run_load() {
  if [ -n "$QUICK" ]; then
    run load 600 python3 -m live.load --targets python,rust --quick --check "$HERE/load/thresholds.json"
  else
    run load 1800 python3 -m live.load --targets python,rust --duration 12 --warmup 2 --soak 20000 --overload --check "$HERE/load/thresholds.json"
  fi
}

case "$PART" in
  upstream) run_upstream ;;
  boundary) run_boundary ;;
  load) run_load ;;
  all) run_upstream; run_boundary; run_load ;;
esac
# the last check: nothing this run started may still be alive. If something is, that is a failure of the run.
cleanup
if [ "$LEFT" = 1 ]; then echo "run.sh: FAIL: processes started by this run were still alive at its end (stopped now, listed above)"; exit 1; fi
if [ "$FAILED" = 1 ]; then exit 1; fi
if [ "$RAN" = 0 ]; then echo "run.sh: nothing ran (every part was skipped, see above)"; exit 3; fi
exit 0
