#!/usr/bin/env bash
# Runs the two shared suites (policy evaluation cases, engine conformance
# vectors) against every engine port whose toolchain is installed.
#
#   ports/conformance/run.sh              all ports
#   ports/conformance/run.sh go php       only these
#   ports/conformance/run.sh -v ...       also print each port's full output
#
# One line per port:
#   python: PASS (<N> eval, <M> conformance)
#   php: SKIP (php is not installed)
#   go: FAIL (exit 1)                     followed by the end of its output
# then `summary: pass=N fail=N skip=N`. The counts are read from what the
# port printed, not from this script. A port without its toolchain is a SKIP,
# never a failure and never a pass. Exit status: 1 if any port failed, else 0.
#
# Nothing is built into the repository except what a port's own script builds
# into its ignored build directory (ports/java/build, ports/rust/target). The
# Go binary is built into a temporary directory.
set -u
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
vectors="$root/spec/conformance/vectors"
bundle="$root/spec/conformance/bundle"
all_ports="python java node go php rust"
limit="${SMARTDELEGATE_CONFORMANCE_TIMEOUT:-1800}"   # seconds per port

verbose=0
selected=""
for arg in "$@"; do
  case "$arg" in
    -v|--verbose) verbose=1 ;;
    -h|--help) sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    python|java|node|go|php|rust) selected="$selected $arg" ;;
    *) echo "run.sh: unknown argument '$arg' (ports: $all_ports)" >&2; exit 2 ;;
  esac
done
[ -n "$selected" ] || selected="$all_ports"

have() { command -v "$1" >/dev/null 2>&1; }
py=python3; have python3 || py=python
guard() { if have timeout; then timeout "$limit" "$@"; else "$@"; fi; }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/smartdelegate-conformance.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Each run_<port> prints the port's output and returns its status; 77 means
# "toolchain missing", with the reason in $tmp/<port>.skip.
skip() { echo "$2" > "$tmp/$1.skip"; return 77; }

need_python() {
  have "$py" || { echo "python3 is not installed"; return 1; }
  "$py" -c "import cryptography" 2>/dev/null || { echo "the Python package cryptography is not installed"; return 1; }
}

run_python() {
  local why; why="$(need_python)" || { skip python "$why"; return 77; }
  cd "$root" || return 1
  PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}" guard "$py" -m sf_smartdelegate conformance "$vectors" "$bundle" || return 1
  # The eval test prints no count: it checks every case of cases.json in one
  # test method. So the count is the number of cases in that file, printed
  # only when the test passed.
  (cd "$root/tests" && guard "$py" -m unittest test_cedar_eval 2>&1) || return 1
  "$py" -c 'import json, sys; print("eval: %d cases, 0 failed" % len(json.load(open(sys.argv[1], encoding="utf-8"))["cases"]))' "$root/spec/conformance/eval/cases.json"
}

run_java() {
  have javac && have java && have jar || { skip java "a JDK (javac, jar, java) is not installed"; return 77; }
  guard "$root/ports/java/build.sh" || return 1
  guard "$root/ports/java/bin/smartdelegate-java" conformance --root "$root"
}

run_node() {
  have node || { skip node "node is not installed"; return 77; }
  guard "$root/ports/node/run_conformance.sh"
}

run_go() {
  have go || { skip go "go is not installed"; return 77; }
  (cd "$root/ports/go" && GOTOOLCHAIN="${GOTOOLCHAIN:-local}" GOFLAGS="${GOFLAGS:--buildvcs=false}" guard go build -o "$tmp/smartdelegate-go" ./cmd/smartdelegate-go) || return 1
  guard "$tmp/smartdelegate-go" conformance --root "$root"
}

run_php() {
  have php || { skip php "php is not installed"; return 77; }
  php -r 'exit(extension_loaded("sodium") ? 0 : 1);' 2>/dev/null || { skip php "php has no sodium extension"; return 77; }
  guard "$root/ports/php/run_conformance.sh"
}

run_rust() {
  have cargo || { skip rust "cargo is not installed"; return 77; }
  guard "$root/ports/rust/run_conformance.sh"
}

# The numbers, from the port's own output. The forms in use:
#   eval: N cases, 0 failed                   <port> policy evaluation (...): N cases, 0 failed
#   N eval cases match real Cedar             [<port> ]conformance: M cases[, S steps], 0 failed
#   <port> engine conformance (in-process): M cases, S steps, 0 failed
count() {  # count eval|conformance <file> -> "<cases> <failed>" or nothing
  if [ "$1" = eval ]; then
    sed -n -E -e 's/^.*(eval|policy evaluation[^:]*): ([0-9]+) cases, ([0-9]+) failed.*$/\2 \3/p' \
              -e 's/^.*[^0-9]([0-9]+) eval cases match real Cedar.*$/\1 0/p' "$2" | tail -n 1
  else
    sed -n -E 's/^(.* )?conformance( \(in-process\))?: ([0-9]+) cases, ([0-9]+ steps, )?([0-9]+) failed.*$/\3 \5/p' "$2" | tail -n 1
  fi
}

pass=0; fail=0; skipped=0
for port in $selected; do
  out="$tmp/$port.out"
  ( "run_$port" ) > "$out" 2>&1
  status=$?
  [ "$verbose" = 1 ] && sed "s/^/  $port| /" "$out"
  if [ "$status" = 77 ] && [ -f "$tmp/$port.skip" ]; then
    echo "$port: SKIP ($(cat "$tmp/$port.skip"))"
    skipped=$((skipped + 1))
    continue
  fi
  read -r eval_n eval_failed <<< "$(count eval "$out")"
  read -r conf_n conf_failed <<< "$(count conformance "$out")"
  problem=""
  if [ "$status" != 0 ]; then problem="exit $status"
  elif [ -z "${eval_n:-}" ] || [ -z "${conf_n:-}" ]; then problem="exit 0, but its output does not report both suites"
  elif [ "$eval_failed" != 0 ] || [ "$conf_failed" != 0 ]; then problem="exit 0, but it reports failed cases"
  elif [ "$eval_n" = 0 ] || [ "$conf_n" = 0 ]; then problem="exit 0, but a suite ran no cases"
  fi
  if [ -z "$problem" ]; then
    echo "$port: PASS ($eval_n eval, $conf_n conformance)"
    pass=$((pass + 1))
  else
    echo "$port: FAIL ($problem${eval_n:+; eval $eval_n cases, $eval_failed failed}${conf_n:+; conformance $conf_n cases, $conf_failed failed})"
    [ "$verbose" = 1 ] || tail -n 25 "$out" | sed "s/^/  $port| /"
    fail=$((fail + 1))
  fi
done

echo "summary: pass=$pass fail=$fail skip=$skipped"
[ "$fail" = 0 ]
