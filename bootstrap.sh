#!/usr/bin/env bash
# From a fresh clone to "everything built and tested", on Linux and macOS.
# (Windows: bootstrap.ps1.)
#
#   ./bootstrap.sh                 virtualenv in .venv, the package installed editable, every
#                                  port built whose toolchain is here, launchers in build/bin,
#                                  then the quick verification (demo, the two shared suites
#                                  against every built port, the scenario harness)
#   ./bootstrap.sh --full          also test_all.sh, the cross-port matrix
#                                  and the live suites: live/idp/run.sh (a real Keycloak) and
#                                  live/run.sh all --quick (PostgreSQL upstream, boundary, load)
#   ./bootstrap.sh --only python,go     only these components (python java node js go php rust)
#   ./bootstrap.sh --install       first install the missing toolchains with the package manager
#                                  (apt-get, dnf or brew). Every command is printed before it
#                                  runs; sudo is used only for apt-get/dnf when you are not
#                                  root, and it asks for your password itself. Without this
#                                  flag nothing is ever installed outside the repository.
#   ./bootstrap.sh --offline       no network: parts that need one fail at once and say why
#   ./bootstrap.sh --clean         remove .venv, build/ and dist/ first
#   ./bootstrap.sh --require java,go    a skipped part named here is a failure (for CI)
#   ./bootstrap.sh --no-verify     build only
#   ./bootstrap.sh -v              show each step's output while it runs
#
# A part whose toolchain is missing is SKIPPED with the reason; it is never
# reported as built or passed. Exit status: 0 nothing failed, 1 something
# failed, 2 usage. Running it again is quick: what is built is kept.
#
# Everything it writes is git-ignored: .venv/, build/, dist/, and the ports'
# own build directories. No key, token or password is written anywhere.
# The work is done by scripts/sd.py (Python 3.8+, standard library), the
# same code bootstrap.ps1 runs on Windows. Details: docs/BUILD.md.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

INSTALL=0; ONLY=""; PASS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --install) INSTALL=1 ;;
    --only) shift; [ $# -gt 0 ] || { echo "bootstrap.sh: --only needs a list, e.g. --only python,go" >&2; exit 2; }; ONLY="$1" ;;
    --only=*) ONLY="${1#--only=}" ;;
    --require) shift; [ $# -gt 0 ] || { echo "bootstrap.sh: --require needs a list" >&2; exit 2; }; PASS+=(--require "$1") ;;
    --require=*) PASS+=("$1") ;;
    --full|--offline|--clean|--no-verify|-v|--verbose) PASS+=("$1") ;;
    -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "bootstrap.sh: unknown option '$1' (try --help)" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$ONLY" ] && PASS+=(--only "$ONLY")
OFFLINE=0; for a in ${PASS[@]+"${PASS[@]}"}; do [ "$a" = "--offline" ] && OFFLINE=1; done
if [ "$INSTALL" = 1 ] && [ "$OFFLINE" = 1 ]; then
  echo "bootstrap.sh: --install needs the network; it cannot be combined with --offline" >&2; exit 2
fi

have() { command -v "$1" >/dev/null 2>&1; }

# Any Python 3.8+ can run the driver; the driver then looks for a 3.10+ for the virtualenv.
find_python() {
  local c
  for c in python3 python3.13 python3.12 python3.11 python3.10 python; do
    if have "$c" && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
      echo "$c"; return 0
    fi
  done
  return 1
}

# run_shown <command...>: print the command, then run it (sudo in front when it needs root and we are not root)
run_shown() {
  if [ "$(id -u)" != 0 ] && { [ "$1" = apt-get ] || [ "$1" = dnf ]; }; then
    echo "bootstrap.sh: the next command uses sudo and may ask for your password"
    set -- sudo "$@"
  fi
  echo "+ $*"
  "$@"
}

PY="$(find_python || true)"
if [ -z "$PY" ]; then
  if [ "$INSTALL" = 1 ]; then
    echo "bootstrap.sh: no Python 3.8+ found; installing one (--install was given)"
    if have brew; then run_shown brew install python@3.12
    elif have apt-get; then run_shown apt-get install -y python3 python3-venv python3-pip
    elif have dnf; then run_shown dnf install -y python3 python3-pip
    else echo "bootstrap.sh: no package manager I know (brew, apt-get, dnf): install Python 3.10+ by hand" >&2; exit 1; fi
    hash -r
    PY="$(find_python || true)"
  fi
  if [ -z "$PY" ]; then
    cat >&2 <<'EOF'
bootstrap.sh: Python 3.10 or newer is required (it is the reference implementation,
and it runs this bootstrap). Install it, then run ./bootstrap.sh again:
  Debian / Ubuntu:  sudo apt-get install -y python3 python3-venv python3-pip
  Fedora:           sudo dnf install -y python3 python3-pip
  macOS:            brew install python@3.12
or let the bootstrap do it:  ./bootstrap.sh --install
EOF
    exit 1
  fi
fi

if [ "$INSTALL" = 1 ]; then
  # Only what the doctor reports as missing; each command is printed before it runs.
  rows=""
  if [ -n "$ONLY" ]; then
    rows=",$ONLY,"; rows="${rows//,js,/,node,}"; rows="${rows#,}"; rows="${rows}venv"
  fi
  if [ -n "$rows" ]; then "$PY" scripts/doctor.py --install --only "$rows"
  else "$PY" scripts/doctor.py --install; fi
  [ $? = 0 ] || echo "bootstrap.sh: some installs failed; continuing with what is here"
  hash -r
fi

exec "$PY" scripts/sd.py bootstrap ${PASS[@]+"${PASS[@]}"}
