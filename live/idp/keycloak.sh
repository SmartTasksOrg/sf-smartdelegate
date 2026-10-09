#!/usr/bin/env bash
# A local Keycloak for the live identity-provider tests.
#
#   keycloak.sh start    download (first use), start on a free loopback port, wait until ready
#   keycloak.sh stop     stop the server this script started (by PID; never by name)
#   keycloak.sh status   "running <url>" (exit 0) or "stopped" (exit 1); "attached <url>" when attached
#   keycloak.sh url      print the base URL
#   keycloak.sh reset    stop and delete the server's database (realms, users, keys)
#
# Attach instead of start: set SD_KEYCLOAK_URL (and SD_KEYCLOAK_ADMIN,
# SD_KEYCLOAK_ADMIN_PASSWORD). Then start/stop/reset do nothing to the server.
#
# Everything this script downloads or writes lives in the cache directory,
# outside the repository:
#   SD_KEYCLOAK_CACHE    default ~/.cache/smartdelegate/keycloak
#   SD_KEYCLOAK_VERSION  default 26.0.7
#   SD_KEYCLOAK_HEAP     default 768m
#   SD_KEYCLOAK_START_TIMEOUT  seconds to wait for readiness, default 240
#
# Exit codes: 0 ok, 1 failed, 3 Keycloak could not be obtained or started.
set -u

CACHE="${SD_KEYCLOAK_CACHE:-$HOME/.cache/smartdelegate/keycloak}"
VERSION="${SD_KEYCLOAK_VERSION:-26.0.7}"
HEAP="${SD_KEYCLOAK_HEAP:-768m}"
START_TIMEOUT="${SD_KEYCLOAK_START_TIMEOUT:-240}"
DIST="$CACHE/keycloak-$VERSION"
TARBALL="$CACHE/keycloak-$VERSION.tar.gz"
BASE="https://github.com/keycloak/keycloak/releases/download/$VERSION"
PIDFILE="$CACHE/keycloak.pid"
PORTFILE="$CACHE/keycloak.port"
ADMINFILE="$CACHE/admin.env"
LOG="$CACHE/keycloak.log"

say() { echo "keycloak.sh: $*" >&2; }
fail() { say "$1"; exit "${2:-1}"; }

attached() { [ -n "${SD_KEYCLOAK_URL:-}" ]; }

local_curl() {  # never through a proxy: the server is on loopback
  curl --noproxy '*' -sS --max-time 10 "$@"
}

ready() {  # $1 = base URL
  [ "$(local_curl -o /dev/null -w '%{http_code}' "$1/realms/master" 2>/dev/null)" = "200" ]
}

pid_is_ours() {  # $1 = pid: alive, and a java process started from our distribution directory
  [ -n "$1" ] && [ -r "/proc/$1/cmdline" ] && tr '\0' ' ' < "/proc/$1/cmdline" | grep -q -- "$CACHE/keycloak-"
}

running_pid() {
  [ -f "$PIDFILE" ] || return 1
  local pid; pid="$(cat "$PIDFILE" 2>/dev/null)"
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  if [ -r /proc/1/cmdline ]; then pid_is_ours "$pid" || return 1; else kill -0 "$pid" 2>/dev/null || return 1; fi
  echo "$pid"
}

base_url() {
  if attached; then echo "${SD_KEYCLOAK_URL%/}"; return 0; fi
  [ -f "$PORTFILE" ] || return 1
  echo "http://127.0.0.1:$(cat "$PORTFILE")"
}

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()
PY
}

port_free() {  # $1 = port
  python3 - "$1" <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(2)
sys.exit(1 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 0)
PY
}

obtain() {
  [ -x "$DIST/bin/kc.sh" ] && return 0
  command -v java >/dev/null 2>&1 || fail "java is not installed (Keycloak $VERSION needs Java 17 or 21)" 3
  mkdir -p "$CACHE" || fail "cannot create $CACHE" 3
  if [ ! -f "$TARBALL" ]; then
    say "downloading Keycloak $VERSION to $CACHE"
    curl -sSL --fail --connect-timeout 30 --max-time 900 -o "$TARBALL.part" "$BASE/keycloak-$VERSION.tar.gz" \
      || { rm -f "$TARBALL.part"; fail "download failed: $BASE/keycloak-$VERSION.tar.gz" 3; }
    mv "$TARBALL.part" "$TARBALL"
  fi
  # the release publishes a .sha1 next to the archive (no .sha256 for 26.0.7)
  if [ ! -f "$TARBALL.sha1" ]; then
    curl -sSL --fail --connect-timeout 30 --max-time 60 -o "$TARBALL.sha1" "$BASE/keycloak-$VERSION.tar.gz.sha1" || rm -f "$TARBALL.sha1"
  fi
  if [ -f "$TARBALL.sha1" ]; then
    local want got
    want="$(tr -d ' \n\r' < "$TARBALL.sha1" | cut -c1-40)"
    got="$(sha1sum "$TARBALL" | cut -c1-40)"
    [ "$want" = "$got" ] || { rm -f "$TARBALL"; fail "checksum mismatch for the Keycloak archive (expected $want, got $got); archive deleted" 3; }
    say "archive sha1 verified: $got"
  else
    say "WARNING: no published checksum could be fetched; the archive is NOT verified"
  fi
  tar -xzf "$TARBALL" -C "$CACHE" || fail "cannot unpack $TARBALL" 3
  [ -x "$DIST/bin/kc.sh" ] || fail "$DIST/bin/kc.sh is missing after unpacking" 3
}

admin_env() {  # generated once per database; never in the repository
  if [ ! -f "$ADMINFILE" ]; then
    ( umask 077; printf 'SD_KEYCLOAK_ADMIN=admin\nSD_KEYCLOAK_ADMIN_PASSWORD=%s\n' \
        "$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')" > "$ADMINFILE" )
  fi
  # shellcheck disable=SC1090
  . "$ADMINFILE"
}

cmd_start() {
  if attached; then
    ready "${SD_KEYCLOAK_URL%/}" || fail "SD_KEYCLOAK_URL is set but ${SD_KEYCLOAK_URL%/}/realms/master does not answer 200" 3
    say "attached to ${SD_KEYCLOAK_URL%/} (not started by this script)"
    return 0
  fi
  if pid="$(running_pid)" && ready "$(base_url)"; then
    say "already running (pid $pid) at $(base_url)"
    return 0
  fi
  obtain
  admin_env
  rm -f "$PIDFILE"
  local port; port="$(free_port)" || fail "no free port" 3
  echo "$port" > "$PORTFILE"
  : > "$LOG"
  say "starting Keycloak $VERSION on 127.0.0.1:$port (heap $HEAP, log $LOG)"
  # No proxy settings and no outbound calls: the server runs on loopback only.
  # kc.sh ends in `exec java`, so the PID recorded here is the JVM.
  (
    cd "$DIST" || exit 1
    unset JAVA_TOOL_OPTIONS HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
    export KC_BOOTSTRAP_ADMIN_USERNAME="$SD_KEYCLOAK_ADMIN" KC_BOOTSTRAP_ADMIN_PASSWORD="$SD_KEYCLOAK_ADMIN_PASSWORD"
    export JAVA_OPTS_KC_HEAP="-Xms128m -Xmx$HEAP"
    exec setsid nohup "$DIST/bin/kc.sh" start-dev --http-host=127.0.0.1 --http-port="$port" --hostname-strict=false \
      >> "$LOG" 2>&1 < /dev/null
  ) &
  local pid=$!
  echo "$pid" > "$PIDFILE"
  local deadline=$(( $(date +%s) + START_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -n 20 "$LOG" >&2
      rm -f "$PIDFILE"
      fail "Keycloak exited during start; see $LOG" 3
    fi
    if ready "http://127.0.0.1:$port"; then
      say "ready at http://127.0.0.1:$port (pid $pid)"
      return 0
    fi
    sleep 2
  done
  tail -n 20 "$LOG" >&2
  cmd_stop
  fail "Keycloak was not ready after ${START_TIMEOUT}s; stopped it" 3
}

cmd_stop() {
  if attached; then say "attached to ${SD_KEYCLOAK_URL%/}: not stopping a server this script did not start"; return 0; fi
  local pid
  if ! pid="$(running_pid)"; then
    rm -f "$PIDFILE"
    say "not running"
  else
    kill "$pid" 2>/dev/null
    local deadline=$(( $(date +%s) + 60 ))
    while kill -0 "$pid" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do sleep 1; done
    if kill -0 "$pid" 2>/dev/null; then
      say "pid $pid did not stop on SIGTERM within 60s; sending SIGKILL"
      kill -9 "$pid" 2>/dev/null
      sleep 1
    fi
    rm -f "$PIDFILE"
    say "stopped pid $pid"
  fi
  if [ -f "$PORTFILE" ]; then
    local port; port="$(cat "$PORTFILE")"
    if port_free "$port"; then say "port $port is free"; else fail "port $port is still in use"; fi
  fi
  return 0
}

cmd_status() {
  if attached; then
    if ready "${SD_KEYCLOAK_URL%/}"; then echo "attached ${SD_KEYCLOAK_URL%/}"; return 0; fi
    echo "attached ${SD_KEYCLOAK_URL%/} (not answering)"; return 1
  fi
  local pid
  if pid="$(running_pid)" && ready "$(base_url)"; then echo "running $(base_url) pid $pid version $VERSION"; return 0; fi
  echo "stopped"; return 1
}

cmd_reset() {
  if attached; then fail "attached to ${SD_KEYCLOAK_URL%/}: reset only applies to a server this script started (use provision.py --reset to delete the test realm)"; fi
  cmd_stop || return 1
  rm -rf "$DIST/data" "$ADMINFILE" "$CACHE/provision.json" "$PORTFILE" "$LOG"
  say "database, admin credential and provisioning record deleted (the download is kept)"
}

case "${1:-}" in
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  status) cmd_status ;;
  url)    base_url || fail "no server: run keycloak.sh start, or set SD_KEYCLOAK_URL" ;;
  reset)  cmd_reset ;;
  *) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
