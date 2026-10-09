#!/usr/bin/env bash
# A private PostgreSQL cluster for the live tests, outside the repository.
#
#   pg.sh start    initdb + start on a free loopback port; prints the DSN
#   pg.sh url      print the DSN (of the private cluster, or SD_PG_DSN when set)
#   pg.sh status   exit 0 when the server answers
#   pg.sh log      print the path of the server log (statement log)
#   pg.sh stop     stop the server (by the PID in postmaster.pid) and delete the cluster
#
# With SD_PG_DSN set, nothing is started or stopped: `url` prints that DSN.
# The cluster lives in $SD_LIVE_HOME/pg (default /var/tmp/smartdelegate-live-<uid>/pg).
# Authentication is scram-sha-256 over 127.0.0.1 only; the Unix socket is in a
# directory only the server's user can enter. The password is generated here
# and kept in a mode-0600 file next to the cluster, never in the repository.
set -euo pipefail

HOME_DIR="${SD_LIVE_HOME:-/var/tmp/smartdelegate-live-$(id -u)}"
PG_DIR="$HOME_DIR/pg"
DATA="$PG_DIR/data"
SOCK="$PG_DIR/sock"
DSN_FILE="$PG_DIR/dsn"
LOG="$PG_DIR/server.log"
DB="${SD_PG_DB:-kestrel_live}"

find_bin() {
  if [ -n "${SD_PG_BIN:-}" ]; then echo "$SD_PG_BIN"; return; fi
  if command -v pg_ctl >/dev/null 2>&1 && command -v initdb >/dev/null 2>&1; then dirname "$(command -v pg_ctl)"; return; fi
  local d
  for d in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin /opt/homebrew/opt/postgresql*/bin /usr/local/opt/postgresql*/bin; do
    if [ -x "$d/pg_ctl" ]; then echo "$d"; return; fi
  done
  echo ""
}

# PostgreSQL refuses to run as root: as root, run its tools as $SD_PG_OS_USER (default postgres).
as_pg() {
  if [ "$(id -u)" = "0" ]; then
    local u="${SD_PG_OS_USER:-postgres}" cmd="" a
    for a in "$@"; do cmd+=" $(printf '%q' "$a")"; done
    su "$u" -s /bin/sh -c "$cmd"
  else
    "$@"
  fi
}

cmd="${1:-}"
case "$cmd" in
  url)
    if [ -n "${SD_PG_DSN:-}" ]; then echo "$SD_PG_DSN"; exit 0; fi
    [ -f "$DSN_FILE" ] || { echo "pg.sh: no private cluster (run: pg.sh start)" >&2; exit 1; }
    cat "$DSN_FILE"
    ;;
  log)
    [ -z "${SD_PG_DSN:-}" ] || { echo "pg.sh: attached with SD_PG_DSN; the server log is not ours to read" >&2; exit 1; }
    echo "$LOG"
    ;;
  status)
    if [ -n "${SD_PG_DSN:-}" ]; then exit 0; fi
    BIN="$(find_bin)"; [ -n "$BIN" ] && [ -f "$DATA/postmaster.pid" ] || exit 1
    as_pg "$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1
    ;;
  start)
    if [ -n "${SD_PG_DSN:-}" ]; then echo "$SD_PG_DSN"; exit 0; fi
    BIN="$(find_bin)"
    [ -n "$BIN" ] || { echo "pg.sh: no PostgreSQL binaries found (set SD_PG_BIN, or SD_PG_DSN to attach to a server)" >&2; exit 3; }
    if [ -f "$DSN_FILE" ] && [ -f "$DATA/postmaster.pid" ] && as_pg "$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
      cat "$DSN_FILE"; exit 0
    fi
    rm -rf "$PG_DIR"
    mkdir -p "$HOME_DIR"; chmod 755 "$HOME_DIR"
    mkdir -p "$PG_DIR"; chmod 711 "$PG_DIR"
    PW="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    PWFILE="$PG_DIR/pwfile"
    ( umask 077; printf '%s\n' "$PW" > "$PWFILE" )
    if [ "$(id -u)" = "0" ]; then
      U="${SD_PG_OS_USER:-postgres}"
      id "$U" >/dev/null 2>&1 || { echo "pg.sh: running as root needs the OS user '$U' (set SD_PG_OS_USER)" >&2; exit 3; }
      install -d -m 700 -o "$U" "$DATA" "$SOCK"
      chown "$U" "$PWFILE"
      touch "$LOG"; chown "$U" "$LOG"; chmod 600 "$LOG"
    else
      mkdir -p "$DATA" "$SOCK"; chmod 700 "$DATA" "$SOCK"; : > "$LOG"; chmod 600 "$LOG"
    fi
    as_pg "$BIN/initdb" -D "$DATA" -U postgres --auth-host=scram-sha-256 --auth-local=scram-sha-256 --pwfile="$PWFILE" -E UTF8 --locale=C >/dev/null
    PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    # fsync off: this is a throwaway cluster. log_statement=all: the tests read
    # the statement log to prove what SQL the enforcement points really sent.
    OPTS="-p $PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories=$SOCK -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=120 -c log_statement=all -c log_line_prefix='%m [%p] %u@%d ' -c shared_buffers=128MB"
    as_pg "$BIN/pg_ctl" -D "$DATA" -l "$LOG" -o "$OPTS" -w -t 60 start >/dev/null
    PGPASSWORD="$PW" "$BIN/psql" -h 127.0.0.1 -p "$PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -q -c "create database $DB" >/dev/null
    rm -f "$PWFILE"
    ( umask 077; printf 'postgresql://postgres:%s@127.0.0.1:%s/%s\n' "$PW" "$PORT" "$DB" > "$DSN_FILE" )
    cat "$DSN_FILE"
    ;;
  stop)
    if [ -n "${SD_PG_DSN:-}" ]; then echo "pg.sh: attached with SD_PG_DSN; nothing to stop" >&2; exit 0; fi
    BIN="$(find_bin)"
    if [ -n "$BIN" ] && [ -f "$DATA/postmaster.pid" ]; then
      as_pg "$BIN/pg_ctl" -D "$DATA" -m fast -w -t 60 stop >/dev/null 2>&1 || true
    fi
    rm -rf "$PG_DIR"
    rmdir "$HOME_DIR" 2>/dev/null || true
    ;;
  *)
    echo "usage: pg.sh start|stop|url|status|log" >&2; exit 2
    ;;
esac
