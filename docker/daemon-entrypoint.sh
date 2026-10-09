#!/bin/sh
# Entrypoint of docker/Dockerfile.daemon. UNTESTED in a container (no Docker
# daemon where it was written); the script itself was run with sh on Linux.
#
# Reads SMARTDELEGATE_ADMIN_KEY_FILE and SMARTDELEGATE_PEP_KEY_FILE (secrets
# mounted as files) into SMARTDELEGATE_ADMIN_KEY and SMARTDELEGATE_PEP_KEY,
# which is where src/sf_smartdelegate/cli.py looks, then runs `sf-smartdelegate`
# with the arguments given. It prints no key and writes nothing.
set -eu

from_file() {   # from_file VAR: when VAR_FILE names a readable file, VAR becomes its content
  var="$1"
  eval "file=\${${var}_FILE:-}"
  [ -n "$file" ] || return 0
  if [ ! -r "$file" ]; then
    echo "smartdelegate-entrypoint: ${var}_FILE=$file cannot be read" >&2
    exit 1
  fi
  value="$(cat "$file")"
  export "$var=$value"
  unset "${var}_FILE" value file
}
from_file SMARTDELEGATE_ADMIN_KEY
from_file SMARTDELEGATE_PEP_KEY

case "${1:-serve}" in
  sh|bash|python|python3) exec "$@" ;;
esac
exec sf-smartdelegate "$@"
