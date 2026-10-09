#!/usr/bin/env bash
# Build the Java port into ./build (ignored by git) and run the whole test
# harness against the Python reference in ../../src. Takes no arguments.
#
#   1. ./build.sh: build/classes, build/smartdelegate.jar (and the class-data
#      archive the launcher uses), compiled with -Xlint:all -Werror
#   2. the test classes into build/test-classes
#   3. dev.smartdelegate.Conformance: the engine suites, the Java client against
#      the reference daemon, then the Java daemon and command line
#      (DaemonChecks: vectors over REST against the Java daemon with the Java
#      client, keys and status codes, concurrency, the command line, and the
#      launcher bin/smartdelegate-java)
#
# Prints the harness summary; exits non-zero if the build or any check fails.
# Environment: PYTHON (default python3), JAVA_HOME (optional).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
python="${PYTHON:-python3}"
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then bin="$JAVA_HOME/bin/"; else bin=""; fi

for tool in "${bin}javac" "${bin}java" "${bin}jar" "$python"; do
  command -v "$tool" >/dev/null 2>&1 || { echo "run_conformance.sh: '$tool' not found on PATH" >&2; exit 2; }
done

build="$here/build"
rm -rf "$build"
"$here/build.sh"
mkdir -p "$build/test-classes"
find "$here/src/test" -name '*.java' -print0 | xargs -0 "${bin}javac" -Xlint:all -Werror -encoding UTF-8 -cp "$build/classes" -d "$build/test-classes"

status=0
PYTHONPATH="$root/src${PYTHONPATH:+:$PYTHONPATH}" \
  "${bin}java" -Dsmartdelegate.launcher="$here/bin/smartdelegate-java" -Dsun.net.httpserver.maxReqTime=5 -cp "$build/classes:$build/test-classes" \
  dev.smartdelegate.Conformance "$root" "$python" -m sf_smartdelegate || status=$?
if [ "$status" -eq 0 ]; then
  echo "java port: all suites passed"
else
  echo "java port: FAILED (exit $status)" >&2
fi
exit "$status"
