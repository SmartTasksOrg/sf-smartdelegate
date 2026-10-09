#!/bin/sh
# Build the Java port with the JDK alone (no Maven, no Gradle):
#
#   build/classes           the engine, client, daemon and command line
#   build/smartdelegate.jar the same, runnable: java -jar build/smartdelegate.jar --help
#   build/smartdelegate.jsa a class-data archive that cuts JVM start-up (optional;
#                           skipped with a note when the JDK cannot make one)
#
# Takes no arguments. build/ is ignored by git. Exits non-zero if a step fails.
# Environment: JAVA_HOME (optional; otherwise javac, jar and java from PATH),
# SMARTDELEGATE_NO_CDS=1 to skip the archive.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/javac" ]; then
  bin="$JAVA_HOME/bin/"
else
  bin=""
fi
for tool in javac jar java; do
  command -v "${bin}$tool" >/dev/null 2>&1 || { echo "build.sh: '$tool' not found (install a JDK 17+ or set JAVA_HOME)" >&2; exit 2; }
done

build="$here/build"
rm -rf "$build/classes" "$build/smartdelegate.jar" "$build/smartdelegate.jsa" "$build/manifest.txt" "$build/sources.txt"
mkdir -p "$build/classes"

# an argument file, so paths with spaces survive
find "$here/src/main/java" -name '*.java' | sort | sed 's/\\/\\\\/g; s/.*/"&"/' > "$build/sources.txt"
"${bin}javac" -Xlint:all -Werror --release 17 -encoding UTF-8 -d "$build/classes" "@$build/sources.txt"

printf 'Main-Class: dev.smartdelegate.Cli\nImplementation-Title: smartdelegate-java\nImplementation-Version: 0.3.0\n' > "$build/manifest.txt"
"${bin}jar" --create --file "$build/smartdelegate.jar" --manifest "$build/manifest.txt" -C "$build/classes" .
rm -f "$build/manifest.txt" "$build/sources.txt"

# Class-data sharing: the JVM dumps the classes one run loaded and maps them
# on later runs instead of parsing them again. The launcher uses the archive
# only when it exists; a stale or foreign archive is ignored by the JVM.
if [ "${SMARTDELEGATE_NO_CDS:-}" != "1" ]; then
  # JAVA_TOOL_OPTIONS would print a banner; it changes nothing the archive depends on
  if ! (unset JAVA_TOOL_OPTIONS; "${bin}java" -XX:ArchiveClassesAtExit="$build/smartdelegate.jsa" -Xlog:disable -Xlog:all=off \
        -cp "$build/smartdelegate.jar" dev.smartdelegate.Warmup >/dev/null 2>&1) || [ ! -s "$build/smartdelegate.jsa" ]; then
    rm -f "$build/smartdelegate.jsa"
    echo "build.sh: no class-data archive (this JDK cannot write one); the launcher works without it, start-up is slower" >&2
  fi
fi
echo "built $build/smartdelegate.jar"
