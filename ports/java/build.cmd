@echo off
rem Build the Java port with the JDK alone (no Maven, no Gradle), on Windows:
rem
rem   build\classes           the engine, client, daemon and command line
rem   build\smartdelegate.jar the same, runnable: java -jar build\smartdelegate.jar --help
rem   build\smartdelegate.jsa a class-data archive that cuts JVM start-up (optional)
rem
rem Takes no arguments. Needs javac, jar and java (JDK 17+) on PATH. build\ is
rem ignored by git. Exits non-zero if compiling or packaging fails.
rem
rem NOT TESTED: this file was written without a Windows machine to run it on.
rem The tested build is build.sh.
setlocal

pushd "%~dp0" || exit /b 1
if exist build\classes rmdir /s /q build\classes
if exist build\smartdelegate.jar del /q build\smartdelegate.jar
if exist build\smartdelegate.jsa del /q /f build\smartdelegate.jsa
mkdir build\classes || goto failed

javac -Xlint:all -Werror --release 17 -encoding UTF-8 -d build\classes src\main\java\dev\smartdelegate\*.java || goto failed
jar --create --file build\smartdelegate.jar --main-class dev.smartdelegate.Cli -C build\classes . || goto failed

rem Class-data sharing: optional; the launcher works without the archive.
set "JAVA_TOOL_OPTIONS="
java -XX:ArchiveClassesAtExit=build\smartdelegate.jsa -Xlog:disable -Xlog:all=off -cp build\smartdelegate.jar dev.smartdelegate.Warmup >nul 2>&1
if not exist build\smartdelegate.jsa echo build.cmd: no class-data archive; the launcher works without it, start-up is slower 1>&2

echo built %CD%\build\smartdelegate.jar
popd
exit /b 0

:failed
popd
exit /b 1
