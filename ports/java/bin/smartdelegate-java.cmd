@echo off
rem The command line of the SmartDelegate Java port, for Windows:
rem
rem   smartdelegate-java <command> [options]        (smartdelegate-java --help)
rem
rem Runs dev.smartdelegate.Cli from ..\build\smartdelegate.jar; build it first
rem with ..\build.cmd. Exit code 0 allow/ok, 2 deny, 1 error.
rem
rem Environment:
rem   SMARTDELEGATE_JAVA        the java.exe to use (full path); overrides everything below
rem   (default)                 java from PATH, the same one build.cmd compiled and tested with;
rem                             only when PATH has none: %JAVA_HOME%\bin\java.exe
rem   SMARTDELEGATE_JAVA_OPTS   extra JVM options (e.g. -Xmx256m)
rem   SMARTDELEGATE_JAVA_CDS=1  map the class-data archive build.cmd made (faster start; off by default)
rem
rem First run on Windows (2026-10-06) failed with "LinkageError occurred while
rem loading main class": the launcher then preferred JAVA_HOME over PATH, and a
rem JAVA_HOME pointing at a JDK older than 17 cannot load this jar. It now uses
rem the PATH java first. The class-data archive is opt-in until it has been
rem seen to work on Windows.
rem
rem Unlike the POSIX launcher, this one leaves JAVA_TOOL_OPTIONS alone. When
rem it is set, the JVM prints a "Picked up JAVA_TOOL_OPTIONS" line on stderr
rem before `serve` prints its URL; a program that reads the URL from the first
rem line of stderr must clear the variable first.
setlocal

set "HERE=%~dp0"
set "JAR=%HERE%..\build\smartdelegate.jar"
if exist "%JAR%" goto have_jar
echo smartdelegate: %JAR% does not exist: run ports\java\build.cmd first 1>&2
exit /b 1

:have_jar
set "JAVA="
if defined SMARTDELEGATE_JAVA set "JAVA=%SMARTDELEGATE_JAVA%"
if defined JAVA goto have_java
where java >nul 2>&1 && set "JAVA=java"
if defined JAVA goto have_java
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set "JAVA=%JAVA_HOME%\bin\java.exe"
if defined JAVA goto have_java
echo smartdelegate: no Java runtime found: install a JDK or JRE 17+ and put java on PATH, or set SMARTDELEGATE_JAVA 1>&2
exit /b 1

:have_java
rem Commands that answer and exit stop at the first JIT tier; `serve` keeps the full JIT.
set "FAST=-XX:TieredStopAtLevel=1"
if /i "%~1"=="serve" set "FAST="
set "CDS="
if not "%SMARTDELEGATE_JAVA_CDS%"=="1" goto run
if exist "%HERE%..\build\smartdelegate.jsa" set CDS=-XX:SharedArchiveFile="%HERE%..\build\smartdelegate.jsa" -Xshare:auto

:run
"%JAVA%" %CDS% %FAST% -Dfile.encoding=UTF-8 %SMARTDELEGATE_JAVA_OPTS% -jar "%JAR%" %*
if not errorlevel 1 exit /b 0
set "RC=%ERRORLEVEL%"
rem exit code 2 is an ordinary deny; only explain a start-up failure
if "%RC%"=="2" exit /b 2
if not "%~1"=="version" if not "%~1"=="--version" exit /b %RC%
echo smartdelegate: the JVM used was "%JAVA%"; this jar needs Java 17 or newer. Check with: "%JAVA%" -version 1>&2
exit /b %RC%
