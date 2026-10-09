#!/usr/bin/env python3
"""The build driver behind bootstrap.sh, bootstrap.ps1, the Makefile and
make.ps1. One implementation, so that Linux, macOS and Windows do the same
thing; the shell and PowerShell files only find a Python and call this.

    python3 scripts/sd.py bootstrap [--only python,go,...] [--full] [--offline] [--clean]
                                    [--require java,go,...] [--no-verify] [-v]
    python3 scripts/sd.py doctor [doctor.py options]
    python3 scripts/sd.py build | test | conformance | matrix | harness
    python3 scripts/sd.py live [idp upstream boundary load] | load | all | dist | clean [--deep]
    python3 scripts/sd.py docker-build | docker-test

Python 3.8+ and the standard library only (it runs before the virtualenv
exists; everything it starts runs under .venv's Python 3.10+).

Rules it keeps:
  - a part whose toolchain or script is missing is SKIPPED with the reason,
    never PASS and never FAIL; --require turns chosen skips into failures (CI)
  - every child process has a time limit; when it runs over, everything in
    its session is stopped (by PID, never by name). After a test step ends,
    whatever it left running in that session is stopped too, and reported
  - nothing is installed (that is `doctor.py --install`, behind bootstrap's
    --install flag) and no key, token or password is written anywhere
  - generated files go to .venv/, build/ and dist/ (all git-ignored), plus what
    a port's own build writes into its ignored directory (ports/java/build,
    ports/rust/target)
"""
from __future__ import print_function

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import doctor  # noqa: E402  (scripts/doctor.py)

IS_WINDOWS = os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""
PORTS = ["python", "java", "node", "go", "php", "rust"]        # the engines
COMPONENTS = ["python", "java", "node", "js", "go", "php", "rust"]
LIVE_PARTS = ["idp", "upstream", "boundary", "load"]
# With SD_NATIVE=1 the bash scripts are not used even where bash exists: the
# code paths Windows takes can then be exercised on Linux and macOS.
NATIVE = IS_WINDOWS or os.environ.get("SD_NATIVE") == "1"


def P(*parts):
    return os.path.join(ROOT, *parts)


def read_version():
    with io.open(P("pyproject.toml"), encoding="utf-8") as f:
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', f.read())
    if not m:
        raise SystemExit("sd.py: no version in pyproject.toml")
    return m.group(1)


VERSION = read_version()
VENV = os.environ.get("SD_VENV") or P(".venv")
VENV_BIN = os.path.join(VENV, "Scripts" if IS_WINDOWS else "bin")
VENV_PY = os.path.join(VENV_BIN, "python" + EXE)
BUILD = P("build")
BIN = P("build", "bin")
LOGS = P("build", "logs")
REPORTS = P("build", "reports")
DIST = P("dist")
VECTORS = P("spec", "conformance", "vectors")
BUNDLE = P("spec", "conformance", "bundle")
RUST_BIN = P("ports", "rust", "target", "release", "smartdelegate" + EXE)
GO_BIN = os.path.join(BIN, "smartdelegate-go" + EXE)
JAVA_JAR = P("ports", "java", "build", "smartdelegate.jar")       # what ports/java/build.sh writes
JAVA_JAR_NATIVE = P("build", "java", "smartdelegate.jar")         # what this file writes when there is no build script to run


def limit(name, default):
    """A time limit in seconds; SD_TIMEOUT_<NAME> overrides it."""
    try:
        return int(os.environ.get("SD_TIMEOUT_" + name.upper(), default))
    except ValueError:
        return default


def say(text=""):
    print(text)
    sys.stdout.flush()


def rel(path):
    try:
        r = os.path.relpath(path, ROOT)
    except ValueError:
        return path
    return path if r.startswith("..") else r.replace(os.sep, "/")


# --------------------------------------------------------------------------- processes

_LOGS_STARTED = set()


def session_pids(sid):
    """The processes of session `sid`, without the caller. Every command is
    started as the leader of a new session, so this is "everything it started
    that did not detach on purpose": `timeout`, which the repository's shell
    scripts use, moves its child into another process GROUP, but not into
    another session."""
    if os.path.isdir("/proc"):
        candidates = [int(n) for n in os.listdir("/proc") if n.isdigit()]
    else:
        try:
            text = subprocess.run(["ps", "-A", "-o", "pid="], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout.decode("ascii", "replace")
        except (OSError, subprocess.SubprocessError):
            text = ""
        candidates = [int(x) for x in text.split() if x.isdigit()]
    found = []
    for pid in candidates:
        try:
            if pid != os.getpid() and os.getsid(pid) == sid and not is_zombie(pid):
                found.append(pid)
        except OSError:
            pass
    return found


def is_zombie(pid):
    """A process that has ended and only waits to be collected by its parent is not "still running"."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            return f.read().rsplit(b")", 1)[1].split()[0] == b"Z"
    except (OSError, IndexError):
        pass
    if not os.path.isdir("/proc"):
        try:
            text = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout
            return text.strip().startswith(b"Z")
        except (OSError, subprocess.SubprocessError):
            pass
    return False


def describe(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return " ".join(f.read().decode("utf-8", "replace").split("\0")).strip()[:100]
    except OSError:
        return "pid %d" % pid


def stop_session(sid, grace=5.0, leader=None):
    """SIGTERM, then SIGKILL, to every process of the session. `leader` is the
    Popen of the session leader when it has not been waited for yet (until
    then it stays in the process table as a zombie). -> what was stopped"""
    pids = session_pids(sid)
    names = [describe(p) for p in pids]
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in pids:
            try:
                os.kill(pid, sig)
            except OSError:
                pass
        deadline = time.time() + grace
        while time.time() < deadline:
            if leader is not None:
                leader.poll()          # collect it, so that it leaves the process table
            pids = [p for p in pids if p in session_pids(sid)]
            if not pids:
                return names
            time.sleep(0.1)
    return names


def kill_tree(proc):
    try:
        if IS_WINDOWS:
            subprocess.call(["taskkill", "/T", "/F", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        else:
            stop_session(proc.pid, leader=proc)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


LEFT_BEHIND = []     # what the last run(..., reap=True) had to stop after the command itself had ended


def run(cmd, cwd=None, env=None, timeout=600, log=None, stream=False, reap=False):
    """Runs one command as the leader of its own session. -> exit status (124
    when it ran over the time limit, 127 when it could not be started). The
    output goes to `log` (a path); with stream it is also shown as it comes
    (and only shown when there is no log). On a time limit, everything in the
    session is stopped. With reap, that also happens after a normal end: a
    test run must not leave daemons behind (what it had to stop is put into
    LEFT_BEHIND and into the log)."""
    import threading
    cmd = [str(c) for c in cmd]
    kw = {"cwd": cwd or ROOT, "env": env or child_env(), "stdin": subprocess.DEVNULL}
    if IS_WINDOWS:
        kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kw["start_new_session"] = True
    out = None
    if log:
        os.makedirs(os.path.dirname(log), exist_ok=True)
        # one log per step and per run of this program: what an earlier run left under the same name goes
        out = open(log, "ab" if log in _LOGS_STARTED else "wb")
        _LOGS_STARTED.add(log)
        out.write(("$ " + " ".join(cmd) + "\n").encode("utf-8"))
        out.flush()
        kw["stderr"] = subprocess.STDOUT
        kw["stdout"] = subprocess.PIPE if stream else out
    note = lambda msg: (out.write(msg.encode("utf-8")) if out else None, sys.stderr.write(msg) if (stream or not out) else None)
    try:
        sys.stdout.flush()
        try:
            proc = subprocess.Popen(cmd, **kw)
        except OSError as e:
            note("could not start %s: %s\n" % (cmd[0], e))
            return 127
        pump = None
        if log and stream:
            def copy():
                target = getattr(sys.stdout, "buffer", None)
                for chunk in iter(lambda: proc.stdout.read1(65536) if hasattr(proc.stdout, "read1") else proc.stdout.read(4096), b""):
                    out.write(chunk)
                    if target:
                        target.write(chunk)
                        target.flush()
            pump = threading.Thread(target=copy, daemon=True)
            pump.start()
        try:
            status = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            status = 124
        except KeyboardInterrupt:
            kill_tree(proc)
            raise
        del LEFT_BEHIND[:]
        if reap and not IS_WINDOWS and status != 124:
            LEFT_BEHIND.extend(stop_session(proc.pid))
            if LEFT_BEHIND:
                note("\n[sd.py] the command ended and left %d process(es) running; stopped: %s\n" % (len(LEFT_BEHIND), "; ".join(LEFT_BEHIND)))
        if pump:
            pump.join(timeout=10)
        if status == 124:
            note("\n[sd.py] killed: no result within %d s: %s\n" % (timeout, " ".join(cmd)))
        return status
    finally:
        if out:
            out.close()


def capture(cmd, cwd=None, env=None, timeout=120):
    """-> (status, combined output); for short commands whose output is read."""
    fd, path = tempfile.mkstemp(prefix="sd-capture-", suffix=".log")
    os.close(fd)
    try:
        status = run(cmd, cwd=cwd, env=env, timeout=timeout, log=path, reap=True)
        with io.open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        return status, text.split("\n", 1)[1] if "\n" in text else ""
    finally:
        os.unlink(path)


def tail(path, n=30):
    try:
        with io.open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return ""
    return "\n".join("    | " + l for l in lines[-n:])


def have(name):
    return shutil.which(name, path=child_env()["PATH"]) is not None


def tool(name):
    """Full path of a tool: on Windows npm, for one, is npm.cmd."""
    return shutil.which(name, path=child_env()["PATH"]) or name


_ENV = {}


def child_env(offline=None):
    """The environment of every child: .venv first on PATH, the reference
    importable, Go without toolchain downloads."""
    if offline is None:
        offline = STATE["offline"]
    key = (offline, os.path.isfile(VENV_PY))
    if key in _ENV:
        return dict(_ENV[key])
    env = dict(os.environ)
    paths = [VENV_BIN] if os.path.isfile(VENV_PY) else []
    env["PATH"] = os.pathsep.join(paths + [env.get("PATH", "")])
    if os.path.isfile(VENV_PY):
        env["VIRTUAL_ENV"] = VENV
    env.pop("PYTHONHOME", None)
    env["PYTHONPATH"] = os.pathsep.join([P("src")] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    env.setdefault("GOTOOLCHAIN", "local")
    env.setdefault("GOFLAGS", "-buildvcs=false")
    # JDK 17 on Windows reads sources in the ANSI code page unless told; this reaches every javac a child starts
    env.setdefault("JDK_JAVAC_OPTIONS", "-encoding UTF-8")
    if IS_WINDOWS:
        # A piped Python on Windows reads and writes the ANSI code page, not UTF-8: JSON with non-ASCII text
        # sent through `call --input -` would be misread, and ports/conformance/matrix.py pipes exactly that
        # (subprocess text mode). UTF-8 mode fixes both. docs/BUILD.md says how to see it without this.
        env.setdefault("PYTHONUTF8", "1")
    if offline:
        env.update({"PIP_NO_INDEX": "1", "GOPROXY": "off", "CARGO_NET_OFFLINE": "true", "npm_config_offline": "true"})
    _ENV[key] = env
    return dict(env)


STATE = {"offline": False, "verbose": False, "only": None, "results": [], "step": 0, "python": None}


def python():
    """The interpreter everything runs under: .venv's when it exists, else
    this one when it can run the reference."""
    if STATE["python"]:
        return STATE["python"]
    if os.path.isfile(VENV_PY):
        STATE["python"] = VENV_PY
        return VENV_PY
    d = doctor.probe_python([sys.executable])
    if d and d["version"] >= (3, 10) and d["cryptography"]:
        STATE["python"] = sys.executable
        return sys.executable
    raise SystemExit("sd.py: there is no .venv and %s cannot run the reference (it needs Python 3.10+ with `cryptography`).\n"
                     "Run the bootstrap first:  %s" % (sys.executable, ".\\bootstrap.ps1" if IS_WINDOWS else "./bootstrap.sh"))


def selected(component):
    return STATE["only"] is None or component in STATE["only"]


# --------------------------------------------------------------------------- results

def record(section, key, status, detail=""):
    STATE["results"].append({"section": section, "key": key, "status": status, "detail": detail})
    return status


def step(title):
    STATE["step"] += 1
    say("")
    say("=== [%d] %s" % (STATE["step"], title))
    name = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:48]
    return os.path.join(LOGS, "%02d-%s.log" % (STATE["step"], name))


def left_behind_note():
    """Says so, once, when the command that just ran left processes behind. -> text for the result line"""
    if not LEFT_BEHIND:
        return ""
    say("    !! WARNING: it LEFT %d PROCESS(ES) RUNNING, which the driver stopped: %s" % (len(LEFT_BEHIND), "; ".join(LEFT_BEHIND)))
    return "WARNING: left %d process(es) running (stopped by the driver)" % len(LEFT_BEHIND)


def do(title, cmd, section, key, ok="BUILT", cwd=None, timeout=600, detail="", env=None):
    """One logged step. -> True when it passed."""
    log = step(title)
    t0 = time.time()
    status = run(cmd, cwd=cwd, timeout=timeout, log=log, stream=STATE["verbose"], env=env, reap=(ok == "PASS"))
    took = "%.0f s" % (time.time() - t0)
    detail = (detail + "; " if detail and LEFT_BEHIND else detail) + left_behind_note()
    if status == 0:
        say("    ok (%s)" % took)
        record(section, key, ok, detail)
        return True
    why = "time limit of %d s" % timeout if status == 124 else "exit %d" % status
    say("    FAILED: %s (%s); log: %s" % (why, took, rel(log)))
    if not STATE["verbose"]:
        say(tail(log))
    record(section, key, "FAILED", "%s; log: %s" % (why, rel(log)))
    return False


def summary(title, next_commands=()):
    say("")
    say("================ " + title)
    order = ["build", "launcher", "verify", "full", "live", "dist", "docker"]
    results = sorted(STATE["results"], key=lambda r: order.index(r["section"]) if r["section"] in order else 99)
    width = max([len(r["key"]) for r in results] + [8])
    failed = 0
    for r in results:
        st = r["status"]
        text = st
        detail = ("(%s)" % r["detail"]) if st == "SKIPPED" and r["detail"] else r["detail"]
        say("  %-8s %-*s  %s" % (text, width, r["key"], detail))
        failed += st == "FAILED"
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    say("  " + " ".join("%s=%d" % (k.lower(), v) for k, v in sorted(counts.items())))
    if next_commands:
        say("")
        say("next commands:")
        for c in next_commands:
            say("  " + c)
    return failed


REQUIRABLE = COMPONENTS + ["live", "harness", "conformance", "test_all", "docker"]


def enforce_require(require):
    """--require a,b: a SKIPPED result of one of these becomes FAILED. A name
    matches a result when it is one of the words of the result's name:
    `java` matches "java" and "conformance java"; `live` matches "live idp"."""
    for want in require:
        for r in STATE["results"]:
            words = r["key"].replace(":", " ").split(" ")
            if want in words and r["status"] == "SKIPPED":
                r["status"] = "FAILED"
                r["detail"] = "required with --require, but skipped: " + r["detail"]


# --------------------------------------------------------------------------- the virtualenv

def stamp_value(mode, base):
    h = hashlib.sha256()
    for path in (P("pyproject.toml"), os.path.join(HERE, "requirements-dev.txt")):
        with open(path, "rb") as f:
            h.update(f.read())
    h.update(("%s %s %s" % (mode, base["version"], ROOT)).encode("utf-8"))
    return h.hexdigest()


def site_packages(py):
    s, text = capture([py, "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"], timeout=60)
    return text.strip().splitlines()[-1] if s == 0 and text.strip() else None


def ensure_venv():
    """Creates .venv and installs the package editable, once. -> True when the
    reference can run from it."""
    base = doctor.find_base_python()
    if base is None or base["version"] < (3, 10):
        found = doctor.vstr(base["version"]) if base else "none"
        say("")
        say("=== python: no Python 3.10+ was found (found: %s)" % found)
        record("build", "python", "FAILED", "needs Python 3.10+ (found: %s); see `python scripts/doctor.py`" % found)
        return False
    if not base["venv"]:
        record("build", "python", "FAILED", "%s has no venv module (Debian/Ubuntu: apt-get install python3-venv)" % base["executable"])
        return False
    offline = STATE["offline"]
    mode = "offline" if offline else "online"
    want = stamp_value(mode, base)
    stamp = os.path.join(VENV, ".sd-stamp")
    alive = os.path.isfile(VENV_PY) and capture([VENV_PY, "-c", "import sys"], timeout=60)[0] == 0
    current = None
    if alive and os.path.isfile(stamp):
        with io.open(stamp, encoding="utf-8") as f:
            current = f.read().strip()
    if alive and current == want:
        d = doctor.probe_python([VENV_PY]) or {}
        say("")
        say("=== python: %s is up to date (Python %s, cryptography %s)" % (rel(VENV), doctor.vstr(d.get("version")), d.get("cryptography")))
        record("build", "python", "BUILT", "%s up to date: Python %s, smartdelegate %s editable, cryptography %s"
               % (rel(VENV), doctor.vstr(d.get("version")), VERSION, d.get("cryptography")))
        STATE["python"] = VENV_PY
        return True

    if not alive:
        args = [base["executable"], "-m", "venv"] + (["--clear"] if os.path.isdir(VENV) else [])
        if offline:
            args.append("--system-site-packages")     # the only place `cryptography` can come from without a network
        log = step("python: create %s with %s (Python %s)" % (rel(VENV), base["executable"], doctor.vstr(base["version"])))
        if run(args + [VENV], timeout=limit("venv", 300), log=log) != 0:
            say(tail(log))
            record("build", "python", "FAILED", "python -m venv failed; log: " + rel(log))
            return False
        say("    ok")
    _ENV.clear()
    STATE["python"] = VENV_PY

    if offline:
        # No index, so no isolated build environment for an editable install:
        # a .pth file makes src/ importable instead. The console script
        # .venv/bin/smartdelegate is then not created; build/bin/smartdelegate is.
        log = step("python: offline, so src/ goes on the path with a .pth file (no pip)")
        sp = site_packages(VENV_PY)
        if not sp:
            record("build", "python", "FAILED", "could not find site-packages of " + rel(VENV))
            return False
        with io.open(os.path.join(sp, "smartdelegate-dev.pth"), "w", encoding="utf-8") as f:
            f.write(P("src") + "\n")
        d = doctor.probe_python([VENV_PY]) or {}
        if not d.get("cryptography"):
            msg = ("--offline: the package `cryptography` is not installed for %s and cannot be downloaded. "
                   "Run once without --offline, or install it system-wide first." % base["executable"])
            say("    FAILED: " + msg)
            record("build", "python", "FAILED", msg)
            return False
        say("    ok")
        detail = "%s (offline: src/ on the path via .pth, system cryptography %s)" % (rel(VENV), d["cryptography"])
    else:
        log = step("python: editable install of the package (pip, -e .), with cryptography")
        t0 = time.time()
        if run([VENV_PY, "-m", "pip", "install", "--disable-pip-version-check", "-e", ROOT], timeout=limit("pip", 900), log=log, stream=STATE["verbose"]) != 0:
            say("    FAILED; log: " + rel(log))
            say(tail(log))
            record("build", "python", "FAILED", "the editable install (pip, -e .) failed (no network? try --offline); log: " + rel(log))
            return False
        say("    ok (%.0f s)" % (time.time() - t0))
        # stale .pth of an earlier --offline run
        sp = site_packages(VENV_PY)
        if sp and os.path.isfile(os.path.join(sp, "smartdelegate-dev.pth")):
            os.unlink(os.path.join(sp, "smartdelegate-dev.pth"))
        log = step("python: optional test and release extras (scripts/requirements-dev.txt)")
        if run([VENV_PY, "-m", "pip", "install", "--disable-pip-version-check", "-r", os.path.join(HERE, "requirements-dev.txt")],
               timeout=limit("pip", 900), log=log, stream=STATE["verbose"]) == 0:
            say("    ok")
            extras = ("BUILT", "build, psycopg2-binary, PyYAML (scripts/requirements-dev.txt)")
        else:
            say("    not installed (optional); log: " + rel(log))
            extras = ("SKIPPED", "pip could not install scripts/requirements-dev.txt; `dist` and the PostgreSQL tests need them; log: " + rel(log))
        d = doctor.probe_python([VENV_PY]) or {}
        detail = "%s: Python %s, smartdelegate %s editable, cryptography %s" % (rel(VENV), doctor.vstr(d.get("version")), VERSION, d.get("cryptography"))
    record("build", "python", "BUILT", detail)
    if not offline:
        record("build", "python extras", extras[0], extras[1])
        if extras[0] != "BUILT":
            return True          # no stamp: the next run tries the extras again
    with io.open(stamp, "w", encoding="utf-8") as f:
        f.write(want + "\n")
    return True


# --------------------------------------------------------------------------- building the ports

def skip_reason(rows, key):
    r = next(x for x in rows if x["key"] == key)
    return "%s: %s%s" % (r["tool"], r["status"], (" (" + r["detail"] + ")") if r["detail"] and r["status"] != doctor.OK else "")


def java_native(out_jar):
    """javac + jar without a shell script: what ports/java/build.sh does,
    minus the class-data archive. Used where that script cannot run."""
    classes = os.path.join(os.path.dirname(out_jar), "classes")
    shutil.rmtree(classes, ignore_errors=True)
    os.makedirs(classes)
    sources = []
    for d, _, files in os.walk(P("ports", "java", "src", "main", "java")):
        sources += [os.path.join(d, f) for f in files if f.endswith(".java")]
    argfile = os.path.join(os.path.dirname(out_jar), "sources.txt")
    with io.open(argfile, "w", encoding="utf-8") as f:
        for s in sorted(sources):
            f.write('"%s"\n' % s.replace("\\", "\\\\"))
    log = os.path.join(LOGS, "java-native.log")
    if run([tool("javac"), "-nowarn", "--release", "17", "-encoding", "UTF-8", "-d", classes, "@" + argfile], timeout=limit("java", 600), log=log) != 0:
        return False, log
    has_cli = os.path.isfile(os.path.join(classes, "dev", "smartdelegate", "Cli.class"))
    manifest = os.path.join(os.path.dirname(out_jar), "manifest.txt")
    with io.open(manifest, "w", encoding="utf-8", newline="\n") as f:
        if has_cli:
            f.write("Main-Class: dev.smartdelegate.Cli\n")
        f.write("Implementation-Title: smartdelegate-java\nImplementation-Version: %s\n" % VERSION)
    ok = run([tool("jar"), "--create", "--file", out_jar, "--manifest", manifest, "-C", classes, "."], timeout=limit("java", 600), log=log) == 0
    for p in (argfile, manifest):
        os.unlink(p)
    return ok, log


def java_script():
    """The port's own build script for this platform, or None."""
    p = P("ports", "java", "build.cmd" if IS_WINDOWS else "build.sh")
    return p if os.path.isfile(p) and not (NATIVE and not IS_WINDOWS) else None


def java_jar():
    """The jar the launcher should use, or None."""
    for p in (JAVA_JAR, JAVA_JAR_NATIVE):
        if os.path.isfile(p):
            return p
    return None


def java_up_to_date():
    """True when the jar of the port's own build script is newer than every source it is made from."""
    if not os.path.isfile(JAVA_JAR):
        return False
    built_at = os.path.getmtime(JAVA_JAR)
    inputs = [P("ports", "java", "build.sh"), P("ports", "java", "build.cmd")]
    for d, _, files in os.walk(P("ports", "java", "src", "main")):
        inputs += [os.path.join(d, f) for f in files]
    return all(os.path.getmtime(p) <= built_at for p in inputs if os.path.isfile(p))


def build_java(quiet=False):
    script = java_script()
    if script and not quiet and java_up_to_date():
        say("")
        say("=== java: %s is newer than its sources; not rebuilt" % rel(JAVA_JAR))
        record("build", "java", "BUILT", rel(JAVA_JAR) + " (up to date)")
        return True
    if script:
        cmd = ["cmd", "/c", script] if IS_WINDOWS else ["sh", script]
        if quiet:
            return run(cmd, cwd=P("ports", "java"), timeout=limit("java", 600), log=os.path.join(LOGS, "java-rebuild.log")) == 0
        return do("java: " + rel(script), cmd, "build", "java", cwd=P("ports", "java"), timeout=limit("java", 600), detail=rel(JAVA_JAR))
    if not quiet:
        step("java: javac + jar (no ports/java/%s to run here)" % ("build.cmd" if IS_WINDOWS else "build.sh"))
    os.makedirs(os.path.dirname(JAVA_JAR_NATIVE), exist_ok=True)
    ok, log = java_native(JAVA_JAR_NATIVE)
    if quiet:
        return ok
    if ok:
        say("    ok")
        record("build", "java", "BUILT", rel(JAVA_JAR_NATIVE) + " (built by scripts/sd.py: no class-data archive)")
    else:
        say("    FAILED; log: " + rel(log))
        say(tail(log))
        record("build", "java", "FAILED", "javac or jar failed; log: " + rel(log))
    return ok


def ensure_java_jar():
    """ports/java/run_conformance.sh removes ports/java/build, and with it the
    jar the launcher runs. Build it again when it is gone."""
    if selected("java") and have("javac") and have("java") and not java_jar() \
            and any(r["key"] == "java" and r["status"] == "BUILT" for r in STATE["results"]):
        say("    (the Java test harness removed ports/java/build; building the jar again)")
        build_java(quiet=True)


def cargo_cache_present():
    home = os.environ.get("CARGO_HOME") or os.path.join(os.path.expanduser("~"), ".cargo")
    cache = os.path.join(home, "registry", "cache")
    return os.path.isdir(cache) and any(os.scandir(cache)) or os.path.isdir(P("ports", "rust", "vendor"))


def build_ports(rows):
    u = lambda k: doctor.usable(rows, k)
    os.makedirs(BIN, exist_ok=True)

    if selected("java"):
        if u("java"):
            build_java()
        else:
            record("build", "java", "SKIPPED", skip_reason(rows, "java"))

    if selected("node"):
        if u("node"):
            record("build", "node", "BUILT", "no build step (ports/node has no dependencies)")
        else:
            record("build", "node", "SKIPPED", skip_reason(rows, "node"))
    if selected("js"):
        if u("node"):
            record("build", "js", "BUILT", "no build step (ports/js is a REST client; `test` and `all` run its tests)")
        else:
            record("build", "js", "SKIPPED", skip_reason(rows, "node"))

    if selected("go"):
        if u("go"):
            do("go: go build -o %s ./cmd/smartdelegate-go" % rel(GO_BIN), [tool("go"), "build", "-trimpath", "-o", GO_BIN, "./cmd/smartdelegate-go"],
               "build", "go", cwd=P("ports", "go"), timeout=limit("go", 900), detail=rel(GO_BIN))
        else:
            record("build", "go", "SKIPPED", skip_reason(rows, "go"))

    if selected("php"):
        if u("php"):
            record("build", "php", "BUILT", "no build step (ports/php has no Composer packages)")
        else:
            record("build", "php", "SKIPPED", skip_reason(rows, "php"))

    if selected("rust"):
        if not u("rust"):
            record("build", "rust", "SKIPPED", skip_reason(rows, "rust"))
        elif STATE["offline"] and not os.path.isfile(RUST_BIN) and not cargo_cache_present():
            step("rust: cargo build --release --offline")
            msg = ("--offline: the first build of ports/rust downloads its crates (Cedar and others) from crates.io, and there is no "
                   "crate cache here. Run once without --offline, or run `cargo fetch --locked` in ports/rust while online.")
            say("    FAILED: " + msg)
            record("build", "rust", "FAILED", msg)
        else:
            cmd = [tool("cargo"), "build", "--release", "--locked"] + (["--offline"] if STATE["offline"] else [])
            ok = do("rust: %s (a first build compiles Cedar: several minutes)" % " ".join(["cargo"] + cmd[1:]), cmd, "build", "rust",
                    cwd=P("ports", "rust"), timeout=limit("rust", 3600), detail=rel(RUST_BIN))
            if not ok and STATE["offline"]:
                STATE["results"][-1]["detail"] += "; --offline: the crates must already be in cargo's cache (run once online, or `cargo fetch --locked`)"


# --------------------------------------------------------------------------- launchers

SH_HEAD = ('#!/bin/sh\n# Generated by scripts/sd.py (the bootstrap); build/ is git-ignored. Do not edit.\n'
           'here="$(cd "$(dirname "$0")" && pwd -P)"\nroot="$(cd "$here/../.." && pwd -P)"\n')
CMD_HEAD = "@echo off\r\nrem Generated by scripts/sd.py (the bootstrap); build\\ is git-ignored. Do not edit.\r\nsetlocal\r\nset \"ROOT=%~dp0..\\..\"\r\n"


def in_root(path, win):
    """The path as the launcher writes it: relative to the repository when it is inside."""
    if os.path.splitdrive(path)[0].lower() != os.path.splitdrive(ROOT)[0].lower():
        return path
    r = os.path.relpath(path, ROOT)
    if r.startswith(".."):
        return path
    return ("%ROOT%\\" + r.replace("/", "\\")) if win else ("$root/" + r.replace(os.sep, "/"))


def write_launcher(name, argv_sh, argv_cmd, cmd_env=""):
    """Writes build/bin/<name> (or <name>.cmd on Windows). -> its path"""
    if IS_WINDOWS:
        path = os.path.join(BIN, name + ".cmd")
        body = CMD_HEAD + cmd_env + argv_cmd + " %*\r\nexit /b %ERRORLEVEL%\r\n"
        with io.open(path, "w", encoding="ascii", newline="") as f:
            f.write(body)
    else:
        path = os.path.join(BIN, name)
        with io.open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(SH_HEAD + "exec " + argv_sh + ' "$@"\n')
        os.chmod(path, 0o755)
    return path


def built(key):
    return any(r["section"] == "build" and r["key"] == key and r["status"] == "BUILT" for r in STATE["results"])


def write_launchers():
    """Uniform command lines for every engine in build/bin. -> {port: path}"""
    os.makedirs(BIN, exist_ok=True)
    q = lambda p: '"%s"' % p
    made = {}
    if built("python"):
        # UTF-8 on pipes, like every other engine's launcher; a value the caller set wins
        made["python"] = write_launcher("smartdelegate", q(in_root(VENV_PY, False)) + " -m sf_smartdelegate",
                                        q(in_root(VENV_PY, True)) + " -m sf_smartdelegate",
                                        cmd_env='if not defined PYTHONUTF8 set "PYTHONUTF8=1"\r\n')
    if built("java"):
        own = P("ports", "java", "bin", "smartdelegate-java" + (".cmd" if IS_WINDOWS else ""))
        jar = java_jar()
        if os.path.isfile(own) and jar == JAVA_JAR:
            made["java"] = write_launcher("smartdelegate-java", ("sh " if not os.access(own, os.X_OK) else "") + q(in_root(own, False)),
                                          "call " + q(in_root(own, True)))
        elif jar and jar_main_class(jar):
            made["java"] = write_launcher("smartdelegate-java", "java -Dfile.encoding=UTF-8 -jar " + q(in_root(jar, False)),
                                          "java -Dfile.encoding=UTF-8 -jar " + q(in_root(jar, True)))
        else:
            record("launcher", "smartdelegate-java", "SKIPPED", "the Java port in this checkout has no command line (no dev.smartdelegate.Cli)")
    if built("node"):
        cli = P("ports", "node", "bin", "cli.mjs")
        made["node"] = write_launcher("smartdelegate-node", "node " + q(in_root(cli, False)), "node " + q(in_root(cli, True)))
    if built("php"):
        cli = P("ports", "php", "bin", "smartdelegate-php")
        made["php"] = write_launcher("smartdelegate-php", "php " + q(in_root(cli, False)), "php " + q(in_root(cli, True)))
    if built("rust"):
        made["rust"] = write_launcher("smartdelegate-rust", q(in_root(RUST_BIN, False)), q(in_root(RUST_BIN, True)))
    if built("go"):
        made["go"] = GO_BIN                      # the binary itself; no shim needed
    # launchers of ports that are not built (any more) would only confuse
    for port, name in (("java", "smartdelegate-java"), ("node", "smartdelegate-node"), ("php", "smartdelegate-php"), ("rust", "smartdelegate-rust")):
        stale = os.path.join(BIN, name + (".cmd" if IS_WINDOWS else ""))
        if port not in made and selected(port) and os.path.isfile(stale):
            os.unlink(stale)
    return made


def jar_main_class(jar):
    try:
        with zipfile.ZipFile(jar) as z:
            return "Main-Class:" in z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
    except (OSError, KeyError, zipfile.BadZipFile):
        return False


def check_launchers(made):
    for port in PORTS:
        if port not in made:
            continue
        path = made[port]
        status, text = capture([path, "version"], cwd=tempfile.gettempdir(), timeout=limit("launcher", 120))
        line = next((l.strip() for l in text.splitlines() if l.strip() and not l.startswith("Picked up ")), "")
        name = os.path.basename(path)
        if status == 0 and VERSION in line:
            record("launcher", name, "PASS", "`%s version` -> %s" % (rel(path), line))
        else:
            # show enough of the output to act on (a JVM names the real cause on its second line)
            shown = " | ".join(l.strip() for l in text.splitlines() if l.strip() and not l.startswith("Picked up "))[:400]
            hint = ""
            if port == "java" and os.environ.get("JAVA_HOME"):
                hint = " [JAVA_HOME=%s; the launcher uses java from PATH first, set SMARTDELEGATE_JAVA to force one]" % os.environ["JAVA_HOME"]
            record("launcher", name, "FAILED", "`%s version` gave exit %s: %s%s" % (rel(path), status, shown, hint))


# --------------------------------------------------------------------------- conformance

def count_suites(text):
    """The numbers a port printed, in the forms ports/conformance/run.sh reads.
    -> ((eval cases, failed) or None, (conformance cases, failed) or None)"""
    ev = co = None
    for line in text.splitlines():
        m = re.match(r"^.*(?:eval|policy evaluation[^:]*): ([0-9]+) cases, ([0-9]+) failed", line)
        if m:
            ev = (int(m.group(1)), int(m.group(2)))
        m = re.match(r"^.*[^0-9]([0-9]+) eval cases match real Cedar", line)
        if m:
            ev = (int(m.group(1)), 0)
        m = re.match(r"^(?:.* )?conformance(?: \(in-process\))?: ([0-9]+) cases, (?:[0-9]+ steps, )?([0-9]+) failed", line)
        if m:
            co = (int(m.group(1)), int(m.group(2)))
    return ev, co


def conformance_native(port, rows):
    """One port's two shared suites without bash. -> (status or 77, output, skip reason)"""
    py = python()
    u = lambda k: doctor.usable(rows, k)
    t = limit("conformance", 1800)
    if port == "python":
        s, out = capture([py, "-m", "sf_smartdelegate", "conformance", VECTORS, BUNDLE], timeout=t)
        if s != 0:
            return s, out, ""
        s, out2 = capture([py, "-m", "unittest", "test_cedar_eval"], cwd=P("tests"), timeout=t)
        if s != 0:
            return s, out + out2, ""
        with io.open(P("spec", "conformance", "eval", "cases.json"), encoding="utf-8") as f:
            n = len(json.load(f)["cases"])
        return 0, out + out2 + "eval: %d cases, 0 failed\n" % n, ""
    if port == "java":
        if not u("java"):
            return 77, "", skip_reason(rows, "java")
        # the port's own command line, from the jar its build script (or java_native) makes
        if not java_jar() and not build_java(quiet=True):
            return 1, "the Java jar could not be built; log: %s\n" % rel(os.path.join(LOGS, "java-native.log")), ""
        return capture([tool("java"), "-Dfile.encoding=UTF-8", "-jar", java_jar(), "conformance", "--root", ROOT], timeout=t) + ("",)
    if port == "node":
        if not u("node"):
            return 77, "", skip_reason(rows, "node")
        return capture([tool("node"), P("ports", "node", "bin", "cli.mjs"), "conformance", VECTORS, BUNDLE], timeout=t) + ("",)
    if port == "go":
        if not u("go"):
            return 77, "", skip_reason(rows, "go")
        with tempfile.TemporaryDirectory(prefix="sd-go-") as tmp:
            exe = os.path.join(tmp, "smartdelegate-go" + EXE)
            s, out = capture([tool("go"), "build", "-o", exe, "./cmd/smartdelegate-go"], cwd=P("ports", "go"), timeout=t)
            if s != 0:
                return s, out, ""
            return capture([exe, "conformance", "--root", ROOT], timeout=t) + ("",)
    if port == "php":
        if not u("php"):
            return 77, "", skip_reason(rows, "php")
        return capture([tool("php"), P("ports", "php", "bin", "smartdelegate-php"), "conformance", VECTORS, BUNDLE], timeout=t) + ("",)
    if port == "rust":
        if not u("rust"):
            return 77, "", skip_reason(rows, "rust")
        offline = ["--offline"] if STATE["offline"] else []
        s, out = capture([tool("cargo"), "build", "--release", "--locked"] + offline, cwd=P("ports", "rust"), timeout=limit("rust", 3600))
        if s != 0:
            return s, out, ""
        s, out = capture([RUST_BIN, "conformance", VECTORS, BUNDLE], timeout=t)
        if s != 0:
            return s, out, ""
        s, out2 = capture([tool("cargo"), "test", "--release", "--locked", "-p", "smartdelegate-core", "--test", "conformance"] + offline
                          + ["--", "--nocapture", "--test-threads=1"], cwd=P("ports", "rust"), timeout=limit("rust", 3600))
        return s, out + out2, ""
    raise ValueError(port)


def conformance(rows, ports, section="verify"):
    """The two shared suites against the given ports. One result per port."""
    ports = [p for p in PORTS if p in ports]
    if not ports:
        return
    run_sh = P("ports", "conformance", "run.sh")
    if not NATIVE and have("bash") and os.path.isfile(run_sh):
        log = step("conformance: ports/conformance/run.sh " + " ".join(ports))
        t0 = time.time()
        status = run(["bash", run_sh] + ports, timeout=limit("conformance", 1800) * 2, log=log, reap=True)
        left_behind_note()
        with io.open(log, encoding="utf-8", errors="replace") as f:
            text = f.read()
        seen = set()
        for line in text.splitlines():
            m = re.match(r"^(%s): (PASS|SKIP|FAIL)\s*(.*)$" % "|".join(PORTS), line)
            if m:
                say("    " + line)
                seen.add(m.group(1))
                st = {"PASS": "PASS", "SKIP": "SKIPPED", "FAIL": "FAILED"}[m.group(2)]
                record(section, "conformance " + m.group(1), st, m.group(3).strip("()") + ("; log: " + rel(log) if st == "FAILED" else ""))
        for p in ports:
            if p not in seen:
                record(section, "conformance " + p, "FAILED", "run.sh printed no line for it (exit %s); log: %s" % (status, rel(log)))
        say("    (%.0f s)" % (time.time() - t0))
        if status != 0 and not STATE["verbose"]:
            say(tail(log, 25))
        return
    step("conformance (without bash): " + " ".join(ports))
    for p in ports:
        status, out, why = conformance_native(p, rows)
        log = os.path.join(LOGS, "conformance-%s.log" % p)
        os.makedirs(LOGS, exist_ok=True)
        with io.open(log, "w", encoding="utf-8") as f:
            f.write(out)
        if status == 77:
            say("    %s: SKIP (%s)" % (p, why))
            record(section, "conformance " + p, "SKIPPED", why)
            continue
        ev, co = count_suites(out)
        problem = ""
        if status != 0:
            problem = "exit %s" % status
        elif not ev or not co:
            problem = "exit 0, but its output does not report both suites"
        elif ev[1] or co[1]:
            problem = "exit 0, but it reports failed cases"
        elif not ev[0] or not co[0]:
            problem = "exit 0, but a suite ran no cases"
        if problem:
            say("    %s: FAIL (%s)" % (p, problem))
            say(tail(log, 25))
            record(section, "conformance " + p, "FAILED", problem + "; log: " + rel(log))
        else:
            say("    %s: PASS (%d eval, %d conformance)" % (p, ev[0], co[0]))
            record(section, "conformance " + p, "PASS", "%d eval, %d conformance" % (ev[0], co[0]))


# --------------------------------------------------------------------------- the other suites

def verify_quick(rows, made):
    py = python()
    launcher = made.get("python")
    cmd = [launcher, "--demo"] if launcher else [py, "-m", "sf_smartdelegate", "--demo"]
    log = step("demo: %s --demo" % (rel(launcher) if launcher else "python -m sf_smartdelegate"))
    status = run(cmd, timeout=limit("demo", 120), log=log)
    with io.open(log, encoding="utf-8", errors="replace") as f:
        text = f.read()
    if status == 0 and "hash chain verifies" in text:
        say("    ok: nine steps, the audit hash chain verifies")
        record("verify", "demo", "PASS", "smartdelegate --demo")
    else:
        say(tail(log))
        record("verify", "demo", "FAILED", "exit %s; log: %s" % (status, rel(log)))
    broken = [p for p in PORTS if selected(p) and any(r["section"] == "build" and r["key"] == p and r["status"] == "FAILED" for r in STATE["results"])]
    for p in broken:
        record("verify", "conformance " + p, "SKIPPED", "its build failed (above), so there is nothing to run")
    conformance(rows, [p for p in PORTS if selected(p) and p not in broken])
    ensure_java_jar()
    harness(quick=True)


def harness(quick=False, section="verify"):
    """The small scenario harness of this repository (harness/README.md) on the reference engine."""
    py = python()
    out = os.path.join(REPORTS, "harness")
    do("example company: smartdelegate policy test --bundle examples/company", [py, "-m", "sf_smartdelegate", "policy", "test", "--bundle", P("examples", "company")],
       section, "example company policy tests", ok="PASS", timeout=limit("harness", 900))
    do("harness: python -m harness run (business scenarios, once each)", [py, "-m", "harness", "run", "--out", out],
       section, "harness run", ok="PASS", timeout=limit("harness", 900), detail="report: " + rel(os.path.join(out, "report.html")))


def matrix(section="full"):
    os.makedirs(REPORTS, exist_ok=True)
    report = os.path.join(REPORTS, "matrix.json")
    cmd = [python(), P("ports", "conformance", "matrix.py"), "--report", report]
    if STATE["only"] is not None:
        cmd += ["--ports", ",".join(p for p in PORTS if p in STATE["only"] or p == "python")]
    do("cross-port matrix: ports/conformance/matrix.py", cmd, section, "cross-port matrix", ok="PASS", timeout=limit("matrix", 3600),
       detail="report: " + rel(report))


def unit_tests(section="full"):
    do("reference unit tests: cd tests && python -m unittest", [python(), "-m", "unittest"], section, "reference unit tests", ok="PASS",
       cwd=P("tests"), timeout=limit("test", 1800))


def powershell():
    for name in (os.environ.get("SD_POWERSHELL"), "pwsh", "powershell"):
        if name and shutil.which(name):
            return shutil.which(name)
    return None


def test_all(section="full"):
    """Everything the repository's own runner runs: test_all.sh, or test_all.ps1 on Windows."""
    logdir = os.path.join(LOGS, "test_all")
    if NATIVE:
        ps = powershell()
        if not ps:
            record(section, "test_all", "SKIPPED", "test_all.ps1 needs PowerShell (pwsh or powershell), and none is on PATH")
            return
        cmd, name = [ps, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", P("test_all.ps1")], "test_all.ps1"
    elif have("bash"):
        cmd, name = ["bash", P("test_all.sh"), "--logs", logdir], "test_all.sh"
    else:
        record(section, "test_all", "SKIPPED", "test_all.sh needs bash")
        return
    log = step("%s: every suite of the repository (several minutes)" % name)
    t0 = time.time()
    status = run(cmd, timeout=limit("test_all", 5400), log=log, stream=STATE["verbose"], reap=True)
    left = left_behind_note()
    text = ""
    if os.path.isfile(log):
        with io.open(log, encoding="utf-8", errors="replace") as f:
            text = f.read()
    block = text[text.rfind("================ summary"):] if "================ summary" in text else ""
    for line in block.splitlines():
        say("    " + line)
    m = re.search(r"pass=(\d+) skip=(\d+) fail=(\d+)", block)
    counts = ("pass=%s skip=%s fail=%s" % m.groups()) if m else "no summary line"
    took = "%.0f s" % (time.time() - t0)
    if status == 0 and m and m.group(3) == "0" and int(m.group(1)) > 0:
        record(section, name, "PASS", "%s (%s)%s; logs: %s" % (counts, took, ("; " + left) if left else "", rel(logdir if not NATIVE else log)))
    else:
        if not block and not STATE["verbose"]:
            say(tail(log, 40))
        why = "time limit" if status == 124 else "exit %s" % status
        record(section, name, "FAILED", "%s, %s (%s); log: %s" % (why, counts, took, rel(log)))


WSL_HINT = "run it under WSL or on Linux: wsl bash -lc './bootstrap.sh && make live'"


LIVE_WINDOWS_WHY = {"idp": "live/idp/run.sh is a bash script that starts Keycloak",
                    "upstream": "live/run.sh is a bash script that starts PostgreSQL",
                    "boundary": "the boundary test needs Linux network namespaces and root",
                    "load": "live/run.sh is a bash script"}


def live(parts, quick=True, section="live"):
    """The suites against real services: live/idp/run.sh (a real Keycloak)
    and live/run.sh (upstream, boundary, load; `all` when all three are
    asked for). Both exit 0 pass, 1 fail, 3 nothing ran; live/run.sh prints
    one line per part, which is where each part's result is read from. A
    script that is not there is a skip. A process a script leaves running is
    a failure, whatever its tests said."""
    parts = [p for p in LIVE_PARTS if p in parts]
    runs = []                                  # (script, arguments, the parts it reports)
    if "idp" in parts:
        runs.append((P("live", "idp", "run.sh"), [], ["idp"]))
    rest = [p for p in parts if p != "idp"]
    q = ["--quick"] if quick else []
    if len(rest) == 3:
        runs.append((P("live", "run.sh"), ["all"] + q, rest))
    else:
        runs += [(P("live", "run.sh"), [p] + q, [p]) for p in rest]
    for script, args, covered in runs:
        if not os.path.isfile(script):
            for part in covered:
                record(section, "live " + part, "SKIPPED", "%s is not in this checkout" % rel(script))
            continue
        if IS_WINDOWS:
            for part in covered:
                record(section, "live " + part, "SKIPPED", "%s; %s" % (LIVE_WINDOWS_WHY[part], WSL_HINT))
            continue
        if not have("bash"):
            for part in covered:
                record(section, "live " + part, "SKIPPED", "needs bash")
            continue
        cmd = ([script] if os.access(script, os.X_OK) else ["bash", script]) + args
        log = step("live %s: %s %s" % (", ".join(covered), rel(script), " ".join(args)))
        t0 = time.time()
        pg_before = private_pg_running()
        status = run(cmd, timeout=limit("live", 4500), log=log, stream=STATE["verbose"], reap=True)
        took = "%.0f s" % (time.time() - t0)
        with io.open(log, encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f.read().splitlines()[1:] if l.strip()]
        # The safety net. The scripts stop what they start and check it themselves; if this ever
        # triggers, a script leaked a process, and that is reported as a failure of its own.
        leaks = ["%s (stopped by the driver)" % x for x in LEFT_BEHIND]
        leaks += [l for l in lines if "LEFT RUNNING" in l]
        if pg_before is False and private_pg_running():
            run(["bash", P("live", "upstream", "pg.sh"), "stop"], timeout=120, log=log)
            leaks.append("the private PostgreSQL cluster (stopped by the driver with live/upstream/pg.sh stop)")
        if leaks:
            say("    " + "!" * 70)
            say("    !! LEFT RUNNING after %s ended:" % rel(script))
            for x in leaks:
                say("    !!   " + x)
            say("    !! A live suite must stop everything it starts. This is a FAILURE, reported below.")
            say("    " + "!" * 70)
            record(section, "live leftovers (%s)" % ", ".join(covered), "FAILED",
                   "%d process(es) were still running when %s ended: %s; log: %s" % (len(leaks), rel(script), "; ".join(leaks)[:400], rel(log)))
        for part in covered:
            outcome, why = live_outcome(part, status, lines, single=(len(covered) == 1))
            key = "live " + part
            if outcome == "PASS":
                say("    %s: PASS%s" % (part, (" " + why) if why else ""))
                record(section, key, "PASS", "%s%s; log: %s" % (why + "; " if why else "", took if len(covered) == 1 else "part of a %s run" % took, rel(log)))
            elif outcome == "SKIPPED":
                say("    %s: SKIP %s" % (part, why))
                record(section, key, "SKIPPED", why)
            else:
                say("    %s: FAILED (%s)" % (part, why))
                record(section, key, "FAILED", "%s; log: %s" % (why, rel(log)))
        if status not in (0, 3) and not STATE["verbose"]:
            say(tail(log))


def load_gated(section="live"):
    """The load and soak run in its full form, gated by the thresholds file:
    the command `live/run.sh load` runs, started directly so that its report
    lands in build/reports/load. Exit 0 within the thresholds, 1 a breach or
    a failed run, 3 no target could run."""
    key = "live load"
    main_py = P("live", "load", "__main__.py")
    if not os.path.isfile(main_py):
        record(section, key, "SKIPPED", "live/load is not in this checkout")
        return
    if IS_WINDOWS:
        record(section, key, "SKIPPED", "the load suite has only been run on Linux; " + WSL_HINT)
        return
    out = os.path.join(REPORTS, "load")
    cmd = [python(), "-m", "live.load", "--targets", "python,rust", "--duration", "12", "--warmup", "2", "--soak", "20000", "--overload",
           "--check", P("live", "load", "thresholds.json"), "--out", out]
    log = step("load: python -m live.load --targets python,rust --duration 12 --warmup 2 --soak 20000 --overload --check live/load/thresholds.json")
    t0 = time.time()
    status = run(cmd, timeout=limit("live", 4500), log=log, stream=STATE["verbose"], reap=True)
    took = "%.0f s" % (time.time() - t0)
    with io.open(log, encoding="utf-8", errors="replace") as f:
        lines = [l.strip() for l in f.read().splitlines()[1:] if l.strip()]
    verdict = next((l for l in reversed(lines) if l.startswith("thresholds:")), "")
    left = left_behind_note()
    if left:
        record(section, "live leftovers (load)", "FAILED", "%s; log: %s" % (left, rel(log)))
    if status == 0:
        say("    PASS (%s): %s" % (took, verdict))
        record(section, key, "PASS", "%s; %s; report: %s" % (verdict, took, rel(os.path.join(out, "report.html"))))
    elif status == 3:
        why = "; ".join(l[len("SKIPPED: "):] for l in lines if l.startswith("SKIPPED: "))[:300] or "no target could run"
        say("    SKIP: " + why)
        record(section, key, "SKIPPED", why)
    else:
        say("    FAILED (%s): %s" % ("time limit" if status == 124 else "exit %d" % status, verdict))
        if not STATE["verbose"]:
            say(tail(log))
        record(section, key, "FAILED", "%s %s; report: %s; log: %s" % ("time limit" if status == 124 else "exit %d" % status, verdict, rel(out), rel(log)))


def private_pg_running():
    """Is the private PostgreSQL of live/upstream/pg.sh up? None when that cannot be told (no script, or attached with SD_PG_DSN)."""
    script = P("live", "upstream", "pg.sh")
    if not os.path.isfile(script) or os.environ.get("SD_PG_DSN") or not have("bash"):
        return None
    try:
        return subprocess.call(["bash", script, "status"], env=child_env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=60) == 0
    except (OSError, subprocess.SubprocessError):
        return None


def live_outcome(part, status, lines, single=True):
    """What a live script's run means for one part. -> (PASS | SKIPPED | FAILED, reason)

    Exit status: 0 something ran and nothing failed, 1 a failure, 3 nothing
    ran. live/run.sh prints one line per part (`upstream  PASS RESULT ran=86
    ...`, `boundary  SKIP needs root`): that line decides for the part, so a
    skipped part of a run that passed as a whole is SKIPPED, never PASS. A
    PASS line that reports no test as run is a skip as well."""
    last = lines[-1][:200] if lines else ""
    if status == 124:
        return "FAILED", "time limit"
    said = None
    for l in lines:
        m = re.match(r"^%s\s+(PASS|FAIL|SKIP)\b\s*(.*)$" % re.escape(part), l)
        if m:
            said = (m.group(1), m.group(2).strip()[:240])
    if said is None:
        if status == 3:
            return "SKIPPED", last or "the script exited with 3: nothing ran"
        if status != 0:
            return "FAILED", "exit %d%s" % (status, "" if single else " and no line for this part")
        if not single:
            return "FAILED", "exit 0, but the script printed no line for this part"
        text = " ".join(lines)
        ran, skipped = re.search(r"Ran (\d+) tests?", text), re.search(r"skipped=(\d+)", text)
        if ran and (ran.group(1) == "0" or (skipped and ran.group(1) == skipped.group(1))):
            return "SKIPPED", "no test ran: the suite skipped itself"
        return "PASS", next((l[l.index("PASSED: ") + 8:][:200] for l in reversed(lines) if "PASSED: " in l), "")
    verdict, text = said
    if verdict == "FAIL":
        return "FAILED", text or "exit %d" % status
    if verdict == "SKIP":
        return "SKIPPED", text or "the script reported SKIP"
    ran = re.search(r"\bran=(\d+)", text) or re.search(r"Ran (\d+) tests?", text)
    if ran and ran.group(1) == "0":
        return "SKIPPED", "the script printed PASS, but no test ran: " + text
    if status not in (0, 3) and single:
        return "FAILED", "exit %d: %s" % (status, text)
    return "PASS", text


# --------------------------------------------------------------------------- dist

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def host_triple():
    s, text = capture([tool("rustc"), "-vV"], timeout=60)
    m = re.search(r"(?m)^host: (\S+)", text)
    return m.group(1) if s == 0 and m else "unknown-host"


def go_host():
    s, text = capture([tool("go"), "env", "GOOS", "GOARCH"], timeout=60)
    parts = text.split()
    return (parts[0], parts[1]) if s == 0 and len(parts) >= 2 else ("", "")


def dist_python(verify):
    py = python()
    s, _ = capture([py, "-c", "import build"], timeout=60)
    if s != 0:
        if STATE["offline"]:
            record("dist", "python sdist + wheel", "SKIPPED", "--offline: the `build` package is not installed in .venv and cannot be downloaded")
            return
        log = step("dist python: pip install build")
        if run([py, "-m", "pip", "install", "--disable-pip-version-check", "build"], timeout=limit("pip", 900), log=log) != 0:
            say(tail(log))
            record("dist", "python sdist + wheel", "FAILED", "could not install the `build` package; log: " + rel(log))
            return
    if STATE["offline"]:
        record("dist", "python sdist + wheel", "SKIPPED", "--offline: `python -m build` creates an isolated environment and downloads setuptools into it")
        return
    if not do("dist python: python -m build (sdist + wheel)", [py, "-m", "build", "--sdist", "--wheel", "--outdir", DIST, ROOT], "dist", "python sdist + wheel",
              timeout=limit("pybuild", 900), detail="sf_smartdelegate-%s.tar.gz, sf_smartdelegate-%s-py3-none-any.whl" % (VERSION, VERSION)):
        return
    if not verify:
        return
    wheel = os.path.join(DIST, "sf_smartdelegate-%s-py3-none-any.whl" % VERSION)
    tmp = tempfile.mkdtemp(prefix="sd-wheel-")
    try:
        log = step("dist python: install the wheel into a fresh virtualenv and run `sf-smartdelegate --demo`")
        venv = os.path.join(tmp, "venv")
        vpy = os.path.join(venv, "Scripts" if IS_WINDOWS else "bin", "python" + EXE)
        exe = os.path.join(venv, "Scripts" if IS_WINDOWS else "bin", "sf-smartdelegate" + EXE)
        env = child_env()
        env.pop("PYTHONPATH", None)          # the wheel must work on its own
        env.pop("VIRTUAL_ENV", None)
        ok = (run([py, "-m", "venv", venv], timeout=300, log=log, env=env) == 0
              and run([vpy, "-m", "pip", "install", "--disable-pip-version-check", wheel], timeout=limit("pip", 900), log=log, env=env) == 0
              and run([exe, "--demo"], cwd=tmp, timeout=120, log=log, env=env) == 0)
        with io.open(log, encoding="utf-8", errors="replace") as f:
            ok = ok and "hash chain verifies" in f.read()
        if ok:
            say("    ok")
            record("dist", "verify wheel", "PASS", "fresh virtualenv, the wheel installed with pip, `sf-smartdelegate --demo`")
        else:
            say(tail(log))
            record("dist", "verify wheel", "FAILED", "log: " + rel(log))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def dist_java(rows, verify):
    if not doctor.usable(rows, "java"):
        record("dist", "java jar", "SKIPPED", skip_reason(rows, "java"))
        return
    if not java_jar() and not build_java(quiet=True):
        record("dist", "java jar", "FAILED", "the jar could not be built; log: " + rel(os.path.join(LOGS, "java-rebuild.log")))
        return
    out = os.path.join(DIST, "smartdelegate-java-%s.jar" % VERSION)
    shutil.copyfile(java_jar(), out)
    record("dist", "java jar", "BUILT", os.path.basename(out) + ("" if jar_main_class(out) else " (library only: no Main-Class)"))
    if verify and jar_main_class(out):
        s, text = capture([tool("java"), "-jar", out, "version"], cwd=tempfile.gettempdir(), timeout=120)
        line = next((l for l in text.splitlines() if VERSION in l), "")
        record("dist", "verify java jar", "PASS" if s == 0 and line else "FAILED", "`java -jar %s version` -> %s" % (os.path.basename(out), line.strip() or "exit %s" % s))
    # the jar with the port's own launchers, laid out as they expect it: bin/smartdelegate-java[.cmd] -> ../build/smartdelegate.jar
    launchers = [P("ports", "java", "bin", n) for n in ("smartdelegate-java", "smartdelegate-java.cmd")]
    if not jar_main_class(out) or not all(os.path.isfile(x) for x in launchers):
        record("dist", "java launcher archive", "SKIPPED", "ports/java/bin has no launchers in this checkout, or the jar has no command line")
        return
    prefix = "smartdelegate-java-%s" % VERSION
    archive = os.path.join(DIST, prefix + ".zip")
    members = [(out, "build/smartdelegate.jar", False)] + [(x, "bin/" + os.path.basename(x), not x.endswith(".cmd")) for x in launchers]
    members += [(P("ports", "java", "README.md"), "README.md", False), (P("LICENSE"), "LICENSE", False)]
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path, arc, executable in members:
            info = zipfile.ZipInfo(prefix + "/" + arc, date_time=time.localtime(os.path.getmtime(path))[:6])
            info.external_attr = (0o100755 if executable else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(path, "rb") as f:
                z.writestr(info, f.read())
    record("dist", "java launcher archive", "BUILT", prefix + ".zip (build/smartdelegate.jar, bin/smartdelegate-java, bin/smartdelegate-java.cmd)")
    if verify and not IS_WINDOWS:
        tmp = tempfile.mkdtemp(prefix="sd-javazip-")
        try:
            with zipfile.ZipFile(archive) as z:
                z.extractall(tmp)
            launcher = os.path.join(tmp, prefix, "bin", "smartdelegate-java")
            os.chmod(launcher, 0o755)          # zipfile.extractall does not restore the mode; `unzip` does
            s, text = capture([launcher, "version"], cwd=tmp, timeout=120)
            s2, text2 = capture([launcher, "conformance", "--root", ROOT], cwd=tmp, timeout=limit("conformance", 1800))
            ev, co = count_suites(text2)
            good = s == 0 and VERSION in text and s2 == 0 and ev and co and not ev[1] and not co[1]
            record("dist", "verify java launcher archive", "PASS" if good else "FAILED",
                   ("unzipped, `bin/smartdelegate-java version` -> %s; `conformance`: %d eval, %d conformance cases, 0 failed" % (text.strip().splitlines()[-1], ev[0], co[0]))
                   if good else "exit %s/%s: %s" % (s, s2, (text + text2).strip()[-200:]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def dist_npm(rows, verify):
    for key, directory, name in (("npm tarball ports/node", P("ports", "node"), "sf-smartdelegate-%s.tgz" % VERSION),
                                 ("npm tarball ports/js", P("ports", "js"), "sf-smartdelegate-client-%s.tgz" % VERSION)):
        if not doctor.usable(rows, "node") or not doctor.usable(rows, "npm"):
            record("dist", key, "SKIPPED", skip_reason(rows, "node" if not doctor.usable(rows, "node") else "npm"))
            continue
        log = os.path.join(LOGS, "dist-npm.log")
        s = run([tool("npm"), "pack", "--pack-destination", DIST], cwd=directory, timeout=limit("npm", 300), log=log)
        out = os.path.join(DIST, name)
        if s != 0 or not os.path.isfile(out):
            record("dist", key, "FAILED", "npm pack: exit %s; log: %s" % (s, rel(log)))
            continue
        record("dist", key, "BUILT", name)
        if not verify:
            continue
        tmp = tempfile.mkdtemp(prefix="sd-npm-")
        try:
            with tarfile.open(out) as t:
                names = t.getnames()
                t.extractall(tmp)
            if "ports/node" in key:
                s, text = capture([tool("node"), os.path.join(tmp, "package", "bin", "cli.mjs"), "version"], cwd=tmp, timeout=120)
                good, what = s == 0 and VERSION in text, "unpacked, `node package/bin/cli.mjs version` -> " + text.strip()
            else:
                s, text = capture([tool("node"), "--input-type=module", "-e",
                                   "const m = await import(process.argv[1]); console.log(Object.keys(m).sort().join(','))",
                                   "file://" + os.path.join(tmp, "package", "index.mjs").replace(os.sep, "/").replace("//", "/")], cwd=tmp, timeout=120)
                good, what = s == 0 and bool(text.strip()), "unpacked, imported package/index.mjs: exports " + text.strip()[:80]
            good = good and "package/package.json" in names
            record("dist", "verify " + key, "PASS" if good else "FAILED", what)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


GO_TARGETS = [("linux", "amd64"), ("linux", "arm64"), ("darwin", "arm64"), ("windows", "amd64")]


def dist_go(rows, verify):
    if not doctor.usable(rows, "go"):
        record("dist", "go binaries", "SKIPPED", skip_reason(rows, "go"))
        return
    host = go_host()
    for goos, goarch in GO_TARGETS:
        name = "smartdelegate-go-%s-%s-%s%s" % (VERSION, goos, goarch, ".exe" if goos == "windows" else "")
        out = os.path.join(DIST, name)
        env = child_env()
        env.update({"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"})
        log = os.path.join(LOGS, "dist-go-%s-%s.log" % (goos, goarch))
        s = run([tool("go"), "build", "-trimpath", "-ldflags", "-s -w", "-o", out, "./cmd/smartdelegate-go"], cwd=P("ports", "go"),
                timeout=limit("go", 900), log=log, env=env)
        if s != 0:
            record("dist", "go %s/%s" % (goos, goarch), "FAILED", "go build: exit %s; log: %s" % (s, rel(log)))
            continue
        record("dist", "go %s/%s" % (goos, goarch), "BUILT", name)
        if verify and (goos, goarch) == host:
            s, text = capture([out, "conformance", "--root", ROOT], timeout=limit("conformance", 1800))
            ev, co = count_suites(text)
            good = s == 0 and ev and co and not ev[1] and not co[1] and ev[0] and co[0]
            record("dist", "verify go %s/%s" % (goos, goarch), "PASS" if good else "FAILED",
                   ("`%s conformance`: %d eval, %d conformance cases, 0 failed" % (name, ev[0], co[0])) if good else "exit %s: %s" % (s, text.strip()[-200:]))


PHAR_BUILDER = r"""<?php
// usage: php -d phar.readonly=0 build_phar.php <source dir> <out.phar>
[$_, $src, $out] = $argv;
@unlink($out);
$phar = new Phar($out);
$phar->startBuffering();
$phar->buildFromDirectory($src, '#/(bin|src)/#');
$phar->setStub("#!/usr/bin/env php\n<?php Phar::mapPhar('smartdelegate-php.phar'); require 'phar://smartdelegate-php.phar/bin/smartdelegate-php'; __HALT_COMPILER();");
$phar->stopBuffering();
"""


def dist_php(rows, verify):
    src = P("ports", "php")
    prefix = "smartdelegate-php-%s" % VERSION
    out = os.path.join(DIST, prefix + ".zip")
    files = []
    for top in ("bin", "src", "public"):
        for d, dirs, names in os.walk(os.path.join(src, top)):
            dirs.sort()
            files += [os.path.join(d, n) for n in sorted(names)]
    files += [os.path.join(src, n) for n in ("composer.json", "README.md") if os.path.isfile(os.path.join(src, n))]
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for path in files:
            arc = prefix + "/" + os.path.relpath(path, src).replace(os.sep, "/")
            info = zipfile.ZipInfo(arc, date_time=time.localtime(os.path.getmtime(path))[:6])
            executable = os.path.relpath(path, src).replace(os.sep, "/").startswith("bin/")
            info.external_attr = (0o100755 if executable else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(path, "rb") as f:
                z.writestr(info, f.read())
        info = zipfile.ZipInfo(prefix + "/LICENSE", date_time=time.localtime(os.path.getmtime(P("LICENSE")))[:6])
        info.external_attr = 0o100644 << 16
        with open(P("LICENSE"), "rb") as f:
            z.writestr(info, f.read())
    record("dist", "php archive", "BUILT", "%s.zip (bin/, src/ with autoload.php, public/, composer.json; no Composer packages needed)" % prefix)
    if not doctor.usable(rows, "php"):
        record("dist", "php phar", "SKIPPED", skip_reason(rows, "php"))
        return
    php = tool("php")
    if verify:
        tmp = tempfile.mkdtemp(prefix="sd-php-")
        try:
            with zipfile.ZipFile(out) as z:
                z.extractall(tmp)
            s, text = capture([php, os.path.join(tmp, prefix, "bin", "smartdelegate-php"), "version"], cwd=tmp, timeout=120)
            record("dist", "verify php archive", "PASS" if s == 0 and VERSION in text else "FAILED",
                   "unzipped, `php bin/smartdelegate-php version` -> " + (text.strip() or "exit %s" % s))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    # the phar: writing one needs phar.readonly=0, which php.ini leaves at 1; the command line may override it
    s, text = capture([php, "-r", "echo extension_loaded('phar') ? ini_get('phar.readonly') : 'none';"], timeout=60)
    setting = text.strip()
    if setting == "none":
        record("dist", "php phar", "SKIPPED", "this PHP has no phar extension; the zip is the PHP artifact")
        return
    tmp = tempfile.mkdtemp(prefix="sd-phar-")
    try:
        builder = os.path.join(tmp, "build_phar.php")
        with io.open(builder, "w", encoding="utf-8") as f:
            f.write(PHAR_BUILDER)
        phar = os.path.join(DIST, prefix + ".phar")
        log = os.path.join(LOGS, "dist-phar.log")
        s = run([php, "-d", "phar.readonly=0", builder, src, phar], timeout=300, log=log)
        how = "php.ini has phar.readonly=%s; built with `php -d phar.readonly=0`" % (setting or "0")
        if s != 0 or not os.path.isfile(phar):
            if os.path.isfile(phar):
                os.unlink(phar)
            record("dist", "php phar", "SKIPPED", "this PHP did not write a phar (%s); the zip is the PHP artifact; log: %s" % (how, rel(log)))
            return
        s, text = capture([php, phar, "version"], cwd=tmp, timeout=120)
        s2, text2 = capture([php, phar, "conformance", VECTORS, BUNDLE], cwd=tmp, timeout=limit("conformance", 1800)) if verify else (0, "")
        ev, co = count_suites(text2) if verify else ((1, 0), (1, 0))
        if s == 0 and VERSION in text and s2 == 0 and ev and co and not ev[1] and not co[1]:
            record("dist", "php phar", "BUILT", "%s.phar (%s)" % (prefix, how))
            if verify:
                record("dist", "verify php phar", "PASS", "`php %s.phar version`, and `conformance`: %d eval, %d conformance cases, 0 failed" % (prefix, ev[0], co[0]))
        else:
            os.unlink(phar)
            record("dist", "php phar", "SKIPPED", "a phar was written but does not run correctly from inside the archive (exit %s/%s), so it was removed; the zip is the PHP artifact" % (s, s2))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def dist_rust(rows, verify):
    if not os.path.isfile(RUST_BIN):
        why = skip_reason(rows, "rust") if not doctor.usable(rows, "rust") else "ports/rust is not built: run the bootstrap (or `build`) first"
        record("dist", "rust binary", "SKIPPED", why)
        return
    triple = host_triple() if have("rustc") else "unknown-host"
    name = "smartdelegate-rust-%s-%s%s" % (VERSION, triple, EXE)
    out = os.path.join(DIST, name)
    shutil.copyfile(RUST_BIN, out)
    os.chmod(out, 0o755)
    record("dist", "rust binary", "BUILT", name + " (host only; other targets: `rustup target add <triple>` and `cargo build --release --target <triple>` with that target's linker, see docs/BUILD.md)")
    if verify:
        s, text = capture([out, "version"], cwd=tempfile.gettempdir(), timeout=60)
        record("dist", "verify rust binary", "PASS" if s == 0 and VERSION in text else "FAILED", "`%s version` -> %s" % (name, text.strip() or "exit %s" % s))


def dist_spec(verify):
    prefix = "smartdelegate-spec-%s" % VERSION
    out = os.path.join(DIST, prefix + ".tar.gz")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0")) or None
    members = []
    for d, dirs, names in os.walk(P("spec")):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        members += [os.path.join(d, n) for n in sorted(names)]
    members += [P("LICENSE"), P("NOTICE")]

    def clean(info):
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        if epoch:
            info.mtime = epoch
        info.mode = 0o755 if info.mode & 0o100 else 0o644
        return info
    with tarfile.open(out, "w:gz", format=tarfile.PAX_FORMAT) as t:
        for path in members:
            if os.path.isfile(path):
                t.add(path, arcname=prefix + "/" + os.path.relpath(path, ROOT).replace(os.sep, "/"), filter=clean)
    with tarfile.open(out) as t:
        names = t.getnames()
    vectors = [n for n in names if "/spec/conformance/vectors/" in n]
    cases = prefix + "/spec/conformance/eval/cases.json" in names
    record("dist", "spec + vectors", "BUILT", "%s.tar.gz (%d files: spec/*.md, openapi.yaml, the conformance bundle, %d vector files, the eval cases)" % (prefix, len(names), len(vectors)))
    if verify:
        good = cases and vectors and prefix + "/spec/PORTING.md" in names and prefix + "/spec/conformance/bundle/policies.json" in names
        record("dist", "verify spec + vectors", "PASS" if good else "FAILED", "the tarball lists PORTING.md, the bundle, the vectors and the eval cases")


def write_checksums(verify):
    names = sorted(n for n in os.listdir(DIST) if os.path.isfile(os.path.join(DIST, n)) and n != "SHA256SUMS")
    path = os.path.join(DIST, "SHA256SUMS")
    with io.open(path, "w", encoding="ascii", newline="\n") as f:
        for n in names:
            f.write("%s  %s\n" % (sha256_file(os.path.join(DIST, n)), n))
    record("dist", "SHA256SUMS", "BUILT", "%d artifacts" % len(names))
    if verify:
        # read the file back the way `sha256sum -c` does, and use that tool too where it exists
        with io.open(path, encoding="ascii") as f:
            listed = [line.rstrip("\n").split("  ", 1) for line in f if line.strip()]
        good = len(listed) == len(names) and all(sha256_file(os.path.join(DIST, n)) == h for h, n in listed)
        how = "%d files hashed again and compared" % len(listed)
        if good and shutil.which("sha256sum"):
            s, text = capture([shutil.which("sha256sum"), "-c", "SHA256SUMS"], cwd=DIST, timeout=300)
            good = s == 0
            how = "`sha256sum -c SHA256SUMS`: %d OK" % text.count(": OK") if good else text.strip()[-200:]
        record("dist", "verify SHA256SUMS", "PASS" if good else "FAILED", how)
    return names


def dist(verify=True):
    rows = doctor.check_all(ROOT)
    if os.path.isdir(DIST):
        shutil.rmtree(DIST)
    os.makedirs(DIST)
    os.makedirs(LOGS, exist_ok=True)
    say("dist: SmartDelegate %s -> %s" % (VERSION, rel(DIST)))
    dist_python(verify)
    dist_java(rows, verify)
    dist_npm(rows, verify)
    dist_go(rows, verify)
    dist_php(rows, verify)
    dist_rust(rows, verify)
    dist_spec(verify)
    names = write_checksums(verify)
    failed = summary("dist summary: %s" % rel(DIST))
    say("")
    for n in names + ["SHA256SUMS"]:
        say("  %10d  %s" % (os.path.getsize(os.path.join(DIST, n)), n))
    return 1 if failed else 0


# --------------------------------------------------------------------------- clean

def clean(deep=False):
    targets = [BUILD, DIST, P("ports", "java", "build"), P(".pytest_cache"), P("harness", "out"), P("ports", "go", "smartdelegate-go" + EXE)]
    if os.path.normcase(os.path.dirname(os.path.abspath(VENV))) == os.path.normcase(ROOT):
        targets.append(VENV)
    if deep:
        targets += [P("ports", "rust", "target"), P("ports", "node", "node_modules")]
    for d, dirs, _ in os.walk(ROOT):
        if os.path.basename(d) in (".git", "target", "node_modules", ".venv"):
            dirs[:] = []
            continue
        for name in list(dirs):
            if name == "__pycache__" or name.endswith(".egg-info"):
                targets.append(os.path.join(d, name))
                dirs.remove(name)

    def writable(func, path, _exc):          # read-only files (the JVM's class-data archive, Windows)
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    removed = []
    for t in targets:
        if os.path.isdir(t):
            shutil.rmtree(t, onerror=writable)
            removed.append(rel(t))
        elif os.path.isfile(t):
            os.unlink(t)
            removed.append(rel(t))
    say("clean: removed " + (", ".join(removed) if removed else "nothing (already clean)"))
    if not deep and os.path.isdir(P("ports", "rust", "target")):
        say("clean: kept ports/rust/target (a rebuild takes several minutes); `clean --deep` removes it too")
    _ENV.clear()
    STATE["python"] = None
    return 0


# --------------------------------------------------------------------------- docker

def docker_ready():
    rows = doctor.check_all(ROOT)
    r = next(x for x in rows if x["key"] == "docker")
    if r["status"] != doctor.OK:
        say("docker: cannot run: %s" % (r["detail"] or "docker with the compose plugin is not installed"))
        say("        the Docker files in docker/ were written without a Docker daemon and have not been built; see docs/BUILD.md")
        return False
    return True


def docker_build():
    if not docker_ready():
        return 3
    for dockerfile, tag in (("docker/Dockerfile.dev", "smartdelegate-dev:" + VERSION), ("docker/Dockerfile.daemon", "smartdelegate:" + VERSION)):
        say("+ docker build -f %s -t %s ." % (dockerfile, tag))
        s = run([tool("docker"), "build", "-f", P(*dockerfile.split("/")), "-t", tag, ROOT], timeout=limit("docker", 7200), stream=True)
        if s != 0:
            return 1
    return 0


def docker_test():
    if not docker_ready():
        return 3
    env = child_env()
    compose = [tool("docker"), "compose", "-f", P("docker", "docker-compose.yml")]
    if os.path.isfile(P("docker", ".env")):
        compose += ["--env-file", P("docker", ".env")]
    else:
        # throwaway values for this run only; they exist in this process's environment and nowhere else
        import secrets
        say("docker-test: there is no docker/.env, so this run uses random throwaway keys (kept in memory only)")
        for name in ("SD_ADMIN_KEY", "SD_PEP_KEY", "SD_UPSTREAM_KEY", "SD_KEYCLOAK_ADMIN_PASSWORD", "POSTGRES_PASSWORD"):
            env.setdefault(name, secrets.token_hex(20))
        compose += ["--env-file", P("docker", ".env.example")]
    say("+ docker compose -f docker/docker-compose.yml up --build --abort-on-container-exit --exit-code-from tests")
    try:
        return run(compose + ["up", "--build", "--abort-on-container-exit", "--exit-code-from", "tests"], timeout=limit("docker", 7200), stream=True, env=env)
    finally:
        run(compose + ["down", "--volumes", "--remove-orphans"], timeout=600, stream=True, env=env)


# --------------------------------------------------------------------------- commands

def show_doctor():
    rows = doctor.decorate(doctor.check_all(ROOT), doctor.package_manager())
    say("")
    doctor.print_table(rows, doctor.components(rows, ROOT), doctor.package_manager())
    return rows


def full_suites():
    test_all()
    ensure_java_jar()
    matrix()
    live(LIVE_PARTS, quick=True)        # live/idp/run.sh, then live/run.sh all --quick (what test_all.sh --live runs)


def cmd_bootstrap(a):
    t0 = time.time()
    if a.clean:
        clean(deep=False)
    os.makedirs(LOGS, exist_ok=True)
    say("SmartDelegate %s bootstrap in %s%s%s" % (VERSION, ROOT, " (offline)" if a.offline else "", " (only: %s)" % a.only if a.only else ""))
    ok = ensure_venv()
    rows = show_doctor()
    made = {}
    if ok:
        build_ports(rows)
        made = write_launchers()
        check_launchers(made)
        if not a.no_verify:
            verify_quick(rows, made)
        if a.full:
            full_suites()
        ensure_java_jar()
    enforce_require([x for x in (a.require or "").split(",") if x])
    sh = not IS_WINDOWS
    nxt = []
    if ok:
        nxt = [(". .venv/bin/activate" if sh else ".\\.venv\\Scripts\\Activate.ps1") + "          # or call build/bin/smartdelegate directly",
               ("build/bin/smartdelegate --demo" if sh else "build\\bin\\smartdelegate.cmd --demo"),
               ("make test" if sh else ".\\make.ps1 test") + "                      # reference unit tests",
               ("./bootstrap.sh --full" if sh else ".\\bootstrap.ps1 -Full") + "           # every suite, the cross-port matrix, live suites that can run",
               ("make dist" if sh else ".\\make.ps1 dist") + "                      # release artifacts with checksums",
               "docs/BUILD.md                  # every target, the test pyramid, Windows notes"]
        if a.full:
            del nxt[3]
    failed = summary("bootstrap summary (%.0f s)" % (time.time() - t0), nxt)
    if made:
        say("")
        say("launchers: " + " ".join(rel(made[p]) for p in PORTS if p in made))
    say("logs: " + rel(LOGS))
    return 1 if failed else 0


def finish(title, require=""):
    enforce_require([x for x in (require or "").split(",") if x])
    return 1 if summary(title) else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sd.py", description="SmartDelegate build driver (see docs/BUILD.md).")
    sub = ap.add_subparsers(dest="cmd")

    def common(p):
        p.add_argument("--only", default="", help="comma-separated components: " + ",".join(COMPONENTS))
        p.add_argument("--offline", action="store_true", help="no network: fail fast where one is needed")
        p.add_argument("--require", default=os.environ.get("SD_REQUIRE", ""), help="comma-separated names whose SKIPPED becomes FAILED (for CI)")
        p.add_argument("-v", "--verbose", action="store_true", help="show each step's output as it runs")
        return p

    b = common(sub.add_parser("bootstrap", help="venv, build every port that has a toolchain, launchers, quick verification"))
    b.add_argument("--full", action="store_true", help="also test_all, the cross-port matrix and the live suites")
    b.add_argument("--clean", action="store_true", help="remove .venv, build/ and dist/ first")
    b.add_argument("--no-verify", action="store_true", help="build only")
    sub.add_parser("doctor", help="scripts/doctor.py", add_help=False)
    for name, text in (("build", "build every port that has a toolchain, write the launchers"), ("test", "the reference unit tests"),
                       ("conformance", "the two shared suites against every installed port"), ("matrix", "every port against every other"),
                       ("harness", "the example company's policy tests and the scenario harness on the reference engine"),
                       ("load", "live/run.sh load"), ("all", "bootstrap --full")):
        common(sub.add_parser(name, help=text))
    lv = common(sub.add_parser("live", help="the suites against real services: " + " ".join(LIVE_PARTS)))
    lv.add_argument("parts", nargs="*", help="default: all four (live/idp/run.sh, then live/run.sh all)")
    lv.add_argument("--quick", action="store_true", help="live/run.sh --quick: short load, no 75 s upstream-timeout case")
    d = common(sub.add_parser("dist", help="release artifacts with SHA256SUMS in dist/"))
    d.add_argument("--no-verify", action="store_true", help="do not run the artifacts")
    c = sub.add_parser("clean", help="remove .venv, build/, dist/ and caches")
    c.add_argument("--deep", action="store_true", help="also ports/rust/target and node_modules")
    sub.add_parser("docker-build", help="build docker/Dockerfile.dev and docker/Dockerfile.daemon")
    sub.add_parser("docker-test", help="the live topology of docker/docker-compose.yml")

    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "doctor":
        return doctor.main(argv[1:])
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return 2
    STATE["offline"] = bool(getattr(a, "offline", False))
    STATE["verbose"] = bool(getattr(a, "verbose", False))
    only = [x for x in getattr(a, "only", "").split(",") if x]
    bad = [x for x in only if x not in COMPONENTS]
    if bad:
        print("sd.py: unknown component(s) in --only: %s (components: %s)" % (", ".join(bad), ", ".join(COMPONENTS)), file=sys.stderr)
        return 2
    STATE["only"] = set(only) | {"python"} if only else None
    require = getattr(a, "require", "")
    bad = [x for x in (require or "").split(",") if x and x not in REQUIRABLE]
    if bad:
        print("sd.py: unknown name(s) in --require: %s (names: %s)" % (", ".join(bad), ", ".join(REQUIRABLE)), file=sys.stderr)
        return 2
    if "require" in argv_has(argv) and STATE["only"] is not None:
        excluded = [x for x in require.split(",") if x in COMPONENTS and x not in STATE["only"]]
        if excluded:
            print("sd.py: --require names %s, which --only leaves out" % ", ".join(excluded), file=sys.stderr)
            return 2

    if a.cmd == "clean":
        return clean(a.deep)
    if a.cmd == "docker-build":
        return docker_build()
    if a.cmd == "docker-test":
        return docker_test()
    if a.cmd == "all":
        a.full, a.clean, a.no_verify = True, False, False
        return cmd_bootstrap(a)
    if a.cmd == "bootstrap":
        return cmd_bootstrap(a)

    os.makedirs(LOGS, exist_ok=True)
    python()            # fails with the instruction to bootstrap when nothing can run the reference
    if a.cmd == "build":
        rows = doctor.check_all(ROOT)
        record("build", "python", "BUILT", "using " + rel(python()))
        build_ports(rows)
        check_launchers(write_launchers())
        return finish("build summary", require)
    if a.cmd == "test":
        STATE["verbose"] = True
        unit_tests("verify")
        return finish("test summary", require)
    if a.cmd == "conformance":
        conformance(doctor.check_all(ROOT), [p for p in PORTS if selected(p)])
        ensure_java_jar_if_built()
        return finish("conformance summary", require)
    if a.cmd == "matrix":
        STATE["verbose"] = True
        matrix("verify")
        return finish("matrix summary", require)
    if a.cmd == "harness":
        harness(quick=False)
        return finish("harness summary", require)
    if a.cmd == "live":
        bad = [x for x in a.parts if x not in LIVE_PARTS]
        if bad:
            print("sd.py: unknown live part(s): %s (parts: %s)" % (", ".join(bad), ", ".join(LIVE_PARTS)), file=sys.stderr)
            return 2
        live(a.parts or LIVE_PARTS, quick=a.quick)
        return finish("live summary", require)
    if a.cmd == "load":
        load_gated()
        return finish("load summary", require)
    if a.cmd == "dist":
        return dist(verify=not a.no_verify)
    return 2


def argv_has(argv):
    """The long options given on the command line (not those defaulted from the environment)."""
    return set(a[2:].split("=")[0] for a in argv if a.startswith("--"))


def ensure_java_jar_if_built():
    """After a stand-alone `conformance`: put back the jar the Java harness removed, when a launcher points at it."""
    launcher = os.path.join(BIN, "smartdelegate-java" + (".cmd" if IS_WINDOWS else ""))
    if os.path.isfile(launcher) and not java_jar() and have("javac"):
        say("    (the Java test harness removed ports/java/build; building the jar again for build/bin/smartdelegate-java)")
        build_java(quiet=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nsd.py: interrupted", file=sys.stderr)
        sys.exit(130)
