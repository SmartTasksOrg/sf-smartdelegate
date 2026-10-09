"""Where each port's command line is, for the live suites that start decision daemons.

`launcher(port, work)` returns the argv and extra environment of a port's CLI,
the way ports/conformance/matrix.py finds them; `available_ports()` says which
can run on this machine without starting anything.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DAEMON_PORTS = ("python", "rust", "node", "go", "php", "java")


class BackendError(Exception):
    """A daemon could not be built or started."""


class Unavailable(BackendError):
    """The toolchain of that port is not on this machine."""


def launcher(port: str, work: Path) -> tuple:
    """-> (argv, env) of a port's command line, the way ports/conformance/matrix.py finds them.
    Raises Unavailable when the toolchain is missing."""
    if port == "python":
        env = {"PYTHONPATH": str(ROOT / "src") + (os.pathsep + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")}
        try:
            subprocess.run([sys.executable, "-c", "import cryptography"], check=True, capture_output=True, timeout=60)
        except (subprocess.SubprocessError, OSError):
            raise Unavailable("the Python package `cryptography` is not installed") from None
        return [sys.executable, "-m", "sf_smartdelegate"], env
    if port == "node":
        if not shutil.which("node"):
            raise Unavailable("node is not installed")
        return ["node", str(ROOT / "ports/node/bin/cli.mjs")], {}
    if port == "php":
        if not shutil.which("php"):
            raise Unavailable("php is not installed")
        try:
            ok = subprocess.run(["php", "-r", "exit(extension_loaded('sodium') ? 0 : 1);"], capture_output=True, timeout=60).returncode == 0
        except (subprocess.SubprocessError, OSError):
            ok = False
        if not ok:
            raise Unavailable("php has no sodium extension")
        return ["php", str(ROOT / "ports/php/bin/smartdelegate-php")], {}
    if port == "go":
        if not shutil.which("go"):
            raise Unavailable("go is not installed")
        exe = work / ("smartdelegate-go.exe" if os.name == "nt" else "smartdelegate-go")
        env = {**os.environ, "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "local"), "GOFLAGS": os.environ.get("GOFLAGS", "-buildvcs=false")}
        try:
            p = subprocess.run(["go", "build", "-o", str(exe), "./cmd/smartdelegate-go"], cwd=str(ROOT / "ports/go"), capture_output=True,
                               text=True, timeout=600, env=env)
        except subprocess.TimeoutExpired:
            raise BackendError("go build did not finish within 600 s") from None
        if p.returncode != 0:
            raise BackendError(f"go build failed:\n{(p.stdout + p.stderr)[-2000:]}")
        return [str(exe)], {}
    if port == "rust":
        exe = ROOT / "ports/rust/target/release" / ("smartdelegate.exe" if os.name == "nt" else "smartdelegate")
        if not exe.exists():
            raise Unavailable("ports/rust/target/release/smartdelegate does not exist (run `cargo build --release` in ports/rust)")
        return [str(exe)], {}
    if port == "java":
        if not shutil.which("java") and not os.environ.get("JAVA_HOME"):
            raise Unavailable("no Java runtime is installed (a JRE 17+ runs the port, a JDK builds it)")
        if os.name == "nt":
            raise Unavailable("the Java launcher ports/java/bin/smartdelegate-java is a shell script; on Windows start the daemon yourself and use url:")
        jar = ROOT / "ports/java/build/smartdelegate.jar"
        if not jar.exists():
            # the port's own build script, into its own git-ignored build directory
            if not shutil.which("javac") and not os.environ.get("JAVA_HOME"):
                raise Unavailable("ports/java/build/smartdelegate.jar does not exist and there is no JDK (javac) to build it with ports/java/build.sh")
            try:
                p = subprocess.run(["sh", str(ROOT / "ports/java/build.sh")], cwd=str(ROOT / "ports/java"), capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                raise BackendError("ports/java/build.sh did not finish within 600 s") from None
            if p.returncode != 0 or not jar.exists():
                raise BackendError(f"ports/java/build.sh failed:\n{(p.stdout + p.stderr)[-2000:]}")
        return [str(ROOT / "ports/java/bin/smartdelegate-java")], {}
    raise BackendError(f"no launcher named '{port}' (known: {', '.join(DAEMON_PORTS)})")


def available_ports() -> tuple:
    """-> ([port, ...], {port: why skipped}) without starting anything but `go build`-free checks."""
    ok, skipped = [], {}
    for port in DAEMON_PORTS:
        if port == "go":
            if shutil.which("go"):
                ok.append(port)
            else:
                skipped[port] = "go is not installed"
            continue
        if port == "java":
            # like go: say whether it can run, without building anything yet
            have_jar = (ROOT / "ports/java/build/smartdelegate.jar").exists()
            if os.name == "nt":
                skipped[port] = "the Java launcher is a shell script; on Windows use url:"
            elif not shutil.which("java") and not os.environ.get("JAVA_HOME"):
                skipped[port] = "no Java runtime is installed"
            elif not have_jar and not shutil.which("javac") and not os.environ.get("JAVA_HOME"):
                skipped[port] = "ports/java/build/smartdelegate.jar does not exist and there is no JDK to build it"
            else:
                ok.append(port)
            continue
        try:
            launcher(port, Path(tempfile.gettempdir()))
            ok.append(port)
        except Unavailable as e:
            skipped[port] = str(e)
    return ok, skipped
