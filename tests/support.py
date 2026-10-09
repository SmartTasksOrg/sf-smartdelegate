import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
PY = ROOT / "src"
sys.path.insert(0, str(PY))
BUNDLE = SPEC / "conformance" / "bundle"
VECTORS = SPEC / "conformance" / "vectors"
OIDC = SPEC / "conformance" / "oidc"
EXAMPLES = ROOT / "examples"
T = 1700000000
FULL_CAP = {"actions": ["read", "create", "update"], "resources": ["crm.customer/*", "billing.refund/*"], "budget": {"EUR": 20000}}
ENV = {**os.environ, "PYTHONPATH": str(PY) + os.pathsep + os.environ.get("PYTHONPATH", "")}
#: The command line under test: this port by default. Set SMARTDELEGATE_TEST_CLI to a
#: JSON array (e.g. '["/repo/ports/rust/target/release/smartdelegate"]') to run the
#: daemon and proxy tests against another port's binary.
CLI = json.loads(os.environ["SMARTDELEGATE_TEST_CLI"]) if os.environ.get("SMARTDELEGATE_TEST_CLI") else [sys.executable, "-m", "sf_smartdelegate"]


def conformance_config(state_dir: str, extra: dict | None = None) -> dict:
    """The configuration every port uses for the shared vectors, plus the
    suite's own `config` when it has one."""
    return {"bundle_dir": str(BUNDLE), "state_dir": state_dir, "allow_test_clock": True, "max_depth": 3, **(extra or {})}


def cases():
    for f in sorted(VECTORS.glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        for c in doc["cases"]:
            yield doc["suite"], dict(c, config=doc.get("config") or {})


def substitute(v, variables):
    if isinstance(v, str) and v.startswith("$"):
        return variables.get(v[1:], v)
    if isinstance(v, list):
        return [substitute(x, variables) for x in v]
    if isinstance(v, dict):
        return {k: substitute(x, variables) for k, x in v.items()}
    return v


def subset(expect, actual, path=""):
    """Every key in `expect` must be present and equal in `actual`."""
    if isinstance(expect, dict) and isinstance(actual, dict):
        for k, ev in expect.items():
            p = f"{path}.{k}" if path else k
            if k not in actual:
                if ev is None:
                    continue
                return f"{p}: missing, expected {ev!r}"
            m = subset(ev, actual[k], p)
            if m:
                return m
        return None
    if isinstance(expect, bool) != isinstance(actual, bool):
        return f"{path}: expected {expect!r}, got {actual!r}"
    return None if expect == actual else f"{path}: expected {expect!r}, got {actual!r}"


def run_case(call, case):
    """`call(op, input) -> result dict`. Returns a list of mismatches."""
    variables, failures = {}, []
    for i, step in enumerate(case["steps"]):
        result = call(step["op"], substitute(step["input"], variables))
        for name, key in (step.get("save") or {}).items():
            cur = result
            for part in key.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            variables[name] = cur
        m = subset(step.get("expect", {}), result)
        if m:
            failures.append(f"step {i} ({step['op']}): {m}")
    return failures


class Daemon:
    """`smartdelegate serve` (or a proxy) on a free port, with its own state directory."""

    ADMIN = "admin-key-for-tests-0123456789"
    PEP = "pep-key-for-tests-0123456789"

    def __init__(self, extra: dict | None = None, command: str = "serve", args: list | None = None, env: dict | None = None, cli: list | None = None):
        self.dir = tempfile.mkdtemp(prefix="smartdelegate-test-")
        self.cli_cmd = cli or CLI
        cfg = conformance_config(os.path.join(self.dir, "state"))
        cfg.update({"admin_key": self.ADMIN, "pep_key": self.PEP})
        cfg.update(extra or {})
        self.config = os.path.join(self.dir, "smartdelegate.json")
        Path(self.config).write_text(json.dumps(cfg), encoding="utf-8")
        self.proc = subprocess.Popen([*self.cli_cmd, command, "--config", self.config, "--listen", "127.0.0.1:0", *(args or [])],
                                     stderr=subprocess.PIPE, text=True, env={**ENV, **(env or {})})
        line = self.proc.stderr.readline()
        m = re.search(r"http://(\S+)", line)
        if not m:
            raise RuntimeError(f"daemon did not start: {line}{self.proc.stderr.read()}")
        self.url = "http://" + m.group(1)

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([*self.cli_cmd, *args, "--config", self.config], capture_output=True, text=True, env=ENV)

    def close(self):
        self.proc.kill()
        self.proc.wait()
        self.proc.stderr.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
