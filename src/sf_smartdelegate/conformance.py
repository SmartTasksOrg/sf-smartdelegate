"""Runner for the shared conformance vectors and for a bundle's own tests.

A case is a list of steps; each step names an operation, its input and a
partial expected result. `save` stores a value from a result and `"$name"` in
a later input is replaced by it. Every port implements these ~40 lines.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path


def substitute(v, variables: dict):
    if isinstance(v, str) and v.startswith("$"):
        return variables.get(v[1:], v)
    if isinstance(v, list):
        return [substitute(x, variables) for x in v]
    if isinstance(v, dict):
        return {k: substitute(x, variables) for k, x in v.items()}
    return v


def subset(expect, actual, path: str = ""):
    """Every key in `expect` must be present and equal in `actual`; objects
    recursively, everything else exactly. Returns a mismatch or None."""
    if isinstance(expect, dict) and isinstance(actual, dict):
        for k, ev in expect.items():
            p = f"{path}.{k}" if path else k
            if k not in actual:
                if ev is None:
                    continue
                return f"{p}: missing, expected {json.dumps(ev)}"
            m = subset(ev, actual[k], p)
            if m:
                return m
        return None
    if isinstance(expect, bool) != isinstance(actual, bool) or expect != actual:
        return f"{path}: expected {json.dumps(expect)}, got {json.dumps(actual)}"
    return None


def run_case(call, case: dict) -> dict:
    variables, failures = {}, []
    for n, step in enumerate(case.get("steps") or []):
        result = call(step.get("op", ""), substitute(step.get("input"), variables))
        for name, key in (step.get("save") or {}).items():
            cur = result
            for part in str(key).split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            variables[name] = cur
        m = subset(step.get("expect") or {}, result)
        if m:
            failures.append({"step": n, "op": step.get("op"), "mismatch": m})
    return {"name": case.get("name"), "passed": not failures, "failures": failures}


def run_vectors(vectors_dir, bundle_dir, max_depth: int = 3) -> dict:
    """Every case against a fresh engine with its own state directory."""
    from .engine import Engine
    results = []
    for f in sorted(Path(vectors_dir).glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        for case in doc.get("cases") or []:
            state = tempfile.mkdtemp(prefix="smartdelegate-conf-")
            try:
                cfg = {"bundle_dir": str(bundle_dir), "state_dir": state, "allow_test_clock": True, "max_depth": max_depth}
                cfg.update(doc.get("config") or {})  # a suite may add settings, e.g. an identity provider
                with Engine(cfg) as e:
                    results.append(run_case(e.call, case))
            finally:
                shutil.rmtree(state, ignore_errors=True)
    return {"total": len(results), "failed": sum(1 for r in results if not r["passed"]), "results": results}


def run_bundle_tests(bundle_dir) -> dict:
    """`<bundle>/tests/*.json` against a throwaway engine per case: no state
    directory, no audit log, test clock on, caller-supplied chains trusted."""
    from .engine import Engine
    results = []
    for f in sorted((Path(bundle_dir) / "tests").glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        for case in doc.get("cases") or []:
            with Engine({"bundle_dir": str(bundle_dir), "allow_test_clock": True, "trust_caller_chain": True, "audit": False}) as e:
                results.append(run_case(e.call, case))
    return {"total": len(results), "failed": sum(1 for r in results if not r["passed"]), "results": results}
