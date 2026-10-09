#!/usr/bin/env python3
"""Add the two agent roles of this folder to an existing bundle.

    python3 agents/bundle-example/merge.py --into <bundle dir> [--dry-run]

What it adds: the entities, the roles `sd-operator` and `sd-integrator`, the
catalog resource `smartdelegate.ops`, `policies/ops.cedar`, and the compiled
form of those policies.

It only adds. A role, a catalog resource, a policy id or an entity that the
target already has with different content stops the merge with nothing
written: an existing role is never overwritten. The merged bundle is loaded
with the reference engine in a temporary copy before the target is touched.

The compiled policies are copied from this folder's policies.json, which the
Rust port produced from policies/ops.cedar. To compile them yourself instead,
run `smartdelegate bundle compile --bundle <bundle dir>` from the Rust port
afterwards: the result is the same file (tests/test_agent_surface.py checks
this when the Rust port is built).

Afterwards: run `smartdelegate policy test`, re-sign a signed bundle, and
reload running engines. Standard library plus the smartdelegate package.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8-sig")) if path.exists() else default


def merged(target: Path) -> dict:
    """file name -> new content (text). Raises ValueError on any collision."""
    out = {}
    ours, theirs = _load(HERE / "entities.json", []), _load(target / "entities.json", [])
    key = lambda e: (e["uid"]["type"], e["uid"]["id"])
    have = {key(e): e for e in theirs}
    for e in ours:
        if key(e) in have and have[key(e)] != e:
            raise ValueError(f"entities.json: {key(e)[0]}::{key(e)[1]} already exists with different content")
    out["entities.json"] = json.dumps(theirs + [e for e in ours if key(e) not in have], indent=2) + "\n"

    for name, top in (("roles.json", "roles"), ("catalog.json", "resources")):
        a, b = _load(HERE / name, {top: {}}), _load(target / name, {top: {}})
        clash = sorted(set(a[top]) & set(b.get(top) or {}))
        if clash:
            raise ValueError(f"{name}: already defines {', '.join(clash)}; nothing is overwritten")
        doc = dict(b)
        doc[top] = {**(b.get(top) or {}), **a[top]}
        out[name] = json.dumps(doc, indent=2) + "\n"

    a, b = _load(HERE / "policies.json", None), _load(target / "policies.json", None)
    if b is None:
        raise ValueError("the target has no policies.json: it is not a compiled bundle")
    clash = sorted(set(a["policies"]) & set(b["policies"]))
    if clash:
        raise ValueError(f"policies.json: policy id(s) already in use: {', '.join(clash)}")
    cedar = (HERE / "policies" / "ops.cedar").read_text(encoding="utf-8")
    existing = target / "policies" / "ops.cedar"
    if existing.exists() and existing.read_text(encoding="utf-8") != cedar:
        raise ValueError("policies/ops.cedar already exists with different content")
    doc = dict(b)
    doc["sources"] = dict(sorted({**(b.get("sources") or {}), **a["sources"]}.items()))
    doc["policies"] = dict(sorted({**b["policies"], **a["policies"]}.items()))
    out["policies.json"] = json.dumps(doc, indent=2) + "\n"
    out["policies/ops.cedar"] = cedar
    return out


def main(argv: list) -> int:
    if "--into" not in argv or argv.index("--into") + 1 >= len(argv) or set(argv) - {"--into", "--dry-run", argv[argv.index("--into") + 1]}:
        print(__doc__)
        return 0 if argv in (["--help"], ["-h"]) else 1
    target = Path(argv[argv.index("--into") + 1])
    try:
        files = merged(target)
        from sf_smartdelegate.bundle import Bundle
        from sf_smartdelegate.errors import EngineError
        with tempfile.TemporaryDirectory(prefix="smartdelegate-merge-") as tmp:
            trial = Path(tmp) / "bundle"
            shutil.copytree(target, trial, ignore=shutil.ignore_patterns("bundle.sig.json"))
            for name, text in files.items():
                (trial / name).parent.mkdir(parents=True, exist_ok=True)
                (trial / name).write_text(text, encoding="utf-8", newline="\n")
            try:
                version = Bundle(trial).version
            except EngineError as e:
                raise ValueError(f"the merged bundle does not load: {e}") from None
    except (ValueError, OSError, KeyError, TypeError) as e:
        print(f"merge: {e}; nothing was written", file=sys.stderr)
        return 1
    if "--dry-run" in argv:
        print(f"would write {', '.join(sorted(files))}; merged bundle version {version}")
        return 0
    for name, text in files.items():
        (target / name).parent.mkdir(parents=True, exist_ok=True)
        (target / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"merged into {target}; bundle version {version}\nnext: smartdelegate policy test --bundle {target}; re-sign if the bundle is signed; reload running engines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
