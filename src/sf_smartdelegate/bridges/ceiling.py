"""Cap a role's ceiling by what the human may actually do in the cloud.

`aws.ceiling_from_simulation`, `gcp.ceiling_from_test_permissions` and
`azure.ceiling_from_permissions` express a human's cloud permissions as a
SmartDelegate capability. `intersect` narrows a role's `cap` by it and
`cap_role` rewrites the role in roles.json. A ceiling is only ever lowered.
"""
from __future__ import annotations

import json
from pathlib import Path

from .. import bundle
from ..errors import EngineError
from ..tokens import Cap, _covers
from . import BridgeError
from .cloudmap import as_cap, narrower
from .directory import _atomic_write


def _minimal(patterns: set) -> list:
    """Sorted, without patterns another one already covers."""
    return sorted(p for p in patterns if not any(q != p and _covers(q, p) for q in patterns))


def intersect(role_cap, human_cap) -> dict:
    """The capability that grants exactly what BOTH capabilities grant.

    actions / resources: every pairwise overlap, each the narrower pattern;
    deny_labels / deny_fields: the union (what either never sees, the result
    never sees); budget: per currency the smaller amount, and only currencies
    both have (a capability without a budget for a currency cannot spend it).

    Guarantees: the result is narrower than each input by the engine's own
    rule (`Cap.check_narrower_than`, checked before returning); it is
    deterministic (sorted, minimal); intersect(x, x) grants what x grants and
    intersect(intersect(a, b), b) == intersect(a, b)."""
    a, b = as_cap(role_cap), as_cap(human_cap)
    pick = lambda xs, ys: _minimal({n for x in xs for y in ys for n in [narrower(x, y)] if n is not None})
    out = Cap(pick(a.actions, b.actions), pick(a.resources, b.resources),
              sorted(set(a.deny_labels) | set(b.deny_labels)), sorted(set(a.deny_fields) | set(b.deny_fields)),
              {c: min(a.budget[c], b.budget[c]) for c in sorted(set(a.budget) & set(b.budget))})
    try:
        out.validate()
        out.check_narrower_than(a)
        out.check_narrower_than(b)
    except EngineError as e:  # cannot happen; if it does, do not hand out a cap that is not narrower
        raise BridgeError("internal", f"intersection is not narrower than its inputs: {e.message}") from None
    return out.to_json()


def _tidy(cap: dict) -> dict:
    return {k: v for k, v in cap.items() if k in ("actions", "resources") or v}


def cap_role(roles_path, role: str, human_cap, *, write: bool = False) -> dict:
    """Lower one role's `cap` in roles.json to its intersection with `human_cap`.

    Returns {"role", "before", "after", "changed", "written"}. Guarantees:
    `after` is never wider than what the file had (it is `intersect(before,
    human_cap)`); other roles and keys are untouched; with `write=True` the
    file is replaced atomically (temporary file, validated by loading every
    role with the engine's `bundle.Role`, then os.replace); with
    `write=False` nothing is written.

    When `human_cap` is a dict with no "budget" key at all, the role's budget is kept:
    a cloud ceiling says nothing about money. Pass "budget": {} to remove it.

    roles.json is part of the bundle version: after a write, the version
    changes, a signed bundle must be re-signed (`smartdelegate bundle sign`),
    and running engines need `reload`. Tokens issued earlier keep the cap
    they were issued with until they expire."""
    path = Path(roles_path)
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
        roles = doc["roles"]
        assert isinstance(roles, dict)
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as e:
        raise BridgeError("roles_unreadable", f"{path}: {e}") from None
    if role not in roles or not isinstance(roles[role], dict) or "cap" not in roles[role]:
        raise BridgeError("unknown_role", f"{path} defines no role named '{role}'")
    before = as_cap(roles[role]["cap"]).to_json()
    human = human_cap.to_json() if hasattr(human_cap, "to_json") else human_cap
    if not isinstance(human, dict):
        raise BridgeError("invalid_cap", "human_cap must be a capability")
    if isinstance(human_cap, dict) and "budget" not in human_cap:
        human = {**human, "budget": before["budget"]}
    after = intersect(before, human)
    changed = after != before
    result = {"role": role, "before": _tidy(before), "after": _tidy(after), "changed": changed, "written": False}
    if write and changed:
        roles[role]["cap"] = _tidy(after)

        def check(tmp: Path) -> None:
            try:
                loaded = json.loads(tmp.read_text(encoding="utf-8"))
                for name, rdef in loaded["roles"].items():
                    bundle.Role(name, rdef)
            except Exception as e:
                raise BridgeError("roles_invalid", f"the new roles.json does not load, nothing was written: {e}") from None

        try:
            _atomic_write(path, json.dumps(doc, indent=2, ensure_ascii=False) + "\n", check)
        except OSError as e:
            raise BridgeError("write_failed", f"{path}: {e.strerror or e}") from None
        result["written"] = True
    return result
