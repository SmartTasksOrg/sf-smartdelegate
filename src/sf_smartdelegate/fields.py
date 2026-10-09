"""Applying a field mask and a row filter to JSON data.

Field paths are relative to the resource: `email`, `address.zip`,
`orders[].total`. `[]` stands for "each element of this array".

Rules (fail closed):
  * a denied path is dropped, or replaced by "[REDACTED]" when the catalog says
    `mask: redact`; its whole subtree goes with it
  * an allowed path is kept; children that have their own catalog entry are
    still checked one by one, other children are kept with the parent
  * a path the catalog does not list, under no allowed parent, is dropped
"""
from __future__ import annotations

from typing import Any

REDACTED = "[REDACTED]"
ALLOW, DENY, REDACT = "allow", "deny", "redact"


class Mask:
    def __init__(self, status: dict[str, str]):
        self.status = status

    def has_children(self, path: str) -> bool:
        a, b = path + ".", path + "[]"
        return any(k.startswith(a) or k.startswith(b) for k in self.status)


def _container(v) -> bool:
    return isinstance(v, (dict, list))


def _walk_value(v, path: str, inherit: bool, mask: Mask, masked: set):
    """Returns (keep, value)."""
    if isinstance(v, dict):
        return True, _walk_object(v, path, inherit, mask, masked)
    if isinstance(v, list):
        p = path + "[]"
        st = mask.status.get(p)
        out = []
        for el in v:
            if st == DENY:
                masked.add(p)
            elif st == REDACT:
                masked.add(p)
                out.append(REDACTED)
            elif st == ALLOW:
                keep, x = _walk_value(el, p, True, mask, masked)
                if keep:
                    out.append(x)
            elif _container(el):
                keep, x = _walk_value(el, p, inherit, mask, masked)
                if keep:
                    out.append(x)
            elif inherit:
                out.append(el)
            else:
                masked.add(p)
        return True, out
    return (True, v) if inherit else (False, None)


def _walk_object(m: dict, prefix: str, inherit: bool, mask: Mask, masked: set) -> dict:
    out = {}
    for k, v in m.items():
        p = f"{prefix}.{k}" if prefix else k
        st = mask.status.get(p)
        if st == DENY:
            masked.add(p)
        elif st == REDACT:
            masked.add(p)
            out[k] = REDACTED
        elif st == ALLOW:
            if mask.has_children(p):
                keep, x = _walk_value(v, p, True, mask, masked)
                if keep:
                    out[k] = x
            else:
                out[k] = v
        elif inherit and not mask.has_children(p):
            out[k] = v
        elif _container(v) and mask.has_children(p):
            keep, x = _walk_value(v, p, inherit, mask, masked)
            if keep:
                out[k] = x
        elif inherit:
            out[k] = v
        else:
            masked.add(p)
    return out


def _same(a, b) -> bool:
    # JSON equality: true is not 1
    return type(a) is type(b) and a == b


def _row_matches(row, row_filter: list) -> bool:
    return all(isinstance(row, dict) and c.get("column") in row and _same(row[c["column"]], c.get("value")) for c in row_filter)


def apply(data: Any, mask: Mask, row_filter: list) -> tuple[Any, list[str], int]:
    """`data` is one record or a list of records. Returns (data, masked paths, rows dropped)."""
    masked: set = set()
    dropped = 0
    if isinstance(data, list):
        out = []
        for r in data:
            if isinstance(r, dict) and _row_matches(r, row_filter):
                out.append(_walk_object(r, "", False, mask, masked))
            else:
                dropped += 1
    elif isinstance(data, dict):
        if _row_matches(data, row_filter):
            out = _walk_object(data, "", False, mask, masked)
        else:
            out, dropped = None, 1
    else:
        # a bare scalar has no field identity, so nothing can authorise it
        out, dropped = None, 1
    return out, sorted(masked), dropped
