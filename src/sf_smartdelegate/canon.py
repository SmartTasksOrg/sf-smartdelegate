"""Canonical JSON (sorted keys, compact) and SHA-256 helpers.

The audit hash chain, approval ids, bundle versions and bundle signatures all
depend on this being byte-identical in every port. Rules: keys sorted by code
point, no whitespace, non-ASCII characters written as themselves, control
characters as \\u00xx (lowercase), integers only.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_value(value: Any) -> str:
    return sha256_hex(canon(value).encode("utf-8"))
