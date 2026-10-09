"""Mutable engine state: revocations, approvals, spend ledger.

One JSON file in the state directory. The engine holds the state-directory
lock for every operation and re-reads the file at the start of each one, so
processes sharing a directory see each other's changes on the next call.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .errors import EngineError

EMPTY = {"revoked": {}, "approvals": {}, "pending": {}, "ledger": {}, "limits": {}, "revoked_users": {}}


class State:
    def __init__(self, dir: Path | None):
        self.path = Path(dir) / "state.json" if dir else None
        self.raw = ""
        self.data = {k: {} for k in EMPTY}
        self.refresh()

    def refresh(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as e:
            raise EngineError("state_io", str(e)) from None
        except UnicodeDecodeError:
            raise EngineError("state_io", "state.json is corrupt") from None
        if text == self.raw:
            return
        try:
            data = json.loads(text)
            assert isinstance(data, dict)
            for k in EMPTY:
                data.setdefault(k, {})
                assert isinstance(data[k], dict)
        except Exception:
            # an unreadable state file must not silently drop revocations
            raise EngineError("state_io", "state.json is corrupt") from None
        self.data, self.raw = data, text

    def save(self) -> None:
        if not self.path:
            return
        text = json.dumps(self.data, separators=(",", ":"))
        tmp = self.path.with_suffix(".json.tmp")
        try:
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as e:
            raise EngineError("state_io", str(e)) from None
        self.raw = text

    def prune(self, now: int) -> None:
        d = self.data
        d["revoked"] = {k: v for k, v in d["revoked"].items() if v + 86400 > now}
        d["approvals"] = {k: v for k, v in d["approvals"].items() if v["exp"] > now}
        d["pending"] = {k: v for k, v in d["pending"].items() if v["requested_at"] + 86400 > now}
