"""Append-only, hash-chained decision log (JSON Lines).

record.hash = sha256(prev_hash + canonical_json(record without "hash")).
Editing, deleting or reordering any line breaks every hash after it.
Truncating the tail is only detectable against a head hash kept elsewhere.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .canon import canon, sha256_hex
from .errors import EngineError

GENESIS = "0" * 64


def verify(path: Path) -> dict:
    """Recompute the whole chain. Raises audit_broken naming the first bad line."""
    prev, n = GENESIS, 0
    try:
        raw = Path(path).read_bytes()
    except OSError as e:
        raise EngineError("audit_io", f"cannot read audit log: {e.strerror or e}") from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise EngineError("audit_broken", "the audit log is not UTF-8") from None
    for lineno, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            assert isinstance(rec, dict)
        except Exception:
            raise EngineError("audit_broken", f"line {lineno}: not JSON") from None
        claimed = rec.pop("hash", "")
        if rec.get("prev") != prev:
            raise EngineError("audit_broken", f"line {lineno}: prev hash does not match the line before")
        if rec.get("seq") != n + 1:
            raise EngineError("audit_broken", f"line {lineno}: sequence number is not {n + 1}")
        if sha256_hex((prev + canon(rec)).encode("utf-8")) != claimed:
            raise EngineError("audit_broken", f"line {lineno}: content does not match its hash")
        prev = claimed
        n += 1
    return {"ok": True, "records": n, "head": prev}


def tail(path: Path, n: int) -> list:
    if not path.exists():
        return []
    # split on "\n" only: canonical JSON writes U+2028, U+0085 and friends
    # as themselves, and str.splitlines() would cut a record in two there
    lines = [l for l in path.read_bytes().decode("utf-8", "replace").split("\n") if l.strip()]
    out = []
    for l in lines[max(0, len(lines) - n):]:
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.seq, self.head = 0, GENESIS
        if self.path.exists():
            v = verify(self.path)
            self.seq, self.head = v["records"], v["head"]
        self.len = self.path.stat().st_size if self.path.exists() else 0

    def _resync(self) -> None:
        """Chain onto the last record if another process appended. The engine
        holds the state-directory lock while this runs."""
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        if size == self.len:
            return
        if size == 0:
            raise EngineError("audit_broken", "the audit log was truncated while in use")
        try:
            with open(self.path, "rb") as f:
                f.seek(max(0, size - (1 << 20)))
                lines = [l for l in f.read().decode("utf-8", "replace").split("\n") if l.strip()]
        except OSError as e:
            raise EngineError("audit_io", f"cannot read audit log: {e.strerror or e}") from None
        try:
            last = json.loads(lines[-1])
            self.seq, self.head, self.len = int(last["seq"]), str(last["hash"]), size
        except Exception:
            raise EngineError("audit_broken", "the last audit record is unreadable") from None

    def append(self, record: dict, ts: int) -> str:
        self._resync()
        rec = dict(record)
        rec.pop("hash", None)
        rec.update(seq=self.seq + 1, ts=ts, prev=self.head)
        h = sha256_hex((self.head + canon(rec)).encode("utf-8"))
        rec["hash"] = h
        try:
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(canon(rec) + "\n")
                f.flush()
                self.len = os.fstat(f.fileno()).st_size
        except OSError as e:
            raise EngineError("audit_io", f"cannot write audit log: {e.strerror or e}") from None
        self.seq += 1
        self.head = h
        return h
