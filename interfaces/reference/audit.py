"""Reference AuditSink and RevocationFeed, both fed from the engine's
audit.jsonl (state directory), plus the functions that move records.

    ship(audit_path, sink)                 verify the chain, then hand the sink every record it does not hold
    JsonlAuditSink(path)                   a second copy of the log with the checks of the contract
    revocations_from_audit(audit_path)     token_revoked / user_revoked records as Revocation events
    FileRevocationFeed(path)               a JSON Lines file as the feed
    apply_revocations(backend, events)     replay revocations on an engine that has its own state

Why: the hash chain cannot show that the newest records were removed, and a
writer of the file can forge a whole new chain; an anchor outside the host
shows both (docs/LIMITATIONS.md, section 12). A verify-only engine with its
own state does not see revocations; nothing distributes them (section 5).
"""
from __future__ import annotations

import json
from pathlib import Path

from sf_smartdelegate import audit as audit_log
from sf_smartdelegate.canon import canon, sha256_hex
from sf_smartdelegate.errors import EngineError

from ..contracts import AuditSink, FeedError, Revocation, SinkError


def read_records(path) -> list:
    """Every record of an audit log whose chain verifies. Raises SinkError
    (audit_broken, audit_io) otherwise: a log that does not verify is not shipped."""
    path = Path(path)
    if not path.exists():
        return []
    try:
        audit_log.verify(path)
    except EngineError as e:
        raise SinkError(e.code, e.message) from None
    # split at "\n" only: U+2028 and friends are data (spec/PORTING.md, Strictness)
    return [json.loads(line) for line in path.read_bytes().decode("utf-8").split("\n") if line.strip()]


def check_append(head: tuple | None, held, records: list) -> list:
    """The records of `records` a sink must add, after the checks every sink
    makes. `held(seq)` returns the hash the sink holds for that sequence
    number. Raises SinkError; the caller then stores nothing."""
    seq, last = head or (0, audit_log.GENESIS)
    new = []
    for rec in records:
        if not isinstance(rec, dict) or not isinstance(rec.get("seq"), int) or not isinstance(rec.get("hash"), str):
            raise SinkError("audit_malformed", "a record without seq or hash")
        body = {k: v for k, v in rec.items() if k != "hash"}
        if sha256_hex((str(rec.get("prev")) + canon(body)).encode("utf-8")) != rec["hash"]:
            raise SinkError("audit_broken", f"record {rec['seq']}: content does not match its hash")
        if rec["seq"] <= seq:
            if held(rec["seq"]) != rec["hash"]:
                raise SinkError("audit_rewritten", f"record {rec['seq']} differs from the one already held: the log was rewritten")
            continue
        if rec["seq"] != seq + 1:
            raise SinkError("audit_gap", f"record {rec['seq']} follows {seq}: records are missing")
        if rec.get("prev") != last:
            raise SinkError("audit_broken", f"record {rec['seq']}: prev is not the hash of record {seq}")
        seq, last = rec["seq"], rec["hash"]
        new.append(rec)
    return new


class JsonlAuditSink:
    def __init__(self, path):
        self.path = Path(path)

    def _held(self) -> list:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_bytes().decode("utf-8").split("\n") if line.strip()]

    def head(self) -> tuple | None:
        held = self._held()
        return (held[-1]["seq"], held[-1]["hash"]) if held else None

    def append(self, records: list) -> None:
        held = {r["seq"]: r["hash"] for r in self._held()}
        last = max(held) if held else 0
        new = check_append((last, held[last]) if held else None, held.get, records)
        try:
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write("".join(canon(r) + "\n" for r in new))
        except OSError as e:
            raise SinkError("sink_io", str(e.strerror or e)) from None


def ship(audit_path, sink: AuditSink, batch: int = 500) -> dict:
    """Give the sink every record it does not hold yet. The record the sink
    already has as its head is sent again first, so a log that was truncated
    and regrown, or re-forged, is refused by the sink instead of extended."""
    records = read_records(audit_path)
    head = sink.head()
    if head is not None and head[0] > len(records):
        raise SinkError("audit_truncated", f"the sink holds {head[0]} records, the log has {len(records)}: the newest were removed")
    start = head[0] - 1 if head else 0
    for i in range(start, len(records), batch):
        sink.append(records[i:i + batch])
    return {"shipped": len(records) - (head[0] if head else 0), "head": sink.head()}


def revocations_from_audit(audit_path, after: int = 0) -> list:
    """The revocations recorded after sequence number `after`."""
    out = []
    for r in read_records(audit_path):
        if r["seq"] <= after:
            continue
        if r.get("event") == "token_revoked":
            out.append(Revocation(r["seq"], "token", r["token_id"], r["ts"], r.get("by")))
        elif r.get("event") == "user_revoked":
            out.append(Revocation(r["seq"], "user", r["user"], r["issued_up_to"], r.get("by")))
    return out


class FileRevocationFeed:
    def __init__(self, path):
        self.path = Path(path)

    def _read(self) -> list:
        if not self.path.exists():
            return []
        try:
            return [Revocation.from_json(json.loads(line)) for line in self.path.read_text(encoding="utf-8").split("\n") if line.strip()]
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise FeedError("feed_unreadable", type(e).__name__) from None

    def publish(self, events: list) -> None:
        have = {e.seq for e in self._read()}
        new = sorted((e for e in {e.seq: e for e in events}.values() if e.seq not in have), key=lambda e: e.seq)
        try:
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write("".join(json.dumps(e.to_json(), sort_keys=True) + "\n" for e in new))
        except OSError as e:
            raise FeedError("feed_io", str(e.strerror or e)) from None

    def poll(self, after: int = 0) -> list:
        return sorted((e for e in self._read() if e.seq > after), key=lambda e: e.seq)


def apply_revocations(backend, events: list) -> int:
    """Replay revocations on another engine (for example a verify-only one
    with its own state directory). Returns the seq of the last event applied;
    keep it and pass it to `poll(after=...)` next time.

    Stops at the first event the engine refuses and raises FeedError: a
    revocation is never skipped. Replaying an event is harmless. A user
    revocation is applied with the receiving engine's clock, so its cut-off
    there is the time of the replay, not `ts`: tokens that user obtained
    between the two are revoked as well. That errs on the side of denying."""
    last = 0
    for e in sorted(events, key=lambda e: e.seq):
        body = {"token_id": e.subject} if e.kind == "token" else {"user": e.subject} if e.kind == "user" else None
        if body is None:
            raise FeedError("feed_malformed", f"event {e.seq}: unknown kind")
        r = backend.call("revoke", dict(body, by=f"feed:{e.by or 'unknown'}"))
        if not r.get("ok"):
            raise FeedError("apply_failed", f"event {e.seq} was not applied ({(r.get('error') or {}).get('code')}); stopped there")
        last = e.seq
    return last
