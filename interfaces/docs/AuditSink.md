# AuditSink

Receive the audit records somewhere the engine's host cannot rewrite.

## Contract

```python
class AuditSink(Protocol):
    def append(self, records: list[dict]) -> None: ...     # in sequence order; raise SinkError to refuse
    def head(self) -> tuple[int, str] | None: ...          # (seq, hash) of the newest record held
```

The source is `audit.jsonl` in the state directory: one canonical JSON object
per line, `hash = sha256(prev + canonical(record without "hash"))`, the first
`prev` is 64 zeros, `seq` starts at 1 (`spec/PORTING.md`, "Audit record";
fields in `docs/SCOPE.md`, section 8.3). `interfaces.reference.ship(audit_path, sink)`
verifies the chain, then sends every record the sink does not hold, starting
with the sink's own head so that a rewritten log is noticed.

## Fails closed

`append` MUST raise and hold nothing new when:

- a sequence number is missing (a gap);
- a record's content does not match its hash, or its `prev` is not the hash
  of the record before it;
- a record differs from the one already held under that sequence number (the
  log was rewritten).

Records already held are skipped without error. `head` survives a restart.
`ship` refuses a log that does not verify, and a log that is shorter than
what the sink holds.

## Security notes

- The chain detects edits, deletions and reordering. It cannot detect that
  the newest records were removed, and whoever can write the file can forge a
  whole new chain. A head kept outside the host shows both: that is what the
  sink is for (LIMITATIONS, section 12; THREAT_MODEL, threat 14).
- Records hold field names, never field values, and never tokens (threat 15).
  They do hold user ids, agent names, resource paths and ids.
- The record of an issued token holds user, role and capability, not the
  groups that were supplied nor who supplied them (threat 25).
- A request that fails at issuance (`role_not_held`, `role_exceeded`,
  `widening`) is answered to the caller and is **not** in the audit log. Log
  those at the token service.
- There is no OpenTelemetry export in the engine. This interface is the export.

## Other languages

Tail `audit.jsonl` as bytes and split at `\n` only (U+2028, U+2029 and U+0085
are data). Verify with any engine port (`audit verify` in the Python, Rust,
Node.js, Go and PHP command lines) or with the formula above. Over REST, with
the admin key: `GET /v1/admin/audit/tail?n=N` and `GET /v1/admin/audit/verify`
(`{"records", "head"}`). There is no REST call that reads from a sequence
number: for complete shipping read the file.

## Reference implementation

`interfaces/reference/audit.py`: `JsonlAuditSink(path)`, `ship`, and
`check_append`, the checks every sink makes, reusable by a sink that stores
elsewhere.

## Checks

`python -m interfaces.contract --audit yourpkg:factory`, with
`factory(location)`: two sinks made with the same `location` share what they hold.

| Check | Requires |
|---|---|
| `audit-head` | an empty sink has no head; after shipping, the head is the log's newest record |
| `audit-replay` | held records are skipped; a second shipment sends nothing; later records follow |
| `audit-gap` | a batch that skips a record, or starts after one, is refused |
| `audit-chain` | an edited record and a record from another chain are refused |
| `audit-rewrite` | a re-forged log and a shortened log are refused; the head does not move |
| `audit-restart` | the head survives a restart |
