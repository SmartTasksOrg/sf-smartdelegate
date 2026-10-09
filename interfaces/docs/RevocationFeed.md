# RevocationFeed

Carry revocations to engines that do not share the issuer's state.

## Contract

```python
class RevocationFeed(Protocol):
    def publish(self, events: list[Revocation]) -> None: ...     # an event already published (same seq) is skipped
    def poll(self, after: int = 0) -> list[Revocation]: ...      # seq > after, in seq order; raise FeedError when unreadable
# Revocation(seq, kind, subject, ts, by)     kind "token": subject is a token id;  kind "user": subject is a user id
```

Why it exists: revocation takes effect on the next decision of every engine
that shares the state directory or sits behind the same daemon. A verify-only
engine with its own state (`verify_only` + `trusted_keys`) keeps honouring a
revoked token until it expires; the product has no channel that distributes
revocations (`docs/LIMITATIONS.md`, section 5). If every enforcement point
asks one daemon, you do not need this interface.

The path: `revocations_from_audit(audit_path, after)` reads `token_revoked`
and `user_revoked` records at the issuer, `publish` sends them, the receiving
side calls `poll(after=cursor)` and `apply_revocations(engine, events)`, which
replays each as `revoke` on the local engine and returns the new cursor.

## Fails closed

- `poll` MUST raise when the feed cannot be read. An empty list means
  "nothing was revoked" and must only ever mean that.
- Events are never dropped, whatever their kind, and come back as published.
- `apply_revocations` stops at the first event the engine refuses and raises;
  it does not skip a revocation.
- Replaying is harmless: at-least-once delivery is enough.

What the kit cannot check for you: what your enforcement points do while the
feed is unreadable. Decide it (keep serving until tokens expire, or deny) and
write it down; a role's `max_ttl` is the bound either way.

## Security notes

- Whoever can publish to the feed can end any token and any user's tokens:
  the same lever as the admin key's `revoke` (THREAT_MODEL, threat 35).
  Whoever can suppress the feed keeps revoked tokens alive at the receivers
  until they expire. Authenticate both ends.
- A replayed user revocation is applied with the receiver's clock: the cut-off
  there is the time of the replay, so tokens that user obtained in between
  are revoked too. That errs towards denying.
- Not reached by any revocation: a cloud credential already issued (AWS
  session, Google down-scoped token, Azure OBO token) lives until its own
  expiry (threats 32, 36).
- The user is matched by the exact string in the token's `sub`.

## Other languages

At the issuer read `token_revoked` (`token_id`, `by`) and `user_revoked`
(`user`, `issued_up_to`, `by`) records from `audit.jsonl`. At each receiver,
with its admin key: `POST /v1/admin/revoke {"token_id": T, "by": "feed"}` or
`{"user": U, "by": "feed"}`. Keep the last applied `seq`.

## Reference implementation

`interfaces/reference/audit.py`: `revocations_from_audit`, `FileRevocationFeed(path)`
(a JSON Lines file; stands in for a queue or a topic), `apply_revocations`.

## Checks

`python -m interfaces.contract --revocation yourpkg:factory`, with
`factory(location)`.

| Check | Requires |
|---|---|
| `feed-order` | every event after the cursor, in sequence order |
| `feed-replay` | a republished event is not duplicated |
| `feed-restart` | events survive a restart |
| `feed-fidelity` | kind, subject, time and `by` come back as published |
| `feed-reaches-verifier` | a token revocation and a user revocation stop the tokens, and a derived sub-agent token, at an engine with its own state; other tokens keep working |
