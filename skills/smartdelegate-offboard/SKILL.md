---
name: smartdelegate-offboard
description: End every SmartDelegate token of a human who left or lost a role - directory sync, revoke-by-user, and verification that the tokens are dead. Use when a person is offboarded, loses a group, or their agents must be stopped now. Requires explicit human confirmation before any revocation.
---

# Offboard: revoke by user, then verify

Three things keep an agent from outliving its human's rights (`spec/ROLES.md`,
"When the human loses the role"):

1. **No new tokens**: membership is checked at issuance, from the identity
   provider's token or from the last directory sync.
2. **Live tokens end**: revoke-by-user ends every token already issued for
   that human, sub-agent tokens included.
3. **The gap**: a role's `max_ttl` bounds what is left if nobody revokes.

Commands are written `smartdelegate ...`; from a clone without installing,
`PYTHONPATH=src python3 -m sf_smartdelegate ...`. They act on the state directory of
the engine named by `--config FILE`; every engine sharing that directory sees
the revocation on its next decision.

## Never without a human

- Never revoke a user without a human confirming, in this conversation, the
  **exact user id** and that they mean it. Revocation is not undoable, ends
  all of that user's tokens (also under roles they still hold) and stops
  their agents' work in progress.
- Never guess the id. The user is matched by the exact string in the token
  (`sub`). A login name and a directory id of one person are two users. Read
  it from an audit record or `token inspect`.
- Never run a directory sync with `--force`: the removal guard exists to
  stop a broken directory answer from removing people.
- Never revoke "to be safe" on a monitoring finding. Report the finding.
- Never claim the person is fully offboarded. State what was done and what
  this does not reach (below).

## Commands

1. Confirm with the human: the user id, the reason, who authorises it. Find
   the exact id if needed:

```bash
sf-smartdelegate audit tail -n 500
```

2. The source of truth comes first: the person is removed or disabled at the
   identity provider. Otherwise they sign in again and get new tokens.

3. Bring the engine's membership up to date and revoke in one step. Shown for
   SCIM; the other directories have their own sync command (`docs/BRIDGES.md`).
   Look at the diff first:

```bash
sf-smartdelegate bridge sync-scim --url "$SCIM_URL" --token-env SCIM_TOKEN --out bundle --dry-run
sf-smartdelegate bridge sync-scim --url "$SCIM_URL" --token-env SCIM_TOKEN --out bundle --revoke --config smartdelegate.json
```

   `--revoke` ends the tokens of everyone the sync removed or who lost a
   group; `--config` names the engine whose state directory holds the
   revocations. Against a running daemon use `--daemon-url` and
   `--admin-key-env` instead, so the daemon reloads before the revoke (that
   form was not run while this skill was written; `tests/test_bridges.py`
   covers it). A signed bundle must be signed again after a sync. The two
   commands above were run against a stand-in SCIM server on loopback, not
   against a real directory.

4. Or revoke one user directly. This form records who asked (`by`):

```bash
sf-smartdelegate call revoke --input '{"user": "alice", "by": "jane.doe"}'
```

   The short form records `by` as `cli`:

```bash
sf-smartdelegate token revoke --user alice
```

5. Verify. The audit log has a `user_revoked` record, and no token of the
   user is alive (exit status 0 and an empty `live_tokens` list):

```bash
sf-smartdelegate audit tail -n 5000 | python3 skills/smartdelegate-offboard/scripts/live_tokens.py --user alice
```

   If you hold one of the user's tokens, the engine itself must say it is dead
   (`"valid": false, "reason": "token_revoked"`):

```bash
sf-smartdelegate token inspect --token "$TOKEN"
```

6. Check that membership is gone, so that no new token can be issued: the
   user is absent from `entities.json` or in no group that holds a role, and
   the engine has reloaded. A token request for them now fails with
   `DELEGATE-ROLE-NOT-HELD`.

## What revocation does not reach

Say this in the report (`docs/LIMITATIONS.md`, sections 5 to 8):

- An engine that verifies tokens with its own state directory keeps honouring
  them until they expire, unless revocations are carried there
  (`interfaces/docs/RevocationFeed.md`).
- A cloud credential already made from a token (AWS session, Google
  down-scoped token, Azure On-Behalf-Of token) lives until its own expiry.
- Revoke-by-user is a cut-off in time, not a ban: a token issued afterwards
  is valid if the person still passes the membership check.
- An ID token issued before the removal still lists the old groups until it
  expires. The engine refuses ID tokens issued at or before the cut-off;
  one issued later from a stale session is accepted.
- An engine that has not reloaded after the sync can still issue from the old
  membership.

## Report

User id, who confirmed, the `user_revoked` record (sequence number,
`issued_up_to`, `by`), the result of the live-token check, whether the
directory and the engine's membership were updated, and the list above.
