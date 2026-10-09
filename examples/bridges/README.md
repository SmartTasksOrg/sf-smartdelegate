# Bridges walkthrough

    pip install cryptography
    python examples/bridges/walkthrough.py

No network and no cloud account: the directory is a fake Microsoft Graph and
the STS client is a fake, both defined in `walkthrough.py`. Nothing in this
folder has been run against a real provider (see `docs/BRIDGES.md`).

What the script does:

1. **Sync.** Reads users, groups and memberships from the fake Graph with
   `bridges.entra.fetch` and writes `entities.json` in a temporary copy of the
   example bundle (`bridges.directory.sync`). Agents in the file are kept.
2. **Claims to groups.** Turns Entra ID-token claims (`groups` = object ids)
   into SmartDelegate groups with `claims_rule.entra.json`, then calls
   `core.delegate(..., role="report-reader", groups=...)`.
3. **Down-scoping.** Builds the `sts.assume_role` arguments for the role's
   `bindings.aws.role_arn` with `bridges.aws.assume_role_request` and shows,
   with a small IAM matcher, that the session policy allows `s3:GetObject` on
   `reports/*` and nothing else the map knows about. A sub-agent's narrower
   token gives a narrower policy.
4. **Removal.** Takes the human out of the group in the fake directory, syncs,
   reloads the engine, and calls `directory.revoke_changed` (what
   `bridge sync-* --revoke` does): the token issued in step 2 and its
   sub-agent's token are refused with `DELEGATE-TOKEN-REVOKED`, and a new
   delegation is refused with `DELEGATE-ROLE-NOT-HELD`, both from the stored
   membership and from a fresh sign-in. The fake STS session from step 3 is
   not ended by any of this. It then shows the caveat: replaying the *old*
   claims still gets a new token until that ID token expires.

Files:

| File | Purpose |
|---|---|
| `walkthrough.py` | the script |
| `cloud_map.json` | SmartDelegate (action, resource) -> AWS / GCP / Azure permissions |
| `group_map.json` | directory group id -> SmartDelegate group, for `bridge sync-* --group-map` |
| `claims_rule.entra.json` | rule for `bridge map-claims --rule` / `claims.groups_from_claims` |

The same pieces from the command line (run from the repository root with
`PYTHONPATH=src`, or after `pip install .`):

    python -m sf_smartdelegate bridge map-claims --claims '{"groups": ["11111111-1111-1111-1111-111111111111"]}' \
        --rule @examples/bridges/claims_rule.entra.json
    python -m sf_smartdelegate bridge aws-session-policy --cap '{"actions": ["read"], "resources": ["s3.object/reports/*"]}' \
        --map examples/bridges/cloud_map.json
    python -m sf_smartdelegate bridge gcp-boundary --cap '{"actions": ["read"], "resources": ["gcs.object/reports/*"]}' \
        --map examples/bridges/cloud_map.json
    python -m sf_smartdelegate bridge azure-scopes --cap '{"actions": ["read"], "resources": ["graph.mail/*"]}' \
        --map examples/bridges/cloud_map.json

With real providers (untested, see the status note in `docs/BRIDGES.md`):

    export OKTA_TOKEN=...          # the secret stays in the environment
    python -m sf_smartdelegate bridge sync-okta --org acme.okta.com --token-env OKTA_TOKEN \
        --out bundle --group-map examples/bridges/group_map.json --dry-run
    # then without --dry-run, and with --revoke to end the tokens of users who were removed or lost a group:
    #   ... --daemon-url http://127.0.0.1:8181 --admin-key-env SD_ADMIN_KEY --revoke
    # A running engine must reload and a signed bundle must be re-signed after every sync.
