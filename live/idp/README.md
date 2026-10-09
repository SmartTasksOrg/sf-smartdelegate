# Live identity-provider tests: SmartDelegate against a real Keycloak

Everything else in this repository tests the identity-provider integrations
against hand-written fakes. This directory runs them against a real server: a
Keycloak that is downloaded, started on a loopback port, filled with the
example company (Kestrel Works: 35 people, 19 nested groups), and used through
its real token endpoint, JWKS and Admin REST API.

**Verified: Keycloak 26.0.7, on 2026-10-05, Linux, Java 21, Python 3.11. 45 tests, 0 failed, 0 skipped.**
The same suite passed against Keycloak 26.8.0 the same day (`SD_KEYCLOAK_VERSION=26.8.0`).
One complete run is recorded in [TRANSCRIPT.md](TRANSCRIPT.md). The findings are written up in
[docs/BRIDGES.md](../../docs/BRIDGES.md#keycloak-verified-against-the-real-server).

No other provider has been run against the real service. See [Not verified](#not-verified).

## Run it

```bash
live/idp/run.sh                 # start -> provision -> tests -> stop.  0 pass, 1 fail, 3 skipped
live/idp/run.sh --transcript    # the same, and rewrite TRANSCRIPT.md
live/idp/run.sh -k D_Ghosting   # only the tests whose name matches
```

Needs `bash`, `curl`, `python3` (3.10+, with `cryptography`, as the engine does)
and Java 17 or 21. The first run downloads about 150 MB. A full run takes
about two minutes on two cores; the server is given a 768 MB heap.

Step by step:

```bash
live/idp/keycloak.sh start                    # download on first use, free port, waits until ready
python3 live/idp/provision.py                 # create or repair the realm (idempotent, ~6 s when it exists)
PYTHONPATH=src python3 -m unittest live.idp.test_live_idp -v
live/idp/keycloak.sh stop                     # by PID; confirms the port is free
live/idp/keycloak.sh status | url | reset     # reset = stop and delete the server's database
python3 live/idp/provision.py --reset         # delete only the test realms
```

`python3 -m unittest live.idp.test_live_idp` works on its own too: it starts
the server if none is running, provisions, and stops what it started. When
Keycloak cannot be downloaded, started or reached, every test is **skipped**
with the reason (and `run.sh` exits 3), never reported as passed.

| File | What it is |
|---|---|
| `keycloak.sh` | `start`, `stop`, `status`, `url`, `reset` for a local Keycloak in dev mode (`start-dev`, built-in database, loopback only, no proxy) |
| `provision.py` | builds the realm from `examples/company/` through the Admin REST API |
| `kc.py` | shared plumbing: where the server is, an Admin REST client, the OIDC calls |
| `test_live_idp.py` | the tests |
| `run.sh` | the whole cycle with an exit code |
| `TRANSCRIPT.md` | the readable record of one run (`--transcript` rewrites it) |

### Where things are kept

Nothing that is downloaded or secret is written into the repository.

| | Where |
|---|---|
| Keycloak archive, unpacked server, its database | `~/.cache/smartdelegate/keycloak/` (`SD_KEYCLOAK_CACHE`) |
| pid, port, log | `keycloak.pid`, `keycloak.port`, `keycloak.log` in that directory |
| bootstrap admin password (generated at first start) | `admin.env` there, mode 0600 |
| client secrets and the 36 test users' passwords (generated at every provisioning) | `provision.json` there, mode 0600 |

The archive is checked against the `.sha1` file published next to it in the
Keycloak release (26.0.7 has no `.sha256`). If no checksum can be fetched the
script says so and continues.

| Variable | Default | |
|---|---|---|
| `SD_KEYCLOAK_VERSION` | `26.0.7` | which release to download and start |
| `SD_KEYCLOAK_CACHE` | `~/.cache/smartdelegate/keycloak` | |
| `SD_KEYCLOAK_HEAP` | `768m` | JVM maximum heap |
| `SD_KEYCLOAK_START_TIMEOUT` | `240` | seconds to wait for readiness |
| `SD_KEYCLOAK_REALM` | `kestrel` | the test realm; a second one, `<realm>-other`, is created too |
| `SD_KEYCLOAK_KEEP` | unset | leave the server running after `run.sh` or the test module |
| `SD_LIVE_TRANSCRIPT` | unset | `1` writes `TRANSCRIPT.md` |
| `SD_LIVE_TIMEOUT` | `1800` | seconds `run.sh` gives the tests |

## Attach to an existing Keycloak

For a docker-compose service or a company test server, name it instead of
letting the scripts start one:

```bash
export SD_KEYCLOAK_URL=http://localhost:8080          # https for anything not on loopback
export SD_KEYCLOAK_ADMIN=admin
export SD_KEYCLOAK_ADMIN_PASSWORD=...
live/idp/run.sh
```

With `SD_KEYCLOAK_URL` set, `keycloak.sh start` only checks that the server
answers, `stop` and `reset` do nothing to it, and `run.sh` leaves it running.

The admin must be allowed to create realms. The run creates the realms
`kestrel` and `kestrel-other` (`SD_KEYCLOAK_REALM` renames them) and, inside
them only, changes memberships, disables a user, shortens the token lifespan
and adds signing keys, putting each back afterwards. **Do not point it at a
realm people use**: `provision.py` resets the passwords and memberships of
every user it manages. `provision.py --reset` deletes both realms.

```yaml
# docker-compose.yml, for example
services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.0.7
    command: start-dev
    environment: {KC_BOOTSTRAP_ADMIN_USERNAME: admin, KC_BOOTSTRAP_ADMIN_PASSWORD: change-me}
    ports: ["8080:8080"]
```

The compose file above was not run here (no Docker daemon); attaching was
tested against a server started by `keycloak.sh`.

## What the realm looks like

`provision.py` reads `examples/company/entities.json` and creates:

- **Users**: the 35 humans, username = entity id (`anna`, `elena`, ...), with
  the attributes `region` and `unit` (only an admin can write them) and a
  generated password; `ex-employee` (disabled, still a member of
  `/employees/support`); 120 `filler-NNN` users in `/pagination-fill`, so that
  the user listing and one member listing need more than one page of 100.
- **Groups**, as a tree, because a Keycloak group has one parent:
  `/employees/{support,finance,hr,sales,procurement,it-ops,compliance,managers}`,
  `/employees/support/support-supervisors`,
  `/employees/finance/finance-approvers/finance-managers`, and so on. The
  company nests some groups under two parents (`support-supervisors` is inside
  `support` and inside `managers`); the second parent becomes a direct
  membership. Provisioning checks that the effective membership of every human
  is exactly the company's.
- **Realm roles**: one per company group, mapped on that group.
- **Clients**

| Client | Purpose |
|---|---|
| `sd-engine` | the engine's audience. One mapper: Group Membership, claim `groups`, full path **on** |
| `sd-engine-leaf` | the same with full path **off** |
| `sd-engine-roles` | no group mapper; User Realm Role mappers writing a flat `roles` claim and the nested `realm_access.roles` into the ID token; one client role |
| `sd-attr-mapper` | wrong on purpose: `groups` filled from a user-editable attribute |
| `sd-other` | another application of the same realm |
| `sd-sync` | service account for `bridge sync-keycloak`, holding exactly the role below |

No second "sync admin" client was needed.

## The least privilege the sync needs

Found by removing one role at a time (`G_LeastPrivilege`):

| `realm-management` client roles of the service account | `bridge sync-keycloak` |
|---|---|
| **`view-users`** | **works: 156 users, 20 groups. This is the minimum.** |
| `view-users` + `query-users` + `query-groups` (what the docs used to say) | works; the two extra roles are already inside `view-users`, which is a composite |
| `query-users` + `query-groups`, or `query-users` alone | **Keycloak answers 200 with empty lists**, as if the realm were empty. Refused by the adapter: `empty_directory` (26.0.7, where `/users/count` says 0) or `truncated_pagination` (26.8.0, where it says 156) |
| `query-groups` alone, or none | HTTP 403 on `/users` |

A credential with `view-users` cannot change anything (a membership change
with it is answered 403).

```bash
export SD_KC_TOKEN=$(curl -s -d grant_type=client_credentials -d client_id=sd-sync -d client_secret="$SECRET" \
    https://kc.example/realms/acme/protocol/openid-connect/token | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
sf-smartdelegate bridge sync-keycloak --url https://kc.example --realm acme --token-env SD_KC_TOKEN --out bundle \
    --group-map group_map.json --attr-map attr_map.json --nested inherit \
    --daemon-url http://127.0.0.1:8181 --admin-key-env SD_ADMIN_KEY --revoke
```

The token lives five minutes by default. From Python:
`keycloak.acquire_token(url, realm, "sd-sync", secret_env="KC_SECRET")`.

## What was verified against the real server

| | Tests | Verified |
|---|---|---|
| a | `A_Oidc` (8) | Role tokens issued from the ID token alone, through the engine and through `sf-smartdelegate serve` (no key on the request). A user outside the group: `role_not_held`. Wrong audience, a token of another realm (same client id, user and group path), six kinds of tampering, an expired token: `id_token_invalid`. Signing-key rotation: the outage an unannounced one causes, `POST /v1/admin/reload` ending it without a restart, a broken JWKS file leaving the old keys in force, and the passive-first order that refuses nobody |
| b | `B_ClaimShapes` (6) | The `groups` claim with full path on (`/employees/support`) and off (`support`); a child-group member does **not** get the parent; a user in no group has no claim; realm and client roles are in the access token, not the ID token, and realm roles inherit from parent groups; a slash in a group name is not escaped. `bridges/claims.py` on all of these |
| c | `C_DirectorySync` (8) | `bridge sync-keycloak`, as a function and as a subprocess: two pages of users, a 120-member group, disabled users, service accounts, `/children`, `--nested direct` and `inherit`, `--user-id id` = the token's `sub`, `--dry-run`, an invalid admin token, the removal guard (12 of 35 people lose every group in Keycloak), `--force`, and `--revoke --daemon-url`: a group removed in Keycloak makes the agent's and the sub-agent's token `token_revoked`, the ID token of the earlier sign-in `id_token_invalid`, and a new delegation `role_not_held`; a fresh sign-in or a refresh yields the roles still held |
| d | `D_Ghosting` (5) | The whole loop in one test with a transcript; the same removal with no sync running (the replay window measured); the default lifespan; a per-client lifespan; a refresh returns current groups |
| e | `E_HarnessScenarios` (3) | The steps of harness scenarios 07 (offboarding mid-task) and 08 (role change), with every delegation made from a Keycloak sign-in and every revoke made by a change in Keycloak plus a sync. Two steps of 07 end differently than in the scenario file, and the transcript says why. A disabled user's old ID token: accepted until the sync, refused after it |
| f | `F_Abuse` (7) | A user editing her own profile cannot change `groups`, her username or her region; the wrong mapper lets her; tokens of four other clients of the realm are refused; `aud`/`azp`/`typ` of ID and access tokens; a disabled user; a group name that imitates a path |
| g | `G_LeastPrivilege` (3) | The table above; the service-account token |
| h | `H_EngineFixes` (5) | Regression tests for the engine fixes the first run led to: another client's access token is refused (`azp`); every ID token Keycloak issues to the engine's client is accepted (direct grant, refresh, with an audience mapper, token exchange where the server has it); `groups_claim: "realm_access.roles"`; and one thing still open (`typ`) |

The differences between the hand-written fakes and the real server, and what
was changed because of them, are listed in docs/BRIDGES.md and repeated in the
offline suite (`tests/test_bridges.py`), whose Keycloak fixtures are now
copies of the real answers.

## What an operator should take from it

Short form; the reasoning and the evidence are in
[docs/BRIDGES.md](../../docs/BRIDGES.md#keycloak-verified-against-the-real-server).

1. **Send the ID token**, never the access token; `idp.audience` is the
   engine's client id. The engine checks `azp`, so an access token that
   Keycloak issued to another application is refused even though its `aud`
   names the engine's client. The engine's client **may have client roles**
   (verified). Do not put an audience mapper naming the engine's client on
   that client itself: its own access token would then pass as an ID token
   (`typ` is not checked).
2. **Group Membership mapper, full path on**, added to the ID token. Map the
   paths with `idp.group_map`. Keep the group nesting in `entities.json`
   (`sync-keycloak --nested inherit`): the claim lists direct groups only.
   For realm roles instead: `"groups_claim": "realm_access.roles"` plus a
   *User Realm Role* mapper that adds them to the ID token; by default only
   the access token has them.
3. **The sync interval is the replay window.** After a removal in Keycloak,
   an ID token from before it keeps yielding the role until the next
   `sync --revoke` has run, and at most until it expires (measured without
   any sync: the rest of an 8 s lifespan; 300 s with Keycloak's default).
   From that sync on it is refused and the user must sign in again or
   refresh; the fresh token carries only what is still held. Run the sync
   with `--revoke` often, alert when it fails, and keep the engine client's
   access-token lifespan and the roles' `max_ttl` short for when it does not.
4. **Key rotation needs a reload, not a restart**, with `idp.jwks_file`: new
   key passive in Keycloak → write the new JWKS to the file →
   `POST /v1/admin/reload` → make the key active.
5. **`view-users` only** for the sync's service account.
6. **Whoever can create groups in the realm can grant roles**: a group named
   `employees/support` is indistinguishable in a token from the subgroup. Run
   the sync on a schedule; it refuses such a realm and so reports it.
7. `user_claim: preferred_username` only while "Edit username" is off;
   otherwise `sub` with `--user-id id`.

## Engine changes the first run led to, and what is still open

The first run of this suite showed four gaps in the engine's OIDC path. They
were then closed in the engine (`spec/PORTING.md`, "OIDC ID tokens"); this
suite did not change the engine and now holds the fixed behaviour.

| Fixed | Regression test against the real server |
|---|---|
| `azp` must equal the audience: another client's access token is no longer accepted as an ID token | `H_EngineFixes.test_an_access_token_issued_to_another_client_is_refused`, `...test_every_id_token_keycloak_issues_to_the_engines_client_is_accepted` |
| An ID token issued at or before the user's revoke cut-off is refused | `D_Ghosting` step (iv), `C_DirectorySync.test_08`, `E_HarnessScenarios.test_a_disabled_users_old_id_token_dies_with_the_sync` |
| `reload` re-reads `idp.jwks_file` | `A_Oidc.test_07_signing_key_rotation`, `test_08_rotation_without_an_outage` |
| `idp.groups_claim` may be a dotted path | `H_EngineFixes.test_groups_claim_reads_a_nested_claim` |

What Keycloak puts in `azp`, as observed: the client the token was issued to,
in every ID token (direct grant, refresh, with a second audience from an
audience mapper, a service account's client-credentials ID token). Token
exchange is refused by 26.0.7 (`unsupported_grant_type`; a preview feature
that is off). On 26.8.0, with "standard token exchange" switched on for the
engine's client, exchanging another client's access token for an ID token
gives `typ: ID`, `aud` = `azp` = the engine's client, which the engine
accepts; the exchanged *access* token has `aud: account` and is refused. No
legitimate ID token was refused by the `azp` rule on either version.

Still open (details in docs/BRIDGES.md, "Engine changes that would help"):

| Open | Evidence |
|---|---|
| `typ` is not checked: the engine's own access token passes as an ID token when an audience mapper puts the client into its own access tokens | `H_EngineFixes.test_the_engines_own_access_token_is_still_not_told_from_an_id_token` (passes while it is so) |
| The revoke cut-off compares whole seconds across two clocks: a sign-in in the second of the revoke is refused once | the tests wait 1.2 s after a revoke before a fresh sign-in |
| A well-formed JWKS with no keys is accepted by `reload` and refuses every sign-in | `A_Oidc.test_07`, step 5 |
| `idp.group_map` cannot add a path's parent groups | `B_ClaimShapes.test_02` |

## Not verified

- **Every other provider.** Microsoft Entra ID, Okta, Google Workspace / Cloud
  Identity, AWS IAM Identity Center, Auth0, and any SCIM server: their
  adapters and claim presets have still only met fakes.
- **The authorization-code flow in a browser.** Sign-in here is the direct
  access grant (username and password at the token endpoint), which a
  production deployment should not enable. The ID token is expected to carry
  the same claims; that was not shown.
- **Keycloak clustering**, an external database, a production (`start`) build
  with TLS and a fixed hostname. The tests use `start-dev` on plain http on
  loopback, where the issuer is `http://127.0.0.1:<port>/realms/<realm>`.
- Keycloak versions other than 26.0.7 and 26.8.0; user federation (LDAP);
  fine-grained admin permissions; identity brokering; realms with many
  thousands of users (the largest listing here is 156).
- The docker-compose attachment shown above (attaching itself was tested).
- Ports other than the Python reference engine. The live suite drives
  `src/sf_smartdelegate` only.
- Windows and macOS.
