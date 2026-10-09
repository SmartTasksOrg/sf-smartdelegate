# IdentitySource

Who is the human, and what do they belong to right now.

## Contract

```python
class IdentitySource(Protocol):
    def identify(self, id_token: str) -> Identity: ...      # Identity(user, groups, issuer, expires_at)
```

- Input: an OIDC **ID token** (never an access token) as the provider issued it.
- Output: `user` (the claim you chose as the user id, `sub` by default) and
  `groups`: SmartDelegate group ids after your mapping, sorted, without
  duplicates. `[]` is a true answer: the human is in no group.
- Error: `IdentityError(code, message)`. Nothing about the human is returned.
- The result goes to `issue_token` as `user` and `groups`. There the group
  list **replaces** the stored membership of that user for the token
  (`spec/ROLES.md`, "issue_token with a role").

Two ways to use it. Pick one per deployment:

| | Who verifies the ID token | Call |
|---|---|---|
| Engine path | the engine, from `idp.*` in its configuration (`spec/API.md`, "Engine configuration") | `issue_token {"id_token", "agent", "role", "task"}`; over REST no key is needed |
| Token-service path | your `IdentitySource` | `issue_token {"user", "groups", "agent", "role", "task"}` with the admin key |

The engine path needs no code. Use the token-service path when the claims
need more than a flat map (Entra overage, Keycloak group paths, several
claims): `sf_smartdelegate.bridges.claims` has the provider rules.

## Fails closed

`identify` MUST raise, never return, when:

- the signature does not verify against the provider's keys, or the text is not a JWT;
- `iss` is not the configured issuer;
- `aud` does not contain this client, or `azp` is present and is another client, or there are several audiences and no `azp`;
- the token has expired;
- the groups claim has the wrong type, or the provider signalled an overage
  (Entra ID leaves the groups out above 200). An overage is never "no groups".

It MUST return `[]`, not `None` and not an error, for a human in no group, and
MUST NOT return groups remembered from an earlier token of that user.

## Security notes

From `docs/THREAT_MODEL.md` and `docs/LIMITATIONS.md`:

- Whoever calls `issue_token` with `user` and `groups` is trusted to tell the
  truth; the engine checks that input against nothing (trust assumptions,
  threat 25). Only a component that verified the sign-in itself may hold the
  admin key: a token service, never an agent, never an enforcement point.
- An ID token can be replayed until it expires: no nonce, no `jti` record
  (threat 26). An ID token issued before the human lost a group still lists
  the group and overrides a newer directory sync. Keep ID-token lifetimes short.
- Dropping unmapped groups is safe for rules that **grant** on membership. A
  `forbid` that depends on membership in a dropped group stops applying to
  that token (threat 27).
- `typ` is not checked by the engine's verification: if your provider puts
  this client id into the audience of the client's own access tokens, such an
  access token passes as an ID token (LIMITATIONS, "Known and not fixed").
- Keys are a static JWKS. A key rotation at the provider needs the new file
  and `reload` (LIMITATIONS, section 5).

## Other languages

Engine path, any language: `POST /v1/token` with
`{"id_token": "...", "agent": "...", "role": "...", "task": "..."}` and no
`Authorization` header. Errors: `id_token_invalid`, `no_idp`, `role_not_held`,
`role_exceeded`, `unknown_role` (`spec/API.md`).

Token-service path: verify the ID token with your platform's OIDC library,
apply the rules above, then `POST /v1/token` with
`{"user", "groups": ["support"], "agent", "role", "task"}` and
`Authorization: Bearer <admin key>`. `groups` as a JSON list of group ids;
send `[]` for a human in no group, omit the key only when membership should
come from `entities.json`.

## Reference implementation

`interfaces/reference/identity.py`: `JwksIdentitySource(issuer, audience, jwks, groups_claim=, group_map=, rule=)`.
It calls the engine's own `verify_id_token` and `bridges.claims.groups_from_claims`.
Verified against a real provider: Keycloak only (`docs/BRIDGES.md`). The other
provider rules were written from documentation and run against fixtures.

## Checks

`python -m interfaces.contract --identity yourpkg:factory`, with
`factory(issuer, audience, jwks, groups_claim, group_map)`. The kit uses the
test provider and ID tokens of `spec/conformance/oidc`.

| Check | Requires |
|---|---|
| `identity-valid-token` | a valid token gives the user and the mapped groups |
| `identity-wrong-audience` | a token for another audience is refused |
| `identity-other-client` | a token issued to another client (`azp`) is refused |
| `identity-wrong-issuer` | a token from another issuer is refused |
| `identity-expired` | an expired token is refused |
| `identity-forged` | a wrong signature, a swapped payload and non-JWT text are refused |
| `identity-no-groups-is-empty` | no groups claim, or an empty one, gives `[]` |
| `identity-no-stale-groups` | groups come from this token only |
| `identity-malformed-groups` | a groups claim of the wrong type is refused |
| `identity-unmapped-dropped` | groups outside the map are dropped; sorted, no duplicates |
| `identity-feeds-issuance` | the result, given to `issue_token`, yields the role or `role_not_held` |
