# DirectorySource

Users, groups and memberships as one snapshot, for the scheduled sync that
writes `entities.json`.

## Contract

```python
class DirectorySource(Protocol):
    def snapshot(self) -> Snapshot: ...     # sf_smartdelegate.bridges.directory.Snapshot
```

`Snapshot`: `users` (`id -> User(id, name, active, attrs)`), `groups`
(`id -> Group(id, name, parents)`), `memberships` (`user id -> set of group
ids the user is a direct member of`), `source`. Nested groups are `parents`,
not flattened memberships. Inactive users are listed with `active=False`.

What happens to it: `interfaces.reference.sync_directory(source, "bundle/entities.json", backend=...)`
calls `bridges.directory.sync` (mapping, removal guard, atomic write), then
`reload`, then revoke-by-user for everyone who was removed or lost a group.
From the command line the same is `sf-smartdelegate bridge sync-scim ... --revoke`
(`docs/BRIDGES.md`, "Inbound 2: directory sync").

## Fails closed

`snapshot` MUST raise `DirectoryError` (or `BridgeError`) and return nothing when:

- the directory is unreachable or answers with an error status;
- a listing is truncated: fewer entries than the directory says exist, a
  repeated page, a missing next page.

It MUST NOT return an empty or partial snapshot in those cases. Written to
`entities.json`, a short listing removes people's access, and with `--revoke`
ends their live tokens. The writer's removal guard (30% by default) stops the
large cases only.

The opposite failure is not in the source's hands: when the sync stops
running, a removed human keeps the membership on disk. Monitor `synced_at` in
`entities.sync.json` (the MCP `status` tool reports its age).

## Security notes

- The sync job is trusted like an administrator: it rewrites `entities.json`,
  and with revocation it holds the admin key (THREAT_MODEL, trust assumptions,
  threats 28, 29, 31). Nothing checks that added membership is true.
- The directory credential is read from an environment variable and never
  written to a file, a message or the result (threat 31).
- `entities.json` is part of the bundle version. A signed bundle must be
  re-signed after a sync; a sync job that signs the bundle itself makes the
  signature worthless against a wrong sync (threat 28).
- Revoke-by-user ends **all** tokens of a user who lost one group, also those
  under roles still held (LIMITATIONS, section 7).

## Other languages

Write `entities.json` in the bundle format (`docs/SCOPE.md`, section 8.2):
a list of `{"uid": {"type", "id"}, "attrs": {}, "parents": [{"type", "id"}]}`,
keeping the entities that are not users or groups (agents). Write to a
temporary file and rename. Then `POST /v1/admin/reload`, then
`POST /v1/admin/revoke {"user": U, "by": "sync"}` for each user who was removed
or lost a group, in that order (admin key). The directory bridges themselves
exist in Python only (LIMITATIONS, section 8).

## Reference implementation

`interfaces/reference/directory.py`: `ScimDirectorySource(base_url, token_env)`
wraps `bridges.scim.fetch`; `sync_directory` is the snapshot-to-engine path.
The Okta, Entra, Keycloak, Google and AWS Identity Center adapters return the
same `Snapshot`. Run against a real service: Keycloak only. The SCIM adapter
was run against a fake server only (`docs/BRIDGES.md`, "What was tested").

## Checks

`python -m interfaces.contract --directory yourpkg:factory`, with
`factory(fault=None)`. Load `interfaces/contract/directory_fixture.json` into
a test instance of your directory (or a test double). `fault` is `None`,
`"unreachable"` or `"truncated"`: return a source whose directory fails that way.

| Check | Requires |
|---|---|
| `directory-matches-fixture` | users, active flags, groups, nesting and direct memberships equal the fixture |
| `directory-consistent` | every membership and parent names a listed user or group |
| `directory-deterministic` | two snapshots of an unchanged directory give the same entities |
| `directory-entities-load` | the engine loads the result; inactive users are absent; nesting grants membership |
| `directory-unreachable-raises` | an unreachable directory raises |
| `directory-truncated-raises` | a truncated listing raises |
