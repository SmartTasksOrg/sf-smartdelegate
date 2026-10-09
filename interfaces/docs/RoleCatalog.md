# RoleCatalog

Roles and their ceilings: `roles.json` in the bundle (`spec/ROLES.md`).

## Contract

```python
class RoleCatalog(Protocol):
    def load(self) -> dict: ...                       # {"roles": {name: {...}}}
    def validate(self, document: dict) -> None: ...   # raises CatalogError
    def write(self, document: dict) -> str: ...       # validates, replaces the whole document, returns its sha256
```

A role: `members` (who holds it), `cap` (the ceiling: actions, resources, deny
lists, budget), and optionally `max_ttl`, `tasks`, `agents`, `bindings`,
`description`. Implement this interface when roles are authored somewhere
else (an IGA tool, a Git repository with review, an admin UI) and published
into the bundle.

A role in `roles.json` is not a role in your IAM. It names which of your
groups hold it and the most an agent may be handed under it. Start from the
permissions the human already has: `sf-smartdelegate bridge ceiling` lowers a
ceiling to what a cloud says the human may do (`docs/BRIDGES.md`, "Inbound 3").

## Fails closed

- `validate` and `write` MUST refuse an unknown key anywhere in a role or its
  `cap`. Dropping it is not allowed: a misspelt `max_ttl` or `tasks` would
  leave the role without that limit.
- `write` MUST leave the stored document complete and unchanged when it
  refuses or fails.
- What `write` stored MUST be what the engine loads: the engine's own loader
  fails the whole bundle on a malformed `roles.json` (`roles_parse`) and a
  failed `reload` keeps the old bundle.

## Security notes

- `roles.json` is covered by the bundle signature when `bundle_public_key` is
  configured. Without a required signature, whoever can write the bundle
  directory sets the ceilings (THREAT_MODEL, threats 13 and 24).
- A wider `cap` that is well-formed is caught only by review. Treat a change
  to `roles.json` like a change to an IAM policy.
- Set `max_ttl` on every role: it bounds how long a token outlives a human's
  loss of the role if nobody revokes (LIMITATIONS, section 6).
- Roles are opt-in per request unless the engine has `require_role: true`
  (threat 22).

## Other languages

`roles.json` is plain JSON; the table of keys and rules is in `spec/ROLES.md`.
Validate by loading: write the candidate into a copy of the bundle and run
`sf-smartdelegate policy check --bundle <copy>`, which fails on `roles_parse`.
Publish by replacing the file atomically, re-signing a signed bundle
(`sf-smartdelegate bundle sign --key <file>`) and `POST /v1/admin/reload`. Read the
names in force from `GET /v1/info` (`roles`).

## Reference implementation

`interfaces/reference/roles.py`: `FileRoleCatalog(bundle_dir)`. `validate`
uses the engine's `bundle.Role` loader; `write` goes through a temporary file
and `os.replace`.

## Checks

`python -m interfaces.contract --roles yourpkg:factory`, with
`factory(bundle_dir)`: a catalog for the roles of that bundle directory (the
kit passes a copy of the conformance bundle).

| Check | Requires |
|---|---|
| `roles-load` | `load` returns the stored document |
| `roles-unknown-key` | a misspelt key in a role, in a `cap` or at the top level is refused; nothing is stored |
| `roles-malformed` | no members, no `cap`, a bad `max_ttl`, a bad pattern, a wrong shape are refused |
| `roles-write-roundtrip` | a valid write is what `load` returns and what the engine loads |
| `roles-ceiling-enforced` | a ceiling written through the catalog is the one the engine enforces |
