# Interfaces: what an adopter implements

SmartDelegate does not replace the identity provider, the directory, the
agent framework or the log pipeline a company already runs. It meets them at
eight small interfaces. Each has a typed contract, a reference implementation
that wraps what the package already does, the same contract stated over REST
for other languages, and contract checks you run against your own
implementation.

| Interface | Question it answers | Maps to | Reference | Page |
|---|---|---|---|---|
| `IdentitySource` | who is the human, and what do they belong to right now | `idp.*` in the engine configuration; `bridges/claims.py` | `JwksIdentitySource` | [IdentitySource.md](docs/IdentitySource.md) |
| `DirectorySource` | users, groups, memberships, as one snapshot for the sync | `bridges/directory.py` `Snapshot`; `bridge sync-*` | `ScimDirectorySource`, `sync_directory` | [DirectorySource.md](docs/DirectorySource.md) |
| `RoleCatalog` | which roles exist and the most each may hand to an agent | `roles.json` | `FileRoleCatalog` | [RoleCatalog.md](docs/RoleCatalog.md) |
| `EnforcementPoint` | a task token and a tool call: authorize, run, filter | `integrations/adapter.py`, `Guard`, the proxies | `AdapterEnforcementPoint` | [EnforcementPoint.md](docs/EnforcementPoint.md) |
| `AgentRuntime` | how a framework holds the task token and narrows it for sub-agents | `exchange_token` | `SimpleRuntime` | [AgentRuntime.md](docs/AgentRuntime.md) |
| `ApprovalChannel` | deliver a held request to a human, bring the verdict back | `approvals`, `approve` | `ConsoleApprovalChannel`, `WebhookApprovalChannel`, `pump` | [ApprovalChannel.md](docs/ApprovalChannel.md) |
| `AuditSink` | keep the audit records where the engine's host cannot rewrite them | `audit.jsonl` | `JsonlAuditSink`, `ship` | [AuditSink.md](docs/AuditSink.md) |
| `RevocationFeed` | carry revocations to engines with their own state | `token_revoked` / `user_revoked` records, `revoke` | `FileRevocationFeed`, `revocations_from_audit`, `apply_revocations` | [RevocationFeed.md](docs/RevocationFeed.md) |

You rarely need all eight. The engine's own `idp` configuration, a directory
bridge, `integrations/adapter.py` and one daemon cover most deployments
without new code; see [docs/INTEGRATE.md](../docs/INTEGRATE.md) for the path.

## Layout

```
interfaces/
  contracts.py        the Protocols and the small data types (standard library only)
  reference/          a reference implementation of each, and the factories the kit calls
  contract/           the contract test kit: python -m interfaces.contract
  docs/               one page per interface
```

`interfaces` is a folder of this repository, not part of the installed
`smartdelegate` package. Use it from a clone with the repository root and
`src` on the path (`PYTHONPATH=src:.`), or copy `contracts.py` and the
reference you start from into your own code.

## The contract test kit

```bash
PYTHONPATH=src:. python3 -m interfaces.contract --list                 # every check, and what each factory receives
PYTHONPATH=src:. python3 -m interfaces.contract --reference            # every check against the reference implementations
PYTHONPATH=src:. python3 -m interfaces.contract --identity mypkg.idp:factory --enforcement mypkg.pep:factory
PYTHONPATH=src:. python3 -m interfaces.contract --audit mypkg.siem:factory --only audit-gap,audit-rewrite --json
```

Exit status 0: every check passed. 1: at least one failed (each failure says
what the implementation did). 2: usage.

You pass a **factory**, not an instance: the kit builds a fresh
implementation per check, in a temporary directory, on the conformance bundle
(`spec/conformance/bundle`) and the test identity provider
(`spec/conformance/oidc`).

| Option | The factory |
|---|---|
| `--identity` | `factory(issuer, audience, jwks, groups_claim, group_map) -> IdentitySource` |
| `--directory` | `factory(fault=None) -> DirectorySource` over a directory holding [`contract/directory_fixture.json`](contract/directory_fixture.json); `fault` is `None`, `"unreachable"` or `"truncated"` |
| `--roles` | `factory(bundle_dir) -> RoleCatalog` |
| `--enforcement` | `factory(backend, tools) -> EnforcementPoint`; `tools` maps a name to `(ToolBinding, function)` |
| `--runtime` | `factory(backend) -> AgentRuntime` |
| `--approval` | `factory(human) -> ApprovalChannel`; `human(payload)` returns `{"approve": bool, "by": user}` or `None` |
| `--audit` | `factory(location) -> AuditSink`; the same `location` twice shares what is held |
| `--revocation` | `factory(location) -> RevocationFeed` |

In a test suite, the same checks as test methods (unittest and pytest both collect them):

```python
from interfaces.contract import contract_testcase
from mypkg.pep import factory

class MyPepContract(contract_testcase("enforcement", factory)):
    pass
```

What the kit is and is not:

- It checks the properties listed on each interface's page: 56 checks in
  all. Passing them is necessary, not sufficient. They say nothing about your
  network, your secret handling or your directory's real behaviour.
- `tests/test_interfaces.py` runs every check against the reference
  implementations and against implementations that are broken on purpose,
  and fails if any check is tripped by none of them.
- It runs Python implementations. For another language, implement the
  contract over REST as each page describes ("Other languages") and port the
  checks you need: `python3 -m interfaces.contract --list --json` prints
  their ids and titles. A driver for implementations in other languages is
  not built.
- It opens no network connection except one attempt to a closed loopback
  port (the "engine unreachable" check).

## The one rule

When an implementation cannot give a true answer, it raises or returns a
refusal. It never returns a partial answer, an empty answer standing for
"unknown", or an allow. Each page lists what that means for its interface
under "Fails closed".
