# AgentRuntime

How an agent framework hands SmartDelegate the current task token and the
tool metadata, and how sub-agents get narrowed tokens.

## Contract

```python
class AgentRuntime(Protocol):
    def begin_task(self, token: str) -> None: ...
    def end_task(self) -> None: ...
    def current_token(self) -> str: ...                       # "" when there is no task
    def register(self, name, binding: ToolBinding, fn) -> None: ...
    def call(self, name: str, arguments: dict) -> Outcome: ...
    def spawn(self, actor, capability=None, ttl=None) -> "AgentRuntime": ...   # raises SpawnRefused
```

Three hooks in a framework:

| When | Hook | Engine operation |
|---|---|---|
| a human starts a task | `begin_task(token)` with the token from `issue_token` (role + task) | none: the token was issued by a token service |
| the model calls a tool | `call(name, arguments)` | `authorize` / `filter`, then `apply_obligations` (see EnforcementPoint) |
| the agent starts a sub-agent | `spawn(actor, capability, ttl)` | `exchange_token {"subject_token", "actor", "cap", "ttl"}` |

The runtime never calls `issue_token`. Obtaining a root token needs a verified
human (IdentitySource); narrowing needs only the parent token.

A sub-agent's capability can be the parent's or less. Both deny lists can
only grow: a `capability` passed to `spawn` must repeat the parent's
`deny_labels` and `deny_fields` or the engine answers `widening`. Omit
`capability` to inherit the parent's.

## Fails closed

- Without a task token every call is refused (`token_invalid`); nothing runs.
- `end_task` forgets the token.
- A token belongs to one task. Another thread or asyncio task of the same
  process MUST NOT see it.
- A tool that was never registered is refused.
- `spawn` MUST raise `SpawnRefused` when the engine refuses (`widening`,
  `depth_exceeded`, `delegation_denied`, `unknown_agent`, a dead parent
  token, an unreachable engine). It MUST NOT return a runtime that holds the
  parent's token, and MUST NOT mint a fresh root token for the sub-agent.

## Security notes

- Capability tokens are bearer tokens: whoever holds one can use it until it
  expires or is revoked. Do not log tokens; hand a sub-agent its own token,
  never the parent's (LIMITATIONS, section 5; THREAT_MODEL, threat 7).
- Agent identity is a name in `entities.json`. Nothing attests that the
  process presenting a token is that agent.
- A sub-agent's token lists the parent's token id among its ancestors:
  revoking the task's token, or the user, stops the whole tree. Spend is
  charged to every token in the chain (THREAT_MODEL, threats 4 and 5).
- The runtime is in the agent's process: see the first security note of
  EnforcementPoint.

## Other languages

`POST /v1/token` with `{"subject_token": "<parent token>", "actor": "<sub-agent>", "cap": {...}, "ttl": 300}`
and no key: holding the parent token is the authority. The answer carries
`token`, `token_id`, `chain`, `role`, `task`, `cap`, `expires_in`; errors are
`widening`, `depth_exceeded`, `unknown_agent`, `delegation_denied`,
`token_invalid`, `token_expired`, `token_revoked` (`spec/API.md`). Keep the
token in whatever your platform uses for request-scoped state (Java
`ThreadLocal` / scoped values, Node.js `AsyncLocalStorage`, Go `context.Context`).
The JavaScript client's `guardTool` and the Node.js port are the nearest
ready-made pieces (`ports/js`, `ports/node`).

## Reference implementation

`interfaces/reference/runtime.py`: `SimpleRuntime(backend)`, about sixty
lines, framework-free. The token is a `contextvars.ContextVar`.

## Checks

`python -m interfaces.contract --runtime yourpkg:factory`, with
`factory(backend)`: a runtime with no task and no tools.

| Check | Requires |
|---|---|
| `runtime-no-task` | no task, no call |
| `runtime-task-token` | calls run under the token of `begin_task`; `end_task` forgets it |
| `runtime-tasks-isolated` | another thread does not see this task's token |
| `runtime-unregistered-tool` | an unregistered tool is refused, not raised |
| `runtime-spawn-narrows` | the sub-agent's token: same human and role, longer chain, narrower capability, derived from the parent's |
| `runtime-spawn-cannot-widen` | a wider request, a forbidden delegation and a spawn without a task raise `SpawnRefused` |
| `runtime-child-dies-with-parent` | revoking the task's token stops its sub-agents |
