# EnforcementPoint

Given a task token and a tool call: authorize, run, filter.

## Contract

```python
class EnforcementPoint(Protocol):
    def invoke(self, token: str, tool: str, arguments: dict) -> Outcome: ...
# Outcome(allowed, value, refusal);  Refusal(reason, rule, detail, approval_id, decision_id)
# ToolBinding(action, resource, id, input, spend, attrs, output)   how a tool maps onto a request
```

Order, for one call:

1. Build the request from the binding: action, resource path, resource id,
   resource attributes, `context.spend` when the tool spends.
2. Ask the engine. `filter` with `strict: true` and the record as `data` when
   the tool writes record data (`input`); `authorize` otherwise. Not a dry run.
3. Only on `effect: allow`, run the tool.
4. Pass what the tool returned through `apply_obligations` with the
   decision's `obligations` (field mask, row filter). Return that.
5. On a denial return the refusal: `reason`, `rule` (`DELEGATE-*`), `detail`,
   and `approval.id` when a human must approve.

## Fails closed

The tool MUST NOT run, and the answer MUST be `allowed: False`, when:

- the engine denies (any reason);
- the engine reports an error (`ok: false`) or cannot be reached;
- the tool has no binding (default deny);
- the arguments cannot be turned into a request (no usable id, a spend amount
  that is not a whole number of minor units, record data that is not an object).

Output that cannot be field-checked (plain text, a number) MUST be withheld
unless the binding says `output="raw"`. A field the decision denies MUST NOT
appear in what is returned. Strict mode denies; it never drops a field from
an input (`spec/PORTING.md`, "Rules that are easy to get wrong").

## Security notes

- An enforcement point inside the agent's process binds an agent that
  cooperates. The agent, or code injected into it, can call the tool
  directly. The boundary an agent cannot skip is a proxy that alone holds the
  upstream credential and is the agent's only network path
  (`docs/LIMITATIONS.md`, section 1; THREAT_MODEL, threat 9).
- Enforcement points are trusted to describe the call truthfully. A resource
  attribute taken from the agent's request is a claim by the agent; a policy
  that restricts on it is satisfied by a false claim. Take such attributes
  from the upstream record (THREAT_MODEL, trust assumptions; `spec/API.md`,
  "Where a resource attribute comes from").
- Give enforcement points the pep key, never the admin key.
- Budget is charged when the decision is made. If the tool then fails, the
  spend stays counted (LIMITATIONS, section 11).
- A tool's error text can echo record data: withhold it (the adapter's
  `tool_failed`).

## Other languages

Against `sf-smartdelegate serve`, with `Authorization: Bearer <pep key>`:

```text
POST /v1/authorize  {"token", "action", "resource": {"path", "id", "attrs"}, "context": {"spend": {"currency", "amount"}}}
POST /v1/filter     the same plus "data" and "strict": true          (tool input)
POST /v1/obligations/apply  {"obligations": <from the allow decision>, "data": <tool result>, "decision_id"}
```

A decision is HTTP 200 with `"effect": "allow" | "deny"`, `"reason"`,
`"rule"`, `"obligations"`, `"approval": {"id", "label"}` when held. HTTP 400
with `"ok": false` is an error, HTTP 401 a wrong key: both are a refusal. A
connection failure or a timeout is a refusal. Ready-made clients:
`ports/js` (REST client), and the engine ports in `ports/` for Java, Node.js,
Go, PHP and Rust. Without writing code: `sf-smartdelegate http-proxy` and
`sf-smartdelegate mcp-proxy` are enforcement points configured by a routes or
tools file (`spec/API.md`, "Proxy configuration"); Python and Rust only.

## Reference implementation

`interfaces/reference/enforcement.py`: `AdapterEnforcementPoint(backend, tools)`,
a thin shape over `integrations/adapter.py`, which the LangChain, LlamaIndex
and function-calling wrappers also use.

## Checks

`python -m interfaces.contract --enforcement yourpkg:factory`, with
`factory(backend, tools)`: `backend` is an `Engine` or a `DaemonClient`,
`tools` maps a name to `(ToolBinding, function)`.

| Check | Requires |
|---|---|
| `pep-allow-masks` | an allowed read returns no denied field value |
| `pep-deny-does-not-run` | on a denial the tool does not run; the refusal has reason and rule id |
| `pep-strict-input` | a write containing a forbidden field is denied, not trimmed |
| `pep-approval-id` | a held call surfaces the engine's approval id; it runs once after approval |
| `pep-budget` | a spend beyond the budget is refused; malformed amounts are refused |
| `pep-engine-unreachable` | no decision, no call |
| `pep-token-per-call` | no token, a garbage token and a revoked token are refused on every call |
| `pep-unknown-tool` | an unbound tool is refused |
| `pep-unmaskable-output` | plain-text output does not reach the caller unchecked |
| `pep-audited` | allowed and denied calls are decisions in the audit log (no dry run) |
