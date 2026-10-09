# SmartDelegate integrations

Ways to put SmartDelegate into the tools and frameworks an agent already runs
in. The Python wrappers all go through one file, [`adapter.py`](adapter.py),
which does four things around a tool call:

1. authorizes it with the engine (record data the tool is about to write is checked in strict mode);
2. runs the tool only after an allow;
3. masks what the tool returned with the decision's obligations before the model sees it;
4. turns a refusal into a structured denial: reason, rule id (`DELEGATE-*`), detail, and the approval id when a human must approve.

```python
from adapter import Adapter, ToolSpec, delegate_for_task

grant = delegate_for_task(engine, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
adapter = Adapter(engine, token=lambda: grant.token)      # engine: smartdelegate.Engine or DaemonClient
record = adapter.call(ToolSpec("read", "crm.customer", id="customer_id"), get_customer, {"customer_id": "c-1"})
```

Quick check, nothing but the package needed:

```bash
PYTHONPATH=src python3 integrations/adapter.py --demo
```

These wrappers run inside the agent's process, so they bind an agent that
cooperates. The boundary an agent cannot skip is a proxy
(`sf-smartdelegate http-proxy`, `sf-smartdelegate mcp-proxy`). See `docs/LIMITATIONS.md`.

## What is here

| Target | Path | Needs installed | Tested here |
|---|---|---|---|
| Adapter | [`adapter.py`](adapter.py) | `smartdelegate` | Yes. Fake tools against the conformance bundle, in-process and through a real `sf-smartdelegate serve` (allow and mask, deny, strict input, budget, approval and retry, revoked token, unreachable daemon). |
| LangChain | [`langchain/tool.py`](langchain/tool.py) | `langchain-core` for `guard_tool`; nothing for `guarded_call` | `guarded_call` with fake tools: always. `guard_tool` on real `StructuredTool`, `Tool` and `BaseTool` objects: only when `langchain_core` can be imported, otherwise that test is skipped and says so. It passed with langchain-core 1.6.6. |
| LlamaIndex | [`llamaindex/tool.py`](llamaindex/tool.py) | `llama-index-core` for `guard_tool`; nothing for `guarded_call` | Same split. `guard_tool` on real `FunctionTool` objects passed with llama-index-core 0.14.25; skipped when the package is missing. |
| OpenAI / Anthropic function calling | [`function-calling/schema.py`](function-calling/schema.py) | `smartdelegate` | Yes, with fake tools and hand-written tool definitions in both shapes. No request was sent to a model API. |
| MCP server | [`mcp/server.py`](mcp/server.py) | `smartdelegate` (the `mcp` package is not used) | Yes. Started as a subprocess and driven over stdio with hand-written JSON-RPC, including malformed input. Also driven once by hand with the `mcp` 1.27.0 Python client (not part of the suite). Not run inside a desktop MCP client. |
| GitHub Action | [`github-action/action.yml`](github-action/action.yml) | GitHub Actions runner | Partly. The shell of each `run:` step is executed by the tests with bash against the conformance bundle (pass, stale bundle, unsigned, wrong key, file changed after signing). The action was not run on GitHub; the `actions/setup-python` and `pip install` steps were not executed. |
| pre-commit | [`precommit/`](precommit/), [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml) | `pre-commit` | Partly. The hooks file is parsed and each hook's `entry` plus `args` is run against a bundle. `pre-commit` itself was not run. |
| VS Code | [`vscode/`](vscode/) | VS Code, `smartdelegate` on PATH | Partly. Every task's command line is run by the tests with the variables filled in. Not run inside VS Code. |
| Flowise | [`flowise/`](flowise/) | Flowise, a running `sf-smartdelegate serve` | Partly. The tool body is run under Node against a real daemon and a stand-in upstream. Not run inside Flowise. |

Run the tests:

```bash
cd tests && python3 -m unittest test_integrations -v
```

A test that needs something that is not installed (LangChain, LlamaIndex,
Node, bash) is reported as skipped with the reason.

## Codes this layer adds

Every refusal carries a reason and its rule id, `DELEGATE-` plus the reason in
upper case. Almost all come from the engine. Three are produced here, before
or after the engine is asked:

| Reason | When |
|---|---|
| `invalid_arguments` | the call's arguments cannot be turned into a request (no usable id, a spend amount that is not a whole number of minor units, tool arguments that are not a JSON object) |
| `unknown_tool` | a dispatcher was asked for a tool that has no `ToolSpec` (default deny) |
| `tool_failed` | the tool raised; its message is withheld because error text can echo record data |

The MCP server adds `admin_required` (see [`mcp/README.md`](mcp/README.md)).

## Tool output that cannot be masked

Masking works on fields, so it needs a record: a dict, a list of dicts, or a
string holding JSON for one of those. Any other return value (plain text, a
number) is replaced by a notice instead of being passed on, the same rule the
MCP proxy applies. For a tool that returns no record data, say so in its spec:
`ToolSpec(..., output="raw")`.
