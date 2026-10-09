# SmartDelegate for LangChain

Wrap any `BaseTool` so its calls are authorized first and its output is masked
before the model sees it.

```python
import sys; sys.path.insert(0, "integrations/langchain"); sys.path.insert(0, "integrations")
from adapter import Adapter, ToolSpec, delegate_for_task
from tool import guard_tool, guard_tools

grant = delegate_for_task(engine, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
adapter = Adapter(engine, token=lambda: grant.token)

safe = guard_tool(get_customer_tool, ToolSpec("read", "crm.customer", id="customer_id"), adapter)
# or a whole list; a tool without a spec is an error, nothing is passed on unguarded
tools = guard_tools(all_tools, SPECS, adapter, only_usable=True)
```

- The wrapped tool keeps its name, description and argument schema.
- A `StructuredTool` or `Tool` is copied with its `func` / `coroutine` replaced. Another `BaseTool` subclass is wrapped in a `StructuredTool` that calls `invoke` / `ainvoke`.
- A denied call returns the denial as text for the model (`on_deny="return"`, the default), or raises `sf_smartdelegate.guard.Denied` (`on_deny="raise"`).
- `only_usable=True` leaves out tools the current token's capability could never use. That trims the list; each call is still decided.
- Tools with `response_format="content_and_artifact"` are refused: the artifact would not be masked.

`langchain_core` is imported only inside `guard_tool`. Without it you get an
`ImportError` that says what to install; `guarded_call(adapter, spec, fn, kwargs={...})`
is the same logic with no framework.

Tested: `guarded_call` always; `guard_tool` on real tools only when
`langchain_core` is importable (passed with langchain-core 1.6.6), otherwise
skipped. No agent loop or model was run.
