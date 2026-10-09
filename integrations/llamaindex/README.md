# SmartDelegate for LlamaIndex

```python
import sys; sys.path.insert(0, "integrations/llamaindex"); sys.path.insert(0, "integrations")
from adapter import Adapter, ToolSpec
from tool import guard_tool

adapter = Adapter(engine, token=lambda: current_task_token)
safe = guard_tool(get_customer_tool, ToolSpec("read", "crm.customer", id="customer_id"), adapter)
```

`guard_tool` returns a new `FunctionTool` with the same metadata (name,
description, schema) whose sync and async functions go through the adapter.
A denied call returns the denial as text (`on_deny="return"`) or raises
`sf_smartdelegate.guard.Denied` (`on_deny="raise"`). `guard_tools(tools, specs, adapter)`
wraps a list and refuses a tool that has no spec.

`llama_index` is imported only inside `guard_tool`; `guarded_call` needs no
framework.

Tested: `guarded_call` always; `guard_tool` on real `FunctionTool` objects only
when `llama_index` is importable (passed with llama-index-core 0.14.25),
otherwise skipped. No agent or model was run.
