# SmartDelegate for function calling

For a tool-calling loop you write yourself (OpenAI, Anthropic, and APIs shaped
like them). No framework and no SDK is imported.

```python
import sys; sys.path.insert(0, "integrations/function-calling"); sys.path.insert(0, "integrations")
from adapter import Adapter, ToolSpec, spend_from
from schema import guard_dispatch, filter_tool_list

TOOLS = {
    "get_customer": (get_customer, ToolSpec("read", "crm.customer", id="customer_id")),
    "refund": (refund, ToolSpec("create", "billing.refund", id="order_id", spend=spend_from("currency", "amount"))),
}
adapter = Adapter(engine, token=lambda: current_task_token)
dispatch = guard_dispatch(TOOLS, adapter)

shown = filter_tool_list(ALL_TOOL_DEFINITIONS, TOOLS, adapter)        # what the model is offered for this task
result = dispatch(call.function.name, call.function.arguments)        # OpenAI: arguments is JSON text
result = dispatch(block.name, block.input)                            # Anthropic: input is an object
```

`dispatch` returns JSON text for the tool-result message. On an allow it is
the tool's return value, masked. On a refusal it is

```json
{"error": {"code": "approval_required", "rule": "DELEGATE-APPROVAL-REQUIRED", "message": "...", "by": "smartdelegate",
           "decision_id": "d-...", "approval": {"id": "..."}}}
```

`filter_tool_list` keeps the definitions whose action and resource the current
token's capability covers, and hides the rest, including any definition that
has no entry in `TOOLS`. It reads the capability with `inspect_token`. It
trims the list; it is not the enforcement. A call to a hidden tool is still
decided by `dispatch`.

Tested with fake tools and hand-written definitions. No request was sent to a
model API.
