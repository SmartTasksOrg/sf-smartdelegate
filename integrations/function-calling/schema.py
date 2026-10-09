"""Function calling (OpenAI, Anthropic and anything shaped like them).

    from schema import guard_dispatch, filter_tool_list
    from adapter import Adapter, ToolSpec, spend_from

    TOOLS = {
        "get_customer": (get_customer, ToolSpec("read", "crm.customer", id="customer_id")),
        "refund": (refund, ToolSpec("create", "billing.refund", id="order_id", spend=spend_from("currency", "amount"))),
    }
    adapter = Adapter(engine, token=lambda: current_task_token)
    dispatch = guard_dispatch(TOOLS, adapter)

    shown = filter_tool_list(ALL_TOOL_SCHEMAS, TOOLS, adapter)   # pass `shown` as tools=...
    result_json = dispatch(call.function.name, call.function.arguments)   # OpenAI
    result_json = dispatch(block.name, block.input)                       # Anthropic

`dispatch` never raises for a refusal: the model gets a JSON object
{"error": {"code", "rule": "DELEGATE-...", "message", "by": "smartdelegate", "approval"?}}.
No framework is imported here.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import adapter as _adapter  # noqa: E402

Adapter, ToolSpec, Denial, Denied = _adapter.Adapter, _adapter.ToolSpec, _adapter.Denial, _adapter.Denied


def _error(code: str, message: str) -> str:
    return json.dumps(Denial(code, _adapter.rule_id(code), message).to_json())


def _entry(entry):
    fn, spec = entry
    if not callable(fn):
        raise TypeError("each tool is (callable, ToolSpec)")
    return fn, ToolSpec.of(spec)


def guard_dispatch(tools: dict, adapter):
    """`tools`: name -> (callable, ToolSpec). Returns
    `dispatch(name, arguments) -> str`, where `arguments` is the JSON text the
    model produced (or the already-parsed object) and the result is JSON text
    for the tool-result message: the masked return value, or an error object.

    A name with no entry is refused (default deny). An exception raised by the
    tool becomes `tool_failed` with the message withheld, because error text
    can echo record data."""
    table = {name: _entry(e) for name, e in tools.items()}

    def dispatch(name: str, arguments="{}") -> str:
        if name not in table:
            return _error(_adapter.UNKNOWN_TOOL, f"tool '{name}' has no access mapping (default deny)")
        fn, spec = table[name]
        args = arguments
        if isinstance(arguments, (str, bytes, bytearray)):
            try:
                args = json.loads(arguments) if arguments.strip() else {}
            except (ValueError, RecursionError):
                return _error(_adapter.INVALID_ARGUMENTS, "the tool arguments are not valid JSON")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return _error(_adapter.INVALID_ARGUMENTS, "the tool arguments must be a JSON object")
        try:
            decision = adapter.authorize(spec, args)
        except Denied as e:
            return json.dumps(Denial.of(e).to_json())
        try:
            result = fn(**args)
        except Exception:
            return _error(_adapter.TOOL_FAILED, "tool failed (details withheld by SmartDelegate)")
        try:
            out = adapter.filter_output(spec, decision, result)
        except Denied as e:
            return json.dumps(Denial.of(e).to_json())
        if isinstance(out, str) and spec.output != "raw" and out != _adapter.WITHHELD:
            return out      # JSON text the tool returned, masked and re-serialised
        try:
            return json.dumps(out, ensure_ascii=False)
        except (TypeError, ValueError):
            return json.dumps(_adapter.WITHHELD)

    return dispatch


def usable_tools(tools: dict, adapter) -> list:
    """Names of the tools the current token's capability could ever use."""
    return adapter.visible({name: _entry(e)[1] for name, e in tools.items()})


def schema_name(schema: dict):
    """The tool name in an OpenAI-style ({"type": "function", "function":
    {"name"}}, or the flat Responses form) or Anthropic-style ({"name",
    "input_schema"}) tool definition."""
    if not isinstance(schema, dict):
        return None
    fn = schema.get("function")
    name = fn.get("name") if isinstance(fn, dict) else schema.get("name")
    return name if isinstance(name, str) else None


def filter_tool_list(schemas: list, tools: dict, adapter) -> list:
    """The tool definitions to show the model for the current task: those
    whose action and resource the token's capability covers. A definition
    with no entry in `tools`, or one whose name cannot be read, is hidden.
    With no valid token the list is empty.

    This trims what the model is offered; it is not the enforcement. A call
    to a hidden tool is still decided by `dispatch`."""
    keep = set(usable_tools(tools, adapter))
    return [s for s in schemas if schema_name(s) in keep]
