"""LangChain: put SmartDelegate in front of any tool.

    from tool import guard_tool, guard_tools
    from adapter import Adapter, ToolSpec

    adapter = Adapter(engine, token=lambda: current_task_token)
    safe = guard_tool(get_customer_tool, ToolSpec("read", "crm.customer", id="customer_id"), adapter)
    agent = create_agent(model, tools=[safe])

The wrapped tool keeps its name, description and argument schema. Each call
is authorized first, and what the tool returns is masked before the model
sees it. A denied call returns the denial as text (on_deny="return", the
default) or raises sf_smartdelegate.guard.Denied (on_deny="raise").

`langchain_core` is imported only by `guard_tool` / `guard_tools`.
`guarded_call` is the same logic without the framework.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import adapter as _adapter  # noqa: E402

Adapter, ToolSpec, Denial, Denied = _adapter.Adapter, _adapter.ToolSpec, _adapter.Denial, _adapter.Denied


def guarded_call(adapter, spec, fn, args: tuple = (), kwargs: dict | None = None, on_deny: str = "return"):
    """Run `fn(*args, **kwargs)` through the adapter. No LangChain needed."""
    return adapter.wrap(spec, fn, on_deny)(*args, **(kwargs or {}))


async def guarded_acall(adapter, spec, fn, args: tuple = (), kwargs: dict | None = None, on_deny: str = "return"):
    return await adapter.awrap(spec, fn, on_deny)(*args, **(kwargs or {}))


def _langchain_tools():
    try:
        import langchain_core.tools as tools
    except ImportError as e:
        raise ImportError("the LangChain integration needs langchain-core: pip install langchain-core "
                          "(guarded_call in this module works without it)") from e
    return tools


def guard_tool(tool, spec, adapter, on_deny: str = "return"):
    """A copy of a LangChain tool whose calls go through the adapter.

    A StructuredTool or Tool (anything with `func` / `coroutine`) is copied
    with those two replaced, so the schema is untouched. Any other BaseTool is
    wrapped in a StructuredTool that calls `tool.invoke` / `tool.ainvoke`."""
    tools = _langchain_tools()
    spec = ToolSpec.of(spec)
    if not isinstance(tool, tools.BaseTool):
        raise TypeError("guard_tool wraps a langchain_core.tools.BaseTool")
    if getattr(tool, "response_format", "content") != "content":
        # the artifact half of (content, artifact) bypasses the model but not
        # downstream code; masking one half only would be a false promise
        raise ValueError(f"tool '{tool.name}' uses response_format='{tool.response_format}', which this wrapper does not mask")
    func, coroutine = getattr(tool, "func", None), getattr(tool, "coroutine", None)
    if func is not None or coroutine is not None:
        update = {}
        if func is not None:
            update["func"] = adapter.wrap(spec, func, on_deny)
        if coroutine is not None:
            update["coroutine"] = adapter.awrap(spec, coroutine, on_deny)
        return tool.model_copy(update=update) if hasattr(tool, "model_copy") else tool.copy(update=update)

    def run(**kwargs):
        return tool.invoke(kwargs)

    async def arun(**kwargs):
        return await tool.ainvoke(kwargs)

    return tools.StructuredTool.from_function(
        func=adapter.wrap(spec, run, on_deny), coroutine=adapter.awrap(spec, arun, on_deny), name=tool.name,
        description=tool.description, args_schema=tool.args_schema or tool.get_input_schema(), return_direct=tool.return_direct)


def guard_tools(tools, specs: dict, adapter, on_deny: str = "return", only_usable: bool = False) -> list:
    """Wrap a list of tools. `specs` maps tool name -> ToolSpec. A tool with
    no spec is an error: nothing is handed to the model unguarded.
    only_usable=True also leaves out the tools the current token's capability
    could never use (see Adapter.visible)."""
    missing = [t.name for t in tools if t.name not in specs]
    if missing:
        raise KeyError("no ToolSpec for: " + ", ".join(missing))
    keep = set(adapter.visible({t.name: specs[t.name] for t in tools})) if only_usable else None
    return [guard_tool(t, specs[t.name], adapter, on_deny) for t in tools if keep is None or t.name in keep]
