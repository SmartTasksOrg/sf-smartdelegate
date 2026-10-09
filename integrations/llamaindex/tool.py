"""LlamaIndex: put SmartDelegate in front of a FunctionTool.

    from tool import guard_tool
    from adapter import Adapter, ToolSpec

    adapter = Adapter(engine, token=lambda: current_task_token)
    safe = guard_tool(get_customer_tool, ToolSpec("read", "crm.customer", id="customer_id"), adapter)
    agent = FunctionAgent(tools=[safe], llm=llm)

The wrapped tool keeps its metadata (name, description, schema). Each call is
authorized first, and what the function returns is masked before it becomes
the tool output. A denied call returns the denial as text (on_deny="return",
the default) or raises sf_smartdelegate.guard.Denied (on_deny="raise").

`llama_index` is imported only by `guard_tool` / `guard_tools`.
`guarded_call` is the same logic without the framework.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import adapter as _adapter  # noqa: E402

Adapter, ToolSpec, Denial, Denied = _adapter.Adapter, _adapter.ToolSpec, _adapter.Denial, _adapter.Denied


def guarded_call(adapter, spec, fn, args: tuple = (), kwargs: dict | None = None, on_deny: str = "return"):
    """Run `fn(*args, **kwargs)` through the adapter. No LlamaIndex needed."""
    return adapter.wrap(spec, fn, on_deny)(*args, **(kwargs or {}))


async def guarded_acall(adapter, spec, fn, args: tuple = (), kwargs: dict | None = None, on_deny: str = "return"):
    return await adapter.awrap(spec, fn, on_deny)(*args, **(kwargs or {}))


def _llamaindex_tools():
    try:
        import llama_index.core.tools as tools
    except ImportError as e:
        raise ImportError("the LlamaIndex integration needs llama-index-core: pip install llama-index-core "
                          "(guarded_call in this module works without it)") from e
    return tools


def guard_tool(tool, spec, adapter, on_deny: str = "return"):
    """A new FunctionTool with the same metadata whose function goes through
    the adapter. Works on a FunctionTool; any other tool is called through
    `tool.call(**kwargs).raw_output`."""
    tools = _llamaindex_tools()
    spec = ToolSpec.of(spec)
    if isinstance(tool, tools.FunctionTool):
        fn, async_fn = tool.fn, tool.async_fn
    elif hasattr(tool, "call") and hasattr(tool, "metadata"):
        def fn(**kwargs):
            return tool.call(**kwargs).raw_output

        async def async_fn(**kwargs):
            return (await tool.acall(**kwargs)).raw_output
    else:
        raise TypeError("guard_tool wraps a llama_index.core.tools.FunctionTool (or another tool with call/metadata)")
    return tools.FunctionTool.from_defaults(fn=adapter.wrap(spec, fn, on_deny), async_fn=adapter.awrap(spec, async_fn, on_deny),
                                            tool_metadata=tool.metadata)


def guard_tools(tools, specs: dict, adapter, on_deny: str = "return", only_usable: bool = False) -> list:
    """Wrap a list of tools. `specs` maps tool name -> ToolSpec. A tool with
    no spec is an error: nothing is handed to the model unguarded.
    only_usable=True also leaves out the tools the current token's capability
    could never use (see Adapter.visible)."""
    names = [t.metadata.name for t in tools]
    missing = [n for n in names if n not in specs]
    if missing:
        raise KeyError("no ToolSpec for: " + ", ".join(missing))
    keep = set(adapter.visible({n: specs[n] for n in names})) if only_usable else None
    return [guard_tool(t, specs[n], adapter, on_deny) for t, n in zip(tools, names) if keep is None or n in keep]
