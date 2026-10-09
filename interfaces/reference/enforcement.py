"""Reference EnforcementPoint: integrations/adapter.py (authorize, run,
filter, structured denial) behind the `invoke(token, tool, arguments)` shape.

In-process: it binds an agent that cooperates. The boundary an agent cannot
skip is a proxy that holds the upstream credential (docs/LIMITATIONS.md,
section 1); the same contract applies to it.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from sf_smartdelegate.errors import rule_id

from ..contracts import Outcome, Refusal, ToolBinding


def load_adapter():
    """integrations/adapter.py as a module. The integrations folder is not a
    package (its sub-folders are named after frameworks), so it is loaded by path."""
    if "adapter" in sys.modules and hasattr(sys.modules["adapter"], "Adapter"):
        return sys.modules["adapter"]
    path = Path(__file__).resolve().parents[2] / "integrations" / "adapter.py"
    spec = importlib.util.spec_from_file_location("adapter", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["adapter"] = module
    spec.loader.exec_module(module)
    return module


def tool_spec(binding: ToolBinding):
    a = load_adapter()
    spend = a.spend_from(*binding.spend) if binding.spend else None
    return a.ToolSpec(binding.action, binding.resource, id=binding.id, input=binding.input, spend=spend, attrs=binding.attrs,
                      output=binding.output)


def refused(reason: str, detail: str) -> Outcome:
    return Outcome(False, None, Refusal(reason, rule_id(reason), detail))


class AdapterEnforcementPoint:
    def __init__(self, backend, tools: dict | None = None):
        """`backend`: a smartdelegate.Engine or DaemonClient.
        `tools`: name -> (ToolBinding, function)."""
        self._adapter_module = load_adapter()
        self.backend = backend
        self.tools: dict = {}
        for name, (binding, fn) in (tools or {}).items():
            self.register(name, binding, fn)

    def register(self, name: str, binding: ToolBinding, fn) -> None:
        self.tools[name] = (tool_spec(binding), fn)

    def invoke(self, token: str, tool: str, arguments: dict) -> Outcome:
        a = self._adapter_module
        if tool not in self.tools:
            return refused(a.UNKNOWN_TOOL, f"no tool named '{tool}' is bound; unbound tools are denied")
        if not isinstance(arguments, dict):
            return refused(a.INVALID_ARGUMENTS, "tool arguments must be an object")
        spec, fn = self.tools[tool]
        result = a.Adapter(self.backend, token if isinstance(token, str) else "").try_call(spec, fn, arguments)
        if result.ok:
            return Outcome(True, result.value)
        d = result.denial
        return Outcome(False, None, Refusal(d.reason, d.rule, d.detail, d.approval_id, d.decision_id))
