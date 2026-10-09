"""SmartDelegate: identity and access management for LLM agents.

This package is the reference implementation. Other languages are ports of it
and are held to the same conformance vectors (spec/conformance).

    from sf_smartdelegate import Engine, Guard

    iam = Engine({"bundle_dir": "bundle", "state_dir": "state"})
    guard = Guard(iam, token=lambda: current_task_token)

    @guard.tool(action="read", resource="crm.customer", id="customer_id")
    def get_customer(customer_id): ...

The short way in is `sf_smartdelegate.core`: `delegate` (a human lends an agent a
role for one task), `narrow` (a sub-agent gets less) and `check`.

`Engine` decides in-process. `DaemonClient` asks a running `smartdelegate serve`.
Both have the same methods. In-process checks bind an agent that cooperates;
the boundary an agent cannot skip is a proxy (`smartdelegate http-proxy`,
`smartdelegate mcp-proxy`). See docs/LIMITATIONS.md.
"""
from ._version import __version__

from .backend import SmartDelegateError, Backend  # noqa: E402
from .client import DaemonClient  # noqa: E402
from .engine import Engine  # noqa: E402
from .errors import EngineError  # noqa: E402
from .guard import ApprovalRequired, Denied, Guard  # noqa: E402
from .sql import SqlGuard  # noqa: E402
from . import core, models  # noqa: E402

__all__ = ["Engine", "DaemonClient", "Guard", "SqlGuard", "Denied", "ApprovalRequired", "SmartDelegateError", "EngineError", "Backend"]
