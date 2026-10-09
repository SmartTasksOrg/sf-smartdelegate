#!/usr/bin/env python3
"""A tool call wrapped the way the smartdelegate-enforce skill describes:
authorize, run, filter. Runs against the bundled example, in memory.

    python3 skills/smartdelegate-enforce/scripts/wrap_tool.py

It prints what the model would receive for an allowed read, a write with a
forbidden field, a spend within and beyond the budget, and a call that waits
for a human. Nothing is written to disk and nothing is contacted. Needs the
smartdelegate package (from a clone: PYTHONPATH=src) and integrations/adapter.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "integrations")]


def main(argv: list) -> int:
    if argv:
        print(__doc__)
        return 0 if argv in (["--help"], ["-h"]) else 2
    from adapter import Adapter, ToolSpec, delegate_for_task, spend_from
    from sf_smartdelegate import core

    engine = core.open_engine()                         # the example bundle; no state directory
    crm = {"c-1": {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU", "notes": "VIP"}}

    # 1. the human lends the agent one role for one task (done by a token service, not by the agent)
    grant = delegate_for_task(engine, user="alice", agent="support-bot", role="support-agent", task="ticket-7")
    adapter = Adapter(engine, token=lambda: grant.token)

    # 2. each tool is bound to an action and a resource; `input` is checked strictly, `spend` is charged
    read = ToolSpec("read", "crm.customer", id="customer_id")
    update = ToolSpec("update", "crm.customer", id="customer_id", input="changes")
    refund = ToolSpec("create", "billing.refund", id="order_id", spend=spend_from("currency", "amount"))

    out = {"read": adapter.call(read, lambda customer_id: crm[customer_id], {"customer_id": "c-1"})}
    for name, spec, fn, args in (
            ("update_with_ssn", update, lambda customer_id, changes: changes, {"customer_id": "c-1", "changes": {"email": "a@example.com", "ssn": "1"}}),
            ("refund_60", refund, lambda **kw: {"order_id": kw["order_id"]}, {"order_id": "o-1", "currency": "EUR", "amount": 6000}),
            ("refund_60_again", refund, lambda **kw: {"order_id": kw["order_id"]}, {"order_id": "o-2", "currency": "EUR", "amount": 6000})):
        r = adapter.try_call(spec, fn, args)             # 3. authorize -> run -> filter; a refusal comes back structured
        out[name] = r.value if r.ok else r.denial.to_json()["error"]

    # 4. a call that policy holds for a second human: surface the approval id, do not approve it yourself
    wide = core.delegate(engine, user="alice", agent="support-bot",
                         capability={"actions": ["create"], "resources": ["billing.refund/*"], "budget": {"EUR": 20000}})
    held = Adapter(engine, wide).try_call(refund, lambda **kw: kw, {"order_id": "o-3", "currency": "EUR", "amount": 15000})
    out["refund_150"] = {"text_for_the_model": held.denial.text()}
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
