"""The operations the load generator issues, taken from the Kestrel Works
company. Each worker process builds its own tokens once, then repeats a
weighted mix. Every operation says whether it expects an allow or a deny, so
the generator can assert the core safety invariant under load: a request that
must be denied is never allowed.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPANY = ROOT / "examples" / "company"
TENANT = "kestrel"
ROLES = json.loads((COMPANY / "roles.json").read_text(encoding="utf-8"))["roles"]

#: a realistic customer record for `filter` (crm.customer): nested, with the
#: fields a support agent may not see, so the mask has real work to do.
CUSTOMER = {"id": "c-load", "name": "Ada Lovelace", "email": "ada@customers.example", "phone": "+32 2 555 0100", "region": "EU",
            "tier": "gold", "notes": "internal: do not upsell " + "x" * 200, "addresses": [{"street": "1 Main St", "city": "Ghent", "zip": "9000", "geo": {"lat": 51.0, "lng": 3.7}} for _ in range(3)],
            "card": {"last4": "4242", "number": "4929000042424242"}}

#: the default mix (operation -> weight). `spend` and `approve` need setup, so
#: they are driven in dedicated phases; the steady mix is the common hot path.
DEFAULT_MIX = {"authorize_allow": 50, "filter_allow": 25, "authorize_deny": 10, "issue": 8, "exchange": 5, "revoke": 2}


def build_setup(call, region: str = "EU") -> dict:
    """One-time per worker: a support token (EU) for the hot path, and a
    finance token for a few variations. `call(op, payload) -> result`."""
    g = call("issue_token", {"user": "anna", "agent": "support-orchestrator", "role": "support-agent", "task": "ticket-load", "tenant": TENANT})
    if g.get("ok") is not True:
        raise RuntimeError(f"issue support token: {g}")
    child = call("exchange_token", {"subject_token": g["token"], "actor": "ticket-triager", "ttl": 600})
    return {"support": g["token"], "support_child": child.get("token"), "support_id": g["token_id"]}


def op_request(op: str, tokens: dict):
    """-> (engine_op, payload, expect) where expect is 'allow' or 'deny'. A
    deny-expected request must never come back allowed, under any load."""
    t = tokens["support"]
    if op == "authorize_allow":
        return "authorize", {"token": t, "action": "read", "resource": {"path": "crm.customer", "id": "c-load", "attrs": {"tenant": TENANT, "region": "EU"}}}, "allow"
    if op == "filter_allow":
        return "filter", {"token": t, "action": "read", "resource": {"path": "crm.customer", "id": "c-load", "attrs": {"tenant": TENANT, "region": "EU"}}, "data": CUSTOMER}, "allow"
    if op == "authorize_deny":
        # a US record for an EU support agent: README rule 9 forbids it
        return "authorize", {"token": t, "action": "read", "resource": {"path": "crm.customer", "id": "c-load", "attrs": {"tenant": TENANT, "region": "US"}}}, "deny"
    if op == "issue":
        return "issue_token", {"user": "anna", "agent": "support-orchestrator", "role": "support-agent", "task": "ticket-load", "tenant": TENANT}, "allow"
    if op == "exchange":
        return "exchange_token", {"subject_token": t, "actor": "ticket-triager", "ttl": 300}, "allow"
    if op == "revoke":
        return "revoke", {"token_id": "load-" + secrets.token_hex(6)}, "allow"   # revoking an id that does not exist still writes state
    raise ValueError(op)
