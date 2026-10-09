"""What a role must and must not receive, computed without the engine.

Field decisions come from company_model.py, this suite's own model of the
company: catalog.json labels, the deny lists of roles.json and four of the
business rules of examples/company/README.md in machine form
(company_model.json). That module imports nothing from the engine. The record walk below (what a
masked record looks like) is written again here from docs/SCOPE.md and the
"Rules (fail closed)" of src/sf_smartdelegate/fields.py's docstring, not by
calling it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
from .company_model import Cap, World

REDACTED = "[REDACTED]"
#: shapes of the sensitive values live/upstream/seed.py generates
CARD = re.compile(rb"4929\d{12}")
IBAN = re.compile(rb"[A-Z]{2}00KEST\d{14}")
NATIONAL_ID = re.compile(rb"NID-\d{9}")
TAX_ID = re.compile(rb"TAX-\d{9}")


class Oracle:
    def __init__(self):
        self.world = World()
        self.roles = json.loads((ROOT / "examples" / "company" / "roles.json").read_text(encoding="utf-8"))["roles"]

    def agent(self, role: str) -> str:
        return self.roles[role]["agents"][0]

    def task(self, role: str, suffix: str = "live") -> str:
        return self.roles[role]["tasks"][0].replace("*", suffix)

    def denied(self, path: str, field: str, role: str, agent: str, depth: int, action: str) -> bool:
        return self.world.field_denied(path=path, field=field, role=role, depth=depth, agent=agent, action=action,
                                       caps=[Cap(self.roles[role]["cap"])]) is not None

    def visible_fields(self, path: str, role: str, *, agent: str | None = None, depth: int = 1, action: str = "read") -> list:
        agent = agent or self.agent(role)
        return sorted(f for f in self.world.catalog[path]["fields"] if not self.denied(path, f, role, agent, depth, action))

    def view(self, path: str, record: dict, role: str, *, agent: str | None = None, depth: int = 1, action: str = "read") -> dict:
        """The record as this principal may see it."""
        agent = agent or self.agent(role)
        fields = self.world.catalog[path]["fields"]

        def put(out: dict, key: str, name: str, value, when_allowed):
            if self.denied(path, name, role, agent, depth, action):
                if fields[name]["mask"] == "redact":
                    out[key] = REDACTED
            else:
                out[key] = when_allowed(value)

        def children(prefix: str) -> bool:
            return any(f.startswith(prefix + ".") or f.startswith(prefix + "[]") for f in fields)

        def inside_allowed(value, prefix: str):
            """Under an allowed parent everything stays, except children the catalog lists and the principal may not see."""
            if isinstance(value, list):
                return [inside_allowed(v, prefix + "[]") for v in value]
            if isinstance(value, dict):
                out = {}
                for k, v in value.items():
                    name = f"{prefix}.{k}"
                    if name in fields:
                        put(out, k, name, v, lambda x, n=name: inside_allowed(x, n))
                    else:
                        out[k] = inside_allowed(v, name)
                return out
            return value

        out: dict = {}
        for k, v in record.items():
            if k in fields:
                put(out, k, k, v, lambda x, n=k: inside_allowed(x, n) if children(n) else x)
            elif children(k) and isinstance(v, dict):
                # not a field itself, but its members are (card.number, bank.iban): only the listed members can stay
                sub: dict = {}
                for ck, cv in v.items():
                    name = f"{k}.{ck}"
                    if name in fields:
                        put(sub, ck, name, cv, lambda x: x)
                out[k] = sub
            # anything else is not in the catalog: dropped
        return out

    def row_filtered(self, path: str, role: str) -> bool:
        reg = self.world.rules["regional"]
        return role in reg["roles"] and path in reg["row_filtered"]

    def regional(self, path: str, role: str) -> bool:
        reg = self.world.rules["regional"]
        return role in reg["roles"] and path in reg["resources"]

    def region(self, user: str) -> str:
        return self.world.region(user)

    def may(self, role: str, action: str, path: str, agent: str | None = None) -> bool:
        return self.world.access_allows(role, agent or self.agent(role), action, path)
