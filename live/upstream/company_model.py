"""A model of the example company for the live upstream suite, without the engine.

It reads the bundle's catalog.json and entities.json (examples/company) and
company_model.json next to this file, which holds four of the rules of
examples/company/README.md in machine form. It imports nothing from
`smartdelegate`: what it says a role may see is compared with what came through
the proxies.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPANY = ROOT / "examples" / "company"
RULES_FILE = Path(__file__).resolve().with_name("company_model.json")


class Cap:
    """The deny lists of a capability."""

    def __init__(self, v: dict | None = None):
        v = v or {}
        self.deny_labels = list(v.get("deny_labels") or [])
        self.deny_fields = list(v.get("deny_fields") or [])


class World:
    def __init__(self, company_dir: Path | str = COMPANY, rules_file: Path | str = RULES_FILE):
        self.dir = Path(company_dir)
        read = lambda name: json.loads((self.dir / name).read_text(encoding="utf-8"))
        self.catalog = {path: {"entity_type": r["entity_type"],
                               "fields": {n: {"labels": list(f.get("labels") or []), "mask": f.get("mask")} for n, f in r["fields"].items()}}
                        for path, r in read("catalog.json")["resources"].items()}
        self.rules = json.loads(Path(rules_file).read_text(encoding="utf-8"))
        self._parents: dict = {}
        self.attrs: dict = {}
        for e in read("entities.json"):
            key = (e["uid"]["type"], e["uid"]["id"])
            self._parents[key] = [(p["type"], p["id"]) for p in e.get("parents") or []]
            self.attrs[key] = e.get("attrs") or {}

    def ancestors(self, type_: str, id_: str) -> set:
        seen: set = set()
        todo = list(self._parents.get((type_, id_), []))
        while todo:
            p = todo.pop()
            if p not in seen:
                seen.add(p)
                todo.extend(self._parents.get(p, []))
        return seen

    def agent_in(self, agent: str, group: str) -> bool:
        return ("AgentGroup", group) in self.ancestors("Agent", agent)

    def region(self, user: str) -> str:
        return self.attrs.get(("User", user), {}).get("region", "")

    def field_labels(self, path: str, field: str) -> list:
        return self.catalog.get(path, {}).get("fields", {}).get(field, {}).get("labels", [])

    def access_allows(self, role: str, agent: str, action: str, path: str) -> bool:
        for row in self.rules["access"]:
            if role not in row["roles"] or action not in row["actions"]:
                continue
            if "*" not in row["resources"] and path not in row["resources"]:
                continue
            if "agents" in row and agent in row["agents"]:
                return True
            if "agent_group" in row and self.agent_in(agent, row["agent_group"]):
                return True
        return False

    def field_view(self, agent: str, path: str) -> dict | None:
        for row in self.rules["field_views"]:
            if row["resource"] == path and self.agent_in(agent, row["agent_group"]):
                return row
        return None

    def field_denied(self, *, path: str, field: str, role: str | None, depth: int, agent: str, action: str, caps: list) -> str | None:
        """Why this principal must not see or set this catalogued field, or None.
        A label or field any of `caps` denies is denied."""
        labels = self.field_labels(path, field)
        fid = f"{path}.{field}"
        for cap in caps:
            if fid in cap.deny_fields:
                return f"the capability denies the field {fid}"
            for label in labels:
                if label in cap.deny_labels:
                    return f"the capability denies the label '{label}'"
        for rule in self.rules["label_rules"]:
            if rule["label"] not in labels:
                continue
            if "only_roles" in rule and role not in rule["only_roles"]:
                return f"label '{rule['label']}' is for roles {rule['only_roles'] or 'nobody'}"
            if "max_depth" in rule and depth > rule["max_depth"]:
                return f"label '{rule['label']}' stops at depth {rule['max_depth']}"
        view = self.field_view(agent, path)
        if view:
            if action == "read":
                if "read" in view and field not in view["read"]:
                    return f"{view['agent_group']} read only {view['read']} of {path}"
                if "read_without_labels" in view and any(l in view["read_without_labels"] for l in labels):
                    return f"{view['agent_group']} do not read {view['read_without_labels']} fields of {path}"
            else:
                if "write" in view and field not in view["write"]:
                    return f"{view['agent_group']} write only {view['write']} of {path}"
                if "write_except" in view and field in view["write_except"]:
                    return f"{view['agent_group']} do not write {view['write_except']} of {path}"
        return None
