#!/usr/bin/env python3
"""Summarise audit records by rule id, user and agent.

    smartdelegate audit tail -n 500 | python3 skills/smartdelegate-monitor/scripts/audit_summary.py
    smartdelegate audit tail -n 500 | python3 skills/smartdelegate-monitor/scripts/audit_summary.py --json

Reads JSON Lines from standard input, as `smartdelegate audit tail` prints
them. Prints counts and the findings whose count reaches a threshold. The
thresholds are starting points, not calibrated values; they are the defaults
of the MCP server's `anomalies` tool, which does the same on a live engine.

Not visible here: refused token requests (DELEGATE-WIDENING,
DELEGATE-ROLE-NOT-HELD, DELEGATE-ROLE-EXCEEDED ...). The engine answers them to
the caller and writes no audit record.

Reads only; standard library only. Exit status: 0 no finding, 3 at least one
finding, 2 usage.
"""
from __future__ import annotations

import json
import sys
from collections import Counter

THRESHOLDS = {"min_decisions": 20, "deny_rate_percent": 50, "capability_denies_per_agent": 5, "revoked_token_uses_per_user": 3,
              "invalid_tokens": 5, "budget_denies_per_token": 3, "policy_errors": 1, "unknown_resources_per_agent": 3, "user_revocations": 3}


def summarise(records: list) -> dict:
    decisions = [r for r in records if r.get("event") == "decision"]
    for r in decisions:
        r["rule"] = "DELEGATE-" + str(r.get("reason") or "deny").upper().replace("_", "-")
    denies = [r for r in decisions if r.get("effect") == "deny"]
    agent = lambda r: (r.get("chain") or ["?"])[-1]
    findings = []

    def per(key, rules, name, code):
        for who, n in sorted(Counter(key(r) for r in denies if r["rule"] in rules).items(), key=lambda kv: (-kv[1], str(kv[0]))):
            if n >= THRESHOLDS[name]:
                findings.append({"code": code, "subject": who, "count": n, "threshold": THRESHOLDS[name]})

    if len(decisions) >= THRESHOLDS["min_decisions"] and len(denies) * 100 >= THRESHOLDS["deny_rate_percent"] * len(decisions):
        findings.append({"code": "deny_rate", "count": len(denies), "of": len(decisions), "threshold": THRESHOLDS["deny_rate_percent"]})
    per(agent, ("DELEGATE-CAPABILITY-ACTION", "DELEGATE-CAPABILITY-RESOURCE"), "capability_denies_per_agent", "capability_probing")
    per(lambda r: r.get("user"), ("DELEGATE-TOKEN-REVOKED",), "revoked_token_uses_per_user", "revoked_token_in_use")
    per(lambda r: r.get("token_id"), ("DELEGATE-BUDGET-EXCEEDED",), "budget_denies_per_token", "budget_exhausted")
    per(agent, ("DELEGATE-UNKNOWN-RESOURCE", "DELEGATE-UNKNOWN-FIELD"), "unknown_resources_per_agent", "catalog_miss")
    by_rule = Counter(r["rule"] for r in decisions)
    for rule, name, code in (("DELEGATE-TOKEN-INVALID", "invalid_tokens", "invalid_tokens"), ("DELEGATE-POLICY-ERROR", "policy_errors", "policy_error")):
        if by_rule[rule] >= THRESHOLDS[name]:
            findings.append({"code": code, "count": by_rule[rule], "threshold": THRESHOLDS[name]})
    events = Counter(str(r.get("event")) for r in records)
    if events["user_revoked"] >= THRESHOLDS["user_revocations"]:
        findings.append({"code": "user_revocations", "count": events["user_revoked"], "threshold": THRESHOLDS["user_revocations"],
                         "subject": sorted({str(r.get("user")) for r in records if r.get("event") == "user_revoked"})})
    unenforced = sum(1 for r in denies if r.get("enforced") is False)
    if unenforced:
        findings.append({"code": "not_enforced", "count": unenforced, "threshold": 1})
    return {"records": len(records), "decisions": len(decisions), "denials": len(denies), "by_rule": dict(sorted(by_rule.items())),
            "events": dict(sorted(events.items())), "denials_by_user": dict(sorted(Counter(str(r.get("user")) for r in denies).items())),
            "denials_by_agent": dict(sorted(Counter(agent(r) for r in denies).items())), "findings": findings}


def main(argv: list) -> int:
    if set(argv) - {"--json"}:
        print(__doc__)
        return 0 if argv in (["--help"], ["-h"]) else 2
    records = []
    for line in sys.stdin.read().split("\n"):       # "\n" only: U+2028 and friends are data in a record
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict):
            records.append(r)
    s = summarise(records)
    if "--json" in argv:
        print(json.dumps(s, indent=2))
    else:
        print(f"{s['records']} records, {s['decisions']} decisions, {s['denials']} denials")
        for title, key in (("by rule", "by_rule"), ("events", "events"), ("denials by user", "denials_by_user"), ("denials by agent", "denials_by_agent")):
            print(f"{title}: " + (", ".join(f"{k} {v}" for k, v in s[key].items()) or "-"))
        for f in s["findings"]:
            print("FINDING " + " ".join(f"{k}={v}" for k, v in f.items()))
    return 3 if s["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
