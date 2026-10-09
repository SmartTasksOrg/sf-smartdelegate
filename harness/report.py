"""report.json and a self-contained report.html for a run of the small harness.

The field names of report.json are the ones the full simulation harness uses
wherever the two overlap (verdict, totals, scenarios, rules, violations,
swimlanes), so one tool can read both. `trace` (every recorded step) is only
written here. No capability token is written: tokens are replaced by the name
the scenario gave them.
"""
from __future__ import annotations

import html
import json
import re
import time
from collections import Counter
from pathlib import Path

SCHEMA_VERSION = 1
DECISION_OPS = ("authorize", "filter", "explain")
_JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
CHECKS = {
    "INV-J": "A scripted step got the outcome the scenario expects.",
    "INV-B": "No field the token's role or capability denies came back in data.",
    "INV-C": "The spend allowed on a token and on each of its ancestors stayed within that token's budget.",
    "INV-D": "Nothing was allowed for a revoked, offboarded or expired token.",
    "INV-I": "The audit log verifies and has a matching record for every decision.",
}


def redact(value, names: dict):
    if isinstance(value, str):
        return f"<token {names[value]}>" if value in names else "<token>" if _JWT.match(value) else value
    if isinstance(value, list):
        return [redact(v, names) for v in value]
    if isinstance(value, dict):
        return {k: redact(v, names) for k, v in value.items()}
    return value


def describe_step(e: dict) -> str:
    """One line saying what a recorded step did."""
    op, req = e.get("op"), e.get("request") or {}
    if op == "issue_token":
        return f"lends {req.get('agent')} the role {req.get('role') or '(none)'} for task {req.get('task')}"
    if op == "exchange_token":
        return f"hands a sub-agent token to {req.get('actor')}" + (f" as role {req.get('role')}" if req.get("role") else "")
    if op in DECISION_OPS:
        res = req.get("resource") if isinstance(req.get("resource"), dict) else {"path": str(req.get("resource")), "id": "?"}
        spend = (req.get("context") or {}).get("spend") if isinstance(req.get("context"), dict) else None
        money = (f", {spend.get('amount', 0) / 100:,.2f} {spend.get('currency')}"
                 if isinstance(spend, dict) and isinstance(spend.get("amount"), int) and not isinstance(spend.get("amount"), bool) else "")
        return f"{req.get('action')} {res.get('path')}/{res.get('id')}{money}" + (" (strict input)" if req.get("strict") else "")
    if op == "approve":
        return f"approves the held request of step {e.get('approval_of')}"
    if op == "revoke":
        return f"revokes every token of {req['user']}" if "user" in req else "revokes a token"
    if op == "handoff":
        return f"hands a work item to {req.get('to')}" + (f" WITH the token(s) {', '.join(req['tokens'])}" if req.get("tokens") else "")
    if op == "advance":
        return f"{req.get('seconds')} seconds pass"
    if op == "skipped":
        return f"skipped: {req.get('why')}"
    return str(op)


CSS = """
:root{--bg:#f6f7f9;--card:#ffffff;--ink:#1b2430;--muted:#5b6777;--line:#d5dae1;--accent:#1f5fae;
--allow-bg:#e2f3e6;--allow-ink:#17592b;--deny-bg:#fbe4e1;--deny-ink:#8a1f12;--err-bg:#fdf0d5;--err-ink:#6d4a00;--info-bg:#e6edf7;--info-ink:#1f3f6e;--bad:#b3261e}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#12161c;--card:#1b222b;--ink:#e6eaf0;--muted:#9aa7b7;--line:#33404f;--accent:#8ab8f0;
--allow-bg:#17361f;--allow-ink:#a6e3b3;--deny-bg:#45201c;--deny-ink:#f5b3aa;--err-bg:#3f3214;--err-ink:#f1d48a;--info-bg:#1d2c44;--info-ink:#b6cdee;--bad:#ff8a80}}
:root[data-theme="dark"]{--bg:#12161c;--card:#1b222b;--ink:#e6eaf0;--muted:#9aa7b7;--line:#33404f;--accent:#8ab8f0;
--allow-bg:#17361f;--allow-ink:#a6e3b3;--deny-bg:#45201c;--deny-ink:#f5b3aa;--err-bg:#3f3214;--err-ink:#f1d48a;--info-bg:#1d2c44;--info-ink:#b6cdee;--bad:#ff8a80}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:20px 16px 60px}h1{font-size:1.5rem;margin:.2em 0}h2{font-size:1.15rem;margin:2em 0 .6em;border-bottom:1px solid var(--line);padding-bottom:.25em}
h3{font-size:1rem;margin:1.2em 0 .4em}p{margin:.5em 0}.muted{color:var(--muted)}code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.top{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
button{font:inherit;color:var(--ink);background:var(--card);border:1px solid var(--line);border-radius:6px;padding:6px 10px;cursor:pointer}
.verdict{display:inline-block;font-weight:700;padding:2px 10px;border-radius:6px;border:2px solid currentColor}
.PASS{color:var(--allow-ink);background:var(--allow-bg)}.FAIL,.ERROR{color:var(--deny-ink);background:var(--deny-bg)}.SKIP{color:var(--err-ink);background:var(--err-bg)}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.tile{flex:1 1 150px;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.tile b{display:block;font-size:1.35rem}.tile span{color:var(--muted);font-size:.85rem}
.scroll{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}tr:last-child td{border-bottom:0}
.tag{display:inline-block;font-size:.72rem;font-weight:700;letter-spacing:.03em;padding:1px 6px;border-radius:4px;border:1px solid currentColor;white-space:nowrap}
.t-allow{color:var(--allow-ink);background:var(--allow-bg)}.t-deny{color:var(--deny-ink);background:var(--deny-bg)}.t-error{color:var(--err-ink);background:var(--err-bg)}
.t-info{color:var(--info-ink);background:var(--info-bg)}.t-bad{color:#fff;background:var(--bad);border-color:var(--bad)}
.viol{background:var(--card);border:1px solid var(--bad);border-left-width:5px;border-radius:8px;padding:10px 12px;margin:10px 0}
.viol pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;margin:.4em 0;color:var(--muted)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:10px 0}summary{cursor:pointer;padding:10px 12px;font-weight:600}
details>.inner{padding:0 12px 12px}
table.lanes{table-layout:fixed;border-collapse:separate;border-spacing:0;font-size:.82rem}
table.lanes th{position:sticky;top:0;background:var(--card);text-transform:uppercase;letter-spacing:.05em;font-size:.76rem;text-align:center;border-bottom:2px solid var(--line);white-space:normal}
table.lanes td{border-bottom:0;padding:4px 4px;border-left:1px dashed var(--line)}table.lanes td:first-child{border-left:0}
.step{border:1px solid var(--line);border-left:5px solid var(--line);border-radius:6px;padding:6px 8px;background:var(--bg)}
.step.s-allow{border-left-color:var(--allow-ink)}.step.s-deny{border-left-color:var(--deny-ink)}.step.s-error{border-left-color:var(--err-ink)}.step.s-info{border-left-color:var(--info-ink)}
.step .who{font-weight:600}.step .why{color:var(--muted);margin-top:3px}.step .tag{margin-top:3px}
td.arrow{padding:10px 18px 2px}.arrow .cap{display:block;text-align:center;color:var(--accent);font-size:.72rem;font-weight:700}
.arrow .line{position:relative;height:12px;border-top:2px solid var(--accent);margin-top:2px}
.arrow .line:after{content:"";position:absolute;top:-7px;border:6px solid transparent}
.arrow .ltr:after{right:-2px;border-left-color:var(--accent)}.arrow .rtl:after{left:-2px;border-right-color:var(--accent)}
td.wide{text-align:center;color:var(--muted);font-size:.8rem;border-left:0}
@media (max-width:640px){main{padding:14px 16px 40px}}
"""

JS = """
(function(){var k='sd-harness-theme',r=document.documentElement,b=document.getElementById('theme');
function get(){try{return localStorage.getItem(k)}catch(e){return null}}
function set(v){try{localStorage.setItem(k,v)}catch(e){}}
var t=get();if(t){r.setAttribute('data-theme',t)}
b.addEventListener('click',function(){var dark=r.getAttribute('data-theme')?r.getAttribute('data-theme')==='dark':matchMedia('(prefers-color-scheme: dark)').matches;
var n=dark?'light':'dark';r.setAttribute('data-theme',n);set(n)});})();
"""


def _e(x) -> str:
    return html.escape(str(x), quote=True)


def _outcome_tag(outcome: str) -> tuple:
    """-> (css class, text label). The label carries the meaning; the colour repeats it."""
    if outcome == "allow":
        return "allow", "ALLOW"
    if outcome == "ok":
        return "allow", "OK"
    if outcome.startswith("deny:"):
        return "deny", "DENY " + outcome[5:]
    if outcome.startswith("error:"):
        return "error", "REFUSED " + outcome[6:]
    return "info", outcome.upper() if outcome != "-" else "NOTE"


def _table(headers: list, rows: list, numeric: set = frozenset()) -> str:
    head = "".join(f"<th{' class=num' if i in numeric else ''}>{_e(h)}</th>" for i, h in enumerate(headers))
    body = "".join("<tr>" + "".join(f"<td{' class=num' if i in numeric else ''}>{c}</td>" for i, c in enumerate(row)) + "</tr>" for row in rows)
    return f"<div class=scroll><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def _swimlane(sw: dict) -> str:
    lanes = sw["lanes"] or ["(none)"]
    n = len(lanes)
    rows = []
    for s in sw["steps"]:
        cls, label = _outcome_tag(s["outcome"])
        if s["op"] in ("advance", "skipped") or s["unit"] not in lanes:
            rows.append(f"<tr><td class=wide colspan={n}>{_e(s['step'])}: {_e(s['what'])}</td></tr>")
            continue
        a = lanes.index(s["unit"])
        b = lanes.index(s["to_unit"]) if s.get("to_unit") in lanes else a
        if s["op"] == "handoff" and a != b:
            lo, hi = min(a, b), max(a, b)
            caption = "WORK ITEM AND TOKEN" if "WITH the token" in s["what"] else "WORK ITEM"
            cells = (f"<td colspan={lo}></td>" if lo else "") + (
                f"<td class=arrow colspan={hi - lo + 1}><span class=cap>{caption}: {_e(lanes[a])} to {_e(lanes[b])}</span>"
                f"<div class=\"line {'ltr' if b > a else 'rtl'}\"></div></td>") + (f"<td colspan={n - hi - 1}></td>" if n - hi - 1 else "")
            rows.append(f"<tr>{cells}</tr>")
        tags = f"<span class=\"tag t-{cls}\">{_e(label)}</span>"
        if s.get("unexpected"):
            tags += f" <span class=\"tag t-bad\">UNEXPECTED: {_e(s['unexpected'])}</span>"
        for inv in s.get("violations") or []:
            tags += f" <span class=\"tag t-bad\">VIOLATION {_e(inv)}</span>"
        cross = f" <span class=muted>(to {_e(lanes[b])})</span>" if b != a and s["op"] != "handoff" else ""
        why = f"<div class=why>{_e(s['why'])}</div>" if s.get("why") else ""
        card = (f"<div class=\"step s-{cls}\"><div><span class=muted>{_e(s['step'])}</span> "
                f"<span class=who>{_e(s['actor'])}</span>{cross}</div><div>{_e(s['what'])}</div><div>{tags}</div>{why}</div>")
        rows.append("<tr>" + "".join(f"<td>{card if i == a else ''}</td>" for i in range(n)) + "</tr>")
    head = "".join(f"<th>{_e(lane)}</th>" for lane in lanes)
    table = f"<div class=scroll><table class=lanes style=\"min-width:{n * 190}px\"><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    cast = ", ".join(f"{k} = {v}" for k, v in sw["cast"].items())
    return (f"<details{' open' if sw.get('open') else ''}><summary>{_e(sw['scenario'])}: {_e(sw['name'])} <span class=muted>(instance {sw['instance']})</span></summary>"
            f"<div class=inner><p>{_e(sw['description'])}</p><p class=muted>Cast: {_e(cast)}. One column per business unit; each card sits in the column of the unit that acts; "
            f"an arrow is a work item handed from one unit to another. The outcome is written on every card.</p>{table}</div></details>")


def build(run, config: dict) -> dict:
    c = run.company
    names = {}
    for e in run.trace:      # token string -> the name the scenario gave it
        resp = e["response"] if isinstance(e["response"], dict) else {}
        if isinstance(resp.get("token"), str):
            names[resp["token"]] = f"{e.get('new_token_name') or e['step']} {resp.get('token_id')}"
    steps = []
    for e in run.trace:
        unit = c.unit(e["actor"]) if e["actor_kind"] in ("human", "agent") else ""
        to = e["request"].get("to") if e["op"] == "handoff" else e.get("to_agent")
        r = redact({"request": e["request"], "response": e["response"]}, names)
        steps.append({"i": e["i"], "instance": e["instance"], "scenario": e["scenario"], "step": e["step"], "kind": e["kind"], "actor": e["actor"],
                      "actor_kind": e["actor_kind"], "unit": unit, "to_unit": c.unit(to) if to else None, "op": e["op"],
                      "what": describe_step(dict(e, request=r["request"])), "outcome": e["outcome"], "rule": e["rule"], "why": e.get("why"),
                      "expected": e["expect"] if isinstance(e.get("expect"), str) else (e.get("expect") or {}).get("outcome"),
                      "unexpected": e.get("unexpected"), "violations": e.get("violations", []), "misbehaviour": None, "ms": e["ms"],
                      "request": r["request"], "response": r["response"]})
    engine = [s for s in steps if s["op"] not in ("handoff", "advance")]
    decisions = [s for s in engine if s["op"] in DECISION_OPS]
    scen = []
    for sid, doc in sorted(run.scenarios.items()):
        mine = [i for i in run.instances if i["scenario"] == sid]
        bad = {v["instance"] for v in run.violations if v["scenario"] == sid}
        if sid in run.skipped:
            scen.append({"id": sid, "name": doc["name"], "units": doc["units"], "status": "SKIP", "why": run.skipped[sid], "instances": 0, "steps": 0,
                         "unexpected": 0, "instances_with_violations": 0})
        elif mine:
            scen.append({"id": sid, "name": doc["name"], "units": doc["units"], "status": "FAIL" if bad else "PASS", "instances": len(mine),
                         "steps": sum(1 for s in steps if s["scenario"] == sid), "unexpected": sum(i["failures"] for i in mine), "instances_with_violations": len(bad)})
    lanes = []
    for sid in sorted({i["scenario"] for i in run.instances}):      # the first instance of each scenario, or the first that went wrong
        insts = [i for i in run.instances if i["scenario"] == sid]
        bad = {v["instance"] for v in run.violations if v["scenario"] == sid}
        inst = next((i for i in insts if i["instance"] in bad), insts[0])
        mine = [s for s in steps if s["instance"] == inst["instance"]]
        units = []
        for s in mine:
            for u in (s["unit"], s["to_unit"]):
                if u and u not in units:
                    units.append(u)
        keep = ("step", "kind", "actor", "actor_kind", "unit", "to_unit", "op", "what", "outcome", "rule", "why", "misbehaviour", "unexpected", "violations", "expected")
        lanes.append({"scenario": sid, "name": run.scenarios[sid]["name"], "description": run.scenarios[sid]["description"], "instance": inst["instance"],
                      "cast": inst["cast"], "lanes": units, "steps": [{k: s[k] for k in keep} for s in mine]})
    by = Counter(v["invariant"] for v in run.violations)
    verdict = "ERROR" if run.harness_errors or any(s["outcome"] == "error:harness_transport" for s in steps) else "FAIL" if run.violations else "PASS"
    ms = sorted(s["ms"] for s in decisions)
    pct = lambda q: ms[min(len(ms) - 1, int(round(q * (len(ms) - 1))))] if ms else 0.0
    return {
        "schema": SCHEMA_VERSION, "harness": "public", "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verdict": verdict, "exit_code": {"PASS": 0, "FAIL": 1, "ERROR": 2}[verdict], "config": config, "seed": config.get("seed"),
        "backend": {"name": run.backend.name, "implementation": run.info.get("implementation"), "kind": "in-process engine" if run.backend.name == "inprocess" else "REST daemon started by somebody else"},
        "features": {"test_clock": run.test_clock, "implementation": run.info.get("implementation")},
        "company": {"humans": len(c.users), "registered_agents": len(c.agents), "roles": sorted(c.roles), "resources": sorted(c.catalog), "policy_version": run.info.get("policy_version")},
        "totals": {"instances": len(run.instances), "recorded_steps": len(steps), "engine_calls": len(engine), "decisions": len(decisions),
                   "humans_acting": len({u for i in run.instances for u in i["cast"].values()}), "wall_seconds": round(run.wall, 3),
                   "decisions_per_second": round(len(decisions) / run.wall, 1) if run.wall else 0, "decision_p50_ms": round(pct(0.5), 3), "decision_p99_ms": round(pct(0.99), 3)},
        "scenarios": scen, "skipped": dict(run.skipped),
        "rules": dict(sorted(Counter(s["rule"] for s in engine if s["op"] != "info").items())),
        "invariants": {k: {"rule": text, "violations": by.get(k, 0)} for k, text in CHECKS.items()},
        "violations": [dict(v, request=redact(v["request"], names), response=redact(v["response"], names), rule=CHECKS[v["invariant"]]) for v in run.violations],
        "audit": run.audit, "harness_errors": list(run.harness_errors), "swimlanes": lanes, "trace": steps,
    }


def to_html(r: dict) -> str:
    t = r["totals"]
    h = ["<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">",
         f"<title>SmartDelegate harness report: {_e(r['verdict'])}</title><style>{CSS}</style></head><body><main>",
         "<div class=top><div><h1>SmartDelegate scenario harness</h1>",
         f"<p class=muted>Generated {_e(r['generated_at'])}. Backend <code>{_e(r['backend']['name'])}</code>, decisions by the {_e(r['backend'].get('implementation'))} engine. "
         f"Policy version <code>{_e(str(r['company']['policy_version'])[:16])}</code>.</p></div>",
         f"<div><span class=\"verdict {_e(r['verdict'])}\">{_e(r['verdict'])}</span> <button id=theme type=button>Light / dark</button></div></div>"]
    if r["violations"]:
        h.append(f"<h2>Violations ({len(r['violations'])})</h2>")
        for v in r["violations"][:40]:
            h.append(f"<div class=viol><div><span class=\"tag t-bad\">{_e(v['invariant'])}</span> <b>{_e(v['scenario'])}</b>, instance {_e(v['instance'])}, step <code>{_e(v['step'])}</code>, "
                     f"actor <code>{_e(v['actor'])}</code>, <code>{_e(v['op'])}</code></div><p>{_e(v['detail'])}</p><p class=muted>Check: {_e(v['rule'])}</p>"
                     f"<pre>request: {_e(json.dumps(v['request'], ensure_ascii=False)[:1500])}\nanswer:  {_e(json.dumps(v['response'], ensure_ascii=False)[:1500])}</pre></div>")
    if r["harness_errors"]:
        h.append("<h2>Harness errors</h2><p>The run could not be carried out as planned; its verdict is not a statement about the engine.</p><ul>"
                 + "".join(f"<li>{_e(e)}</li>" for e in r["harness_errors"]) + "</ul>")
    tiles = [(t["instances"], "scenario instances"), (t["humans_acting"], "humans acting"), (t["engine_calls"], "requests to the engine"), (t["decisions"], "decisions"),
             (f"{t['wall_seconds']} s", "wall time"), (len(r["violations"]), "violations"), (r["audit"].get("decisions_matched", 0), "decisions found in the audit log")]
    h.append("<h2>What ran</h2><div class=tiles>" + "".join(f"<div class=tile><b>{_e(v)}</b><span>{_e(k)}</span></div>" for v, k in tiles) + "</div>")
    rows = [[f"<code>{_e(s['id'])}</code><br>{_e(s['name'])}", _e(", ".join(s["units"])), s["instances"], s["steps"], s["unexpected"],
             f"<span class=\"tag {'t-allow' if s['status'] == 'PASS' else 't-error' if s['status'] == 'SKIP' else 't-deny'}\">{_e(s['status'])}</span>"
             + (f"<br><span class=muted>{_e(s['why'])}</span>" if s.get("why") else "")] for s in r["scenarios"]]
    h.append("<h2>Scenarios</h2>" + _table(["Scenario", "Units", "Instances", "Steps", "Unexpected", "Result"], rows, {2, 3, 4}))
    rows = [[f"<code>{_e(k)}</code>", (f"<span class=\"tag t-bad\">{d['violations']}</span>" if d["violations"] else "0"), _e(d["rule"])] for k, d in r["invariants"].items()]
    h.append("<h2>Checks</h2>" + _table(["Id", "Violations", "What must hold"], rows))
    h.append("<h2>Engine answers by rule id</h2>" + _table(["Rule", "Count"], [[f"<code>{_e(k)}</code>", v] for k, v in r["rules"].items()], {1}))
    h.append("<h2>Swimlanes: one instance of each scenario</h2>")
    for n, sw in enumerate(r["swimlanes"]):
        h.append(_swimlane(dict(sw, open=n == 0)))
    h.append(f"</main><script>{JS}</script></body></html>")
    return "".join(h)


def write(report: dict, out_dir) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {"json": out / "report.json", "html": out / "report.html"}
    paths["json"].write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    paths["html"].write_text(to_html(report), encoding="utf-8")
    return {k: str(v) for k, v in paths.items()}
