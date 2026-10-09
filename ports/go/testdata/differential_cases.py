#!/usr/bin/env python3
"""Prints the differential cases as JSON: {"cases": [{"name", "config"?, "steps": [{"op", "input", "save"?}]}]}.

interop_test.go runs every step in the Go port and in the Python reference
and compares the two results. There are no expected values here: the
reference is the oracle. The inputs are mostly malformed, odd or at a limit,
which is where two implementations drift apart.

Standard library only. `RAW(text)` puts JSON text into the output verbatim,
for numbers Python would not write the way the case needs (1.0, -0.0, NaN,
integers beyond 64 bits).
"""
import json
import re
import sys

FULL = {"actions": ["read", "create", "update"], "resources": ["crm.customer/*", "billing.refund/*"], "budget": {"EUR": 20000}}
REFUND = {"path": "billing.refund", "id": "r-1"}
OMIT = "<omit>"
cases = []


def RAW(text):
    return {"__raw__": text}


def clean(i):
    return {k: v for k, v in i.items() if v != OMIT}


def issue(save="t", **kw):
    i = {"user": "alice", "agent": "support-bot", "cap": FULL}
    i.update(kw)
    return {"op": "issue_token", "input": clean(i), "save": {save: "token", save + "_id": "token_id"}}


def authz(tok="$t", action="read", res=None, **kw):
    i = {"token": tok, "action": action, "resource": res if res is not None else {"path": "crm.customer", "id": "c-1"}}
    i.update(kw)
    return {"op": "authorize", "input": clean(i)}


def flt(data, tok="$t", action="read", res=None, **kw):
    s = authz(tok, action, res, **kw)
    s["op"] = "filter"
    s["input"]["data"] = data
    return s


def call(op, **i):
    return {"op": op, "input": i}


def exchange(save=None, **kw):
    i = {"subject_token": "$t", "actor": "refund-helper", "ttl": 300}
    i.update(kw)
    s = {"op": "exchange_token", "input": clean(i)}
    if save:
        s["save"] = {save: "token", save + "_id": "token_id"}
    return s


def spend(n, **kw):
    return authz(action="create", res=REFUND, context={"spend": {"currency": "EUR", "amount": n}}, **kw)


def case(name, steps, config=None):
    c = {"name": name, "steps": steps}
    if config:
        c["config"] = config
    cases.append(c)


ANY_CAP = {"actions": ["*"], "resources": ["*"]}

# ---- context ---------------------------------------------------------------
contexts = [
    RAW('{"x":1.5}'), {"x": None}, {"x": [1, [2, {"a": True}], "s"]}, RAW('{"x":9223372036854775808}'),
    RAW('{"x":-9223372036854775808}'), RAW('{"x":-9223372036854775809}'),
    {"x": {"__entity": {"type": "User", "id": "alice"}}}, {"x": {"__entity": {"type": "bad type", "id": "a"}}},
    {"x": {"__entity": {"type": "User", "id": "a"}, "y": 1}}, {"x": {"__entity": {"type": "User\n", "id": "a"}}},
    {"x": {"__entity": "s"}}, {"x": {"__extn": {"fn": "ip", "arg": "1.2.3.4"}}}, {"iam": {}}, "str", [], 0, False, {},
    RAW('{"x":NaN}'), RAW('{"x":1e400}'), RAW('{"x":1E2}'), RAW('{"x":-0.0}'),
    {"spend": "x"}, {"spend": {"currency": "EUR", "amount": True}}, {"spend": {"currency": "EUR", "amount": -1}},
    {"spend": {"currency": "USD", "amount": 1}}, {"spend": {"currency": 5, "amount": 1}}, {"spend": {"currency": "EUR"}},
    {"spend": {"currency": "EUR", "amount": 0}}, {"spend": {}}, {"spend": []},
    RAW('{"spend":{"currency":"EUR","amount":1.0}}'), RAW('{"spend":{"currency":"EUR","amount":9223372036854775807}}'),
    {"spend": {"currency": "EUR", "amount": 20001}}, {"deep": {"a": {"b": {"c": [[[[{"d": []}]]]]}}}},
    {"\u00e9\U0001f600": "\U0001F600\u0001\u2028\"\\", "\uffff": "z", "a": ""},
]
steps = [issue()]
for c in contexts:
    steps += [authz(context=c), authz(action="create", res=REFUND, context=c), authz(context=c, dry_run=True, explain=True)]
case("context value types", steps)

# ---- resource, action, fields, token ----------------------------------------
resources = [
    OMIT, "str", {"path": ""}, {"path": 5}, {"id": "c-1"}, {"path": "crm.customer", "id": 5}, {"path": "crm.customer", "id": ""},
    {"path": "crm.customer"}, {"path": "nope", "id": "x"}, {"path": "crm.customer", "id": "c-1", "attrs": "x"},
    {"path": "crm.customer", "id": "c-1", "attrs": []}, {"path": "crm.customer", "id": "c-1", "attrs": None},
    {"path": "crm.customer", "id": "c-1", "attrs": {"tenant": "t1", "owner": {"__entity": {"type": "User", "id": "alice"}}, "tags": ["a", 1, True]}},
    RAW('{"path":"crm.customer","id":"c-1","attrs":{"a":1.5}}'), {"path": "crm.customer", "id": "c-1", "attrs": {"a": None}},
    {"path": "crm.customer", "id": "c-1", "attrs": {"tenant": 5}}, {"path": "crm.customer", "id": "\u00e9\U0001F600\n"},
    {"path": "hr.salary", "id": "s-1"}, {"path": "hr.salary", "id": "s-1", "attrs": {"frozen": False}},
    {"path": "hr.salary", "id": "s-1", "attrs": {"frozen": True}}, {"path": "hr.salary", "id": "s-1", "attrs": {"frozen": "yes"}},
    {"path": "billing.refund", "id": "r", "attrs": {"customer_owner": "alice"}}, [], None, 5,
]
steps = [issue(), issue("tc", user="carol", cap=ANY_CAP)]
for r in resources:
    steps += [authz(res=r), authz(tok="$tc", res=r),
              authz(action="create", res=r, context={"spend": {"currency": "EUR", "amount": 5}}, dry_run=True)]
for a in [OMIT, 5, "", None, "delete", "*", "read "]:
    steps.append(authz(action=a))
for f in [["email", "email"], ["nope"], [5], [], "email", ["addresses[].geo", "card.number"], ["id", "ssn", "card.number", "card.last4"],
          None, {"email": 1}, [None], [["email"]]]:
    steps += [authz(fields=f), authz(tok="$tc", fields=f, explain=True)]
for tok in [OMIT, "", 5, None, "x", "a.b.c", "a.b", "..", "${t}!", "${t}=", "${t}A", "${t}AA", "${t}AAA", "${t}AAAA", " ${t}", "${t}.",
            "$t_id", ["$t"], "${t}\n", "${t}$$", "!${t}", "${t}*-_+/", "${t}!!!!", "${t}~~~~~~~~", "${t}\u00e9\u00e9", "${t}/+/+", "${t}____"]:
    steps += [authz(tok=tok), call("inspect_token", token=tok), clean({"op": "exchange_token", "input": clean({"subject_token": tok, "actor": "refund-helper"})}),
              call("revoke", **clean({"token": tok}))]
case("resource, action, fields and token shapes", steps)

# ---- data --------------------------------------------------------------------
REC = {"id": "c-1", "name": "A", "email": "a@x", "ssn": "123", "region": "EU", "tier": "gold", "notes": "n",
       "addresses": [{"street": "s", "geo": {"lat": RAW("1.5"), "lon": 2}}, "str", 5, [{"geo": 1, "x": 2}], None, {"geo": [1, 2]}],
       "card": {"last4": "1234", "number": "4111", "extra": 1}, "unknown": 1, "nested": {"a": [1, {"b": 2}]}, "phone": None}
datas = [
    REC, [REC, dict(REC, region="US"), dict(REC, region=["EU"]), {"name": "no region"}, 5, "s", None, [REC], {}],
    5, None, "str", RAW("1.5"), True, [], {}, {"region": "EU"}, [[{"region": "EU"}]],
    {"region": "EU", "card": "flat", "addresses": "flat"},
    {"region": "EU", "card": ["4111", {"number": "x", "last4": "y"}], "addresses": {"geo": 1, "street": "s"}},
    {"region": "EU", "card": {"number": {"deep": [1, 2]}, "last4": ["a"]}, "addresses": [[[{"geo": 1, "k": 2}]]]},
    {"region": "EU", "card.number": "dotted key", "addresses[].geo": "x", "card": {"number.x": 1}},
    {"region": "EU", "amount": RAW("1e100"), "x": RAW("-0.0"), "y": RAW("1e16"), "z": RAW("0.0001"), "w": RAW("1.5e-7"),
     "v": RAW("123456789012345678"), "u": RAW("12345678901234567890123"), "t": RAW("1e15"), "s": RAW("0.00001"),
     "r": RAW("123456.789e3"), "q": RAW("5e-324"), "p": RAW("1.7976931348623157e308"), "o": RAW("100.0"), "n": RAW("-1E-2")},
]
steps = [issue(), issue("tc", user="carol", cap=ANY_CAP),
         issue("td", cap=dict(FULL, deny_labels=["pii"], deny_fields=["crm.customer.tier", "crm.customer.card.last4"]))]
for d in datas:
    for tok in ["$t", "$tc", "$td"]:
        steps += [flt(d, tok=tok), flt(d, tok=tok, strict=True)]
    steps += [flt(d, action="update", strict=True), flt(d, action="update"), flt(d, fields=["email", "card.number"]),
              {"op": "explain", "input": dict(flt(d)["input"])}, flt(d, action="delete"), flt(d, tok="bad")]
steps += [call("filter", token="$t", action="read", resource={"path": "crm.customer", "id": "c-1"}),
          call("explain", token="$t", action="read", resource={"path": "crm.customer", "id": "c-1"}),
          call("audit_verify"), call("audit_tail", n=400)]
case("filter data shapes", steps)
case("filter data shapes in shadow mode",
     steps[:40] + [authz(tok="bad"), flt(REC, tok="bad"), flt(REC, action="delete"), call("info")], {"mode": "shadow"})

# ---- issue_token -------------------------------------------------------------
caps = [
    OMIT, None, "x", [], {}, {"actions": "read"}, {"actions": [1]}, {"actions": ["re*ad"]}, {"actions": [""]}, ANY_CAP, {"actions": ["**"]},
    {"resources": ["crm.*/x*"]}, {"budget": []}, RAW('{"budget":{"EUR":1.5}}'), {"budget": {"EUR": True}}, {"budget": {"EUR": -1}},
    {"budget": "x"}, {"budget": 0}, {"budget": False}, {"bugdet": {}, "zz": 1},
    RAW('{"actions":["read"],"resources":["*"],"budget":{"EUR":9223372036854775807,"USD":0}}'),
    {"actions": None, "resources": None, "deny_labels": None, "deny_fields": None, "budget": None},
    {"actions": ["read", "read", "r*"], "resources": ["crm.customer/c-*", "crm.customer/c-1"], "deny_labels": ["pii", "pii"], "deny_fields": ["x"]},
    {"deny_labels": "pii"}, {"deny_fields": [None]}, 0, False, True, 5,
]
steps = []
for c in caps:
    steps += [issue(cap=c), issue(cap=c, role="support-agent"), issue(cap=c, role="auditor", user="carol"), call("inspect_token", token="$t")]
for ttl in [-5, 0, 1, RAW("1000.0"), True, "60", 999999, RAW("9223372036854775807"), RAW("99999999999999999999"),
            RAW("-99999999999999999999"), None, 600, 601]:
    steps += [issue(ttl=ttl), issue(ttl=ttl, role="supervisor", user="bob", task="escalation-9", cap=OMIT), exchange(ttl=ttl)]
for u in [OMIT, 5, "", None, "zed", "dave", "carol", "erin", "bob", "\u00e5lice \U0001F600", ["alice"]]:
    steps += [issue(user=u), issue(user=u, role="support-agent", cap=OMIT), issue(user=u, role="auditor", cap=OMIT)]
for a in [OMIT, 5, "", None, "ghost", "rogue-bot", "refund-helper", "summarizer"]:
    steps += [issue(agent=a), issue(agent=a, role="supervisor", user="bob", task="escalation-1", cap=OMIT)]
for extra in [{"tenant": 5}, {"tenant": ""}, {"tenant": "t1", "task": "ticket-1"}, {"task": 5}, {"task": ["x"]}, {"tenant": None, "task": None},
              {"id_token": "abc"}, {"id_token": 5}, {"id_token": ""}]:
    steps += [issue(**extra), call("inspect_token", token="$t")]
case("issue_token input shapes", steps)

# ---- roles and groups ----------------------------------------------------------
steps = []
groups = [
    "support", ["support", "nope", "support"], [{"type": "Group", "id": "supervisors"}, "support", {"type": "Group", "id": "support"}],
    [5], {"type": "Group", "id": "support"}, [], "", None, [{"type": "Group"}], [{"type": 5, "id": "support"}],
    [{"type": "bad type", "id": "support"}], [{"type": "User", "id": "bob"}],
    [{"type": "AgentGroup", "id": "support-agents"}, {"type": "Group", "id": "compliance"}], 0, False, [[]], ["compliance", "supervisors"],
]
for g in groups:
    for u in ["alice", "dave", "carol"]:
        for role in [OMIT, "support-agent", "supervisor", "auditor", "nope", 5, ""]:
            steps.append(issue(user=u, groups=g, role=role, task="escalation-7"))
        steps += [issue(user=u, groups=g, role="auditor", cap=OMIT), call("inspect_token", token="$t"), authz(), flt(REC),
                  exchange("c", actor="summarizer", ttl=60), authz(tok="$c"), call("inspect_token", token="$c")]
narrow = {"actions": ["read"], "resources": ["crm.customer/c-1"]}
for role, kw in [
    ("supervisor", {}), ("supervisor", {"task": "other"}), ("supervisor", {"task": "escalation-"}),
    ("supervisor", {"task": "escalation-1", "agent": "refund-helper"}),
    ("supervisor", {"task": "escalation-1", "cap": {"actions": ["update"], "resources": ["crm.customer/*"]}}),
    ("supervisor", {"task": "escalation-1", "cap": dict(narrow, budget={"EUR": 50001})}),
    ("supervisor", {"task": "escalation-1", "cap": dict(narrow, budget={"USD": 1})}),
    ("supervisor", {"task": "escalation-1", "cap": dict(narrow, budget={"EUR": 50000}, deny_labels=["zz", "aa"], deny_fields=["b", "a", "b"])}),
    ("supervisor", {"task": "escalation-1", "cap": {"actions": ["re*"], "resources": ["crm.customer/c-1"]}}),
    ("supervisor", {"task": "escalation-1", "cap": {"actions": ["read"], "resources": ["crm.*"]}}),
    ("support-agent", {"cap": {"actions": ["read"], "resources": ["crm.customer/*"]}, "ttl": 3600}),
    ("support-agent", {"cap": {"actions": ["read"], "resources": ["crm.customer/*"], "deny_labels": ["secret"]}}),
    ("auditor", {"cap": ANY_CAP}), ("auditor", {"cap": {"actions": ["delete", "x*"], "resources": ["a/b"]}}),
]:
    i = {"user": "bob", "agent": "support-bot", "role": role, "cap": OMIT}
    i.update(kw)
    steps += [issue(**i), call("inspect_token", token="$t"),
              authz(action="create", res=REFUND, context={"spend": {"currency": "EUR", "amount": 30000}}),
              exchange(ttl=60, role=role), exchange(ttl=60, role="auditor"), exchange(ttl=60, task="escalation-2")]
steps.append(call("info"))
case("roles and live groups", steps)
case("roles with require_role", steps[:60], {"require_role": True})

# ---- delegation ----------------------------------------------------------------
steps = [issue(), exchange("t2"), exchange("t3", subject_token="$t2", actor="summarizer"),
         exchange(subject_token="$t3", actor="summarizer"), exchange(subject_token="$t3", actor="refund-helper")]
crm = ["crm.customer/c-*"]
for kw in [
    {}, {"ttl": 601}, {"ttl": 600}, {"actor": "ghost"}, {"actor": "rogue-bot"}, {"actor": "support-bot"}, {"actor": 5}, {"actor": OMIT},
    {"cap": {"actions": ["read", "delete"], "resources": ["crm.customer/*"], "budget": {"EUR": 1}}},
    {"cap": {"actions": ["read"], "resources": ["crm.customer/*", "hr.salary/*"]}},
    {"cap": {"actions": ["read"], "resources": crm, "budget": {"EUR": 20001}}}, {"cap": {"actions": ["read"], "resources": crm, "budget": {"USD": 0}}},
    {"cap": {"actions": ["rea*"], "resources": crm}}, {"cap": {"actions": ["read*"], "resources": crm}}, {"cap": {"actions": [], "resources": []}},
    {"cap": {}}, {"cap": {"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["pii"], "budget": {"EUR": 100}}},
    {"cap": "x"}, {"cap": {"x": 1}}, {"cap": None}, {"task": "t-1"}, {"role": "auditor"}, {"role": ""}, {"role": 5}, {"task": 5},
]:
    steps += [exchange("x", **kw), call("inspect_token", token="$x"), authz(tok="$x"), flt(REC, tok="$x"),
              exchange("y", subject_token="$x", actor="summarizer", ttl=30,
                       cap={"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["pii"]}),
              flt(REC, tok="$y")]
steps += [
    call("inspect_token", token="$t", now=1700000899), call("inspect_token", token="$t", now=1700000900),
    call("inspect_token", token="$t", now=1699999940), call("inspect_token", token="$t", now=1699999939),
    authz(now=1700000900), authz(tok="$t3", now=1699999000), exchange(now=1700009999),
    call("revoke", token_id="$t2_id", by="admin"), authz(tok="$t3"), authz(tok="$t2"), authz(), call("inspect_token", token="$t3"),
    exchange(subject_token="$t3", actor="summarizer"), call("revoke"), call("revoke", token_id=5), call("revoke", token="$t", by=5), authz(),
    call("revoke", token_id="never-issued"), call("audit_tail", n=5), call("audit_verify"), call("approvals"),
]
case("delegation, expiry and revocation", steps)

# ---- approval --------------------------------------------------------------------
big = {"spend": {"currency": "EUR", "amount": 15000}}
note = {"order_id": "o", "amount": 15000, "internal_note": "x"}
held = {"op": "authorize", "input": {"token": "$t", "action": "create", "resource": REFUND, "context": big}, "save": {"aid": "approval.id"}}
held2 = {"op": "filter", "input": {"token": "$t", "action": "create", "resource": REFUND, "context": big, "data": note, "strict": True},
         "save": {"aid2": "approval.id"}}
steps = [
    issue(), authz(action="create", res=REFUND, context=big, dry_run=True), call("approvals"), held, call("approvals"),
    call("approve", approval_id="$aid", by="alice"), call("approve", approval_id="$aid", by="carol"),
    call("approve", approval_id="$aid", by="nobody"), call("approve", approval_id="$aid"), call("approve", by="bob"),
    call("approve", approval_id="nope", by="bob"), call("approve", approval_id=5, by="bob"),
    call("approve", approval_id="$aid", by="bob", ttl=10), call("approvals"), call("approve", approval_id="$aid", by="bob"),
    authz(action="create", res=REFUND, context=big, dry_run=True, explain=True), authz(action="create", res=REFUND, context=big, now=1700000010),
    authz(action="create", res=REFUND, context=big), authz(action="create", res=REFUND, context=big), call("approvals"),
    held2, call("approve", approval_id="$aid2", by="bob", ttl=-5), authz(action="create", res=REFUND, context=big),
    call("approve", approval_id="$aid2", by="bob"), {"op": "filter", "input": dict(held2["input"])},
    authz(action="create", res=REFUND, context=big), authz(action="create", res=REFUND, context=big),
    authz(action="create", res=REFUND, context={"spend": {"currency": "EUR", "amount": 15000}, "note": "\U0001F600\u0001\u2028\"\\\u00e9",
                                                 "n": [3, 1, 2], "m": {"b": 1, "a": {"__entity": {"type": "User", "id": "x"}}}}),
    authz(action="create", res={"path": "billing.refund", "id": "\u00e9\U0001F600"}, context=big), call("approvals"),
    call("audit_verify"), call("audit_tail", n=50),
]
case("approval flow", steps)

# ---- spend -----------------------------------------------------------------------
refunds = {"actions": ["create"], "resources": ["billing.refund/*"]}
steps = [
    issue(), exchange("h", cap=dict(refunds, budget={"EUR": 12000})), exchange("h2", cap=dict(refunds, budget={"EUR": 12000})),
    exchange("nb", actor="summarizer", cap=refunds),
    spend(9000, tok="$h"), spend(4000, tok="$h"), spend(3000, tok="$h", dry_run=True), spend(3000, tok="$h", now=1700000100),
    spend(9000, tok="$h2", now=1700000100), spend(8000, tok="$h2", now=1700000100), spend(1, tok="$nb"),
    spend(8001, now=1700000200), spend(8000, now=1700000200), spend(1, now=1700000200), spend(0, now=1700000200),
    spend(0, tok="$h", now=1700000200), call("audit_tail", n=3), call("audit_verify"),
]
case("spend across a delegation tree", steps)

steps = [issue()] + [spend(1, now=1700000000 + k) for k in (0, 1, 2, 3, 59, 60, 61, 62, 63, 64, 121, 122, 200)]
steps += [spend(1, now=1700000201, dry_run=True), spend(1, now=1700000202, explain=True), issue("u", user="erin")]
steps += [spend(1, tok="$u", now=1700000300) for _ in range(5)]
case("rate limit window", steps)

# ---- apply_obligations, audit_tail, odd requests -----------------------------------
OB = {"fields": {"allow": ["id", "n", "addresses", "card"], "deny": ["ssn", "addresses[].geo"], "redact": ["card.number"]}}
rows = [{"n": 1}, {"n": True}, {"n": RAW("1.0")}, {"n": "1"}, {}, {"n": None}, {"n": [1]}, {"n": [True]}, {"n": {"a": 1}},
        {"n": RAW("12345678901234567890123")}, {"n": 0}, {"n": False}]
one = {"n": 1, "id": "a", "ssn": "s", "card": {"number": "4", "x": 1}, "addresses": [{"geo": 1, "s": 2}]}
steps = []
for rf in [
    OMIT, [], [{"column": "n", "op": "eq", "value": 1}], [{"column": "n", "value": True}], [{"column": "n", "value": RAW("1.0")}],
    [{"column": "n"}], [{"value": 1}], [{"column": "n", "value": [1]}], [{"column": "n", "value": {"a": 1}}],
    [{"column": "n", "value": RAW("12345678901234567890123")}], [{"column": "n", "value": 0}], [{"column": 5, "value": 1}],
    [{"column": None, "value": 1}], ["x", 5, {"column": "n", "value": "1"}], "x", {"column": "n", "value": 1},
    [{"column": "n", "value": 1}, {"column": "id", "value": "a"}], [{"column": "n", "value": RAW("-0.0")}],
]:
    ob = dict(OB)
    if rf != OMIT:
        ob["row_filter"] = rf
    steps += [call("apply_obligations", obligations=ob, data=rows), call("apply_obligations", obligations=ob, data=one)]
paths = {"fields": {"allow": ["a", "a.b", "a[]", "a[].c"], "deny": ["a.d", "a[].e"], "redact": ["a.f", "a[].g", "h[]", "k"]}}
for ob in [OMIT, None, "x", [], {}, {"fields": None}, {"fields": []}, {"fields": {}}, {"fields": {"allow": "id", "deny": None, "redact": 5}},
           {"fields": {"allow": ["id", 5, None, "id"], "deny": ["id"], "redact": ["id"]}}, paths]:
    for d in [OMIT, {"id": 1, "x": 2, "a": {"b": 1, "d": 2, "f": 3, "z": 4}, "h": [1, 2], "k": {"deep": 1}},
              [{"id": 1, "a": [{"c": 1, "e": 2, "g": 3, "z": 4}, 5, [{"c": 1, "e": 2}]]}], 5, None]:
        steps.append({"op": "apply_obligations", "input": clean({"obligations": ob, "data": d, "decision_id": "d-test"})})
steps += [call("apply_obligations", obligations=OB, data={"id": 1}, decision_id=5),
          call("apply_obligations", obligations=OB, data={"id": 1}, decision_id=""), call("audit_tail", n=3)]
for n in [0, -1, 2, "x", RAW("1.5"), True, RAW("99999999999999999999"), RAW("-99999999999999999999"), None, OMIT]:
    steps.append({"op": "audit_tail", "input": clean({"n": n})})
steps += [call("audit_verify"), call("nonsense"), call(""), {"op": "info", "input": []}, {"op": "info", "input": None},
          {"op": "info", "input": "s"}, {"op": "info", "input": 5}, call("authorize"), call("filter"), call("explain"), call("issue_token"),
          call("exchange_token"), call("inspect_token"), call("apply_obligations"), call("revoke"), call("approve"), call("approvals", x=1),
          call("AUTHORIZE")]
case("apply_obligations, audit_tail and odd requests", steps)

# ---- caller-supplied chains --------------------------------------------------------
chains = [
    {"user": "alice", "agents": ["support-bot"]}, {"user": "alice", "agents": []}, {"user": "alice", "agents": "support-bot"},
    {"user": "alice", "agents": [5, "support-bot", None, "refund-helper"]}, "str", [], 5, False, {}, {"agents": ["support-bot"]},
    {"user": 5, "agents": ["support-bot"]}, {"user": "carol", "agents": ["support-bot", "summarizer"], "tenant": "t1", "task": "k", "role": "auditor"},
    {"user": "dave", "agents": ["support-bot"], "groups": ["support"]}, {"user": "alice", "agents": ["support-bot"], "groups": []},
    {"user": "alice", "agents": ["support-bot"], "groups": 5},
    {"user": "alice", "agents": ["support-bot"], "groups": [{"type": "Group", "id": "compliance"}], "role": 5, "tenant": 5},
    {"user": "alice", "agents": ["ghost"]}, {"user": "zed", "agents": ["support-bot"]},
]
customer = {"path": "crm.customer", "id": "c-1"}
steps = [issue()]
for ch in chains:
    for extra in [{}, {"action": "create", "resource": REFUND, "context": {"spend": {"currency": "EUR", "amount": 5}}}, {"action": "delete"},
                  {"resource": {"path": "crm.customer", "id": "c-1", "attrs": {"tenant": "t2"}}}]:
        i = {"chain": ch, "action": "read", "resource": customer}
        i.update(extra)
        steps += [{"op": "authorize", "input": i}, {"op": "filter", "input": dict(i, data=REC)}, {"op": "explain", "input": dict(i, data=[REC])}]
    steps += [call("authorize", token="$t", chain=ch, action="read", resource=customer),
              call("authorize", token="", chain=ch, action="read", resource=customer)]
steps.append(call("audit_tail", n=10))
case("caller-supplied chains, trusted", steps, {"trust_caller_chain": True})
case("caller-supplied chains, not trusted", steps)
case("caller-supplied chains, trusted, shadow, no audit", steps, {"trust_caller_chain": True, "mode": "shadow", "audit": False})

# ---- offboarding: revoke by user ---------------------------------------------------
T0 = 1700000000
steps = [issue(now=T0, task="ticket-1"), exchange("c", now=T0), issue("b", user="bob", now=T0), issue("late", now=T0 + 10),
         call("revoke", user="alice", by="hr", now=T0 + 5), authz(now=T0 + 6), authz(tok="$c", now=T0 + 6), authz(tok="$b", now=T0 + 6), authz(tok="$late", now=T0 + 11),
         flt({"id": "c-1", "region": "EU"}, now=T0 + 6), call("inspect_token", token="$t", now=T0 + 6), call("inspect_token", token="$late", now=T0 + 11),
         exchange(now=T0 + 6), exchange(subject_token="$late", now=T0 + 11), call("revoke", token="$t", now=T0 + 6),
         issue("same", now=T0 + 5), authz(tok="$same", now=T0 + 6), issue("after", now=T0 + 6), authz(tok="$after", now=T0 + 7),
         authz(now=T0 + 99999), authz(now=T0 - 99999),
         call("revoke", user="alice", token="$after", token_id="x", now=T0 + 3), authz(tok="$after", now=T0 + 7), authz(tok="$late", now=T0 + 11),
         call("revoke", user="alice", now=T0 + 20), authz(tok="$after", now=T0 + 21), authz(tok="$late", now=T0 + 21),
         call("revoke", user="\u00e5lice \U0001F600", now=T0), call("revoke", user="nobody"), call("approvals"), call("audit_tail", n=8), call("audit_verify"), call("info")]
for u in ["", 5, None, ["alice"], {"id": "alice"}, True, 0, False, 1.5]:
    steps += [call("revoke", user=u, now=T0 + 30), call("revoke", user=u, token_id="tid-1", now=T0 + 30), call("revoke", user=u, token="$b", by=5, now=T0 + 30)]
steps += [authz(tok="$b", now=T0 + 31), call("revoke", by="x"), call("revoke", user="bob", by=["x"], now=T0 + 40), authz(tok="$b", now=T0 + 41), call("audit_tail", n=40)]
case("offboarding: revoke by user", steps)
case("offboarding in shadow mode, no state directory", steps[:14], {"mode": "shadow", "state_dir": None})

# ---- the rest ----------------------------------------------------------------------
case("line separators inside audit records",
     [issue(task="a\u2028b"), issue(task="a\u0085b\u001fc\u007f"), issue(user="erin", tenant="t\u2029", task="x\ry"), authz(),
      call("audit_tail", n=10), call("audit_verify"), issue(), authz(), call("audit_tail", n=2)])
case("engine limits from config",
     [issue(ttl=5000), issue(ttl=OMIT), exchange("a", ttl=50), exchange(subject_token="$a", actor="summarizer", ttl=50),
      call("revoke", token_id="x"), call("approvals"), call("info")],
     {"max_ttl": 120, "default_ttl": 7, "max_depth": 2, "approval_ttl": 5, "issuer": "smartdelegate://other", "mode": "enforce"})
case("verify-only engine", [issue(), call("info"), authz(tok="x.y.z")], {"verify_only": True})
case("no state directory",
     [issue(), authz(), call("audit_verify"), call("audit_tail"), call("approvals"), spend(9000), spend(9000), spend(9000),
      call("revoke", token="$t"), authz()], {"state_dir": None})

text = json.dumps({"cases": cases}, ensure_ascii=False, separators=(",", ":"))
text = re.sub(r'\{"__raw__":("(?:[^"\\]|\\.)*")\}', lambda m: json.loads(m.group(1)), text)
sys.stdout.reconfigure(encoding="utf-8")
sys.stdout.write(text + "\n")
