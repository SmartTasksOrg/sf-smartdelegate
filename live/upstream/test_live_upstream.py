"""The enforcement points against a real upstream: PostgreSQL 16, a REST
service on top of it in a process of its own, and an MCP server on the same
database.

    cd <repo> && python3 -m unittest -v live.upstream.test_live_upstream

Every expectation about data is computed without the engine: the rows come
from the test's own SQL, and what a role may see comes from
live/upstream/oracle.py (catalog labels, role deny lists, the business rules).
The HTTP-proxy and MCP-proxy cases run once against the Python reference and
once against the Rust port; SD_LIVE_IMPLS=python (or rust) limits that.

A test that exposes a defect is kept, marked `@finding("L-n")` (an expected
failure) and described in live/FINDINGS.md with its reproduction. If the
product is fixed the test reports an unexpected success, which is the cue to
remove the mark.
"""
from __future__ import annotations

import json
import os
import random
import re
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from .oracle import CARD, IBAN, NATIONAL_ID, REDACTED, TAX_ID, Oracle
from .shapes import RESOURCES, shape
from .stack import COMPANY, ROOT, TENANT, Stack, Unavailable, cli_of, die_with_parent, http_request, pg_log_path, record_pid, stop_process

IMPLS = [x for x in os.environ.get("SD_LIVE_IMPLS", "python,rust").split(",") if x]
FULL = os.environ.get("SD_LIVE_FULL") == "1"
#: behaviour worth comparing between the two proxies: {key: {impl: value}}
OBSERVED: dict = {}
ORACLE = Oracle()
#: user -> role used in the cases; the unit's orchestrator is the agent
#: resources whose routes need the region (stated by the agent on list routes: a claim, see spec/API.md)
REGIONAL = ("customers", "tickets", "refunds", "opportunities", "contracts")
PEOPLE = {"anna": "support-agent", "chloe": "support-agent", "ben": "support-agent", "elena": "support-supervisor", "gina": "ap-clerk",
          "karin": "treasury", "liam": "payroll-officer", "maya": "hr-partner", "oskar": "hr-manager", "petra": "sales-rep", "quinn": "sales-rep",
          "sofia": "sales-manager", "uma": "buyer", "yara": "it-operator", "carla": "auditor"}


_CARDS: set = set()


def cards_in(blob: bytes) -> list:
    """Card numbers of the seeded data found in `blob`. The pattern alone is not enough: sixteen decimal
    digits starting 4929 also turn up, now and then, inside a hexadecimal hash or decision id."""
    if not _CARDS:
        from . import seed
        _CARDS.update(row[10].encode() for row in seed.generate()["customers"][1])
    return [m for m in CARD.findall(blob) if m in _CARDS]


def finding(fid: str):
    """An expected failure tied to an entry of live/FINDINGS.md."""
    def mark(fn):
        fn.__doc__ = f"[known defect {fid}, see live/FINDINGS.md] " + (fn.__doc__ or "")
        fn.finding = fid
        return unittest.expectedFailure(fn)
    return mark


def observe(key: str, impl: str, value) -> None:
    OBSERVED.setdefault(key, {})[impl] = value


def statement_shape(sql: str) -> str:
    """A logged statement with its literals removed: what the query *is*, whatever the values."""
    s = re.sub(r"'(?:[^']|'')*'", "?", sql)
    s = re.sub(r"\b\d+\b", "?", s)
    return re.sub(r"\s+", " ", s).strip()


class PgLog:
    """Reads the statements PostgreSQL logged since a mark (log_statement=all on the private cluster)."""

    def __init__(self):
        self.path = pg_log_path()

    def mark(self) -> int:
        return self.path.stat().st_size if self.path else 0

    def statements(self, since: int) -> list:
        if not self.path:
            return []
        with open(self.path, "rb") as f:
            f.seek(since)
            text = f.read().decode("utf-8", "replace")
        out, cur = [], None
        for line in text.split("\n"):
            m = re.search(r" LOG:  (?:statement|execute [^:]*): (.*)$", line)
            if m:
                cur = [m.group(1)]
                out.append(cur)
            elif cur is not None and line.startswith("\t"):
                cur.append(line.strip())
            else:
                cur = None
        # the test's own look at the request log is not something an enforcement point sent
        return [s for s in (" ".join(x) for x in out) if not re.match(r"select (n,|coalesce\(max\(n\))", s)]


class LiveCase(unittest.TestCase):
    """A stack per class, tokens per user, and a record of everything an agent received."""
    impl = "python"
    stack: Stack
    maxDiff = 2000

    @classmethod
    def setUpClass(cls):
        if cls.impl not in IMPLS:
            raise unittest.SkipTest(f"{cls.impl} is not in SD_LIVE_IMPLS")
        try:
            cls.stack = Stack(cls.impl, reseed=True)
        except Unavailable as e:
            raise unittest.SkipTest(str(e)) from None
        cls.seen = []            # bytes: everything any agent received through an enforcement point
        cls._tokens = {}
        cls.pglog = PgLog()
        cls.base = cls.stack.proxy_url + "/company"

    @classmethod
    def tearDownClass(cls):
        st = getattr(cls, "stack", None)
        if st is not None:
            st.close()

    # ---- tokens
    @classmethod
    def grant(cls, user: str, role: str | None = None, fresh: bool = False, suffix: str = "live") -> dict:
        role = role or PEOPLE[user]
        key = (user, role)
        g = cls._tokens.get(key)
        if fresh or g is None or g["expires_at"] - time.time() < 120:
            g = cls.stack.issue(user, role, ORACLE.task(role, suffix))
            if not fresh:
                cls._tokens[key] = g
        return g

    @classmethod
    def token(cls, user: str, role: str | None = None) -> str:
        return cls.grant(user, role)["token"]

    # ---- the agent's side
    def call(self, method: str, path: str, user: str | None = None, *, token: str | None = None, body=None, headers=None, timeout: float = 60.0, base: str | None = None):
        r = http_request(method, (base or self.base) + path, token=token or (self.token(user) if user else None), body=body, headers=headers, timeout=timeout)
        type(self).seen.append(r.everything())
        return r

    def rq(self, region: str, extra: str = "") -> str:
        """The query of a call on one record. Routes in the form of spec/API.md take the record's region from
        the upstream (`lookup`), so the agent states nothing; the form used before reads it from `?region=`."""
        return f"?{extra}" if extra else ""

    def writes(self, since: int) -> list:
        """What reached the upstream other than reads (a `lookup` is a GET made with the proxy's own credential)."""
        return [x for x in self.api_log(since) if x["method"] != "GET"]

    def api_log(self, since: int = 0) -> list:
        return self.stack.sql("select n, method, path, query, status, key_ok, had_authorization, header_names from api_request_log where n > %s order by n", (since,))

    def api_mark(self) -> int:
        return self.stack.sql("select coalesce(max(n), 0) as n from api_request_log")[0]["n"]

    def rows(self, resource: str, where: str = "", params: tuple = (), tenant: str = TENANT) -> list:
        table, _, key = RESOURCES[resource]
        return self.stack.sql(f"select * from {table} where tenant = %s {('and ' + where) if where else ''} order by {key}", (tenant, *params))

    def expected_list(self, resource: str, user: str, limit: int, offset: int = 0, role: str | None = None, agent: str | None = None, depth: int = 1) -> list:
        """What a list call must return: the upstream's page (every region), minus the rows and fields this role may not have."""
        role = role or PEOPLE[user]
        table, path, key = RESOURCES[resource]
        page = self.stack.sql(f"select * from {table} where tenant = %s order by {key} limit %s offset %s", (TENANT, limit, offset))
        out = []
        for row in page:
            if ORACLE.row_filtered(path, role) and row["region"] != ORACLE.region(user):
                continue
            out.append(ORACLE.view(path, shape(resource, row), role, agent=agent, depth=depth))
        return json.loads(json.dumps(out, default=str))


class HttpProxyCases:
    """`smartdelegate http-proxy` in front of company-api, holding its key."""

    # ------------------------------------------------------------------ fields
    def test_01_only_permitted_fields_arrive_for_every_role_and_resource(self):
        checked = 0
        for user, role in sorted(PEOPLE.items()):
            for resource, (_, path, _) in RESOURCES.items():
                region = ORACLE.region(user)
                q = f"?region={region}&limit=120" if resource in REGIONAL else "?limit=120"
                r = self.call("GET", f"/{TENANT}/{resource}{q}", user)
                if not ORACLE.may(role, "read", path):
                    self.assertEqual(r.status, 403, f"{user}/{role} must not read {path}: {r.raw[:200]}")
                    continue
                self.assertEqual(r.status, 200, f"{user}/{role} reads {path}: {r.raw[:300]}")
                body = r.json
                self.assertEqual(sorted(body), ["items", "next"], "only the record list and the keys the route keeps survive the envelope")
                want = self.expected_list(resource, user, 120)
                self.assertEqual(len(body["items"]), len(want), f"{user}/{role} {path}: row count")
                for got, exp in zip(body["items"], want):
                    self.assertEqual(got, exp, f"{user}/{role} {path} record {exp.get('id') or exp.get('employee_id')}")
                checked += len(want)
        self.assertGreater(checked, 3000)
        observe("records compared field by field (15 role tokens x 11 resources)", self.impl, checked)

    def test_02_single_records_are_masked_like_the_catalog_and_the_role_say(self):
        eu = self.rows("customers", "region = 'EU'")[0]
        for user in ("anna", "petra", "sofia", "carla"):
            r = self.call("GET", f"/{TENANT}/customers/{eu['id']}{self.rq('EU')}", user)
            self.assertEqual(r.status, 200, r.raw[:200])
            self.assertEqual(r.json, json.loads(json.dumps(ORACLE.view("crm.customer", shape("customers", eu), PEOPLE[user]))))
            self.assertEqual(r.json["card"]["number"], REDACTED)
        vendor = self.rows("vendors")[0]
        got = {u: self.call("GET", f"/{TENANT}/vendors/{vendor['id']}", u).json for u in ("karin", "gina", "uma", "carla")}
        self.assertEqual(got["karin"]["bank"], {"bic": vendor["bank_bic"], "iban": vendor["bank_iban"]}, "treasury is the one role that sees bank details")
        self.assertEqual(got["karin"]["tax_id"], vendor["tax_id"])
        for u in ("gina", "uma", "carla"):
            self.assertEqual(got[u]["bank"], {"iban": REDACTED}, u)
            self.assertNotIn("tax_id", got[u])
        emp = self.rows("employees", "id = 'anna'")[0]
        views = {u: self.call("GET", f"/{TENANT}/employees/anna", u).json for u in ("oskar", "maya", "liam", "yara", "carla")}
        self.assertEqual(views["oskar"]["national_id"], emp["national_id"])
        self.assertEqual(views["oskar"]["bank_account"], REDACTED)
        self.assertEqual(sorted(views["liam"]), ["bank_account", "id", "job_title", "name", "national_id", "region", "start_date", "status", "unit"])
        self.assertEqual((views["liam"]["bank_account"], views["liam"]["national_id"]), (REDACTED, REDACTED))
        self.assertEqual(sorted(k for k, v in views["yara"].items() if v != REDACTED), ["email", "id", "job_title", "manager", "name", "region", "start_date", "status", "unit"])
        for u, v in views.items():
            self.assertEqual(v, json.loads(json.dumps(ORACLE.view("hr.employee", shape("employees", emp), PEOPLE[u]))), u)
        sal = self.rows("salaries", "employee_id = 'anna'")[0]
        self.assertEqual(self.call("GET", f"/{TENANT}/salaries/anna", "oskar").json["base"], sal["base"])
        self.assertEqual(self.call("GET", f"/{TENANT}/salaries/anna", "liam").json, {"employee_id": "anna", "currency": sal["currency"], "grade": sal["grade"], "base": sal["base"], "bonus": sal["bonus"]})
        self.assertEqual(self.call("GET", f"/{TENANT}/salaries/anna", "maya").status, 403)
        self.assertEqual(self.call("GET", f"/{TENANT}/salaries/anna", "carla").json, {"employee_id": "anna", "currency": sal["currency"], "grade": sal["grade"]})

    def test_03_a_sub_agent_receives_less_than_the_agent_that_started_it(self):
        parent = self.grant("anna", fresh=True, suffix="sub")
        child = self.stack.admin("exchange_token", {"subject_token": parent["token"], "actor": "ticket-triager", "ttl": 300})
        self.assertTrue(child.get("ok"), child)
        r = self.call("GET", f"/{TENANT}/customers?region=EU&limit=60", token=child["token"])
        self.assertEqual(r.status, 200, r.raw[:200])
        want = self.expected_list("customers", "anna", 60, agent="ticket-triager", depth=2)
        self.assertEqual(r.json["items"], want)
        self.assertTrue(all("notes" not in c and all("geo" not in a for a in c["addresses"]) for c in r.json["items"]), "internal fields stop at the agent the human started")
        r = self.call("PATCH", f"/{TENANT}/customers/{want[0]['id']}{self.rq('EU')}", token=child["token"], body={"phone": "+1 000"})
        self.assertEqual((r.status, r.code), (403, "no_matching_permit"), "only the orchestrator updates a customer")

    # -------------------------------------------------------------- row filters
    def test_04_row_filter_by_region_holds_on_whole_tables(self):
        for user in ("anna", "chloe", "petra"):
            region = ORACLE.region(user)
            for resource in (("customers", "tickets") if PEOPLE[user].startswith("support") else ("customers",)):
                table = RESOURCES[resource][0]
                counts = {r["region"]: r["n"] for r in self.stack.sql(f"select region, count(*) as n from {table} where tenant = %s group by region", (TENANT,))}
                r = self.call("GET", f"/{TENANT}/{resource}?region={region}&limit=10000", user, timeout=120)
                self.assertEqual(r.status, 200)
                items = r.json["items"]
                self.assertEqual({i["region"] for i in items}, {region})
                self.assertEqual(len(items), counts[region], f"{user} {resource}: SQL says {counts}, {len(items)} rows arrived")
                ids = {row["id"] for row in self.stack.sql(f"select id from {table} where tenant = %s and region = %s", (TENANT, region))}
                self.assertEqual({i["id"] for i in items}, ids)
                self.assertEqual(int(r.header("X-SmartDelegate-Masked") or -1) >= 1, True)
                observe(f"rows of {resource} for a {region} {PEOPLE[user]} / rows of the tenant in SQL", self.impl, f"{len(items)}/{sum(counts.values())}")
        # the auditor is not regional: every row of the tenant, and none of another tenant
        r = self.call("GET", f"/{TENANT}/customers?region=EU&limit=10000", "carla", timeout=120)
        total = self.stack.sql("select count(*) as n from customers where tenant = %s", (TENANT,))[0]["n"]
        self.assertEqual(len(r.json["items"]), total)
        other = {row["id"] for row in self.stack.sql("select id from customers where tenant <> %s", (TENANT,))}
        self.assertFalse(other & {i["id"] for i in r.json["items"]})

    def test_05_wrong_region_missing_region_other_tenant(self):
        us = self.rows("customers", "region = 'US'")[0]
        mark = self.api_mark()
        r = self.call("GET", f"/{TENANT}/customers?region=US&limit=5", "anna")
        self.assertEqual((r.status, r.code), (403, "policy_forbid"))
        r = self.call("GET", f"/{TENANT}/customers?limit=5", "anna")
        self.assertEqual(r.status, 400, "the route needs the region to decide; without it nothing is forwarded")
        r = self.call("GET", f"/osprey/customers?region=EU&limit=5", "anna")
        self.assertEqual((r.status, r.code), (403, "tenant_mismatch"))
        r = self.call("GET", f"/osprey/customers?region=EU&limit=5", "carla")
        self.assertEqual((r.status, r.code), (403, "tenant_mismatch"), "not even the auditor crosses tenants")
        self.assertEqual(self.api_log(mark), [], "none of these reached the upstream")
        us_ticket = self.rows("tickets", "region = 'US'")[0]
        for path, rid in (("customers", us["id"]), ("tickets", us_ticket["id"])):
            mark = self.api_mark()
            r = self.call("GET", f"/{TENANT}/{path}/{rid}{self.rq('EU')}", "anna")
            # the region is the record's own: refused, after one read made with the proxy's credential
            self.assertEqual((r.status, r.code), (403, "policy_forbid"))
            self.assertEqual([(x["method"], x["key_ok"]) for x in self.api_log(mark)], [("GET", True)])
            self.assertNotIn(us["email"].encode(), r.raw)
        if True:
            # another tenant: refused before anything is looked up, the same for an id that exists and one that does not
            other = self.rows("customers", tenant="osprey")[0]
            mark = self.api_mark()
            for rid in (other["id"], "c-99999"):
                for user in ("anna", "carla"):
                    r = self.call("GET", f"/osprey/customers/{rid}", user)
                    self.assertEqual((r.status, r.code), (403, "tenant_mismatch"), rid)
            self.assertEqual(self.api_log(mark), [])
            # inside the tenant a record that does not exist is a plain 404, with nothing of the upstream's body
            r = self.call("GET", f"/{TENANT}/customers/c-99999", "anna")
            self.assertEqual((r.status, r.code), (404, "not_found"))

    def test_06_a_refund_of_another_region_does_not_reach_a_regional_agent(self):
        """README rule 9: support works refunds of its own region only. (Finding L-1: with the region
        taken from the request this leaked. The route now takes it from the record.)"""
        us = self.rows("refunds", "region = 'US'")[0]
        r = self.call("GET", f"/{TENANT}/refunds/{us['id']}{self.rq('EU')}", "anna")
        observe("L-1: an EU support agent asks for a US refund by id", self.impl, f"{r.status} {r.code or 'the refund'}")
        self.assertFalse(r.status == 200 and isinstance(r.json, dict) and r.json.get("region") == "US", f"an EU support agent read the US refund {us['id']}")
        self.assertEqual((r.status, r.code), (403, "policy_forbid"))
        eu = self.rows("refunds", "region = 'EU'")[0]
        r = self.call("GET", f"/{TENANT}/refunds/{eu['id']}{self.rq('EU')}", "anna")
        self.assertEqual(r.json, json.loads(json.dumps(ORACLE.view("billing.refund", shape("refunds", eu), "support-agent"))))

    def test_06b_lists_of_regional_resources_hold_the_agents_own_region_only(self):
        """(Finding L-1b: the refund, contract and opportunity permits had no row filter, so a list route,
        where the region can only be a claim, returned every region. The company bundle now has them.)"""
        for user, resources in (("anna", ("refunds",)), ("chloe", ("refunds",)), ("petra", ("opportunities", "contracts")), ("quinn", ("opportunities", "contracts"))):
            region = ORACLE.region(user)
            for resource in resources:
                table = RESOURCES[resource][0]
                r = self.call("GET", f"/{TENANT}/{resource}?region={region}&limit=10000", user, timeout=120)
                items = (r.json or {}).get("items") or []
                n = self.stack.sql(f"select count(*) as n from {table} where tenant = %s and region = %s", (TENANT, region))[0]["n"]
                observe(f"L-1b: regions in the list of {resource} for a {region} {PEOPLE[user]}", self.impl, sorted({i["region"] for i in items}))
                self.assertEqual({i["region"] for i in items}, {region}, f"{user} {resource}")
                self.assertEqual(len(items), n)
        # the claim itself is still only a claim: stating another region is refused by the policy, stating one's own shows one's own
        self.assertEqual(self.call("GET", f"/{TENANT}/refunds?region=US&limit=5", "anna").code, "policy_forbid")
        # finance is not regional: every region of the tenant, and nothing of another tenant
        r = self.call("GET", f"/{TENANT}/refunds?region=EU&limit=10000", "gina", timeout=120)
        self.assertEqual(len(r.json["items"]), self.stack.sql("select count(*) as n from refunds where tenant = %s", (TENANT,))[0]["n"])

    def test_06c_the_tenant_always_comes_from_the_route(self):
        """No policy filters rows by tenant: the tenant is the path segment the upstream is asked about, and every
        route (and every tool mapping) states it as a fixed attribute, so the engine's tenant check always runs."""
        here = Path(__file__).parent
        routes = json.loads((here / "routes.json").read_text(encoding="utf-8"))["routes"]
        self.assertEqual([r["path"] for r in routes if r.get("attrs", {}).get("tenant") != "{tenant}" or not r["path"].startswith("/{tenant}/")], [])
        self.assertEqual([r["path"] for r in routes if "tenant" in {**r.get("attrs_from_request", {}), **r.get("attrs_from_record", {})}], [])
        tools = json.loads((here / "mcp_tools.json").read_text(encoding="utf-8"))["tools"]
        self.assertEqual([n for n, m in tools.items() if m.get("attrs", {}).get("tenant") != TENANT], [])
        other = {r["id"] for r in self.stack.sql("select id from refunds where tenant <> %s", (TENANT,))}
        for user in ("anna", "gina", "carla"):
            r = self.call("GET", f"/{TENANT}/refunds?region={ORACLE.region(user)}&limit=10000", user, timeout=120)
            self.assertFalse(other & {i["id"] for i in r.json["items"]}, user)
            self.assertEqual(self.call("GET", f"/osprey/refunds?region={ORACLE.region(user)}&limit=5", user).code, "tenant_mismatch")

    # ------------------------------------------------------------------- writes
    def test_07_a_write_with_a_forbidden_field_is_refused_and_the_row_is_unchanged(self):
        row = self.rows("customers", "region = 'EU'")[3]
        url = f"/{TENANT}/customers/{row['id']}?region=EU"
        for body, why in (({"tier": "platinum"}, "tier is not a contact field"),
                          ({"phone": "+32 1", "notes": "vip"}, "one forbidden field poisons the whole write"),
                          ({"ssn": "1"}, "a field the catalog does not list"),
                          ({"addresses": [{"street": "1 A St", "geo": {"lat": 1, "lng": 2}}]}, "a forbidden field nested inside a permitted one"),
                          ({"card": {"number": "4929000000000000"}}, "card numbers: nobody")):
            mark = self.api_mark()
            r = self.call("PATCH", url, "anna", body=body)
            self.assertEqual((r.status, r.code), (403, "field_denied"), f"{why}: {r.raw[:200]}")
            self.assertEqual(self.writes(mark), [], f"{why}: the upstream must not see the write")
            self.assertEqual(self.rows("customers", "id = %s", (row["id"],))[0], row, why)
        mark = self.api_mark()
        r = self.call("PATCH", url, "anna", body={"phone": "+32 2 555 0199", "addresses": [{"street": "9 New St", "city": "Ghent", "zip": "9000"}]})
        self.assertEqual(r.status, 200, r.raw[:300])
        after = self.rows("customers", "id = %s", (row["id"],))[0]
        self.assertEqual((after["phone"], after["addresses"]), ("+32 2 555 0199", [{"street": "9 New St", "city": "Ghent", "zip": "9000"}]))
        self.assertEqual({k: v for k, v in after.items() if k not in ("phone", "addresses")}, {k: v for k, v in row.items() if k not in ("phone", "addresses")})
        # the echo is masked with the *update* permissions: contact fields only
        self.assertEqual(r.json, {"email": row["email"], "phone": "+32 2 555 0199", "addresses": after["addresses"], "card": {"number": REDACTED}})
        log = self.writes(mark)
        self.assertEqual([(x["method"], x["path"], x["query"], x["key_ok"], x["had_authorization"]) for x in log], [("PATCH", f"/{TENANT}/customers/{row['id']}", "region=EU", True, False)])
        # roles without the permission, and the one role with it, on a vendor's bank details
        v = self.rows("vendors")[5]
        for user in ("gina", "uma", "carla"):
            r = self.call("PATCH", f"/{TENANT}/vendors/{v['id']}", user, body={"bank": {"iban": "DE00KEST00000000000001"}})
            self.assertEqual(r.status, 403, f"{user}: {r.raw[:200]}")
        self.assertEqual(self.rows("vendors", "id = %s", (v["id"],))[0], v)
        r = self.call("PATCH", f"/{TENANT}/vendors/{v['id']}", "karin", body={"bank": {"iban": "DE00KEST00000000000001", "bic": "KESTDE2X"}})
        self.assertEqual(r.status, 200, r.raw[:300])
        self.assertEqual(self.rows("vendors", "id = %s", (v["id"],))[0]["bank_iban"], "DE00KEST00000000000001")

    def test_08_a_regional_agent_cannot_change_a_record_of_another_region(self):
        """The upstream endpoint does no check of its own (most do not). (Finding L-1: the region the
        policy judged used to be the one in the query string, written by the agent.)"""
        us = self.rows("customers", "region = 'US'")[1]
        mark = self.api_mark()
        r = self.call("PATCH", f"/{TENANT}/legacy/customers/{us['id']}{self.rq('EU')}", "anna", body={"phone": "+00 L-1"})
        after = self.rows("customers", "id = %s", (us["id"],))[0]
        observe("L-1: PATCH of a US customer by an EU agent (upstream without a check of its own)", self.impl, f"{r.status} {r.code or 'written'}")
        if after != us:
            self.stack.sql("update customers set phone = %s where id = %s", (us["phone"], us["id"]))
        self.assertEqual(after, us, "an EU support agent changed a US customer")
        self.assertEqual((r.status, r.code), (403, "policy_forbid"))
        self.assertEqual(self.writes(mark), [])
        # and its own region still works through the same route
        eu = self.rows("customers", "region = 'EU'")[20]
        r = self.call("PATCH", f"/{TENANT}/legacy/customers/{eu['id']}{self.rq('EU')}", "anna", body={"phone": "+32 2 555 0808"})
        self.assertEqual(r.status, 200, r.raw[:200])
        self.assertEqual(self.rows("customers", "id = %s", (eu["id"],))[0]["phone"], "+32 2 555 0808")

    def test_08b_a_route_that_takes_the_region_from_the_request_is_only_as_good_as_the_agents_word(self):
        """The documented risk, kept on purpose: `attrs_from_request` on a write, an upstream that does not
        check. The proxy says so when it starts; the write goes through."""
        us = self.rows("customers", "region = 'US'")[4]
        r = http_request("PATCH", f"{self.stack.proxy_url}/company_claims/{TENANT}/legacy/customers/{us['id']}?region=EU", token=self.token("anna"), body={"phone": "+00 claimed"})
        after = self.rows("customers", "id = %s", (us["id"],))[0]
        self.stack.sql("update customers set phone = %s where id = %s", (us["phone"], us["id"]))
        self.assertEqual((r.status, after["phone"]), (200, "+00 claimed"), "an attribute the agent supplies is a claim")
        log = self.stack.log_text("proxy")
        self.assertIn("(PATCH /company_claims/{tenant}/legacy/customers/{id}) trusts request-supplied attributes: region", log)
        self.assertNotIn("(PATCH /company/{tenant}/legacy/customers/{id}) trusts", log)
        self.assertEqual(log.count("is a list route decided on request-supplied attributes"), 5)

    def test_09_a_repeated_query_parameter_cannot_split_the_proxy_and_the_upstream(self):
        """The upstream checks the stated region against the record (409 otherwise) and, like most
        frameworks, reads the first `region`. (Finding L-2: the proxy used to decide on the last one
        and forward both.)"""
        us = self.rows("customers", "region = 'US'")[2]
        mark = self.api_mark()
        for q in ("region=US&region=EU", "region=EU&region=US", "region=EU&region=EU"):
            r = self.call("PATCH", f"/{TENANT}/customers/{us['id']}?{q}", "anna", body={"phone": "+00 L-2"})
            observe(f"L-2: PATCH ?{q} of a US customer by an EU agent", self.impl, f"{r.status} {r.code}")
            self.assertEqual((r.status, r.code), (400, "query_duplicate"), q)
        for q in ("region=EU;region=US", "%72egion=US&region=EU", "region=EU&Region=US", "region=EU&=US", "region=%45U&region=US", "region=EU&region%3DUS", "region=E%ZZ"):
            r = self.call("PATCH", f"/{TENANT}/customers/{us['id']}?{q}", "anna", body={"phone": "+00 L-2"})
            self.assertEqual(r.status, 400, q)
            self.assertIn(r.code, ("query_ambiguous", "query_not_allowed", "query_duplicate"), q)
        self.assertEqual(self.api_log(mark), [], "none of these reached the upstream")
        self.assertEqual(self.rows("customers", "id = %s", (us["id"],))[0], us)
        # the upstream receives the query as the proxy parsed it, not as the agent wrote it
        eu = self.rows("customers", "region = 'EU'")[21]
        mark = self.api_mark()
        r = self.call("PATCH", f"/{TENANT}/customers/{eu['id']}?region=%45%55&&", "anna", body={"phone": "+32 2 555 0909"})
        self.assertEqual(r.status, 200, r.raw[:200])
        self.assertEqual([x["query"] for x in self.writes(mark)], ["region=EU"])
        r = self.call("GET", f"/{TENANT}/customers?limit=2&region=EU&offset=%31", "anna")
        self.assertEqual(r.status, 200)
        self.assertEqual(self.api_log(mark)[-1]["query"], "limit=2&region=EU&offset=1")

    def test_09b_a_chunked_body_cannot_carry_a_second_request_or_an_unchecked_write(self):
        """A request framed with Transfer-Encoding is refused and its connection closed: nothing of it, and
        nothing hidden behind it, reaches the upstream."""
        import socket
        eu = self.rows("customers", "region = 'EU'")[30]
        token = self.token("anna")
        host, port = self.stack.proxy_url.split("//")[1].split(":")
        body = json.dumps({"tier": "platinum", "notes": "smuggled"})
        hidden = f"PATCH /company/{TENANT}/customers/{eu['id']} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
        seen = {}
        for name, framing in (("chunked", "Transfer-Encoding: chunked\r\n"), ("chunked + Content-Length", "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n"),
                              ("two Content-Lengths", f"Content-Length: 0\r\nContent-Length: {len(body)}\r\n")):
            mark = self.api_mark()
            raw = (f"PATCH /company/{TENANT}/customers/{eu['id']} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\n{framing}\r\n"
                   f"{len(body):x}\r\n{body}\r\n0\r\n\r\n{hidden}").encode()
            with socket.create_connection((host, int(port)), timeout=10) as c:
                c.sendall(raw)
                c.settimeout(3)
                out = b""
                try:
                    while True:
                        chunk = c.recv(65536)
                        if not chunk:
                            break
                        out += chunk
                except socket.timeout:
                    pass
            type(self).seen.append(out)
            status = out[9:12].decode("latin-1")
            seen[name] = f"{status}, {out.count(b'HTTP/1.1 ')} response(s), connection {'closed' if b'HTTP/1.1' in out else '?'}"
            seen[name] = f"{status} x{out.count(b'HTTP/1.1 ')}, upstream calls {len(self.api_log(mark))}"
            self.assertEqual(self.rows("customers", "id = %s", (eu["id"],))[0], eu, f"{name}: the row was changed")
        observe("request bodies not framed by one Content-Length: status x responses on the connection", self.impl, seen)
        for name, what in seen.items():
            self.assertRegex(what, r"^(400|411) x1, upstream calls 0$", f"{name}: must be refused, the connection closed, nothing forwarded")

    # ----------------------------------------------------------- spend, approval
    def refund(self, n: int, user: str, amount: int, customer: dict, tag: str) -> dict:
        return {"id": f"r-{self.impl}-{tag}-{n}", "order_id": f"o-{tag}-{n}", "customer_id": customer["id"], "region": customer["region"],
                "amount": amount, "currency": "EUR" if customer["region"] == "EU" else "USD", "reason": "damaged", "requested_by": user}

    def ledger(self, token_id: str) -> dict:
        return self.stack.state().get("ledger", {}).get(token_id, {})

    def test_10_budget_is_enforced_and_the_ledger_equals_the_rows_written(self):
        g = self.grant("anna", fresh=True, suffix="budget")
        cust = self.rows("customers", "region = 'EU'")[7]
        written = []
        for n in range(4):
            body = self.refund(n, "anna", 5000, cust, "budget")
            r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=body)
            self.assertEqual(r.status, 201, r.raw[:300])
            self.assertEqual(r.json, {**{k: v for k, v in body.items()}, "internal_note": "fraud score 0.11"}, "the echo carries no status: support may not set it")
            written.append(body["id"])
        mark = self.api_mark()
        over = self.refund(4, "anna", 100, cust, "budget")
        r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=over)
        self.assertEqual((r.status, r.code), (403, "budget_exceeded"), "200.00 per task: the fifth refund, of 1.00, is over")
        for bad, status in (({**over, "amount": "100"}, 400), ({**over, "amount": 1.5}, 400), ({**over, "amount": -100}, 400), ({**over, "amount": True}, 400),
                            ({k: v for k, v in over.items() if k != "amount"}, 400), ({**over, "currency": "GBP"}, 403)):
            r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=bad)
            self.assertEqual(r.status, status, f"{bad}: {r.raw[:200]}")
        self.assertEqual(self.writes(mark), [])
        rows = self.stack.sql("select id, amount, currency, origin from refunds where id like %s order by id", (f"r-{self.impl}-budget-%",))
        self.assertEqual([x["id"] for x in rows], written)
        if self.stack.state_dir:
            self.assertEqual(self.ledger(g["token_id"]), {"EUR": sum(x["amount"] for x in rows)}, "ledger == what the database holds")
        # accounts payable: a payment within the limit, and separation of duties on the body's own fields
        gp = self.grant("gina", fresh=True, suffix="pay")
        vendor = self.rows("vendors")[0]
        pay = {"id": f"pay-{self.impl}-1", "kind": "po", "ref": "po-00001", "vendor_id": vendor["id"], "amount": 90000, "currency": "EUR", "requested_by": "uma", "approved_by": "wendy"}
        r = self.call("POST", f"/{TENANT}/payments", token=gp["token"], body=pay)
        self.assertEqual(r.status, 201, r.raw[:300])
        self.assertEqual(r.json["beneficiary"], {"name": vendor["name"], "iban": REDACTED})
        for bad in ({**pay, "id": f"pay-{self.impl}-2", "requested_by": "gina"}, {**pay, "id": f"pay-{self.impl}-3", "approved_by": "gina"},
                    {**pay, "id": f"pay-{self.impl}-4", "approved_by": "uma"}, {**pay, "id": f"pay-{self.impl}-5", "kind": "payroll"}):
            r = self.call("POST", f"/{TENANT}/payments", token=gp["token"], body=bad)
            self.assertEqual(r.status, 403, f"{bad}: {r.raw[:200]}")
        paid = self.stack.sql("select id, amount from payments where id like %s", (f"pay-{self.impl}-%",))
        self.assertEqual(paid, [{"id": pay["id"], "amount": 90000}])
        if self.stack.state_dir:
            self.assertEqual(self.ledger(gp["token_id"]), {"EUR": 90000})

    def test_11_a_budget_is_reserved_before_the_upstream_call_and_not_refunded(self):
        """Finding L-3, kept as designed and now documented (spec/API.md): the decision reserves the spend
        before the upstream is called, so that a budget can never be overrun; a write the upstream then
        refuses is not refunded. A reserve/commit/release operation needs an engine change."""
        if not self.stack.state_dir:
            self.skipTest("attached to somebody else's daemon: its ledger cannot be read")
        g = self.grant("anna", fresh=True, suffix="l3")
        cust = self.rows("customers", "region = 'EU'")[8]
        taken = {**self.refund(0, "anna", 5000, cust, "l3"), "id": "r-00001"}      # an id the database already has: 409
        r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=taken)
        self.assertEqual((r.status, r.code), (409, "upstream_error"))
        observe("L-3: ledger after one refund the upstream refused (no row written)", self.impl, self.ledger(g["token_id"]))
        self.assertEqual(self.ledger(g["token_id"]), {"EUR": 5000}, "reserved, not refunded")
        self.assertEqual(self.stack.sql("select origin from refunds where id = 'r-00001'"), [{"origin": "seed"}])
        # what the proxy can see before deciding costs nothing: a refund for a customer that does not exist
        ghost = {**self.refund(1, "anna", 5000, cust, "l3"), "customer_id": "c-does-not-exist"}
        r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=ghost)
        self.assertEqual((r.status, r.code), (404, "not_found"))
        self.assertEqual(self.ledger(g["token_id"]), {"EUR": 5000})
        # and the region the refund is judged on is the customer's, whatever the body says
        us = self.rows("customers", "region = 'US'")[8]
        r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body={**self.refund(2, "anna", 100, us, "l3"), "region": "EU", "currency": "EUR"})
        self.assertEqual((r.status, r.code), (403, "policy_forbid"))
        self.assertEqual(self.stack.sql("select 1 from refunds where id like %s", (f"r-{self.impl}-l3-%",)), [])

    def test_12_an_approval_required_write_reaches_the_database_only_after_approval(self):
        g = self.grant("anna", fresh=True, suffix="approval")
        cust = self.rows("customers", "region = 'EU'")[9]
        body = self.refund(0, "anna", 6000, cust, "approval")
        mark = self.api_mark()
        r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=body)
        self.assertEqual((r.status, r.code), (403, "approval_required"), r.raw[:300])
        aid = r.json["error"]["approval"]["id"]
        self.assertEqual(r.json["error"]["approval"]["label"], "refund-over-50")
        self.assertEqual(self.writes(mark), [])
        self.assertEqual(self.stack.sql("select 1 from refunds where id = %s", (body["id"],)), [], "held: nothing in the database")
        self.assertEqual(self.stack.admin("approve", {"approval_id": aid, "by": "anna"})["error"]["code"], "self_approval")
        self.assertEqual(self.stack.admin("approve", {"approval_id": aid, "by": "gina"})["error"]["code"], "approval_denied")
        r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=body)
        self.assertEqual(r.code, "approval_required", "refused approvals approve nothing")
        self.assertEqual(self.stack.sql("select 1 from refunds where id = %s", (body["id"],)), [])
        self.assertTrue(self.stack.admin("approve", {"approval_id": aid, "by": "elena"}).get("ok"))
        changed = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body={**body, "amount": 7000})
        self.assertEqual(changed.code, "approval_required", "the approval is for the exact request: another amount is a new request")
        r = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=body)
        self.assertEqual(r.status, 201, r.raw[:300])
        self.assertEqual(self.stack.sql("select amount, origin from refunds where id = %s", (body["id"],)), [{"amount": 6000, "origin": "api"}])
        again = self.call("POST", f"/{TENANT}/refunds", token=g["token"], body=body)
        self.assertEqual(again.code, "approval_required", "one approval, one use: the same request again is held again")
        self.assertEqual(self.stack.sql("select count(*) as n from refunds where id like %s", (f"r-{self.impl}-approval-%",))[0]["n"], 1)
        if self.stack.state_dir:
            self.assertEqual(self.ledger(g["token_id"]), {"EUR": 6000})

    # --------------------------------------------------------------- revocation
    def test_13_a_revoked_users_token_stops_at_the_proxy(self):
        g = self.grant("ben", fresh=True, suffix="offboard")
        child = self.stack.admin("exchange_token", {"subject_token": g["token"], "actor": "refund-worker", "ttl": 300})
        self.assertEqual(self.call("GET", f"/{TENANT}/customers?region=EU&limit=3", token=g["token"]).status, 200)
        self.assertEqual(self.call("GET", f"/{TENANT}/customers?region=EU&limit=3", token=child["token"]).status, 200)
        time.sleep(1.1)     # the cut-off is "issued up to this second"
        self.assertTrue(self.stack.admin("revoke", {"user": "ben", "by": "live-test"}).get("ok"))
        mark = self.api_mark()
        for t in (g["token"], child["token"]):
            r = self.call("GET", f"/{TENANT}/customers?region=EU&limit=3", token=t)
            self.assertEqual((r.status, r.code), (403, "token_revoked"))
        self.assertEqual(self.api_log(mark), [], "a revoked token never reaches the upstream")
        # by token id: the parent's revocation ends the sub-agent's token too
        g2 = self.grant("chloe", fresh=True, suffix="revoke")
        child2 = self.stack.admin("exchange_token", {"subject_token": g2["token"], "actor": "refund-worker", "ttl": 300})
        self.assertTrue(self.stack.admin("revoke", {"token_id": g2["token_id"]}).get("ok"))
        self.assertEqual(self.call("GET", f"/{TENANT}/customers?region=US&limit=3", token=child2["token"]).code, "token_revoked")
        for bad in ("", "abc.def.ghi", g["token"][:-4] + "AAAA", g["token"].split(".")[0] + "." + g["token"].split(".")[1] + "."):
            r = self.call("GET", f"/{TENANT}/customers?region=EU&limit=3", token=bad or None)
            self.assertIn(r.status, (401, 403), bad[:20])
            self.assertNotEqual(r.status, 200)

    # --------------------------------------------- responses that cannot be checked
    def test_14_non_json_responses_are_withheld(self):
        for path in ("/export/customers.csv", "/export/statement.pdf"):
            r = self.call("GET", f"/{TENANT}{path}?region=EU", "anna")
            observe(f"filtered route, upstream answers {path.rsplit('.', 1)[1]}", self.impl, f"{r.status} {r.code}")
            self.assertEqual(r.status, 502, r.raw[:200])
            self.assertIn(r.code, ("unfilterable_response", "upstream_unreadable"))
            self.assertEqual(cards_in(r.raw), [])

    def test_14b_a_passthrough_route_hands_on_the_upstreams_bytes_untouched(self):
        """`"response": "passthrough"` (spec/API.md): for responses that hold no record data."""
        direct = http_request("GET", f"{self.stack.api_url}/{TENANT}/export/statement.pdf", headers={"X-Api-Key": self.stack.api_key})
        r = http_request("GET", f"{self.stack.proxy_url}/company_raw/{TENANT}/export/statement.pdf?region=EU", token=self.token("anna"))
        observe("passthrough route, binary (non-UTF-8) upstream body", self.impl, f"{r.status} {r.code or ''} identical={r.raw == direct.raw}".replace("  ", " "))
        self.assertEqual((r.status, r.raw), (200, direct.raw))

    def test_15_error_statuses_keep_the_status_and_lose_the_body(self):
        for status in (400, 404, 409, 429, 500, 503):
            r = self.call("GET", f"/{TENANT}/error/{status}?region=EU", "anna")
            self.assertEqual((r.status, r.code), (status, "upstream_error"))
            self.assertEqual(cards_in(r.raw), [])
            self.assertNotIn(b"notes", r.raw)
        r = self.call("GET", f"/{TENANT}/customers/c-99999{self.rq('EU')}", "anna")
        self.assertEqual((r.status, r.code), (404, "not_found"), "the upstream's 404 body names another record; none of it arrives")
        self.assertNotIn(b"did_you_mean", r.raw)

    def test_16_a_redirect_is_not_followed(self):
        eu = self.rows("customers", "region = 'EU'")[0]
        mark = self.api_mark()
        r = self.call("GET", f"/{TENANT}/moved/customers/{eu['id']}{self.rq('EU')}", "anna")
        log = self.api_log(mark)
        expected = [f"/{TENANT}/customers/{eu['id']}", f"/{TENANT}/moved/customers/{eu['id']}"]     # the lookup, then the call
        self.assertEqual([x["path"] for x in log], expected, "nothing went upstream after the redirect: the proxy did not go where Location pointed")
        observe("upstream answers 302 with a Location and a JSON record in the body", self.impl,
                f"agent gets {r.status}, Location {'kept' if r.header('Location') else 'dropped'}, body {'masked record' if r.json == json.loads(json.dumps(ORACLE.view('crm.customer', shape('customers', eu), 'support-agent'))) else r.raw[:60]!r}")
        self.assertEqual(cards_in(r.raw), [])
        self.assertNotIn(r.status, (301, 303, 307, 308))
        if isinstance(r.json, dict) and "id" in r.json:
            self.assertEqual(r.json, json.loads(json.dumps(ORACLE.view("crm.customer", shape("customers", eu), "support-agent"))))

    def test_17_a_slow_upstream_is_waited_for_and_how_many_others_wait_with_it(self):
        eu = self.rows("customers", "region = 'EU'")[0]
        token = self.token("anna")
        t0 = time.monotonic()
        r = self.call("GET", f"/{TENANT}/slow/customers/{eu['id']}{self.rq('EU', 'seconds=2')}", token=token)
        self.assertEqual(r.status, 200)
        self.assertGreaterEqual(time.monotonic() - t0, 2.0)
        self.assertEqual(r.json["id"], eu["id"])

    def test_17b_slow_upstream_calls_do_not_hold_up_the_other_agents(self):
        eu = self.rows("customers", "region = 'EU'")[0]
        token = self.token("anna")
        # six slow calls in flight; how long does an ordinary one take meanwhile?
        results = []
        slow = [threading.Thread(target=lambda: results.append(http_request("GET", f"{self.base}/{TENANT}/slow/customers/{eu['id']}{self.rq('EU', 'seconds=3')}", token=token, timeout=60).status))
                for _ in range(6)]
        for t in slow:
            t.start()
        time.sleep(0.5)
        t0 = time.monotonic()
        fast = self.call("GET", f"/{TENANT}/customers/{eu['id']}{self.rq('EU')}", token=token)
        waited = time.monotonic() - t0
        for t in slow:
            t.join(timeout=90)
        self.assertEqual(fast.status, 200)
        self.assertEqual(results, [200] * 6)
        observe("an ordinary call while 6 calls wait 3 s on a slow upstream route", self.impl, f"answered after {waited:.2f} s")
        self.assertLess(waited, 1.5, "slow upstream calls must not hold up the others")

    @unittest.skipUnless(FULL, "takes 60+ s: set SD_LIVE_FULL=1 (run.sh without --quick)")
    def test_18_an_upstream_slower_than_60_seconds_is_given_up_on(self):
        eu = self.rows("customers", "region = 'EU'")[0]
        t0 = time.monotonic()
        r = self.call("GET", f"/{TENANT}/slow/customers/{eu['id']}{self.rq('EU', 'seconds=75')}", "anna", timeout=120)
        took = time.monotonic() - t0
        observe("upstream silent for 75 s", self.impl, f"{r.status} {r.code} after {took:.0f} s")
        self.assertEqual((r.status, r.code), (502, "upstream_unreachable"))
        self.assertLess(took, 70)

    def test_19_a_response_over_32_mb_is_not_passed_on(self):
        token = self.token("anna")
        r = self.call("GET", f"/{TENANT}/bulk/customers?region=EU&mb=6", token=token, timeout=180)
        self.assertEqual(r.status, 200, r.raw[:200])
        items = r.json
        self.assertGreater(len(items), 1000)
        self.assertEqual({i["region"] for i in items}, {"EU"})
        self.assertEqual(cards_in(r.raw), [])
        t0 = time.monotonic()
        r = self.call("GET", f"/{TENANT}/bulk/customers?region=EU&mb=33", token=token, timeout=180)
        observe("filtered route, 33 MB JSON response", self.impl, f"{r.status} {r.code} ({r.json['error']['message'] if r.code else ''}) in {time.monotonic() - t0:.1f} s")
        self.assertEqual(r.status, 502, r.raw[:200])
        self.assertIn(r.code, ("unfilterable_response", "upstream_unreadable"))
        self.assertLess(len(r.raw), 2000)

    def test_19b_a_passthrough_response_over_32_mb_is_refused_not_cut(self):
        """docs/LIMITATIONS.md section 10: responses are buffered, 32 MB cap. A capped response must
        be an error, not the first 32 MB with a 200."""
        direct = http_request("GET", f"{self.stack.api_url}/{TENANT}/bulk/customers?mb=33", headers={"X-Api-Key": self.stack.api_key}, timeout=180)
        r = http_request("GET", f"{self.stack.proxy_url}/company_raw/{TENANT}/bulk/customers?region=EU&mb=33", token=self.token("anna"), timeout=180)
        observe("passthrough route, 33 MB response", self.impl, f"{r.status} {r.code or ''}; {len(r.raw)} of {len(direct.raw)} bytes reach the agent".replace(" ;", ";"))
        self.assertGreater(len(direct.raw), 33 * 1024 * 1024)
        self.assertEqual((r.status, r.code), (502, "unfilterable_response"))

    # ----------------------------------------------------------------- injection
    def test_20_injection_through_ids_and_query_values_does_not_change_the_sql(self):
        token = self.token("anna")
        counts = lambda: {t: self.stack.sql(f"select count(*) as n from {t}")[0]["n"] for t in ("customers", "tickets", "refunds", "vendors", "employees")}
        before = counts()
        # a baseline: the statements the same endpoints send for honest input
        m0 = self.pglog.mark()
        self.call("GET", f"/{TENANT}/customers/c-00001{self.rq('EU')}", token=token)
        self.call("GET", f"/{TENANT}/customers?region=EU&limit=3&offset=2", token=token)
        self.call("GET", f"/{TENANT}/customers/c-99999{self.rq('EU')}", token=token)
        time.sleep(0.3)
        baseline = {statement_shape(s) for s in self.pglog.statements(m0)}
        m1, a1 = self.pglog.mark(), self.api_mark()
        for bad in ("c-00001'--", "c-00001';drop table company.customers;--", "c-00001%27%20OR%20%271%27=%271", "c-00001%00", "1 OR 1=1", "c-00001\"", "c-00001%3Bselect",
                    "c-00001/../../osprey/customers/c-00002", "..%2F..%2Fosprey%2Fcustomers", "c-00001%2F..%2Fc-00002", "*", "c-00001)", "%c0%af"):
            r = self.call("GET", f"/{TENANT}/customers/{bad.replace(' ', '%20')}{self.rq('EU')}", token=token)
            self.assertEqual((r.status, r.code), (403, "no_route"), bad)
        for tenant in ("kestrel'--", "kestrel%27%20or%201=1", "kestrel;x", "%2e%2e"):
            r = self.call("GET", f"/{tenant}/customers?region=EU", token=token)
            self.assertIn(r.status, (403,), tenant)
        self.assertEqual(self.api_log(a1), [], "ids that are not plain never reach the upstream")
        for q in ("region=EU&limit=1;drop%20table%20company.customers", "region=EU&limit=1%20union%20select%20*%20from%20company.salaries", "region=EU&offset=0)--",
                  "region=EU&limit=-1", "region=EU&limit=1e9", "region=EU&offset=%27", "region=EU&limit=3&offset=0%20or%201=1"):
            r = self.call("GET", f"/{TENANT}/customers?{q}", token=token)
            self.assertIn(r.status, (200, 400), q)
            if r.status == 200:
                self.assertTrue(all(i["region"] == "EU" for i in r.json["items"]), q)
        for q in ("region=EU'%20OR%20'1'='1", "region=EU%27--", "region=EU&debug=1", "region=EU&limit=3&select=*", "region=EU&regio%6e=US", "region=EU&limit=3&%72egion=US"):
            r = self.call("GET", f"/{TENANT}/customers?{q}", token=token)
            self.assertIn(r.status, (400, 403), f"{q}: {r.raw[:120]}")
        time.sleep(0.3)
        shapes = {statement_shape(s) for s in self.pglog.statements(m1)}
        if self.pglog.path:
            self.assertTrue(shapes, "the hostile calls that were forwarded must show in the statement log")
            self.assertEqual(shapes - baseline, set(), "a hostile value changed the shape of a statement")
            self.assertFalse([s for s in self.pglog.statements(m1) if re.search(r"drop\s+table|union\s+select|salaries", statement_shape(s), re.I)],
                             "hostile text may appear inside a quoted value (the API logs its requests), never as SQL")
            observe("statement shapes during the injection attempts that honest calls do not also produce", self.impl, len(shapes - baseline))
        self.assertEqual(counts(), before)

    # --------------------------------------------------------------- concurrency
    def test_21_many_agents_at_once_get_only_their_own_data(self):
        users = ["anna", "chloe", "petra", "quinn", "carla", "sofia", "elena", "ben"]
        tokens = {u: self.grant(u, fresh=(u == "ben"), suffix="conc")["token"] for u in users}
        pages = [(resource, offset) for resource in ("customers", "tickets", "opportunities") for offset in (0, 150, 900)]
        expected = {}
        for u in users:
            for resource, offset in pages:
                if ORACLE.may(PEOPLE[u], "read", RESOURCES[resource][1]):
                    expected[(u, resource, offset)] = self.expected_list(resource, u, 40, offset)
        problems, decisions, lock = [], [], threading.Lock()

        def agent(user: str, seed: int):
            rnd = random.Random(seed)
            mine = [k for k in expected if k[0] == user]
            for _ in range(12):
                _, resource, offset = rnd.choice(mine)
                r = http_request("GET", f"{self.base}/{TENANT}/{resource}?region={ORACLE.region(user)}&limit=40&offset={offset}", token=tokens[user], timeout=120)
                with lock:
                    type(self).seen.append(r.everything())
                    decisions.append(r.header("X-SmartDelegate-Decision"))
                    if r.status != 200:
                        problems.append(f"{user} {resource}@{offset}: HTTP {r.status} {r.error or r.raw[:120]}")
                    elif r.json["items"] != expected[(user, resource, offset)]:
                        problems.append(f"{user} {resource}@{offset}: the response is not this agent's view of that page")

        threads = [threading.Thread(target=agent, args=(u, i)) for i, u in enumerate(users * 3)]
        t0 = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=300)
        self.assertEqual(problems, [])
        self.assertEqual(len(decisions), len(threads) * 12)
        self.assertEqual(len(set(decisions)), len(decisions), "every call has a decision id of its own")
        observe("24 agents x 12 list calls at once: wrong or foreign responses", self.impl, f"{len(problems)} of {len(decisions)} ({time.monotonic() - t0:.1f} s)")

    # ------------------------------------------------------------ the upstream key
    def test_90_the_agents_headers_do_not_reach_the_upstream_and_its_key_never_reaches_the_agent(self):
        eu = self.rows("customers", "region = 'EU'")[0]
        mark = self.api_mark()
        r = self.call("GET", f"/{TENANT}/customers/{eu['id']}{self.rq('EU')}", "anna",
                      headers={"X-Api-Key": "guess", "X-Forwarded-For": "10.0.0.1", "Cookie": "session=1", "X-Evil": "1", "Host": "evil.example", "Forwarded": "for=1.2.3.4"})
        self.assertEqual(r.status, 200)
        log = self.api_log(mark)
        self.assertEqual(len(log), 1)
        names = set(log[0]["header_names"].split(","))
        self.assertTrue(log[0]["key_ok"], "the proxy's key, not the agent's guess")
        self.assertFalse(log[0]["had_authorization"])
        self.assertFalse(names & {"authorization", "x-forwarded-for", "cookie", "x-evil", "forwarded"}, names)
        every = self.stack.sql("select count(*) filter (where had_authorization) as with_token, count(*) filter (where not key_ok) as without_key, count(*) as n from api_request_log")[0]
        self.assertGreater(every["n"], 300)
        self.assertEqual((every["with_token"], every["without_key"]), (0, 0), "of everything the proxy forwarded since this class reloaded the database")
        # straight to the upstream with the capability token and no key: refused
        r = http_request("GET", f"{self.stack.api_url}/{TENANT}/customers/{eu['id']}", token=self.token("anna"))
        self.assertEqual(r.status, 401)
        key = self.stack.api_key.encode()
        self.assertGreater(len(type(self).seen), 300)
        self.assertFalse([1 for blob in type(self).seen if key in blob], "the upstream key is in something an agent received")
        for name in ("proxy", "daemon"):
            self.assertNotIn(self.stack.api_key, self.stack.log_text(name), f"the upstream key is in the {name}'s stderr")
        if self.stack.state_dir:
            audit = (self.stack.state_dir / "audit.jsonl").read_bytes()
            self.assertNotIn(key, audit)
            self.assertEqual(cards_in(audit), [], "the audit log holds field names, never values")
            for pattern in (IBAN, NATIONAL_ID, TAX_ID):
                self.assertIsNone(pattern.search(audit), "the audit log holds field names, never values")
        observe("answers received by agents and searched for the upstream key", self.impl, len(type(self).seen))

    def test_91_nobody_ever_received_a_card_number_and_bank_details_only_treasury(self):
        blobs = type(self).seen
        self.assertFalse([1 for b in blobs if cards_in(b)], "a full card number reached an agent")

    def test_92_an_unreachable_upstream_is_an_error_without_the_key(self):
        with Stack(self.impl, daemon=True) as s:
            t = s.issue("anna", "support-agent", "ticket-down")["token"]
            self.assertEqual(http_request("GET", f"{s.proxy_url}/company/{TENANT}/customers?region=EU&limit=1", token=t).status, 200)
            stop_process(s.api_proc)
            r = http_request("GET", f"{s.proxy_url}/company/{TENANT}/customers?region=EU&limit=1", token=t)
            observe("upstream process gone", self.impl, f"{r.status} {r.code}")
            self.assertEqual((r.status, r.code), (502, "upstream_unreachable"))
            self.assertNotIn(s.api_key.encode(), r.everything())
            self.assertNotIn(s.api_key, s.log_text("proxy"))

    def test_93_the_audit_chain_is_valid_and_holds_the_proxys_decisions(self):
        r = self.call("GET", f"/{TENANT}/customers?region=EU&limit=2", "anna")
        did = r.header("X-SmartDelegate-Decision")
        v = self.stack.admin("audit_verify")
        self.assertTrue(v.get("ok"), v)
        self.assertGreater(v["records"], 500)
        tail = self.stack.admin("audit_tail", {"n": 10})["records"]
        mine = [x for x in tail if x.get("decision_id") == did]
        self.assertEqual(sorted(x["event"] for x in mine), ["decision", "obligations_applied"])
        observe("audit records after the HTTP cases (chain verified)", self.impl, v["records"])


def tearDownModule():
    """Print what was observed, side by side for the two proxies. SD_LIVE_OBSERVED=<file> also saves it as JSON."""
    if not OBSERVED:
        return
    out = ["", "observed behaviour (python reference | rust port); DIFF marks where they differ"]
    for key in sorted(OBSERVED):
        v = OBSERVED[key]
        vals = [str(v.get(i, "-")) for i in ("python", "rust")]
        differs = len(v) > 1 and len({json.dumps(x, sort_keys=True, default=str) for x in v.values()}) > 1
        out.append(f"  {'DIFF' if differs else '    '} {key}: {vals[0]} | {vals[1]}")
    print("\n".join(out), file=sys.stderr)
    if os.environ.get("SD_LIVE_OBSERVED"):
        Path(os.environ["SD_LIVE_OBSERVED"]).write_text(json.dumps(OBSERVED, indent=2, sort_keys=True, default=str), encoding="utf-8")


class HttpProxyPython(HttpProxyCases, LiveCase):
    impl = "python"


class HttpProxyRust(HttpProxyCases, LiveCase):
    """The Rust port's proxy: the same routes file, the same cases."""
    impl = "rust"

    def test_09b_a_chunked_body_cannot_carry_a_second_request_or_an_unchecked_write(self):
        super().test_09b_a_chunked_body_cannot_carry_a_second_request_or_an_unchecked_write()


# ====================================================================== SqlGuard

class SqlGuardPostgres(unittest.TestCase):
    """`smartdelegate.SqlGuard` with a psycopg2 connection to the same database."""
    maxDiff = 2000

    @classmethod
    def setUpClass(cls):
        try:
            cls.stack = Stack("python", proxy=False, api=False, daemon=False, reseed=True)
        except Unavailable as e:
            raise unittest.SkipTest(str(e)) from None
        sys.path.insert(0, str(ROOT / "src"))
        import psycopg2
        from sf_smartdelegate import Engine, SqlGuard
        cls.engine = Engine(json.loads(cls.stack.config.read_text()))
        cls.db = psycopg2.connect(cls.stack.dsn, connect_timeout=15, options="-c search_path=company")
        cls.db.autocommit = True
        cls.SqlGuard = SqlGuard
        cls.sql = SqlGuard(cls.engine, cls.db, paramstyle="format")
        cls.pglog = PgLog()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "db", None) is not None:
            cls.db.close()
        if getattr(cls, "engine", None) is not None:
            cls.engine.close()
        if getattr(cls, "stack", None) is not None:
            cls.stack.close()

    def tok(self, user: str, role: str | None = None, sub: str | None = None) -> str:
        role = role or PEOPLE[user]
        t = self.engine.issue_token(ORACLE.agent(role), user=user, role=role, task=ORACLE.task(role, "sql"), tenant=TENANT)["token"]
        return self.engine.exchange_token(t, sub, ttl=300)["token"] if sub else t

    def select(self, token, table, path, *, region=None, tenant=TENANT, **kw):
        """A query on one of the per-tenant views, with the attributes the caller vouches for."""
        attrs = {"tenant": tenant, **({"region": region} if region else {})}
        return self.sql.select(token, table, path, attrs=attrs, **kw)

    COLUMNS = {"kestrel_customers": ["id", "name", "email", "phone", "region", "tier", "notes", "addresses", "card_last4", "card_number"],
               "kestrel_vendors": ["id", "name", "region", "status", "onboarded_by", "contact_email", "tax_id", "risk_score", "bank_bic", "bank_iban"],
               "kestrel_employees": ["id", "name", "email", "unit", "region", "manager", "job_title", "start_date", "status", "national_id", "home_address", "bank_account", "emergency_contact"],
               "kestrel_salaries": ["employee_id", "currency", "grade", "base", "bonus", "notes"]}

    def test_00_the_postgres_tests_of_the_offline_suite_pass(self):
        """tests/test_guard_sql.py PostgresTests, skipped without SMARTDELEGATE_PG_DSN."""
        p = subprocess.run([sys.executable, "-m", "unittest", "-v", "test_guard_sql.PostgresTests"], cwd=str(ROOT / "tests"), capture_output=True, text=True, timeout=300,
                           env={**os.environ, "SMARTDELEGATE_PG_DSN": self.stack.dsn})
        tail = p.stderr.strip().splitlines()[-3:]
        observe("tests/test_guard_sql.py PostgresTests with SMARTDELEGATE_PG_DSN", "python", " / ".join(x for x in tail if x.strip()))
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.assertRegex(p.stderr, r"Ran [3-9] tests")
        self.assertNotIn("skipped", p.stderr.splitlines()[-1])

    def test_01_columns_are_the_ones_the_role_may_see(self):
        for user, table, path in (("carla", "kestrel_customers", "crm.customer"), ("carla", "kestrel_vendors", "procurement.vendor"), ("gina", "kestrel_vendors", "procurement.vendor"),
                                  ("oskar", "kestrel_employees", "hr.employee"), ("maya", "kestrel_employees", "hr.employee"), ("liam", "kestrel_employees", "hr.employee"),
                                  ("yara", "kestrel_employees", "hr.employee"), ("oskar", "kestrel_salaries", "hr.salary"), ("liam", "kestrel_salaries", "hr.salary"),
                                  ("carla", "kestrel_salaries", "hr.salary")):
            mark = self.pglog.mark()
            rows = self.sql.select(self.tok(user), table, path, columns=self.COLUMNS[table], limit=50)
            want = [c for c in self.COLUMNS[table] if c in ORACLE.visible_fields(path, PEOPLE[user])]
            self.assertEqual(list(rows[0]), want, f"{user} {table}")
            self.assertEqual(len(rows), 50)
            if self.pglog.path:
                time.sleep(0.15)
                sent = [s for s in self.pglog.statements(mark) if table in s]
                self.assertEqual(sent, [f'SELECT {", ".join(chr(34) + c + chr(34) for c in want)} FROM "{table}" LIMIT 50'], "the statement PostgreSQL logged")
        blob = json.dumps(self.sql.select(self.tok("carla"), "kestrel_customers", "crm.customer", columns=self.COLUMNS["kestrel_customers"]), default=str).encode()
        self.assertEqual(cards_in(blob), [])
        with self.assertRaises(PermissionError):
            self.sql.select(self.tok("maya"), "kestrel_salaries", "hr.salary", columns=self.COLUMNS["kestrel_salaries"])
        with self.assertRaises(PermissionError):
            self.sql.select(self.tok("carla"), "kestrel_customers", "crm.customer", columns=["card_number", "card_last4"])

    def test_02_a_role_whose_rules_need_resource_attributes_gets_nothing_without_them(self):
        """Fails closed. (Finding L-7: SqlGuard had no way to state them at all; `attrs=` and
        `row_attrs=` are the two ways now, tests 03 and 08.)"""
        for user in ("anna", "petra"):
            with self.assertRaises(PermissionError) as cm:
                self.sql.select(self.tok(user), "kestrel_customers", "crm.customer", columns=["id"])
            self.assertEqual(cm.exception.reason, "no_matching_permit")

    def test_03_the_row_filter_is_in_the_where_clause_and_counts_match(self):
        for user in ("anna", "chloe", "petra"):
            region = ORACLE.region(user)
            mark = self.pglog.mark()
            rows = self.select(self.tok(user), "kestrel_customers", "crm.customer", region=region, columns=["id", "region", "email", "notes", "card_number"])
            n = self.stack.sql("select count(*) as n from customers where tenant = %s and region = %s", (TENANT, region))[0]["n"]
            self.assertEqual(len(rows), n)
            self.assertEqual({r["region"] for r in rows}, {region})
            self.assertEqual(set(rows[0]), {"id", "region", "email"} | ({"notes"} if user != "petra" else set()))
            if self.pglog.path:
                time.sleep(0.15)
                sent = [s for s in self.pglog.statements(mark) if "kestrel_customers" in s]
                self.assertEqual(len(sent), 1)
                self.assertTrue(sent[0].endswith(f"""FROM "kestrel_customers" WHERE "region" = '{region}'"""), sent[0])
        # the wrong region stated: refused before any SQL
        with self.assertRaises(PermissionError) as cm:
            self.select(self.tok("anna"), "kestrel_customers", "crm.customer", region="US", columns=["id"])
        self.assertEqual(cm.exception.reason, "policy_forbid")
        # a caller condition can only narrow
        rows = self.select(self.tok("anna"), "kestrel_customers", "crm.customer", region="EU", columns=["id", "region"], where={"region": "US"})
        self.assertEqual(rows, [])

    def test_04_identifiers_values_and_limits_cannot_change_the_statement(self):
        t = self.tok("carla")
        before = self.stack.sql("select count(*) as n from customers")[0]["n"]
        for table in ('kestrel_customers"; drop table company.customers; --', "kestrel_customers; select 1", "company.salaries", 'x" union select * from "salaries', ""):
            with self.assertRaises(ValueError):
                self.sql.select(t, table, "crm.customer", columns=["id"])
        mark = self.pglog.mark()
        for value in ("c-00001' OR '1'='1", "c-00001'; drop table company.customers; --", "\\'; select pg_sleep(5); --", "c-00001\x00"):
            try:
                self.assertEqual(self.sql.select(t, "kestrel_customers", "crm.customer", columns=["id"], where={"id": value}), [])
            except ValueError:
                pass    # psycopg2 refuses a NUL byte itself
        for col in ('id" = \'x\' OR 1=1 --', "1=1 or id", "card_number", "tenant"):
            with self.assertRaises(PermissionError):
                self.sql.select(t, "kestrel_customers", "crm.customer", columns=["id"], where={col: "x"})
        rows = self.sql.select(t, "kestrel_customers", "crm.customer", columns=["id", 'email" , "card_number', "card_number", "*", "tenant"], limit=2)
        self.assertEqual([list(r) for r in rows], [["id"], ["id"]], "a column that is not a permitted catalog field is left out, whatever its text")
        for limit in ("1; drop table company.customers", "1 union select 1", None):
            if limit is None:
                continue
            with self.assertRaises(ValueError):
                self.sql.select(t, "kestrel_customers", "crm.customer", columns=["id"], limit=limit)
        if self.pglog.path:
            time.sleep(0.15)
            shapes = {statement_shape(s) for s in self.pglog.statements(mark) if "kestrel_customers" in s}
            self.assertEqual(shapes, {'SELECT "id" FROM "kestrel_customers" WHERE "id" = ?', 'SELECT "id" FROM "kestrel_customers" LIMIT ?'})
            observe("statement shapes PostgreSQL logged for hostile SqlGuard values", "python", sorted(shapes))
        self.assertEqual(self.stack.sql("select count(*) as n from customers")[0]["n"], before)

    def test_05_a_json_column_is_masked_inside_like_the_same_record_through_the_proxy(self):
        """`addresses` is permitted, `addresses[].geo` (label internal) is not, for a sales rep and for any
        sub-agent. (Finding L-8: SqlGuard returned the column whole. Every row now goes through the
        decision's field mask.)"""
        for label, token, role, agent, depth in (("sales-rep", self.tok("petra"), "sales-rep", None, 1),
                                                 ("support sub-agent", self.tok("anna", sub="ticket-triager"), "support-agent", "ticket-triager", 2),
                                                 ("support agent", self.tok("anna"), "support-agent", None, 1)):
            rows = self.select(token, "kestrel_customers", "crm.customer", region="EU", columns=["id", "addresses", "notes", "card_number"], limit=40)
            raw = {r["id"]: r for r in self.stack.sql("select id, addresses, notes from customers where id = any(%s)", ([r["id"] for r in rows],))}
            want = [{k: v for k, v in ORACLE.view("crm.customer", raw[r["id"]], role, agent=agent, depth=depth).items()} for r in rows]
            self.assertEqual(rows, want, label)
            geo = sum(1 for r in rows for a in r["addresses"] if "geo" in a)
            self.assertEqual(geo > 0, "addresses[].geo" in ORACLE.visible_fields("crm.customer", role, agent=agent, depth=depth), label)
            observe(f"L-8: address entries with `geo` in 40 rows selected through SqlGuard, {label}", "python", geo)

    def test_06_nested_catalog_fields_cannot_be_selected_at_all(self):
        """`bank.iban` is not a column name; `bank_iban` is not a catalog field. Treasury, the one role
        that may see IBANs, cannot read them through SqlGuard from flat columns: a nested catalog field
        is reachable only inside a JSON column (test 05). Fails closed; a documented limit (spec/API.md)."""
        rows = self.sql.select(self.tok("karin"), "kestrel_vendors", "procurement.vendor", columns=self.COLUMNS["kestrel_vendors"], limit=5)
        self.assertEqual(list(rows[0]), ["id", "name", "region", "status", "onboarded_by", "contact_email", "tax_id", "risk_score"])
        self.assertIsNone(IBAN.search(json.dumps(rows).encode()))

    def test_07_revoked_and_foreign_tenant_tokens_get_no_statement(self):
        t = self.tok("carla")
        self.engine.revoke(self.engine.inspect_token(t)["claims"]["jti"])
        mark = self.pglog.mark()
        with self.assertRaises(PermissionError) as cm:
            self.sql.select(t, "kestrel_customers", "crm.customer", columns=["id"])
        self.assertEqual(cm.exception.reason, "token_revoked")
        with self.assertRaises(PermissionError) as cm:
            self.select(self.tok("carla"), "kestrel_customers", "crm.customer", tenant="osprey", columns=["id"])
        self.assertEqual(cm.exception.reason, "tenant_mismatch")
        if self.pglog.path:
            time.sleep(0.15)
            self.assertEqual([s for s in self.pglog.statements(mark) if "kestrel_customers" in s], [])

    def test_08_one_decision_per_row_on_a_table_that_mixes_tenants_and_regions(self):
        """`row_attrs`: tenant and region are read from each row, the way the policy sees one record.
        No view per tenant, nothing the caller has to vouch for."""
        counts = {(r["tenant"], r["region"]): r["n"] for r in self.stack.sql("select tenant, region, count(*) as n from customers group by 1, 2")}
        for user in ("anna", "chloe", "petra", "carla"):
            role, region = PEOPLE[user], ORACLE.region(user)
            before = self.engine.call("audit_verify", {})["records"]
            rows = self.sql.select(self.tok(user), "customers", "crm.customer", columns=["id", "region", "email", "addresses", "notes", "card_number"],
                                   row_attrs={"tenant": "tenant", "region": "region"})
            decisions = self.engine.call("audit_verify", {})["records"] - before - 1     # one record is the token
            want = sum(n for (t, reg), n in counts.items() if t == TENANT and (reg == region or role == "auditor"))
            self.assertEqual(len(rows), want, user)
            self.assertFalse({r["id"] for r in rows} & {r["id"] for r in self.stack.sql("select id from customers where tenant <> %s", (TENANT,))})
            self.assertEqual({r["region"] for r in rows}, {region} if role != "auditor" else {"EU", "US", "APAC"})
            self.assertTrue(all("tenant" not in r and r.get("card_number") is None for r in rows))
            self.assertEqual(decisions, len(counts), "one decision for each (tenant, region) the query returned, not one per row")
            observe(f"SqlGuard row_attrs on the 3000-row customers table, {role}: rows returned / decisions made", "python", f"{len(rows)} / {decisions}")
        one = self.sql.select(self.tok("anna"), "customers", "crm.customer", columns=["id", "email"], row_attrs={"tenant": "tenant", "region": "region"},
                              where={"id": self.stack.sql("select id from customers where tenant = 'osprey' limit 1")[0]["id"]})
        self.assertEqual(one, [], "another tenant's record, asked for by id")


# ====================================================================== MCP proxy

class McpProxyCases:
    """`smartdelegate mcp-proxy` in front of company-mcp (stdio), which holds the database credential."""

    @classmethod
    def setUpClass(cls):
        if cls.impl not in IMPLS:
            raise unittest.SkipTest(f"{cls.impl} is not in SD_LIVE_IMPLS")
        try:
            cls.stack = Stack(cls.impl, proxy=False, api=False, reseed=True)
        except Unavailable as e:
            raise unittest.SkipTest(str(e)) from None
        cls.seen = []
        cls._tokens = {}
        cls.pglog = PgLog()

    @classmethod
    def tearDownClass(cls):
        st = getattr(cls, "stack", None)
        if st is not None:
            st.close()

    def setUp(self):
        import queue
        self.token_file = self.stack.tmp / f"token-{self.id().rsplit('.', 1)[-1][:40]}"
        self.grant_now = self.stack.issue("anna", "support-agent", ORACLE.task("support-agent", "mcp-" + self.id().rsplit("_", 1)[-1][:12]))
        self.token_file.write_text(self.grant_now["token"])
        argv, env = cli_of(self.impl)
        self.stderr_path = self.stack.tmp / "mcp-proxy.stderr"
        self.stderr_file = open(self.stderr_path, "ab")
        self.tools_file = Path(__file__).parent / "mcp_tools.json"
        self.p = subprocess.Popen([*argv, "mcp-proxy", "--config", str(self.stack.config), "--tools", str(self.tools_file),
                                   "--token-file", str(self.token_file), "--", sys.executable, str(Path(__file__).parent / "mcp_server.py")],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr_file, text=True, encoding="utf-8", bufsize=1,
                                  env={**os.environ, **env, "COMPANY_MCP_DSN": self.stack.dsn, "COMPANY_MCP_TENANT": TENANT}, preexec_fn=die_with_parent)
        record_pid(self.p.pid)
        self.lines = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self.n = 0
        self.unsolicited = []
        self.addCleanup(self.stop)

    def _pump(self):
        try:
            for line in self.p.stdout:
                self.lines.put(line)
        except (OSError, ValueError):
            pass
        self.lines.put(None)

    def stop(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            pass
        stop_process(self.p)
        self.stderr_file.close()

    def rpc(self, method: str, params: dict | None = None, timeout: float = 30.0) -> dict:
        import queue
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}) + "\n")
        self.p.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                line = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                self.fail(f"no answer to {method} within {timeout} s")
            if line is None:
                self.fail(f"the MCP proxy closed its output: {self.stderr_path.read_text(errors='replace')[-500:]}")
            type(self).seen.append(line.encode("utf-8"))
            msg = json.loads(line)
            if msg.get("id") == self.n and "method" not in msg:
                return msg
            self.unsolicited.append(msg)

    def tool(self, name: str, **arguments) -> dict:
        msg = self.rpc("tools/call", {"name": name, "arguments": arguments})
        self.assertIn("result", msg, msg)
        return msg["result"]

    def row(self, table: str, where: str, params: tuple = ()) -> dict:
        return self.stack.sql(f"select * from {table} where tenant = %s and {where} order by 1 limit 1", (TENANT, *params))[0]

    def view(self, row: dict, role: str = "support-agent", **kw) -> dict:
        return json.loads(json.dumps(ORACLE.view("crm.customer", shape("customers", row), role, **kw), default=str))

    def test_01_handshake_and_only_mapped_tools_are_listed(self):
        self.assertEqual(self.rpc("initialize")["result"]["serverInfo"]["name"], "company-mcp")
        names = [t["name"] for t in self.rpc("tools/list")["result"]["tools"]]
        mapped = list(json.loads(self.tools_file.read_text())["tools"])
        mapped = [t["name"] for t in __import__("live.upstream.mcp_server", fromlist=["TOOLS"]).TOOLS if t["name"] in mapped]
        self.assertEqual(names, mapped)
        self.assertNotIn("run_sql", names)
        self.assertEqual(self.rpc("ping").get("result"), {})

    def test_02_a_real_record_is_masked_in_text_and_structured_content_and_side_channels_are_cut(self):
        eu = self.row("customers", "region = 'EU'")
        r = self.tool("get_customer", customer_id=eu["id"], region="EU")
        want = self.view(eu)
        self.assertEqual(r["structuredContent"], want)
        self.assertEqual(json.loads(r["content"][0]["text"]), want)
        self.assertEqual(sorted(r), ["content", "structuredContent"], "_meta is dropped")
        self.assertEqual(self.unsolicited, [], "the server's log notification and its sampling request must not reach the agent")
        self.assertEqual(want["card"]["number"], REDACTED)
        # asked again as a sub-agent: the runtime swaps the token file, the same tool returns less
        child = self.stack.admin("exchange_token", {"subject_token": self.grant_now["token"], "actor": "ticket-triager", "ttl": 300})
        self.token_file.write_text(child["token"])
        r = self.tool("get_customer", customer_id=eu["id"], region="EU")
        self.assertEqual(r["structuredContent"], self.view(eu, agent="ticket-triager", depth=2))
        self.assertNotIn("notes", r["structuredContent"])

    def test_03_lists_are_row_filtered_on_real_rows(self):
        r = self.tool("list_customers", region="EU", limit=400)
        page = self.stack.sql("select * from customers where tenant = %s order by id limit 400", (TENANT,))
        want = [self.view(row) for row in page if row["region"] == "EU"]
        self.assertEqual(r["structuredContent"], want)
        self.assertEqual(json.loads(r["content"][0]["text"]), want)
        self.assertGreater(len(want), 100)
        denied = self.tool("list_customers", region="US", limit=5)
        self.assertTrue(denied["isError"])
        self.assertIn("policy_forbid", denied["content"][0]["text"])
        us = self.row("customers", "region = 'US'")
        r = self.tool("get_customer", customer_id=us["id"], region="EU")
        self.assertTrue(r["isError"], "the region is the record's own, looked up by the proxy")
        self.assertIn("policy_forbid", r["content"][0]["text"])
        self.assertNotIn(us["email"], json.dumps(r))
        self.assertEqual(self.unsolicited, [], "nothing of the proxy's own lookups reaches the agent")

    def test_04_an_unmapped_tool_and_unlisted_methods_never_reach_the_server(self):
        r = self.tool("run_sql", sql="create table company.pwned_by_mcp (x int)")
        self.assertTrue(r["isError"])
        self.assertIn("default deny", r["content"][0]["text"])
        self.assertIsNone(self.stack.sql("select to_regclass('company.pwned_by_mcp') as t")[0]["t"])
        for method in ("resources/read", "resources/list", "prompts/list", "sampling/createMessage", "logging/setLevel", "completion/complete"):
            msg = self.rpc(method, {"uri": "company://dump"})
            self.assertEqual(msg["error"]["code"], -32601, method)
            self.assertEqual(cards_in(json.dumps(msg).encode()), [])

    def test_05_text_images_and_error_details_are_withheld(self):
        eu = self.row("customers", "region = 'EU'")
        r = self.tool("export_customers_csv", region="EU")
        self.assertIn("withheld", r["content"][0]["text"])
        r = self.tool("customer_card_image", customer_id=eu["id"], region="EU")
        self.assertEqual([c["type"] for c in r["content"]], ["text", "text"])
        self.assertTrue(all("withheld" in c["text"] for c in r["content"]))
        msg = self.rpc("tools/call", {"name": "get_customer", "arguments": {"customer_id": "c-99999", "region": "EU"}})
        self.assertTrue("error" in msg or msg["result"].get("isError"), msg)
        self.assertNotIn("nearest", json.dumps(msg), "the server's error text names another record")
        self.assertEqual(cards_in(json.dumps(msg).encode()), [])

    def test_06_a_forbidden_argument_field_is_refused_and_the_row_is_unchanged(self):
        eu = self.row("customers", "region = 'EU'")
        for changes in ({"tier": "platinum"}, {"phone": "+1", "notes": "x"}, {"addresses": [{"street": "1", "geo": {"lat": 1, "lng": 1}}]}):
            r = self.tool("update_customer", customer_id=eu["id"], region="EU", changes=changes)
            self.assertTrue(r.get("isError"), r)
            self.assertIn("field_denied", r["content"][0]["text"])
            self.assertEqual(self.row("customers", "id = %s", (eu["id"],)), eu)
        r = self.tool("update_customer", customer_id=eu["id"], region="EU", changes={"phone": "+32 2 000"})
        self.assertNotIn("isError", r)
        self.assertEqual(self.row("customers", "id = %s", (eu["id"],))["phone"], "+32 2 000")
        # the echo is masked with the *update* permissions: contact fields, and `geo` is not one
        self.assertEqual(json.loads(r["content"][0]["text"]), {"email": eu["email"], "phone": "+32 2 000", "card": {"number": REDACTED},
                                                               "addresses": [{k: v for k, v in a.items() if k != "geo"} for a in eu["addresses"]]})

    def test_07_a_regional_agent_cannot_change_a_record_of_another_region_through_a_tool(self):
        """(Finding L-1: the tool mapping took the region from the call's arguments.)"""
        us = self.row("customers", "region = 'US'")
        r = self.tool("update_customer", customer_id=us["id"], region="EU", changes={"phone": "+00 L-1 mcp"})
        after = self.row("customers", "id = %s", (us["id"],))
        observe("L-1: update_customer on a US record by an EU agent passing region=EU", self.impl, "written" if after != us else "refused")
        if after != us:
            self.stack.sql("update customers set phone = %s where id = %s", (us["phone"], us["id"]))
        self.assertEqual(after, us)
        self.assertTrue(r.get("isError"))
        self.assertIn("policy_forbid", r["content"][0]["text"])

    def test_07b_a_mapping_that_takes_the_region_from_the_arguments_is_only_as_good_as_the_agents_word(self):
        """The documented risk, kept on purpose (`attrs_from_request`); the proxy names the tool when it starts."""
        us = self.row("customers", "region = 'US'")
        r = self.tool("update_customer_as_claimed", customer_id=us["id"], region="EU", changes={"phone": "+00 claimed"})
        after = self.row("customers", "id = %s", (us["id"],))
        self.stack.sql("update customers set phone = %s where id = %s", (us["phone"], us["id"]))
        self.assertNotIn("isError", r)
        self.assertEqual(after["phone"], "+00 claimed")
        self.assertIn("tool update_customer_as_claimed trusts request-supplied attributes: region", self.stderr_path.read_text())

    def test_08_spend_budget_and_approval_against_rows_actually_written(self):
        eu = self.row("customers", "region = 'EU'")
        mk = lambda n, amount: {"id": f"r-mcp-{self.impl}-{n}", "order_id": f"o-mcp-{n}", "customer_id": eu["id"], "region": "EU", "amount": amount, "currency": "EUR",
                                "reason": "late", "requested_by": "anna"}
        ok = self.tool("create_refund", refund=mk(1, 5000))
        self.assertNotIn("isError", ok)
        self.assertEqual(json.loads(ok["content"][0]["text"]), {**mk(1, 5000), "internal_note": "fraud score 0.11"})
        held = self.tool("create_refund", refund=mk(2, 9000))
        self.assertTrue(held["isError"])
        self.assertEqual(self.stack.sql("select 1 from refunds where id = %s", (mk(2, 0)["id"],)), [])
        aid = re.search(r"id ([0-9a-f]{24})", held["content"][0]["text"]).group(1)
        self.assertTrue(self.stack.admin("approve", {"approval_id": aid, "by": "elena"}).get("ok"))
        self.assertNotIn("isError", self.tool("create_refund", refund=mk(2, 9000)))
        self.assertNotIn("isError", self.tool("create_refund", refund=mk(3, 5000)))
        over = self.tool("create_refund", refund=mk(4, 1100))
        self.assertTrue(over["isError"])
        self.assertIn("budget_exceeded", over["content"][0]["text"])
        for bad in (mk(5, "100"), {k: v for k, v in mk(5, 100).items() if k != "currency"}, {**mk(5, 100), "status": "paid"}):
            self.assertTrue(self.tool("create_refund", refund=bad).get("isError"), bad)
        rows = self.stack.sql("select id, amount, origin from refunds where id like %s order by id", (f"r-mcp-{self.impl}-%",))
        self.assertEqual([(x["id"], x["amount"], x["origin"]) for x in rows], [(mk(1, 0)["id"], 5000, "mcp"), (mk(2, 0)["id"], 9000, "mcp"), (mk(3, 0)["id"], 5000, "mcp")])
        self.assertEqual(self.stack.state()["ledger"][self.grant_now["token_id"]], {"EUR": 19000})

    def test_09_a_revoked_user_stops_tool_calls(self):
        eu = self.row("customers", "region = 'EU'")
        self.assertNotIn("isError", self.tool("get_customer", customer_id=eu["id"], region="EU"))
        self.assertTrue(self.stack.admin("revoke", {"token_id": self.grant_now["token_id"]}).get("ok"))
        r = self.tool("get_customer", customer_id=eu["id"], region="EU")
        self.assertTrue(r["isError"])
        self.assertIn("token_revoked", r["content"][0]["text"])
        self.token_file.write_text("")
        self.assertTrue(self.tool("get_customer", customer_id=eu["id"], region="EU")["isError"])

    def test_10_other_roles_through_the_same_tools(self):
        vendor = self.row("vendors", "true")
        emp = self.row("employees", "id = 'ben'")
        for user, role in (("karin", "treasury"), ("gina", "ap-clerk"), ("oskar", "hr-manager"), ("carla", "auditor")):
            self.token_file.write_text(self.stack.issue(user, role, ORACLE.task(role, "mcp"))["token"])
            r = self.tool("get_vendor", vendor_id=vendor["id"])
            if ORACLE.may(role, "read", "procurement.vendor"):
                self.assertEqual(r["structuredContent"], json.loads(json.dumps(ORACLE.view("procurement.vendor", shape("vendors", vendor), role))), user)
            else:
                self.assertTrue(r.get("isError"), user)
            r = self.tool("get_employee", employee_id="ben")
            if ORACLE.may(role, "read", "hr.employee"):
                self.assertEqual(r["structuredContent"], json.loads(json.dumps(ORACLE.view("hr.employee", shape("employees", emp), role))), user)
            else:
                self.assertTrue(r.get("isError"), user)

    def test_90_the_database_credential_and_card_numbers_never_reach_the_agent(self):
        eu = self.row("customers", "region = 'EU'")
        self.tool("get_customer", customer_id=eu["id"], region="EU")
        self.rpc("tools/call", {"name": "create_refund", "arguments": {"refund": {"id": "r-00001", "order_id": "o", "customer_id": eu["id"], "region": "EU", "amount": 100,
                                                                                 "currency": "EUR", "reason": "dup", "requested_by": "anna"}}})
        password = re.search(r"://[^:]+:([^@]+)@", self.stack.dsn).group(1).encode()
        blobs = type(self).seen
        self.assertGreater(len(blobs), 10)
        self.assertFalse([1 for b in blobs if password in b or cards_in(b)])
        self.assertNotIn(password, self.stderr_path.read_bytes())
        v = self.stack.admin("audit_verify")
        self.assertTrue(v.get("ok"), v)
        observe("MCP: lines received by the agent and searched for the DB password and card numbers", self.impl, len(blobs))


class McpProxyPython(McpProxyCases, unittest.TestCase):
    impl = "python"


class McpProxyRust(McpProxyCases, unittest.TestCase):
    impl = "rust"


if __name__ == "__main__":
    unittest.main()
