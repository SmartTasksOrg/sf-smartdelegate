"""The Python middleware and the SQL connector."""
import json
import os
import shutil
import sqlite3
import tempfile
import unittest

from support import FULL_CAP, conformance_config

from sf_smartdelegate import ApprovalRequired, Denied, Engine, Guard, SqlGuard

ALL_COLUMNS = ["id", "name", "email", "ssn", "region", "tier", "notes"]
ROWS = [
    ("c-1", "Ada Lovelace", "ada@example.com", "123-45-6789", "EU", "gold", "threatened to churn"),
    ("c-2", "Bo Diaz", "bo@example.com", "987-65-4321", "US", "silver", ""),
    ("c-3", "Cy Tran", "cy@example.com", "555-00-1111", "EU", "bronze", ""),
]


ADDRESSES = [{"street": "1 Main St", "zip": "1000", "geo": {"lat": 50, "lng": 4}}]


class NestedAndAttributes:
    """Shared by the SQLite and the PostgreSQL classes: `self.nested` is a table
    (id, region, tenant, addresses, blob) whose `addresses` holds JSON, and
    `self.sql` a SqlGuard on it."""

    def test_rows_are_masked_inside_a_json_column(self):
        rows = self.sql.select(self.token, self.nested, "crm.customer", columns=["id", "addresses"], where={"id": "c-1"})
        self.assertEqual(rows, [{"id": "c-1", "addresses": [{"street": "1 Main St", "zip": "1000"}]}], "addresses[].geo is not for this principal")
        carol = self.engine.issue_token("support-bot", {"actions": ["read"], "resources": ["crm.customer/*"]}, user="carol")["token"]
        full = self.sql.select(carol, self.nested, "crm.customer", columns=["id", "addresses"], where={"id": "c-1"})
        self.assertEqual(full[0]["addresses"], ADDRESSES)

    def test_json_text_that_cannot_be_parsed_is_withheld(self):
        rows = self.sql.select(self.token, self.nested, "crm.customer", columns=["id", "addresses"], where={"id": "c-3"})
        self.assertEqual(rows, [{"id": "c-3"}])

    def test_attributes_the_caller_states(self):
        t = self.engine.issue_token("support-bot", FULL_CAP, user="alice", tenant="acme")["token"]
        # what the caller states is not checked against the rows: this table mixes tenants, and the
        # other tenant's EU row comes back too. One table per tenant, or row_attrs (next test)
        self.assertEqual([r["id"] for r in self.sql.select(t, self.nested, "crm.customer", columns=["id"], attrs={"tenant": "acme"})], ["c-1", "c-3", "c-9"])
        with self.assertRaises(Denied) as cm:
            self.sql.select(t, self.nested, "crm.customer", columns=["id"], attrs={"tenant": "other-co"})
        self.assertEqual(cm.exception.reason, "tenant_mismatch")
        sql, params, d = self.sql.build_select(t, self.nested, "crm.customer", columns=["id"], attrs={"tenant": "acme"})
        self.assertEqual(d["effect"], "allow")

    def test_one_decision_per_row_on_the_rows_own_attributes(self):
        t = self.engine.issue_token("support-bot", FULL_CAP, user="alice", tenant="acme")["token"]
        rows = self.sql.select(t, self.nested, "crm.customer", columns=["id", "addresses", "ssn"], row_attrs={"tenant": "tenant", "region": "region"}, id_column="id")
        # c-1 and c-3: acme and EU. c-2 is US (the policy's row filter), c-9 is another tenant's
        self.assertEqual([r["id"] for r in rows], ["c-1", "c-3"])
        self.assertEqual(rows[0], {"id": "c-1", "addresses": [{"street": "1 Main St", "zip": "1000"}]})
        self.assertNotIn("tenant", rows[0])
        one = self.engine.issue_token("support-bot", {"actions": ["read"], "resources": ["crm.customer/c-3"]}, user="alice", tenant="acme")["token"]
        rows = self.sql.select(one, self.nested, "crm.customer", columns=["id"], row_attrs={"tenant": "tenant", "region": "region"}, id_column="id")
        self.assertEqual(rows, [{"id": "c-3"}], "the capability names one record: the others are dropped row by row")
        self.assertEqual(self.sql.select(t, self.nested, "crm.customer", columns=["id"], row_attrs={"tenant": "tenant"}, where={"ssn": "x"}), [])
        self.assertEqual(self.sql.select(t, self.nested, "crm.customer", columns=["id"], row_attrs={"tenant": "tenant"}), [],
                         "the row filter names `region`, which was not fetched: nothing can be shown")
        self.engine.revoke(self.engine.inspect_token(t)["claims"]["jti"])
        with self.assertRaises(Denied) as cm:
            self.sql.select(t, self.nested, "crm.customer", columns=["id"], row_attrs={"tenant": "tenant", "region": "region"})
        self.assertEqual(cm.exception.reason, "token_revoked")


NESTED_ROWS = [("c-1", "EU", "acme", json.dumps(ADDRESSES), "111"), ("c-2", "US", "acme", "[]", "222"),
               ("c-3", "EU", "acme", "not json", "333"), ("c-9", "EU", "other-co", json.dumps(ADDRESSES), "999")]


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="smartdelegate-g-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.engine = Engine(conformance_config(os.path.join(self.dir, "state")))
        self.addCleanup(self.engine.close)
        self.token = self.engine.issue_token("support-bot", FULL_CAP, user="alice")["token"]
        self.current = self.token
        self.guard = Guard(self.engine, token=lambda: self.current)


class GuardTests(Base):
    def test_tool_output_is_masked_before_it_is_returned(self):
        calls = []

        @self.guard.tool(action="read", resource="crm.customer", id="customer_id")
        def get_customer(customer_id):
            calls.append(customer_id)
            return {"id": customer_id, "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU", "notes": "x"}

        self.assertEqual(get_customer("c-1"), {"id": "c-1", "email": "ada@example.com", "region": "EU"})
        self.assertEqual(calls, ["c-1"])

    def test_denied_tool_never_runs(self):
        ran = []

        @self.guard.tool(action="delete", resource="crm.customer", id="customer_id")
        def delete_customer(customer_id):
            ran.append(customer_id)

        with self.assertRaises(Denied) as cm:
            delete_customer("c-1")
        self.assertEqual(cm.exception.reason, "capability_action")
        self.assertEqual(ran, [])

    def test_input_fields_are_checked_strictly(self):
        saved = []

        @self.guard.tool(action="update", resource="crm.customer", id="customer_id", input="changes")
        def update_customer(customer_id, changes):
            saved.append(changes)
            return {"id": customer_id, **changes}

        self.assertEqual(update_customer("c-1", {"email": "new@example.com"}), {"email": "new@example.com"})
        with self.assertRaises(Denied) as cm:
            update_customer("c-1", {"tier": "platinum"})
        self.assertEqual(cm.exception.reason, "field_denied")
        self.assertEqual(saved, [{"email": "new@example.com"}])

    def test_spend_budget_and_approval(self):
        paid = []

        @self.guard.tool(action="create", resource="billing.refund", id="order_id", spend=lambda a: ("EUR", a["amount"]))
        def refund(order_id, amount):
            paid.append(amount)
            return {"order_id": order_id, "amount": amount, "currency": "EUR", "internal_note": "fraud score 0.2"}

        self.assertEqual(refund("o-1", 5000), {"order_id": "o-1", "amount": 5000, "currency": "EUR"})
        with self.assertRaises(ApprovalRequired) as cm:
            refund("o-2", 15000)
        self.assertEqual(paid, [5000])
        self.engine.approve(cm.exception.approval_id, by="bob")
        self.assertEqual(refund("o-2", 15000)["amount"], 15000)
        with self.assertRaises(Denied) as cm2:
            refund("o-3", 1000)  # 5000 + 15000 + 1000 > 20000
        self.assertEqual(cm2.exception.reason, "budget_exceeded")
        self.assertEqual(paid, [5000, 15000])

    def test_sub_agent_token_narrows_what_the_same_tool_returns(self):
        @self.guard.tool(action="read", resource="crm.customer", id="customer_id")
        def get_customer(customer_id):
            return {"id": customer_id, "email": "ada@example.com", "tier": "gold", "region": "EU"}

        self.current = self.engine.exchange_token(self.token, "refund-helper", cap={"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["pii"]}, ttl=300)["token"]
        self.assertEqual(get_customer("c-1"), {"id": "c-1", "tier": "gold", "region": "EU"})
        with self.assertRaises(Denied):
            get_customer("c-2")

    def test_revoked_token_stops_the_tool(self):
        @self.guard.tool(action="read", resource="crm.customer", id="customer_id")
        def get_customer(customer_id):
            return {"id": customer_id}

        self.engine.revoke(self.engine.inspect_token(self.token)["claims"]["jti"])
        with self.assertRaises(Denied) as cm:
            get_customer("c-1")
        self.assertEqual(cm.exception.reason, "token_revoked")


class SqlTests(NestedAndAttributes, Base):
    nested = "nested_customers"

    def setUp(self):
        super().setUp()
        self.db = sqlite3.connect(":memory:")
        self.db.execute("create table nested_customers (id text, region text, tenant text, addresses text, ssn text)")
        self.db.executemany("insert into nested_customers values (?,?,?,?,?)", NESTED_ROWS)
        self.db.execute("create table customers (id text, name text, email text, ssn text, region text, tier text, notes text)")
        self.db.executemany("insert into customers values (?,?,?,?,?,?,?)", ROWS)
        self.sql = SqlGuard(self.engine, self.db)

    def test_select_names_only_permitted_columns_and_adds_the_row_filter(self):
        sql, params, _ = self.sql.build_select(self.token, "customers", "crm.customer", columns=["id", "email", "ssn", "notes"])
        self.assertEqual(sql, 'SELECT "id", "email" FROM "customers" WHERE "region" = ?')
        self.assertEqual(params, ["EU"])
        rows = self.sql.select(self.token, "customers", "crm.customer", columns=["id", "email", "ssn", "notes"])
        self.assertEqual(rows, [{"id": "c-1", "email": "ada@example.com"}, {"id": "c-3", "email": "cy@example.com"}])

    def test_asking_for_every_column_returns_only_permitted_ones(self):
        rows = self.sql.select(self.token, "customers", "crm.customer", columns=ALL_COLUMNS, where={"id": "c-1"})
        self.assertEqual(sorted(rows[0]), ["email", "id", "name", "region", "tier"])
        self.assertEqual(len(rows), 1)
        self.assertNotIn("ssn", rows[0])
        self.assertNotIn("notes", rows[0])
        self.assertEqual(rows[0]["email"], "ada@example.com")

    def test_cannot_filter_on_a_hidden_column(self):
        with self.assertRaises(Denied):
            self.sql.select(self.token, "customers", "crm.customer", columns=["id"], where={"ssn": "123-45-6789"})

    def test_only_hidden_columns_requested_is_a_denial(self):
        with self.assertRaises(Denied):
            self.sql.select(self.token, "customers", "crm.customer", columns=["ssn"])

    def test_identifiers_and_values_cannot_inject_sql(self):
        with self.assertRaises(ValueError):
            self.sql.select(self.token, 'customers"; drop table customers; --', "crm.customer", columns=["id"])
        rows = self.sql.select(self.token, "customers", "crm.customer", columns=["id"], where={"id": "c-1' OR '1'='1"})
        self.assertEqual(rows, [])
        self.assertEqual(self.db.execute("select count(*) from customers").fetchone()[0], 3)

    def test_denied_principal_gets_no_query(self):
        t = self.engine.issue_token("support-bot", {"actions": ["create"], "resources": ["billing.refund/*"]}, user="alice")["token"]
        with self.assertRaises(Denied):
            self.sql.build_select(t, "customers", "crm.customer", columns=["id"])

    def test_compliance_user_sees_all_rows_and_columns(self):
        t = self.engine.issue_token("support-bot", {"actions": ["read"], "resources": ["crm.customer/*"]}, user="carol")["token"]
        rows = self.sql.select(t, "customers", "crm.customer", columns=["id", "ssn"])
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["ssn"], "123-45-6789")


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(os.environ.get("SMARTDELEGATE_PG_DSN"), "set SMARTDELEGATE_PG_DSN (and install psycopg2) to run against PostgreSQL")
class PostgresTests(NestedAndAttributes, Base):
    nested = "smartdelegate_nested"

    """The same connector against a real PostgreSQL server."""

    def setUp(self):
        super().setUp()
        import psycopg2

        self.db = psycopg2.connect(os.environ["SMARTDELEGATE_PG_DSN"])
        self.addCleanup(self.db.close)
        cur = self.db.cursor()
        cur.execute("drop table if exists smartdelegate_customers")
        cur.execute("create table smartdelegate_customers (id text, name text, email text, ssn text, region text, tier text, notes text)")
        cur.executemany("insert into smartdelegate_customers values (%s,%s,%s,%s,%s,%s,%s)", ROWS)
        # addresses is JSONB where it can be; the row that is not JSON stays text in a second column type
        cur.execute("drop table if exists smartdelegate_nested")
        cur.execute("create table smartdelegate_nested (id text, region text, tenant text, addresses jsonb, ssn text)")
        cur.executemany("insert into smartdelegate_nested values (%s,%s,%s,%s,%s)", [r if r[0] != "c-3" else (r[0], r[1], r[2], None, r[4]) for r in NESTED_ROWS])
        self.db.commit()
        self.sql = SqlGuard(self.engine, self.db, paramstyle="format")

    def tearDown(self):
        self.db.rollback()
        self.db.cursor().execute("drop table if exists smartdelegate_customers")
        self.db.cursor().execute("drop table if exists smartdelegate_nested")
        self.db.commit()

    def test_json_text_that_cannot_be_parsed_is_withheld(self):
        # JSONB cannot hold text that is not JSON; a NULL stays a NULL
        rows = self.sql.select(self.token, self.nested, "crm.customer", columns=["id", "addresses"], where={"id": "c-3"})
        self.assertEqual(rows, [{"id": "c-3", "addresses": None}])

    def test_column_and_row_filtering(self):
        rows = self.sql.select(self.token, "smartdelegate_customers", "crm.customer", columns=["id", "email", "ssn", "notes"])
        self.assertEqual(sorted(r["id"] for r in rows), ["c-1", "c-3"])
        self.assertEqual(set(rows[0]), {"id", "email"})

    def test_values_are_bound_not_interpolated(self):
        rows = self.sql.select(self.token, "smartdelegate_customers", "crm.customer", columns=ALL_COLUMNS, where={"id": "c-1' OR '1'='1"})
        self.assertEqual(rows, [])
        with self.assertRaises(Denied):
            self.sql.select(self.token, "smartdelegate_customers", "crm.customer", columns=["id"], where={"ssn": "123-45-6789"})

    def test_compliance_user_sees_all_rows(self):
        t = self.engine.issue_token("support-bot", {"actions": ["read"], "resources": ["crm.customer/*"]}, user="carol")["token"]
        self.assertEqual(len(self.sql.select(t, "smartdelegate_customers", "crm.customer", columns=["id", "ssn"])), 3)
