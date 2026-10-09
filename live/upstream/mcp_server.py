"""company-mcp: an MCP server (stdio, newline-delimited JSON-RPC 2.0) whose
tools read and write the Kestrel Works database.

    COMPANY_MCP_DSN=postgresql://... [COMPANY_MCP_TENANT=kestrel] python3 -m live.upstream.mcp_server

The framing is that of examples/fake_mcp_server.py; the data is real rows. The
database credential is this process's own: the agent talks to it only through
`smartdelegate mcp-proxy`, which starts it. Like the stand-in, it is careless
on purpose: it logs whole records as notifications, tucks them into `_meta`,
asks the client to sample a prompt containing a record, offers a
`resources/read` dump and has one tool (`run_sql`) nobody should be able to
reach.
"""
from __future__ import annotations

import base64
import json
import os
import sys

import psycopg2
import psycopg2.extras

try:
    from .shapes import shape
except ImportError:  # run as a script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from shapes import shape

OBJ = {"type": "object"}
TOOLS = [
    {"name": "get_customer", "description": "Fetch one customer", "inputSchema": {"type": "object", "properties": {"customer_id": {"type": "string"}, "region": {"type": "string"}}}},
    {"name": "list_customers", "description": "List customers (every region)", "inputSchema": OBJ},
    {"name": "update_customer", "description": "Change customer fields", "inputSchema": OBJ},
    {"name": "update_customer_as_claimed", "description": "The same as update_customer (a second name, mapped differently by the proxy in the tests)", "inputSchema": OBJ},
    {"name": "create_refund", "description": "Insert a refund", "inputSchema": OBJ},
    {"name": "get_vendor", "description": "Fetch one vendor with bank details", "inputSchema": OBJ},
    {"name": "list_invoices", "description": "List invoices", "inputSchema": OBJ},
    {"name": "get_employee", "description": "Fetch one employee", "inputSchema": OBJ},
    {"name": "export_customers_csv", "description": "Plain-text export", "inputSchema": OBJ},
    {"name": "customer_card_image", "description": "An image of the customer's card", "inputSchema": OBJ},
    {"name": "run_sql", "description": "Run any SQL. Dangerous and unmapped", "inputSchema": OBJ},
]
WRITABLE = ("name", "email", "phone", "tier", "notes", "addresses")


def out(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg, default=str) + "\n")
    sys.stdout.flush()


def reply(id_, result) -> None:
    out({"jsonrpc": "2.0", "id": id_, "result": result})


def text(value) -> dict:
    return {"type": "text", "text": value if isinstance(value, str) else json.dumps(value, default=str)}


class ToolError(Exception):
    pass


def main() -> int:
    dsn = os.environ.get("COMPANY_MCP_DSN", "")
    tenant = os.environ.get("COMPANY_MCP_TENANT", "kestrel")
    if not dsn:
        print("company-mcp: set COMPANY_MCP_DSN", file=sys.stderr)
        return 2
    conn = psycopg2.connect(dsn, connect_timeout=15, options="-c search_path=company -c statement_timeout=30000")
    conn.autocommit = True
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def one(table: str, resource: str, rid, key: str = "id") -> dict:
        cur.execute(f"select * from {table} where tenant = %s and {key} = %s", (tenant, rid))
        row = cur.fetchone()
        if row is None:
            cur.execute(f"select * from {table} where tenant = %s order by {key} limit 1", (tenant,))
            raise ToolError("not found; the nearest record is " + json.dumps(shape(resource, cur.fetchone()), default=str))
        return shape(resource, row)

    def call(name: str, a: dict):
        if name == "get_customer":
            rec = one("customers", "customers", a.get("customer_id"))
            out({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": rec}})
            out({"jsonrpc": "2.0", "id": "srv-sampling-1", "method": "sampling/createMessage",
                 "params": {"messages": [{"role": "user", "content": text(rec)}], "maxTokens": 10}})
            return {"content": [text(rec)], "structuredContent": rec, "_meta": {"raw": rec}}
        if name == "list_customers":
            cur.execute("select * from customers where tenant = %s order by id limit %s", (tenant, max(1, min(int(a.get("limit") or 50), 5000))))
            rows = [shape("customers", r) for r in cur.fetchall()]
            return {"content": [text(rows)], "structuredContent": rows}
        if name in ("update_customer", "update_customer_as_claimed"):
            changes = a.get("changes") if isinstance(a.get("changes"), dict) else {}
            cols = [c for c in WRITABLE if c in changes]
            if not cols or set(changes) - set(WRITABLE):
                raise ToolError("unknown or missing fields")
            one("customers", "customers", a.get("customer_id"))
            cur.execute(f"update customers set {', '.join(c + ' = %s' for c in cols)} where tenant = %s and id = %s",
                        (*[json.dumps(changes[c]) if c == "addresses" else changes[c] for c in cols], tenant, a.get("customer_id")))
            return {"content": [text(one("customers", "customers", a.get("customer_id")))]}
        if name == "create_refund":
            r = a.get("refund") if isinstance(a.get("refund"), dict) else {}
            customer = one("customers", "customers", r.get("customer_id"))
            if customer["region"] != r.get("region"):
                raise ToolError("the refund's region is not the customer's: " + json.dumps(customer, default=str))
            cur.execute("insert into refunds (id, tenant, order_id, customer_id, region, amount, currency, reason, status, requested_by, internal_note, origin) "
                        "values (%s,%s,%s,%s,%s,%s,%s,%s,'requested',%s,'fraud score 0.11','mcp')",
                        (r.get("id"), tenant, r.get("order_id"), r.get("customer_id"), r.get("region"), r.get("amount"), r.get("currency"), r.get("reason"), r.get("requested_by")))
            return {"content": [text(one("refunds", "refunds", r.get("id")))]}
        if name == "get_vendor":
            rec = one("vendors", "vendors", a.get("vendor_id"))
            return {"content": [text(rec)], "structuredContent": rec}
        if name == "list_invoices":
            cur.execute("select * from invoices where tenant = %s order by id limit %s", (tenant, max(1, min(int(a.get("limit") or 50), 2000))))
            rows = [shape("invoices", r) for r in cur.fetchall()]
            return {"content": [text(rows)], "structuredContent": rows}
        if name == "get_employee":
            rec = one("employees", "employees", a.get("employee_id"))
            return {"content": [text(rec)], "structuredContent": rec}
        if name == "export_customers_csv":
            cur.execute("select id, name, email, card_number from customers where tenant = %s order by id limit 50", (tenant,))
            return {"content": [text("id,name,email,card_number\n" + "".join(f"{r['id']},{r['name']},{r['email']},{r['card_number']}\n" for r in cur.fetchall()))]}
        if name == "customer_card_image":
            rec = one("customers", "customers", a.get("customer_id"))
            blob = base64.b64encode(("CARD " + rec["card"]["number"]).encode()).decode()
            return {"content": [{"type": "image", "data": blob, "mimeType": "image/png"},
                                {"type": "resource", "resource": {"uri": "company://card", "text": rec["card"]["number"]}}]}
        if name == "run_sql":
            cur.execute(str(a.get("sql") or "select 1"))
            return {"content": [text(cur.fetchall() if cur.description else "ok")]}
        raise ToolError("no such tool")

    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if not isinstance(msg, dict):
            continue
        method, id_ = msg.get("method"), msg.get("id")
        if id_ is None or method is None:
            continue    # notifications, and replies to our own requests
        if method == "initialize":
            reply(id_, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "resources": {}, "logging": {}},
                        "serverInfo": {"name": "company-mcp", "version": "0"}})
        elif method == "ping":
            reply(id_, {})
        elif method == "tools/list":
            reply(id_, {"tools": TOOLS})
        elif method == "resources/read":
            reply(id_, {"contents": [{"uri": "company://dump", "text": json.dumps(one("customers", "customers", "c-00001"), default=str)}]})
        elif method == "tools/call":
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            try:
                reply(id_, call(str(params.get("name")), args))
            except ToolError as e:
                out({"jsonrpc": "2.0", "id": id_, "error": {"code": -32000, "message": str(e)}})
            except psycopg2.Error as e:
                out({"jsonrpc": "2.0", "id": id_, "error": {"code": -32001, "message": "database error: " + str(e).strip()}})
        else:
            out({"jsonrpc": "2.0", "id": id_, "error": {"code": -32601, "message": "no such method"}})
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
