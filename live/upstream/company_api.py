"""company-api: a REST service on top of the Kestrel Works database.

    COMPANY_API_KEY=... COMPANY_API_DSN=postgresql://... python3 -m live.upstream.company_api [[host:]port]

The listen address is `[host:]port` on the command line, or COMPANY_API_HOST
(default 127.0.0.1) and COMPANY_API_PORT (default 0: any free port). The key
and the DSN can also be given as files: COMPANY_API_KEY_FILE,
COMPANY_API_DSN_FILE (secrets mounted into a container).

A separate process with a credential of its own: every request must carry
`X-Api-Key`. The agent never has that key; the SmartDelegate HTTP proxy adds
it. A request that arrives with an `Authorization` header is refused, because
the proxy must not pass the agent's capability token on.

It behaves like an API nobody wrote with agents in mind: it returns every
column, every region of a tenant, debug data in list envelopes, record data
in error bodies, CSV and binary exports, a redirect, a slow endpoint and a
bulk endpoint of any size. It does real SQL: reads and writes hit PostgreSQL.

    GET    /healthz                                   no key
    GET    /{tenant}/{resource}                       ?limit=&offset=   (every region; `region` is accepted and ignored)
    GET    /{tenant}/{resource}/{id}
    PATCH  /{tenant}/customers/{id}                   ?region=R: refused (409) unless the record is in region R
    PATCH  /{tenant}/legacy/customers/{id}            no cross-check at all
    PATCH  /{tenant}/vendors/{id}                     {"bank": {"iban", "bic"}}
    PATCH  /{tenant}/invoices/{id}                    {"status", "po_id"}
    POST   /{tenant}/tickets
    POST   /{tenant}/refunds                          the refund's region must be the customer's (409)
    POST   /{tenant}/payments
    GET    /{tenant}/export/customers.csv             text/csv
    GET    /{tenant}/export/statement.pdf             application/pdf (binary)
    GET    /{tenant}/moved/customers/{id}             302 to /{tenant}/customers/{id}, the record in the body
    GET    /{tenant}/slow/customers/{id}?seconds=N    answers after N seconds
    GET    /{tenant}/bulk/customers?mb=N              a JSON list of at least N MB
    GET    /{tenant}/error/{status}                   that status, with a record in the body

Query parameters: the FIRST value of a repeated parameter is used (the
behaviour of `parse_qs(...)[name][0]`, Flask's `request.args.get`, Go's
`url.Values.Get`).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg2
import psycopg2.extras
import psycopg2.pool

try:
    from .shapes import RESOURCES, shape
except ImportError:  # run as a script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from shapes import RESOURCES, shape

MAX_BODY = 1 << 20
WRITABLE = {
    "customers": ("name", "email", "phone", "tier", "notes", "addresses"),
    "invoices": ("status", "po_id"),
}
INSERT = {
    "tickets": ("id", "customer_id", "region", "subject", "body", "status", "priority", "internal_notes"),
    "refunds": ("id", "order_id", "customer_id", "region", "amount", "currency", "reason", "requested_by"),
    "payments": ("id", "kind", "ref", "vendor_id", "amount", "currency", "requested_by", "approved_by", "paid_by"),
}


class Api:
    def __init__(self, dsn: str, key: str):
        self.key = key
        self.pool = psycopg2.pool.ThreadedConnectionPool(1, 24, dsn, connect_timeout=15, options="-c search_path=company -c statement_timeout=60000")
        self.gate = threading.BoundedSemaphore(24)

    def run(self, fn):
        with self.gate:
            conn = self.pool.getconn()
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    out = fn(cur)
                conn.commit()
                return out
            except BaseException:
                conn.rollback()
                raise
            finally:
                self.pool.putconn(conn)


class HttpError(Exception):
    def __init__(self, status: int, body: dict):
        self.status, self.body = status, body


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "company-api"
    disable_nagle_algorithm = True
    timeout = 120

    def log_message(self, *a):
        pass

    # ---- plumbing
    def _send(self, status: int, payload: bytes, ctype: str = "application/json", headers: dict | None = None):
        self._status = status
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, status: int, body, headers: dict | None = None):
        self._send(status, json.dumps(body, default=str).encode("utf-8"), headers=headers)

    def _log(self, key_ok: bool):
        path, _, query = self.path.partition("?")
        try:
            self.server.api.run(lambda cur: cur.execute(
                "insert into api_request_log (method, path, query, status, key_ok, had_authorization, header_names) values (%s,%s,%s,%s,%s,%s,%s)",
                (self.command, path[:500], query[:500], getattr(self, "_status", 0), key_ok, self.headers.get("Authorization") is not None,
                 ",".join(sorted(k.lower() for k in self.headers.keys())))))
        except Exception:
            pass

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise HttpError(400, {"error": "bad Content-Length"})
        if n > MAX_BODY:
            raise HttpError(413, {"error": "body too large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise HttpError(400, {"error": "body is not JSON"})
        if not isinstance(body, dict):
            raise HttpError(400, {"error": "body must be an object"})
        return body

    def _handle(self):
        api = self.server.api
        self._status = 0
        path, _, query = self.path.partition("?")
        if path == "/healthz":
            return self._json(200, {"ok": True})
        key_ok = self.headers.get("X-Api-Key") == api.key
        try:
            if not key_ok:
                raise HttpError(401, {"error": "bad api key"})
            if self.headers.get("Authorization"):
                raise HttpError(400, {"error": "unexpected Authorization header"})
            q = {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}   # first value wins
            parts = [urllib.parse.unquote(p) for p in path.strip("/").split("/")]
            self._route(api, parts, q)
        except HttpError as e:
            self._json(e.status, e.body)
        except psycopg2.Error as e:
            # a careless API: database errors go straight into the response
            self._json(409 if isinstance(e, psycopg2.IntegrityError) else 500, {"error": "database error", "detail": str(e).strip()})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        finally:
            self._log(key_ok)

    do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = _handle

    # ---- routes
    def _route(self, api: Api, parts: list, q: dict):
        m = self.command
        if len(parts) < 2:
            raise HttpError(404, {"error": "not found"})
        tenant, head = parts[0], parts[1]

        def one(resource: str, rid: str) -> dict:
            table, _, keycol = RESOURCES[resource]
            row = api.run(lambda cur: (cur.execute(f"select * from {table} where tenant = %s and {keycol} = %s", (tenant, rid)), cur.fetchone())[1])
            if row is None:
                # an error body that says more than it should
                near = api.run(lambda cur: (cur.execute(f"select * from {table} where tenant = %s order by {keycol} limit 1", (tenant,)), cur.fetchone())[1])
                raise HttpError(404, {"error": "not found", "did_you_mean": shape(resource, near) if near else None})
            return shape(resource, row)

        if head in RESOURCES and m == "GET" and len(parts) == 2:
            table, _, keycol = RESOURCES[head]
            limit = max(1, min(int(q.get("limit", "100")), 10000)) if q.get("limit", "100").isdigit() else 100
            offset = int(q.get("offset", "0")) if q.get("offset", "0").isdigit() else 0
            sql = f"select * from {table} where tenant = %s order by {keycol} limit %s offset %s"
            rows = api.run(lambda cur: (cur.execute(sql, (tenant, limit + 1, offset)), cur.fetchall())[1])
            total = api.run(lambda cur: (cur.execute(f"select count(*) as n from {table} where tenant = %s", (tenant,)), cur.fetchone())[1])["n"]
            more = len(rows) > limit
            return self._json(200, {"items": [shape(head, r) for r in rows[:limit]], "next": offset + limit if more else None, "total": total,
                                    "debug": {"sql": sql, "first_row": shape(head, rows[0]) if rows else None}})
        if head in RESOURCES and m == "GET" and len(parts) == 3:
            return self._json(200, one(head, parts[2]))

        if m == "PATCH" and ((head == "customers" and len(parts) == 3) or (head == "legacy" and len(parts) == 4 and parts[2] == "customers")):
            rid = parts[-1]
            body = self._body()
            cols = [c for c in WRITABLE["customers"] if c in body]
            if not cols or set(body) - set(WRITABLE["customers"]):
                raise HttpError(422, {"error": "unknown or missing fields", "writable": WRITABLE["customers"]})
            current = one("customers", rid)
            if head == "customers" and "region" in q and q["region"] != current["region"]:
                raise HttpError(409, {"error": "region mismatch", "record": current})
            vals = [json.dumps(body[c]) if c == "addresses" else body[c] for c in cols]
            api.run(lambda cur: cur.execute(f"update customers set {', '.join(c + ' = %s' for c in cols)} where tenant = %s and id = %s", (*vals, tenant, rid)))
            return self._json(200, one("customers", rid))
        if m == "PATCH" and head == "vendors" and len(parts) == 3:
            body = self._body()
            bank = body.get("bank")
            if not isinstance(bank, dict) or set(body) != {"bank"} or set(bank) - {"iban", "bic"} or not bank:
                raise HttpError(422, {"error": "send {\"bank\": {\"iban\", \"bic\"}}"})
            one("vendors", parts[2])
            sets = [("bank_" + k, v) for k, v in bank.items()]
            api.run(lambda cur: cur.execute(f"update vendors set {', '.join(c + ' = %s' for c, _ in sets)} where tenant = %s and id = %s",
                                            (*[v for _, v in sets], tenant, parts[2])))
            return self._json(200, one("vendors", parts[2]))
        if m == "PATCH" and head == "invoices" and len(parts) == 3:
            body = self._body()
            cols = [c for c in WRITABLE["invoices"] if c in body]
            if not cols or set(body) - set(WRITABLE["invoices"]):
                raise HttpError(422, {"error": "unknown or missing fields"})
            one("invoices", parts[2])
            api.run(lambda cur: cur.execute(f"update invoices set {', '.join(c + ' = %s' for c in cols)} where tenant = %s and id = %s",
                                            (*[body[c] for c in cols], tenant, parts[2])))
            return self._json(200, one("invoices", parts[2]))

        if m == "POST" and head in INSERT and len(parts) == 2:
            body = self._body()
            if set(body) - set(INSERT[head]) or "id" not in body:
                raise HttpError(422, {"error": "unknown fields, or no id", "accepted": INSERT[head]})
            row = {c: body.get(c) for c in INSERT[head]}
            row["tenant"] = tenant
            if head == "refunds":
                customer = one("customers", str(row["customer_id"]))
                if customer["region"] != row["region"]:
                    raise HttpError(409, {"error": "the refund's region is not the customer's", "customer": customer})
                row.update(status="requested", internal_note="fraud score 0.11", origin="api")
            elif head == "payments":
                vendor = one("vendors", str(row["vendor_id"]))
                row.update(status="scheduled", beneficiary_name=vendor["name"], beneficiary_iban=vendor["bank"]["iban"], origin="api")
            elif head == "tickets":
                one("customers", str(row["customer_id"]))
                row["internal_notes"] = row.get("internal_notes") or ""
            cols = list(row)
            api.run(lambda cur: cur.execute(f"insert into {RESOURCES[head][0]} ({', '.join(cols)}) values ({', '.join(['%s'] * len(cols))})", [row[c] for c in cols]))
            return self._json(201, one(head, str(row["id"])))

        if m == "GET" and head == "export" and len(parts) == 3 and parts[2] == "customers.csv":
            rows = api.run(lambda cur: (cur.execute("select id, name, email, region, card_number from customers where tenant = %s order by id limit 200", (tenant,)), cur.fetchall())[1])
            text = "id,name,email,region,card_number\n" + "".join(f"{r['id']},{r['name']},{r['email']},{r['region']},{r['card_number']}\n" for r in rows)
            return self._send(200, text.encode("utf-8"), "text/csv; charset=utf-8")
        if m == "GET" and head == "export" and len(parts) == 3 and parts[2] == "statement.pdf":
            row = api.run(lambda cur: (cur.execute("select name, card_number from customers where tenant = %s order by id limit 1", (tenant,)), cur.fetchone())[1])
            blob = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Title (Statement " + f"{row['name']} {row['card_number']}".encode() + b") >>\nendobj\n" + bytes(range(256)) * 8 + b"\n%%EOF\n"
            return self._send(200, blob, "application/pdf")
        if m == "GET" and head == "moved" and len(parts) == 4 and parts[2] == "customers":
            return self._json(302, one("customers", parts[3]), {"Location": f"/{tenant}/customers/{parts[3]}"})
        if m == "GET" and head == "slow" and len(parts) == 4 and parts[2] == "customers":
            try:
                seconds = min(float(q.get("seconds", "1")), 300.0)
            except ValueError:
                seconds = 1.0
            time.sleep(max(0.0, seconds))
            return self._json(200, one("customers", parts[3]))
        if m == "GET" and head == "bulk" and len(parts) == 3 and parts[2] == "customers":
            mb = max(1, min(int(q.get("mb", "1")) if q.get("mb", "1").isdigit() else 1, 256))
            rows = api.run(lambda cur: (cur.execute("select * from customers where tenant = %s order by id limit 200", (tenant,)), cur.fetchall())[1])
            chunk = (",".join(json.dumps(shape("customers", r), default=str) for r in rows)).encode("utf-8")
            reps = (mb * 1024 * 1024) // (len(chunk) + 1) + 1
            self._status = 200
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(2 + reps * len(chunk) + (reps - 1)))
            self.end_headers()
            self.wfile.write(b"[")
            for i in range(reps):
                self.wfile.write((b"," if i else b"") + chunk)
            self.wfile.write(b"]")
            return None
        if m == "GET" and head == "error" and len(parts) == 3 and parts[2].isdigit() and 400 <= int(parts[2]) <= 599:
            row = api.run(lambda cur: (cur.execute("select * from customers where tenant = %s order by id limit 1", (tenant,)), cur.fetchone())[1])
            return self._json(int(parts[2]), {"error": "simulated", "context": shape("customers", row) if row else None})
        raise HttpError(404, {"error": "not found"})


def _setting(name: str) -> str:
    """NAME, or the content of the file NAME_FILE names."""
    if os.environ.get(name):
        return os.environ[name]
    path = os.environ.get(name + "_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError as e:
            print(f"company-api: {name}_FILE: {e}", file=sys.stderr)
    return ""


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    key, dsn = _setting("COMPANY_API_KEY"), _setting("COMPANY_API_DSN")
    if len(key) < 16 or not dsn:
        print("company-api: set COMPANY_API_KEY (16+ characters) and COMPANY_API_DSN (or the _FILE forms)", file=sys.stderr)
        return 2
    host, port = os.environ.get("COMPANY_API_HOST", "127.0.0.1"), os.environ.get("COMPANY_API_PORT", "0")
    if argv:
        h, _, port = argv[0].rpartition(":")
        host = h or host
    try:
        server = ThreadingHTTPServer((host, int(port)), Handler)
    except (OSError, ValueError) as e:
        print(f"company-api: cannot listen on {host}:{port}: {e}", file=sys.stderr)
        return 2
    server.daemon_threads = True
    server.api = Api(dsn, key)
    print(f"company-api on http://{server.server_address[0]}:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
