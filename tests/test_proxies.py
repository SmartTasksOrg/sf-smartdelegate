"""The two enforcement points an agent cannot skip: the HTTP egress proxy and
the MCP proxy. Both run as real processes against stand-in upstreams."""
import json
import os
import re
import subprocess
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from support import CLI, ENV, EXAMPLES, FULL_CAP, Daemon

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http(method, url, token=None, body=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
    try:
        with OPENER.open(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null"), dict(e.headers)


class HttpProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.crm = subprocess.Popen([sys.executable, str(EXAMPLES / "fake_crm.py"), "0"], stdout=subprocess.PIPE, text=True)
        cls.crm_url = re.search(r"http://\S+", cls.crm.stdout.readline()).group(0)
        routes = json.loads((EXAMPLES / "routes.json").read_text())
        routes["upstreams"]["crm"]["base_url"] = "env:CRM_URL"
        routes["upstreams"]["crm2"] = dict(routes["upstreams"]["crm"])     # the same upstream under a second name, for a route of its own
        routes["routes"] += [
            # a write decided on attributes of the record the upstream holds, not on what the agent says
            {"upstream": "crm", "method": "POST", "path": "/guarded/refunds", "action": "create", "resource": "billing.refund",
             "lookup": "/customers/{body.order_id}", "attrs_from_record": {"customer_owner": "name"},
             "spend": {"currency": "body.currency", "amount": "body.amount"}},
            {"upstream": "crm", "method": "POST", "path": "/broken/refunds", "action": "create", "resource": "billing.refund",
             "lookup": "/customers/{body.order_id}", "attrs_from_record": {"customer_owner": "no.such.field"}},
            {"upstream": "crm2", "method": "GET", "path": "/customers/{id}", "action": "read", "resource": "crm.customer", "id": "{id}",
             "lookup": "/customers/{id}", "attrs_from_record": {"region": "region"}},
            {"upstream": "crm", "method": "GET", "path": "/claimed/customers", "action": "read", "resource": "crm.customer", "data_key": "items",
             "attrs_from_request": {"region": "query.region"}, "query": ["region"]},
        ]
        import tempfile
        cls.tmp = tempfile.mkdtemp(prefix="smartdelegate-routes-")
        cls.routes = os.path.join(cls.tmp, "routes.json")
        Path(cls.routes).write_text(json.dumps(routes))
        cls.proxy = Daemon(command="http-proxy", args=["--routes", cls.routes], env={"CRM_API_KEY": "upstream-secret-key", "CRM_URL": cls.crm_url})
        cls.url = cls.proxy.url + "/crm"

    @classmethod
    def tearDownClass(cls):
        cls.proxy.close()
        cls.crm.kill()
        cls.crm.wait()
        cls.crm.stdout.close()

    def issue(self, user="alice", cap=None):
        with open(os.path.join(self.tmp, "cap.json"), "w") as f:
            json.dump(cap or FULL_CAP, f)
        r = self.proxy.cli("token", "issue", "--user", user, "--agent", "support-bot", "--cap", "@" + os.path.join(self.tmp, "cap.json"), "--raw")
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    def test_agent_cannot_reach_the_upstream_directly(self):
        status, _, _ = http("GET", self.crm_url + "/customers/c-1", token=self.issue())
        self.assertIn(status, (400, 401))

    def test_response_is_masked_and_the_upstream_key_is_injected(self):
        status, body, headers = http("GET", self.url + "/customers/c-1", token=self.issue())
        self.assertEqual(status, 200)
        self.assertEqual(body["email"], "ada@example.com")
        self.assertEqual(body["card"], {"last4": "4242", "number": "[REDACTED]"})
        self.assertEqual(body["addresses"], [{"street": "1 Main St", "zip": "1000"}])
        for hidden in ("ssn", "notes"):
            self.assertNotIn(hidden, body)
        self.assertTrue(headers.get("X-SmartDelegate-Decision", "").startswith("d-"))

    def test_row_filter_hides_records_outside_the_users_region(self):
        status, body, _ = http("GET", self.url + "/customers/c-2", token=self.issue())
        self.assertEqual((status, body), (200, None))

    def test_list_envelope_is_filtered_and_unlisted_keys_are_dropped(self):
        status, body, _ = http("GET", self.url + "/customers", token=self.issue())
        self.assertEqual(status, 200)
        self.assertEqual(sorted(body), ["items", "next"])
        self.assertEqual([r["id"] for r in body["items"]], ["c-1"])
        self.assertNotIn("ssn", json.dumps(body))

    def test_no_token_bad_token_no_route(self):
        self.assertEqual(http("GET", self.url + "/customers/c-1")[0], 401)
        status, body, _ = http("GET", self.url + "/customers/c-1", token="abc.def.ghi")
        self.assertEqual((status, body["error"]["code"]), (403, "token_invalid"))
        status, body, _ = http("DELETE", self.url + "/customers/c-1", token=self.issue())
        self.assertEqual((status, body["error"]["code"]), (403, "no_route"))
        status, body, _ = http("GET", self.proxy.url + "/billing/anything", token=self.issue())
        self.assertEqual((status, body["error"]["code"]), (403, "no_route"))

    def test_path_tricks_and_unlisted_query_parameters_are_refused(self):
        t = self.issue()
        for path in ("/customers/..%2F..%2Freport", "/customers/c-1%2F..%2Fc-2", "/customers/..", "/customers/c-1;x=1", "/customers/c-1/../../report"):
            status, body, _ = http("GET", self.url + path, token=t)
            self.assertEqual((status, body["error"]["code"]), (403, "no_route"), path)
        status, body, _ = http("GET", self.url + "/customers/c-1?include=ssn", token=t)
        self.assertEqual((status, body["error"]["code"]), (400, "query_not_allowed"))
        status, body, _ = http("GET", self.url + "/customers?limit=10&debug=1", token=t)
        self.assertEqual((status, body["error"]["code"]), (400, "query_not_allowed"))
        self.assertEqual(http("GET", self.url + "/customers?limit=10", token=t)[0], 200)

    def test_a_query_the_upstream_could_read_differently_is_refused(self):
        t = self.issue()
        for q, code in (("limit=1&limit=2", "query_duplicate"), ("limit=1;cursor=2", "query_ambiguous"), ("=1", "query_ambiguous"),
                        ("limi%74=1", "query_ambiguous"), ("limit=%zz", "query_ambiguous"), ("limit=%", "query_ambiguous"),
                        ("limit=%00", "query_ambiguous"), ("limit=%ff", "query_ambiguous"), ("LIMIT=1", "query_not_allowed"),
                        ("limit=1&cursor=a&limit=3", "query_duplicate")):
            status, body, _ = http("GET", self.url + "/customers?" + q, token=t)
            self.assertEqual((status, body["error"]["code"], body["error"]["by"]), (400, code, "smartdelegate"), q)
        for q in ("limit=10&cursor=a%20b", "limit=10&&cursor=x", "cursor=a+b", "limit"):
            self.assertEqual(http("GET", self.url + "/customers?" + q, token=t)[0], 200, q)

    def raw(self, request: bytes) -> bytes:
        import socket
        host, port = self.proxy.url.split("//")[1].split(":")
        with socket.create_connection((host, int(port)), timeout=10) as c:
            c.sendall(request)
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
        return out

    def test_a_body_not_framed_by_content_length_is_refused_and_the_connection_closed(self):
        t = self.issue()
        head = f"PATCH /crm/customers/c-1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {t}\r\nContent-Type: application/json\r\n"
        hidden = f"GET /crm/customers/c-1 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {t}\r\n\r\n"
        chunked = '{"tier":"platinum"}'
        for extra, status, code in (("Transfer-Encoding: chunked\r\n", b"411", b"length_required"),
                                    ("Transfer-Encoding: chunked\r\nContent-Length: 4\r\n", b"400", b"invalid_input"),
                                    ("Content-Length: 4\r\nTransfer-Encoding: identity\r\n", b"400", b"invalid_input"),
                                    ("Content-Length: 0\r\nContent-Length: 19\r\n", b"400", b"invalid_input"),
                                    ("Content-Length: abc\r\n", b"400", b"invalid_input")):
            out = self.raw((head + extra + "\r\n" + f"{len(chunked):x}\r\n{chunked}\r\n0\r\n\r\n" + hidden).encode())
            self.assertTrue(out.startswith(b"HTTP/1.1 " + status), (extra, out[:80]))
            self.assertIn(code, out)
            self.assertEqual(out.count(b"HTTP/1.1 "), 1, "what followed on the connection must not be read as a second request")
            self.assertNotIn(b"ada@example.com", out)
        carol = self.issue(user="carol", cap={"actions": ["read"], "resources": ["crm.customer/*"]})
        self.assertEqual(http("GET", self.url + "/customers/c-1", token=carol)[1]["tier"], "gold", "nothing was written")

    def test_attributes_from_the_upstream_record(self):
        t = self.issue()
        refund = {"order_id": "c-1", "amount": 100, "currency": "EUR", "reason": "late"}
        self.assertEqual(http("POST", self.url + "/guarded/refunds", token=t, body=refund)[0], 201, "the record exists and the decision allows: forwarded")
        status, body, _ = http("POST", self.url + "/guarded/refunds", token=t, body={**refund, "order_id": "c-404"})
        self.assertEqual((status, body["error"]["code"]), (404, "not_found"))
        self.assertNotIn("123-45-6789", json.dumps(body))
        for bad in ("../report", "c-1/x", "c 1", ""):
            status, body, _ = http("POST", self.url + "/guarded/refunds", token=t, body={**refund, "order_id": bad})
            self.assertEqual((status, body["error"]["code"]), (400, "invalid_input"), bad)
        status, body, _ = http("POST", self.url + "/guarded/refunds", token=t, body={k: v for k, v in refund.items() if k != "order_id"})
        self.assertEqual(status, 400)
        status, body, _ = http("POST", self.url + "/broken/refunds", token=t, body=refund)
        self.assertEqual((status, body["error"]["code"]), (502, "lookup_failed"))
        # a token that does not cover the resource is refused before anything is looked up: the answer
        # is the same whether or not the record exists
        narrow = self.issue(cap={"actions": ["read"], "resources": ["crm.customer/c-1"]})
        for cid in ("c-1", "c-404"):
            status, body, _ = http("POST", self.url + "/guarded/refunds", token=narrow, body={**refund, "order_id": cid})
            self.assertEqual((status, body["error"]["code"]), (403, "capability_action"), cid)
        for cid in ("c-2", "c-404"):
            status, body, _ = http("GET", self.proxy.url + "/crm2/customers/" + cid, token=narrow)
            self.assertEqual((status, body["error"]["code"]), (403, "capability_resource"), cid)
        # a read of the looked-up record is answered from it, masked like any other
        status, body, headers = http("GET", self.proxy.url + "/crm2/customers/c-1", token=t)
        self.assertEqual((status, body.get("email"), (body.get("card") or {}).get("number")), (200, "ada@example.com", "[REDACTED]"), body)
        self.assertNotIn("ssn", body)
        self.assertEqual(http("GET", self.proxy.url + "/crm2/customers/c-404", token=t)[0], 404)

    def test_the_start_log_names_the_routes_that_trust_the_request(self):
        p = subprocess.Popen([*CLI, "http-proxy", "--config", self.proxy.config, "--routes", self.routes, "--listen", "127.0.0.1:0"],
                             stderr=subprocess.PIPE, text=True, env={**ENV, "CRM_URL": self.crm_url, "CRM_API_KEY": "upstream-secret-key"})
        try:
            log = "".join(p.stderr.readline() for _ in range(3))
        finally:
            p.kill()
            p.wait()
            p.stderr.close()
        self.assertIn("(GET /crm/claimed/customers) trusts request-supplied attributes: region", log)
        self.assertIn("warning: route", log)
        self.assertNotIn("guarded", log)

    def test_capability_limits_which_record(self):
        t = self.issue(cap={"actions": ["read"], "resources": ["crm.customer/c-1"]})
        self.assertEqual(http("GET", self.url + "/customers/c-1", token=t)[0], 200)
        status, body, _ = http("GET", self.url + "/customers/c-3", token=t)
        self.assertEqual((status, body["error"]["code"]), (403, "capability_resource"))

    def test_write_with_a_forbidden_field_never_reaches_the_upstream(self):
        t = self.issue()
        status, body, _ = http("PATCH", self.url + "/customers/c-1", token=t, body={"tier": "platinum"})
        self.assertEqual((status, body["error"]["code"]), (403, "field_denied"))
        carol = self.issue(user="carol", cap={"actions": ["read"], "resources": ["crm.customer/*"]})
        self.assertEqual(http("GET", self.url + "/customers/c-1", token=carol)[1]["tier"], "gold")
        status, body, _ = http("PATCH", self.url + "/customers/c-1", token=t, body={"phone": "+32 2 555 0199"})
        # the echo of the record is masked with the *update* field permissions
        self.assertEqual((status, body), (200, {"email": "ada@example.com", "phone": "+32 2 555 0199", "card": {"number": "[REDACTED]"}}))

    def test_non_json_upstream_response_is_withheld(self):
        status, body, _ = http("GET", self.url + "/report", token=self.issue())
        self.assertEqual((status, body["error"]["code"]), (502, "unfilterable_response"))
        self.assertNotIn("123-45-6789", json.dumps(body))

    def test_upstream_error_body_is_withheld(self):
        status, body, _ = http("GET", self.url + "/customers/c-404", token=self.issue())
        self.assertEqual(status, 404)
        self.assertNotIn("123-45-6789", json.dumps(body))

    def test_spend_is_enforced_from_the_request_body(self):
        t = self.issue(cap={**FULL_CAP, "budget": {"EUR": 7000}})
        refund = {"order_id": "o-1", "amount": 5000, "currency": "EUR", "reason": "late"}
        status, body, _ = http("POST", self.url + "/refunds", token=t, body=refund)
        self.assertEqual(status, 201)
        self.assertEqual(body, refund)  # internal_note is masked
        status, body, _ = http("POST", self.url + "/refunds", token=t, body=refund)
        self.assertEqual((status, body["error"]["code"]), (403, "budget_exceeded"))
        status, body, _ = http("POST", self.url + "/refunds", token=t, body={"order_id": "o-2", "amount": "5000", "currency": "EUR"})
        self.assertEqual(status, 400)

    def test_approval_flow_through_the_proxy(self):
        t = self.issue()
        refund = {"order_id": "o-9", "amount": 15000, "currency": "EUR", "reason": "damaged"}
        status, body, _ = http("POST", self.url + "/refunds", token=t, body=refund)
        self.assertEqual((status, body["error"]["code"]), (403, "approval_required"))
        r = self.proxy.cli("approve", body["error"]["approval"]["id"], "--by", "bob")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(http("POST", self.url + "/refunds", token=t, body=refund)[0], 201)

    def test_audit_chain_is_valid_with_proxy_and_cli_writing(self):
        http("GET", self.url + "/customers/c-1", token=self.issue())
        r = self.proxy.cli("audit", "verify")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(json.loads(r.stdout)["ok"])


class RoutesFile(unittest.TestCase):
    """What the proxy refuses to start with, and how it reads a query."""

    def test_request_supplied_attributes_must_be_declared(self):
        from sf_smartdelegate.httpproxy import check_routes
        base = {"upstream": "crm", "method": "GET", "path": "/customers/{id}", "action": "read", "resource": "crm.customer"}
        ok = lambda **kw: check_routes({"upstreams": {"crm": {"base_url": "http://x"}}, "routes": [dict(base, **kw)]})
        self.assertEqual(ok(attrs={"tenant": "acme", "id": "{id}"}), ([], []))
        for bad in ({"attrs": {"region": "query.region"}}, {"attrs": {"owner": "body.owner"}}, {"attrs": {"x": "{nope}"}},
                    {"attrs_from_request": {"region": "EU"}}, {"attrs_from_request": {"region": "{id}"}},
                    {"attrs_from_record": {"region": "region"}}, {"lookup": "customers/{id}"}, {"lookup": "/customers/{other}"},
                    {"attrs": {"region": "EU"}, "attrs_from_request": {"region": "query.region"}},
                    {"lookup": "/customers/{id}", "attrs_from_record": {"region": ""}}, {"attrs": []}):
            errors, _ = ok(**bad)
            self.assertEqual(len(errors), 1, bad)
        errors, notes = ok(attrs_from_request={"region": "query.region"}, lookup="/customers/{id}", attrs_from_record={"owner": "owner.id"})
        self.assertEqual(errors, [])
        self.assertEqual(len(notes), 1)
        self.assertEqual(check_routes({"upstreams": {"crm": {"base_url": "http://x"}}, "routes": [{**base, "lookup": "/c/{body.customer_id}/{query.x}"}]}), ([], []))
        self.assertEqual(len(check_routes([])[0]), 1)

    def test_a_routes_file_in_the_old_form_stops_the_proxy_with_the_reason(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="smartdelegate-routes-")
        routes = os.path.join(d, "routes.json")
        Path(routes).write_text(json.dumps({"upstreams": {"crm": {"base_url": "http://127.0.0.1:9"}}, "routes": [
            {"upstream": "crm", "method": "POST", "path": "/refunds", "action": "create", "resource": "billing.refund", "attrs": {"customer_owner": "body.customer_owner"}}]}))
        with Daemon() as base:
            r = subprocess.run([*CLI, "http-proxy", "--config", base.config, "--routes", routes, "--listen", "127.0.0.1:0"], capture_output=True, text=True, env=ENV, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("attrs_from_request", r.stderr)

    def test_a_value_that_is_not_an_expression_stops_the_proxy(self):
        """Finding L-10: a typo must never turn a check into a constant."""
        from sf_smartdelegate.httpproxy import check_routes, expr_problem, resolve_expr
        base = {"upstream": "crm", "method": "POST", "path": "/refunds/{id}", "action": "create", "resource": "billing.refund"}
        ok = lambda **kw: check_routes({"upstreams": {"crm": {"base_url": "http://x"}}, "routes": [dict(base, **kw)]})[0]
        for good in ({"id": "{id}"}, {"id": "body.id"}, {"id": {"literal": "singleton"}}, {"spend": {"currency": {"literal": "EUR"}, "amount": "body.amount"}},
                     {"spend": {"currency": "query.cur", "amount": 500}}, {"request": "unchecked"}, {"response": "passthrough"}, {"attrs": {"kind": "po", "n": 3, "b": True}}):
            self.assertEqual(ok(**good), [], good)
        for bad in ({"id": "body"}, {"id": "id"}, {"id": "{nope}"}, {"id": "body."}, {"spend": {"currency": "EUR", "amount": "body.amount"}},
                    {"spend": {"currency": "body.currency", "amount": "amount"}}, {"spend": {"currency": "body.currency"}}, {"spend": "body.amount"},
                    {"spnd": {"currency": "body.currency", "amount": "body.amount"}}, {"input": "body"}, {"request": "uncheked"}, {"response": "pasthrough"},
                    {"attrs": {"x": "body"}}, {"attrs": {"x": None}}, {"query": "limit"}, {"upstream": "nope"}, {"action": ""}):
            self.assertEqual(len(ok(**bad)), 1, bad)
        self.assertEqual(len(check_routes({"upstreams": {"crm": {"base_url": "http://x", "header": {}}}, "routes": []})[0]), 1)
        self.assertEqual(len(check_routes({"upstreams": {}, "routes": [], "rotues": []})[0]), 1)
        self.assertEqual(resolve_expr({"literal": "body.x"}, {"body": {"x": 1}}, {}), ("body.x", True))
        self.assertEqual(resolve_expr("args", {"args": {"a": 1}}, {}), ({"a": 1}, True))
        self.assertIsNone(expr_problem("args", ("args",), whole=True))
        self.assertIsNotNone(expr_problem("args", ("args",)))

    def test_an_environment_variable_that_is_not_set_stops_the_proxy(self):
        import tempfile
        d = tempfile.mkdtemp(prefix="smartdelegate-routes-")
        routes = os.path.join(d, "routes.json")
        Path(routes).write_text(json.dumps({"upstreams": {"crm": {"base_url": "env:SD_TEST_NO_SUCH_URL", "headers": {"X-Api-Key": "env:SD_TEST_NO_SUCH_KEY"}}}, "routes": []}))
        with Daemon() as base:
            for env, missing in (({}, "SD_TEST_NO_SUCH_URL"), ({"SD_TEST_NO_SUCH_URL": "http://127.0.0.1:9"}, "SD_TEST_NO_SUCH_KEY"), ({"SD_TEST_NO_SUCH_URL": "http://127.0.0.1:9", "SD_TEST_NO_SUCH_KEY": ""}, "SD_TEST_NO_SUCH_KEY")):
                r = subprocess.run([*CLI, "http-proxy", "--config", base.config, "--routes", routes, "--listen", "127.0.0.1:0"], capture_output=True, text=True, env={**ENV, **env}, timeout=60)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(missing, r.stderr)

    def test_query_parsing_and_what_is_forwarded(self):
        from sf_smartdelegate.httpproxy import parse_query, serialise_query
        pairs, err = parse_query("a=x%20y&b=%2B1&c=p+q&&d", ["a", "b", "c", "d"])
        self.assertIsNone(err)
        self.assertEqual(pairs, [("a", "x y"), ("b", "+1"), ("c", "p+q"), ("d", "")])
        self.assertEqual(serialise_query(pairs), "a=x%20y&b=%2B1&c=p%2Bq&d=")
        self.assertEqual(parse_query("a=1&A=2", ["a", "A"])[1][0], "query_duplicate")
        self.assertEqual(parse_query("a=caf\u00e9", ["a"])[1][0], "query_ambiguous")
        self.assertEqual(parse_query("a=caf%C3%A9", ["a"])[0], [("a", "caf\u00e9")])


class McpProxy(unittest.TestCase):
    def setUp(self):
        self.d = Daemon()  # used for its config, state directory and CLI
        self.addCleanup(self.d.close)
        cap = os.path.join(self.d.dir, "cap.json")
        Path(cap).write_text(json.dumps(FULL_CAP))
        self.token_file = os.path.join(self.d.dir, "token")
        Path(self.token_file).write_text(self.d.cli("token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@" + cap, "--raw").stdout.strip())
        self.p = subprocess.Popen(
            [*CLI, "mcp-proxy", "--config", self.d.config, "--tools", str(EXAMPLES / "mcp_tools.json"), "--token-file", self.token_file,
             "--", sys.executable, str(EXAMPLES / "fake_mcp_server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=ENV)
        self.addCleanup(self.stop)
        self.n = 0

    def stop(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)
        self.p.stdout.close()

    def rpc(self, method, params=None):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}) + "\n")
        self.p.stdin.flush()
        msg = json.loads(self.p.stdout.readline())
        self.assertEqual(msg["id"], self.n)
        return msg

    def call(self, name, **arguments):
        return self.rpc("tools/call", {"name": name, "arguments": arguments})["result"]

    def test_handshake_passes_and_unmapped_tools_are_hidden(self):
        self.assertEqual(self.rpc("initialize")["result"]["serverInfo"]["name"], "fake-crm")
        names = [t["name"] for t in self.rpc("tools/list")["result"]["tools"]]
        self.assertEqual(names, ["get_customer", "update_customer", "refund", "export_report"])

    def test_tool_result_is_masked_in_text_and_structured_content(self):
        r = self.call("get_customer", customer_id="c-1")
        expected = {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "region": "EU", "tier": "gold"}
        self.assertEqual(r["structuredContent"], expected)
        self.assertEqual(json.loads(r["content"][0]["text"]), expected)
        self.assertNotIn("123-45-6789", json.dumps(r))
        self.assertEqual(sorted(r), ["content", "structuredContent"])  # _meta is dropped

    def test_server_log_notifications_do_not_reach_the_agent(self):
        # the fake server emits notifications/message carrying the whole record
        # before it answers; rpc() asserts the next line is the answer itself
        for _ in range(3):
            self.assertNotIn("123-45-6789", json.dumps(self.call("get_customer", customer_id="c-1")))

    def test_unmapped_tool_is_denied_without_reaching_the_server(self):
        r = self.call("drop_database")
        self.assertTrue(r["isError"])
        self.assertIn("default deny", r["content"][0]["text"])
        self.assertNotIn("database dropped", json.dumps(r))

    def test_unlisted_methods_are_blocked(self):
        msg = self.rpc("resources/read", {"uri": "crm://dump"})
        self.assertEqual(msg["error"]["code"], -32601)
        self.assertNotIn("ssn", json.dumps(msg))

    def test_non_json_tool_output_is_withheld(self):
        r = self.call("export_report")
        self.assertNotIn("123-45-6789", json.dumps(r))
        self.assertIn("withheld", r["content"][0]["text"])

    def test_forbidden_argument_field_is_denied(self):
        r = self.call("update_customer", customer_id="c-1", changes={"tier": "platinum"})
        self.assertTrue(r["isError"])
        self.assertIn("field_denied", r["content"][0]["text"])
        ok = self.call("update_customer", customer_id="c-1", changes={"email": "new@example.com"})
        self.assertEqual(json.loads(ok["content"][0]["text"]), {"email": "new@example.com"})

    def test_spend_approval_and_token_rotation(self):
        ok = self.call("refund", order_id="o-1", amount=5000, currency="EUR")
        self.assertEqual(json.loads(ok["content"][0]["text"]), {"order_id": "o-1", "amount": 5000, "currency": "EUR"})
        held = self.call("refund", order_id="o-2", amount=15000, currency="EUR")
        self.assertTrue(held["isError"])
        aid = re.search(r"id ([0-9a-f]{24})", held["content"][0]["text"]).group(1)
        self.assertEqual(self.d.cli("approve", aid, "--by", "bob").returncode, 0)
        self.assertNotIn("isError", self.call("refund", order_id="o-2", amount=15000, currency="EUR"))
        # the runtime swaps in a narrower sub-agent token; the proxy picks it up on the next call
        cap = os.path.join(self.d.dir, "narrow.json")
        Path(cap).write_text(json.dumps({"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["pii"]}))
        child = self.d.cli("token", "exchange", "--token", Path(self.token_file).read_text(), "--actor", "refund-helper", "--cap", "@" + cap, "--ttl", "300", "--raw").stdout.strip()
        Path(self.token_file).write_text(child)
        self.assertEqual(self.call("get_customer", customer_id="c-1")["structuredContent"], {"id": "c-1", "region": "EU", "tier": "gold"})
        self.assertTrue(self.call("refund", order_id="o-3", amount=100, currency="EUR")["isError"])

    def test_revoked_token_stops_tool_calls(self):
        tid = json.loads(self.d.cli("token", "inspect", "--token", Path(self.token_file).read_text()).stdout)["claims"]["jti"]
        self.assertEqual(self.d.cli("token", "revoke", "--id", tid).returncode, 0)
        r = self.call("get_customer", customer_id="c-1")
        self.assertTrue(r["isError"])
        self.assertIn("token_revoked", r["content"][0]["text"])


class McpToolsFile(unittest.TestCase):
    """Finding L-10: `"input": "args"` used to be read as the constant "args", and the arguments were not checked."""

    def start(self, tools: dict):
        d = Daemon()
        self.addCleanup(d.close)
        cap = os.path.join(d.dir, "cap.json")
        Path(cap).write_text(json.dumps(FULL_CAP))
        token = os.path.join(d.dir, "token")
        Path(token).write_text(d.cli("token", "issue", "--user", "alice", "--agent", "support-bot", "--cap", "@" + cap, "--raw").stdout.strip())
        tf = os.path.join(d.dir, "tools.json")
        Path(tf).write_text(json.dumps(tools))
        p = subprocess.Popen([*CLI, "mcp-proxy", "--config", d.config, "--tools", tf, "--token-file", token, "--", sys.executable, str(EXAMPLES / "fake_mcp_server.py")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENV)

        def stop():
            p.stdin.close()
            p.wait(timeout=10)
            p.stdout.close()
            p.stderr.close()
        self.addCleanup(stop)
        return p

    def call(self, p, name, **arguments):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())["result"]

    def test_all_arguments_as_record_data_are_field_checked(self):
        p = self.start({"server": "crm", "tools": {"update_customer": {"action": "update", "resource": "crm.customer", "input": "args"},
                                                   "update_part": {"action": "update", "resource": "crm.customer", "input": "args.changes"}}})
        r = self.call(p, "update_customer", tier="platinum")
        self.assertTrue(r.get("isError"), r)
        self.assertIn("field_denied", r["content"][0]["text"])
        self.assertNotIn("isError", self.call(p, "update_customer", email="new@example.com"))
        # the mapping says where the record data is; a call that does not carry it there is refused, not waved through
        for arguments in ({}, {"changes": "tier=platinum"}, {"tier": "platinum"}):
            r = self.call(p, "update_part", **arguments)
            self.assertTrue(r.get("isError"), arguments)
            self.assertIn("invalid_input", r["content"][0]["text"])

    def test_a_tools_file_with_a_value_that_is_not_an_expression_is_refused(self):
        from sf_smartdelegate.mcpproxy import check_tools
        base = {"action": "update", "resource": "crm.customer"}
        ok = lambda **kw: check_tools({"server": "crm", "tools": {"t": dict(base, **kw)}})[0]
        for good in ({"input": "args"}, {"input": "args.changes"}, {"id": "args.id"}, {"id": {"literal": "one"}}, {"attrs": {"tenant": "acme", "n": 1}},
                     {"spend": {"currency": {"literal": "EUR"}, "amount": "args.amount"}}, {"lookup": {"tool": "get", "arguments": {"id": "args.id", "kind": {"literal": "x"}}}}):
            self.assertEqual(ok(**good), [], good)
        for bad in ({"input": "arg"}, {"input": "changes"}, {"input": "body"}, {"input": {"literal": {}}}, {"input": ""}, {"id": "args"}, {"id": "customer_id"},
                    {"spend": {"currency": "EUR", "amount": "args.amount"}}, {"inptu": "args"}, {"response": "raw"}, {"attrs": {"x": "args"}},
                    {"lookup": {"tool": "get", "arguments": {"id": "id"}}}, {"lookup": {"tool": "get", "args": {}}}, {"action": None}):
            self.assertEqual(len(ok(**bad)), 1, bad)
        self.assertEqual(len(check_tools({"tools": {}, "tool": {}})[0]), 1)
        p = self.start({"server": "crm", "tools": {"update_customer": dict(base, input="changes")}})
        self.assertEqual(p.wait(timeout=20), 1)
        self.assertIn("not an expression", p.stderr.read())


if __name__ == "__main__":
    unittest.main()
