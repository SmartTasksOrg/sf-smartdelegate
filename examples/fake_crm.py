"""A stand-in upstream REST service for demos and tests. It returns far more
than an agent should see, and it only answers callers that hold its API key,
which the agent never does: the SmartDelegate proxy adds it.

    python examples/fake_crm.py 9000
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = "upstream-secret-key"
CUSTOMERS = {
    "c-1": {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "phone": "+32 2 555 0100", "ssn": "123-45-6789",
            "region": "EU", "tier": "gold", "notes": "threatened to churn", "addresses": [{"street": "1 Main St", "zip": "1000", "geo": {"lat": 50, "lng": 4}}],
            "card": {"last4": "4242", "number": "4242424242424242"}},
    "c-2": {"id": "c-2", "name": "Bo Diaz", "email": "bo@example.com", "phone": "+1 555 0101", "ssn": "987-65-4321",
            "region": "US", "tier": "silver", "notes": "", "addresses": [], "card": {"last4": "1111", "number": "4111111111111111"}},
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        raw = (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _authed(self):
        if self.headers.get("X-Api-Key") != API_KEY:
            self._send(401, {"error": "bad api key"})
            return False
        if self.headers.get("Authorization"):
            # the proxy must not leak the agent's capability token upstream
            self._send(400, {"error": "unexpected Authorization header"})
            return False
        return True

    def do_GET(self):
        if not self._authed():
            return
        path = self.path.split("?")[0]
        if path == "/customers":
            return self._send(200, {"items": list(CUSTOMERS.values()), "next": "cursor-2", "debug": {"sql": "select * from customers"}})
        if path == "/report":
            return self._send(200, "Ada Lovelace, ssn 123-45-6789", "text/plain")
        cid = path.rsplit("/", 1)[-1]
        if path.startswith("/customers/") and cid in CUSTOMERS:
            return self._send(200, CUSTOMERS[cid])
        self._send(404, {"error": "not found", "hint": "known ssn 123-45-6789"})

    def do_PATCH(self):
        if not self._authed():
            return
        cid = self.path.rsplit("/", 1)[-1]
        if cid not in CUSTOMERS:
            return self._send(404, {"error": "not found"})
        CUSTOMERS[cid].update(self._body())
        self._send(200, CUSTOMERS[cid])

    def do_POST(self):
        if not self._authed():
            return
        b = self._body()
        self._send(201, {"order_id": b.get("order_id"), "amount": b.get("amount"), "currency": b.get("currency"), "reason": b.get("reason"), "internal_note": "fraud score 0.2"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"fake crm on http://127.0.0.1:{server.server_address[1]}", flush=True)
    server.serve_forever()
