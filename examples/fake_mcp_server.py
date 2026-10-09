"""A minimal MCP server (stdio, newline-delimited JSON-RPC) for demos and
tests. Its tools return more than an agent should see."""
import json
import sys

CUSTOMER = {"id": "c-1", "name": "Ada Lovelace", "email": "ada@example.com", "ssn": "123-45-6789", "region": "EU", "tier": "gold", "notes": "threatened to churn"}
TOOLS = [
    {"name": "get_customer", "description": "Fetch a customer", "inputSchema": {"type": "object", "properties": {"customer_id": {"type": "string"}}}},
    {"name": "update_customer", "description": "Change customer fields", "inputSchema": {"type": "object"}},
    {"name": "refund", "description": "Refund an order", "inputSchema": {"type": "object"}},
    {"name": "export_report", "description": "Plain-text export", "inputSchema": {"type": "object"}},
    {"name": "drop_database", "description": "Dangerous and unmapped", "inputSchema": {"type": "object"}},
]


def reply(id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": id, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method, id = msg.get("method"), msg.get("id")
    if id is None:
        continue
    if method == "initialize":
        reply(id, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake-crm", "version": "0"}})
    elif method == "tools/list":
        reply(id, {"tools": TOOLS})
    elif method == "resources/read":
        reply(id, {"contents": [{"uri": "crm://dump", "text": json.dumps(CUSTOMER)}]})
    elif method == "tools/call":
        name, args = msg["params"]["name"], msg["params"].get("arguments", {})
        if name == "get_customer":
            # a chatty server: logs the record and tucks it into _meta as well
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": CUSTOMER}}) + "\n")
            reply(id, {"content": [{"type": "text", "text": json.dumps(CUSTOMER)}], "structuredContent": CUSTOMER, "_meta": {"raw": CUSTOMER}})
        elif name == "update_customer":
            reply(id, {"content": [{"type": "text", "text": json.dumps({**CUSTOMER, **args.get("changes", {})})}]})
        elif name == "refund":
            reply(id, {"content": [{"type": "text", "text": json.dumps({"order_id": args.get("order_id"), "amount": args.get("amount"), "currency": args.get("currency"), "internal_note": "fraud score 0.2"})}]})
        elif name == "export_report":
            reply(id, {"content": [{"type": "text", "text": "Ada Lovelace, ssn 123-45-6789"}]})
        else:
            reply(id, {"content": [{"type": "text", "text": "database dropped"}]})
    else:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no such method"}}) + "\n")
        sys.stdout.flush()
