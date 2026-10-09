# Using SmartDelegate

All commands assume `pip install sf-smartdelegate` (or `pip install .` in a clone).

## 1. A working directory

```bash
sf-smartdelegate init work && cd work     # bundle/ (policies, entities, catalog, roles), smartdelegate.json
sf-smartdelegate policy test              # the bundle's own tests
```

## 2. A human lends an agent a role

```bash
TOKEN=$(sf-smartdelegate token issue --user alice --agent support-bot --role support-agent --task ticket-7 --raw)
sf-smartdelegate token inspect --token "$TOKEN"
```

Refused cases worth trying: `--user dave` (does not hold the role), `--role supervisor`
(Alice is not a supervisor), `--cap '{"actions":["read"],"resources":["hr.salary/*"]}'`
(more than the role allows).

## 3. Check a call and mask the data

```bash
sf-smartdelegate authorize --token "$TOKEN" --action read --resource crm.customer/c-1 \
  --data '{"id":"c-1","name":"Ada","ssn":"123-45-6789","region":"EU"}'
sf-smartdelegate explain --token "$TOKEN" --action create --resource billing.refund/r-1 \
  --context '{"spend":{"currency":"EUR","amount":15000}}'
```

Exit code 0 is allow, 2 is deny, 1 is an error.

## 4. From Python

```python
from sf_smartdelegate import core, Guard

iam = core.open_engine("bundle", "state")
grant = core.delegate(iam, user="alice", agent="support-bot", role="support-agent", task="ticket-7")

guard = Guard(iam, token=lambda: grant.token)

@guard.tool(action="read", resource="crm.customer", id="customer_id")
def get_customer(customer_id):
    return crm.get(customer_id)        # the return value is masked before the agent sees it
```

## 5. A sub-agent

```bash
CHILD=$(sf-smartdelegate token exchange --token "$TOKEN" --actor summarizer --ttl 300 \
  --cap '{"actions":["read"],"resources":["crm.customer/c-1"],"deny_labels":["secret","pii"]}' --raw)
```

## 6. The boundary an agent cannot skip

```bash
sf-smartdelegate serve                               # REST decision daemon for any language
sf-smartdelegate http-proxy --routes routes.json     # holds the upstream credential
sf-smartdelegate mcp-proxy --tools tools.json -- <mcp server command>
```

`examples/routes.json`, `examples/mcp_tools.json`, `examples/fake_crm.py` and
`examples/fake_mcp_server.py` are a stand-in upstream and MCP server to point the proxies at. `examples/quickstart.py` is the in-process version of steps 2 to 5.

## 7. Your identity provider

```bash
# users and groups from the directory; end the tokens of people who lost access
sf-smartdelegate bridge sync-okta --org example.okta.com --token-env OKTA_TOKEN --out bundle --group-map group_map.json --revoke
# or let the engine read groups from each ID token: set idp.groups_claim in smartdelegate.json
```

See `examples/bridges/` and `docs/BRIDGES.md`. The bridges have been tested against fakes only.

## 8. Offboarding

```bash
sf-smartdelegate token revoke --user alice     # every token already issued for her, sub-agents included
sf-smartdelegate audit verify
```

## 9. Other languages

Each port has the same `call(op, input)` and a README: `ports/java`, `ports/node`,
`ports/go`, `ports/php`, `ports/rust`. Editing `.cedar` policies needs the Rust
port once, to compile them: `smartdelegate bundle compile` there.
