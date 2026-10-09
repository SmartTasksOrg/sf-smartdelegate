# demo

`sf-smartdelegate --demo` runs the scripted walk below against the example bundle
that ships inside the package (`src/sf_smartdelegate/example_bundle`, the same
files as `spec/conformance/bundle`). It needs no setup and writes nothing
outside a temporary directory.

What it shows, in order:

1. Alice, who is in the support group, lends `support-bot` her `support-agent` role for one ticket.
2. The bot reads a customer. The SSN, the internal notes and the card number never reach the model.
3. A 60 EUR refund goes through.
4. A second one does not: the role's budget for the task is 100 EUR.
5. Alice asks for a 500 EUR budget and is refused: more than her role allows.
6. The bot hands a read-only slice to a sub-agent, which cannot widen it again.
7. Dave, who is not in support, is refused the same role.
8. The identity provider says Alice left the group: refused, although the stored membership still lists her.
9. The audit log's hash chain verifies.

`request.json` is one request you can try by hand:

```bash
sf-smartdelegate init work && cd work
TOKEN=$(sf-smartdelegate token issue --user alice --agent support-bot --role support-agent --task ticket-7 --raw)
sf-smartdelegate call filter --input "$(python3 -c "import json,sys; d=json.load(open('../demo/request.json')); d['token']=sys.argv[1]; print(json.dumps(d))" "$TOKEN")"
```
