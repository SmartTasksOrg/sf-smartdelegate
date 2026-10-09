# ApprovalChannel

Deliver a held request to a human and bring the verdict back.

## Contract

```python
class ApprovalChannel(Protocol):
    def deliver(self, request: ApprovalRequest) -> None: ...   # raise when it could not be delivered
    def verdicts(self) -> list[Verdict]: ...                    # each verdict once
# ApprovalRequest(id, label, user, agent, action, resource, requested_at)
# Verdict(approval_id, approve, by)
```

A policy marked `@require_approval("label")` holds the call: the decision is
`deny` with reason `approval_required` and `approval: {"id", "label"}`, and the
request appears under `approvals`. `interfaces.reference.pump(backend, channel, delivered)`
does one round: deliver what is new, collect verdicts, call
`approve {"approval_id", "by"}` for each approval. The agent then retries the
same call. An approval is bound to the exact request, is good for one call,
and expires (`approval_ttl`, 900 seconds by default).

A rejection is not sent to the engine: there is no "reject" operation. The
request stays held and the agent's call stays denied.

## Fails closed

- No answer is no verdict. Silence, a timeout, an unreadable reply, a reply
  without the approver's identity: none of them becomes an approval.
- `by` MUST be the human who answered. A channel MUST NOT substitute a
  service identity or a fixed approver: the engine's two rules about who may
  approve are decided on `by`.
- A verdict belongs to the request it answers.
- Each verdict is returned once.
- If `deliver` raises, the request stays pending and is offered again in the
  next round.

## Security notes

- The engine refuses the user the agent acts for (`self_approval`) and anyone
  no policy permits (`approval_denied`; action `approve` on the agent). It
  does **not** authenticate the approver: `by` is whatever the holder of the
  admin key says (THREAT_MODEL, threat 17). Authenticate the human in the
  channel: a signed-in chat identity, a ticket system's assignee.
- The approver's groups are read from `entities.json`, never from live membership.
- `approve` needs the admin key, which also issues tokens for any user,
  revokes and reloads (threat 19). Run the pump in a small trusted service,
  not in the agent and not in the chat bot's general-purpose code.
- An `ApprovalRequest` holds no token and no record values: label, user,
  agent, action and `path/id` only. Do not add record data on the way.

## Other languages

With `Authorization: Bearer <admin key>`:

```text
GET  /v1/admin/approvals      -> {"pending": {id: {label, user, agent, action, resource, requested_at}}, "granted": {id: {by, exp}}}
POST /v1/admin/approve        {"approval_id", "by", "ttl"?}     errors: unknown_approval, self_approval, approval_denied
```

Poll `approvals` (there is no push), remember which ids were delivered, and
call `approve` only on an explicit yes.

## Reference implementation

`interfaces/reference/approval.py`: `ConsoleApprovalChannel` (a terminal, or
any function), `WebhookApprovalChannel(post)` (webhook-shaped stub: it builds
the JSON body and hands it to your `post` function; replies come back through
`receive`; it opens no connection), and `pump`.

## Checks

`python -m interfaces.contract --approval yourpkg:factory`, with
`factory(human)`: `human(payload)` stands for the person at the far end and
returns `{"approve": bool, "by": user}` or `None`.

| Check | Requires |
|---|---|
| `approval-delivers` | the human is shown id, label, user, agent, action, resource, and no token |
| `approval-silence` | no answer, an empty answer, a non-boolean answer, an answer without `by`: nothing is approved |
| `approval-reject` | a rejection is not an approval |
| `approval-names-approver` | the audit record names the human who approved; the verdict is returned once |
| `approval-not-laundered` | the requesting user and a user without the right cannot approve through the channel |
| `approval-own-requests-only` | approving one of two requests approves one |
