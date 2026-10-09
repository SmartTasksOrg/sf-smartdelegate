---
name: smartdelegate-delegate
description: Obtain a role-scoped SmartDelegate task token for an agent, inspect it, and narrow it for a sub-agent. Use when an agent is about to start work for a human and needs a capability token, when a sub-agent must be handed part of what the agent holds, or when token issuance fails with DELEGATE-ROLE-NOT-HELD, DELEGATE-ROLE-EXCEEDED or DELEGATE-WIDENING.
---

# Delegate: one role, one task, never more

A human lends an agent **one role they hold, for one task**. The token that
comes back cannot carry more than the role's ceiling (`roles.json`), a
sub-agent's token cannot carry more than its parent's, and policy still
decides every call. Reference: `spec/ROLES.md`, `spec/API.md` ("Tokens").

Commands are written `smartdelegate ...`. From a clone without installing the
package, the same command is `PYTHONPATH=src python3 -m sf_smartdelegate ...`. The
commands act on the engine named by `--config FILE` (or `./smartdelegate.json`).

## Never without a human

- Never issue a root token on your own initiative. `token issue --user` is an
  administrator's statement that this human asked for this task. If no human
  asked, there is nothing to delegate.
- Never choose `--user` or `--groups` yourself, and never retry with another
  user, another role or other groups after a refusal. `--groups` replaces the
  stored membership and is checked against nothing.
- Never ask for a longer lifetime, a wider capability or a different role to
  get past a refusal.
- Never put a token in a file that is committed, in a log, in a prompt or in
  a tool result. A token is a bearer credential.
- Never hand a sub-agent your own token. Give it an exchanged one.

## Commands

See which roles exist:

```bash
sf-smartdelegate info
```

The human's token service issues the task token. With a verified sign-in the
ID token is the credential (identity and groups come from it):

```bash
sf-smartdelegate token issue --id-token "$ID_TOKEN" --agent support-bot --role support-agent --task ticket-7 --raw
```

Without an identity provider configured, an administrator states the user:

```bash
sf-smartdelegate token issue --user alice --agent support-bot --role support-agent --task ticket-7 --raw
```

Leave out `--cap`: the token then carries the role's ceiling. Pass `--cap` only
to ask for less. Check what you were given before you use it:

```bash
sf-smartdelegate token inspect --token "$TOKEN"
```

Narrow for a sub-agent. The capability must be the parent's or less, and it
must repeat the parent's `deny_labels` and `deny_fields` (deny lists only
grow). Without `--cap` the sub-agent inherits the parent's capability.

```bash
sf-smartdelegate token exchange --token "$TOKEN" --actor summarizer --cap @sub.json --ttl 300 --raw
```

`sub.json` for a read-only slice of one record, under a parent that denies the label `secret`:

```json
{"actions": ["read"], "resources": ["crm.customer/c-1"], "deny_labels": ["secret"]}
```

## When issuance is refused

The command exits 1 and prints `{"ok": false, "error": {"code", "message", "rule"}}`.
These refusals are answered to the caller and are **not** written to the audit log.

| Rule | Meaning | What to do |
|---|---|---|
| `DELEGATE-ROLE-NOT-HELD` | the human does not hold the role right now | Stop. Tell the human which role was asked and that their access administrator decides membership. Do not try another role or user |
| `DELEGATE-ROLE-EXCEEDED` | more than the role allows: capability, budget, or a task or agent the role does not list | Ask for less: drop `--cap`, or use a task name and an agent the role lists. The message names what exceeded |
| `DELEGATE-UNKNOWN-ROLE` | no such role | use a name from `sf-smartdelegate info` |
| `DELEGATE-ROLE-REQUIRED` | this engine issues only for a named role | add `--role` |
| `DELEGATE-DELEGATION-DENIED` | no policy lets this human, or this agent, hand authority to that agent | Stop and report; a policy author decides |
| `DELEGATE-WIDENING` | the sub-agent was asked more than the parent holds, or a deny list was dropped | ask for the same or less; repeat the parent's deny lists |
| `DELEGATE-DEPTH-EXCEEDED` | the chain of agents is too long | do the work at the current level |
| `DELEGATE-ID-TOKEN-INVALID` | the ID token did not verify, or predates the user's revocation | the human signs in again |

For any other rule id: `python3 skills/smartdelegate-explain/scripts/rules.py --all`.

## What a token is good for

- It expires (`expires_in`; a role's `max_ttl` caps it). Ask the human to start the task again; do not look for a way to renew.
- Its budget is charged for every spend of itself and of every sub-agent below it.
- It dies when it is revoked, when a token above it is revoked, or when its human is offboarded.
