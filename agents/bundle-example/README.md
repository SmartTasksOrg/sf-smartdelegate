# Bundle fragment for the two agent definitions

The agents in this folder run under SmartDelegate's own rule: a human lends
the agent one role for one task. This fragment is the bundle side of that.

| File | Holds |
|---|---|
| `catalog.json` | the resource `smartdelegate.ops`: one id per operations tool of the MCP server |
| `entities.json` | groups `sd-operators`, `sd-integrators`; example users `olivia`, `ian`; agents `smartdelegate-operator`, `smartdelegate-integrator` |
| `roles.json` | `sd-operator` (read five monitoring tools) and `sd-integrator` (read `status`), each with `max_ttl`, `tasks`, `agents` |
| `policies/ops.cedar` | who may delegate to each agent; what each role may read; a forbid on action `operate` for both roles |
| `policies.json` | `policies/ops.cedar` compiled by the Rust port |
| `tests/ops.json` | policy unit tests |
| `merge.py` | adds all of the above to an existing bundle; never overwrites |

It is a complete, loadable bundle by itself:

```bash
sf-smartdelegate policy check --bundle agents/bundle-example
sf-smartdelegate policy test --bundle agents/bundle-example
```

Add it to your bundle (work on a copy; `--dry-run` first):

```bash
python3 agents/bundle-example/merge.py --into bundle --dry-run
python3 agents/bundle-example/merge.py --into bundle
```

Then replace the example users with your own groups' members (or let the
directory sync do it: map your operator group to `sd-operators`), run your
policy tests, sign the bundle again if it is signed, and reload.

## What it grants and what it does not

Enforced by the MCP server when it runs with `--govern`
(`integrations/mcp/README.md`): every monitoring tool call is action `read`,
every privileged tool call is action `operate`, on `smartdelegate.ops/<tool>`.

| | `sd-operator` | `sd-integrator` |
|---|---|---|
| `status` | yes | yes |
| `audit_tail`, `audit_verify`, `pending_approvals`, `anomalies` | yes | no |
| `approve`, `revoke_user`, `reload`, `delegate` | no | no |
| hand the token on to a sub-agent | no: no policy lets these agents delegate | no |

Nothing in this fragment permits `operate`. If you want an agent that may,
say, revoke users, that is a separate role with its own members, a ceiling
that lists `smartdelegate.ops/revoke_user` with action `operate`, and a permit
you write and review. Consider `@require_approval` on that permit.

Outside `--govern` these roles have no effect: the engine's own
administration (`issue_token` with a user, `revoke`, `approve`, `reload`) is
guarded by the admin key, not by capability tokens.

`tests/test_agent_surface.py` loads this fragment with the reference engine,
merges it into the conformance bundle, and proves the table above with engine
calls and through a governed MCP server.
