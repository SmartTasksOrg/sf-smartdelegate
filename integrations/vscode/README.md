# SmartDelegate in VS Code

Three tasks, no extension. They need the `smartdelegate` command on PATH and a bundle
in `bundle/` of the workspace (edit the paths in `tasks.json` otherwise).

Setup:

1. Copy [`tasks.json`](tasks.json) to `.vscode/tasks.json` (or merge its `tasks` into yours).
2. Copy [`smartdelegate.explain.json`](smartdelegate.explain.json) to `.vscode/smartdelegate.explain.json`.

Then "Tasks: Run Task":

| Task | Command |
|---|---|
| SmartDelegate: policy check | `sf-smartdelegate policy check --bundle bundle` |
| SmartDelegate: policy test | `sf-smartdelegate policy test --bundle bundle` |
| SmartDelegate: explain the request in the open file | `sf-smartdelegate call explain --input @<open file> --config .vscode/smartdelegate.explain.json --bundle bundle` |

The third task reads the open file as one request and prints every check and
every field decision. [`request.example.json`](request.example.json) is such a
file. It names the principal with `chain` instead of a token, the same form
the bundle's `tests/*.json` use, which is why the task passes a config with
`"trust_caller_chain": true`. That config is for authoring policies. Do not use
it for a daemon or a proxy.

Tested: `tests/test_integrations.py` runs each task's command line with
`${workspaceFolder}` and `${file}` filled in. The tasks were not run inside
VS Code.
