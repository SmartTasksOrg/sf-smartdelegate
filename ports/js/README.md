# JavaScript client

A thin REST client for `sf-smartdelegate serve` and a `guardTool` wrapper. No
dependencies, Node 18 or newer, TypeScript types in `index.d.ts`. It is not a
port of the engine: decisions are made by the daemon.

```
node --test test/*.test.mjs        # starts the Python reference daemon for each case
```
