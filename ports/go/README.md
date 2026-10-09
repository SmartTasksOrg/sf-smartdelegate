# SmartDelegate, Go port

A native Go implementation of the SmartDelegate engine (spec version 0.3.0):
capability tokens (EdDSA JWT with an RFC 8693 `act` chain), narrowing-only
delegation, roles and live group membership, Cedar policy evaluated from the
compiled `policies.json`, field masking, budgets, human approval and the
hash-chained audit log. It also has a command line, a REST daemon and a REST
client.

The Python package in `src/sf_smartdelegate` is the reference. This port follows
it operation by operation; `spec/` describes the formats and the behaviour.

## Requirements

- Go 1.21 or newer (developed and tested with Go 1.24.7 only; see "Not tested").
- No third-party modules: standard library only.
- For the interoperability tests: `python3` with the `cryptography` package.
  Without them those tests are skipped and say so.

## Using the engine from code

```go
package main

import (
	"fmt"

	smartdelegate "github.com/SmartTasksOrg/sf-smartdelegate/ports/go"
)

func main() {
	engine, err := smartdelegate.NewEngine(map[string]any{
		"bundle_dir": "spec/conformance/bundle",
		"state_dir":  "state", // signing key, state.json, audit.jsonl, lock
	})
	if err != nil {
		panic(err) // *smartdelegate.EngineError: Code, Message
	}
	defer engine.Close()

	// alice lends the agent her role "support-agent" for this task
	issued := engine.Call("issue_token", map[string]any{"user": "alice", "agent": "support-bot", "role": "support-agent"})
	if issued["ok"] != true {
		panic(fmt.Sprint(issued["error"]))
	}

	request := map[string]any{
		"token":    issued["token"],
		"action":   "read",
		"resource": map[string]any{"path": "crm.customer", "id": "c-1"},
	}
	decision := engine.Call("authorize", request)
	fmt.Println(decision["effect"], decision["rule"]) // allow DELEGATE-POLICY-PERMIT

	// filter: the decision plus the data with denied fields removed
	request["data"] = map[string]any{"id": "c-1", "name": "Ada", "ssn": "123-45-6789", "region": "EU"}
	filtered := engine.Call("filter", request)
	fmt.Println(smartdelegate.Canon(filtered["data"]), filtered["masked"]) // {"id":"c-1","name":"Ada","region":"EU"} [ssn]
}
```

`Call(op, payload)` takes any operation of `spec/API.md`. It never panics and
has no error return: a request that cannot be processed comes back as
`{"ok": false, "error": {"code", "message", "rule"}}`, and a deny is a normal
result with `"effect": "deny"`. One engine may be used from many goroutines;
calls are serialised.

Numbers: JSON integers are `int64` in inputs and results (an integer outside
64 bits is a `*big.Int`). `Call` accepts any Go integer type, `json.Number`
and `*big.Int`. A `float64` is a float, and floats are refused in a `context`,
in a `cap` and in entity attributes, as in the reference. So do not decode
request bodies with `encoding/json` into `map[string]any` (every number
becomes a `float64`): use `smartdelegate.ParseJSON`, `engine.CallJSON(op,
body)`, or a `json.Decoder` with `UseNumber`.

Other exported pieces: `NewClient(url, pepKey, adminKey)` (same `Call`, over
REST), `Listen` / `NewHandler` (the daemon), `LoadBundle`, `SignBundle`,
`Keygen`, `KeyID`, `Manifest`, `VersionOf`, `VerifyAudit`, `Canon`,
`ParseJSON`, `MarshalIndent`, `IsAuthorized` (the policy evaluator alone) and
the conformance runner (`RunVectors`, `RunEvalCases`, `RunBundleTests`,
`RunCase`, `Subset`).

## Command line

```
go build -o smartdelegate-go ./cmd/smartdelegate-go

smartdelegate-go info --bundle ../../spec/conformance/bundle
smartdelegate-go token issue --user alice --agent support-bot --role support-agent --raw --config smartdelegate.json
smartdelegate-go authorize --token "$T" --action read --resource crm.customer/c-1 --config smartdelegate.json
smartdelegate-go call filter --input @request.json --config smartdelegate.json
smartdelegate-go serve --config smartdelegate.json --listen 127.0.0.1:8181
smartdelegate-go conformance
```

Commands: `info`, `version`, `policy check`, `policy test`, `bundle keygen
<prefix>`, `bundle sign --key <file>`, `token issue|exchange|inspect|revoke` (`revoke --id | --token | --user`),
`authorize`, `explain`, `approvals`, `approve <id> --by USER`, `audit
verify|tail [-n N]`, `call <op> [--input JSON|@file|-]`, `serve [--listen
host:port]`, `conformance [<vectors dir> <bundle dir>] [--root DIR]`. Flags
and exit codes are those of the reference CLI: 0 for ok/allow, 2 for a deny,
1 for an error.

Configuration is resolved as the reference does: `--config FILE`, else
`SMARTDELEGATE_CONFIG`, else `./smartdelegate.json`; `bundle_dir`,
`state_dir` and `idp.jwks_file` in the file are relative to the file;
`--bundle DIR`, `--state DIR` and `--shadow` override it;
`SMARTDELEGATE_ADMIN_KEY` and `SMARTDELEGATE_PEP_KEY` override the keys.

`serve` implements the routes, key rules, status codes and body limit of the
reference daemon (`src/sf_smartdelegate/daemon.py`, `spec/openapi.yaml`) and
prints the same first line on standard error. It does not terminate TLS.

## State directory and locking

Each operation takes an exclusive lock on `<state_dir>/lock` and re-reads
`state.json` first.

- Linux, macOS, the BSDs: `flock(2)`, the same lock the Python reference and
  the Rust port take. A state directory can be shared with them (tested with
  the Python reference, see below).
- Windows: `LockFileEx` on the first byte of the file, which is the byte the
  reference locks with `msvcrt.locking`. This compiles (`GOOS=windows go
  build ./...`) but has never been run.
- Other platforms (`lock_other.go`): no file lock. Do not share a state
  directory between processes there.
- As `spec/PORTING.md` says, do not share a state directory with the Java
  port (a different kind of lock).

## Tests

```
go vet ./... && gofmt -l .
go test ./...                 # everything; about 20 s with python3 present
go test -race ./...           # same, with the race detector (needs cgo)
go test -short ./...          # skips the test that starts 78 reference daemons
./run_conformance.sh          # go run ./cmd/smartdelegate-go conformance
```

What `go test` runs (counts as observed on Linux amd64, Go 1.24.7, Python 3.11):

| Test | What |
|---|---|
| `TestEvalCases` | the 95 policy evaluation cases of `spec/conformance/eval/cases.json` |
| `TestConformanceInProcess` | the 78 conformance cases (327 steps), fresh engine and state directory per case |
| `TestConformanceOverREST` | the same 78 cases through this port's daemon and client |
| `TestCanonicalJSON`, `TestParseJSON*`, `TestFloatRepr`, `TestLooseEquality` | canonical JSON (key order by code point with non-BMP keys, escapes), exact integers, parser strictness |
| `TestConcurrentUse`, `TestConcurrentSpendStaysWithinBudget` | one engine from 12 goroutines, two engines on one state directory, budget never overspent, audit chain intact |
| `TestCallFailsClosed`, `TestAuditFailureRefuses`, `TestAuditTamperingIsDetected`, `TestSignedBundle`, `TestCedarLongsAre64Bit`, `TestNewEngineErrors` | failure paths, signatures, 64-bit overflow |
| `TestDaemon*`, `TestClient`, `TestListen` | daemon keys, status codes, body limit, ID-token path, client |
| `TestCLI*` | the binary: config resolution, flags, exit codes, `serve`, `conformance`, `run_conformance.sh` |
| `TestIDTokenProviderRules` | `azp` and several audiences, the revoked-user cut-off against the ID token's `iat`, a nested (dotted) group claim, `reload` re-reading `idp.jwks_file` (rotation; a broken file or a broken bundle keeps the old keys and the old bundle); every step is also compared with the reference |
| `TestIDTokenAlgorithms` | 132 generated ID tokens over RS256/384/512, ES256/384, EdDSA |
| `TestRevokeUser` | `revoke {"user"}`: cut-off by `iat` that never moves back, sub-agent tokens, precedence over `token`/`token_id`, `user_revoked` audit event, `revoked_users` in `state.json` (missing key, never pruned), `task` in token results |
| `TestAncestorBudgetTravelsWithTheToken` | the `lim` claim: a verify-only engine with its own state directory enforces an ancestor's budget (Go to Go, and with the reference in both directions); a malformed `lim` is `token_invalid` |
| `TestApprovalIsBoundToResourceAttrs` | an approval given for one set of `resource.attrs` is not used by a request with another; the approval id is byte-identical to the reference's with and without attrs |
| `TestStrict*` (9 tests) | one per bullet of "Strictness (0.3)" in `spec/PORTING.md`: audit lines end at `\n` only, strict base64url, full-match type names, `containsAll`/`containsAny` operands, policy JSON shapes, `anc`, files that are not UTF-8 and `entities.json` shape, signing-key creation race, an empty signing key file (waited for, then `state_io`; never "no key") |

Interoperability with the Python reference (skipped without `python3` +
`cryptography`):

| Test | What |
|---|---|
| `TestInteropTokens` | tokens issued by each are accepted by the other (trusted keys, verify-only, shared signing key), including a role token with `grp`, and delegation across the two |
| `TestInteropBundles` | a bundle signed by each loads in the other; same version; same `bundle.sig.json`; a changed file is refused by both |
| `TestInteropAudit` | a log written by each verifies in the other (same record count and head); a tampered line is found by both |
| `TestInteropSharedStateDirectory` | one state directory and signing key, a running Go engine and the reference CLI taking turns: spend, token revocation, revoke-by-user and approval made by one are seen by the other; one valid audit chain of 32 records |
| `TestInteropCanonicalJSON` | canonical form byte-identical on fixed and 3000 generated documents |
| `TestInteropDifferential` | 2887 requests (`testdata/differential_cases.py`: malformed, odd and limit inputs) sent to both engines; results compared |
| `TestInteropBundleShapes` | 481 bundles, valid and broken in every file: both load the same ones and refuse the others with the same code |
| `TestInteropAnnotations` | every form of `@row_filter`, `@rate_limit`, `@require_approval` and catalog labels/masks; 997+ requests compared |
| `TestInteropDaemonBehaviour` | 575 raw HTTP requests to both daemons: same status and body |
| `TestInteropClientAgainstReferenceDaemon` | the 78 conformance cases, this port's client against the reference daemon |
| `TestIDTokenAlgorithms/the_reference_agrees` | the 132 ID tokens get the same answer from the reference |

The comparisons leave out what two correct engines may answer differently:
message wording, random token ids, and hashes computed over them.

The reference's own tests can be pointed at this port's binary:

```
go build -o /tmp/smartdelegate-go ./cmd/smartdelegate-go
cd ../../tests
SMARTDELEGATE_TEST_CLI='["/tmp/smartdelegate-go"]' python3 -m unittest test_conformance.DaemonConformance
SMARTDELEGATE_RUST_BIN=/tmp/smartdelegate-go python3 -m unittest test_interop   # the Python/Rust interop suite, with this binary in the Rust port's place
```

## Known differences from the reference

Codes, reasons and all other output are meant to be identical, and the tests
above found no difference on what they send (re-run against the reference at
0.3.0, after its "Strictness (0.3)" fixes). These differences are known and
left in place; each was re-checked against that reference:

- **Integers outside 64 bits.** Python integers are unbounded. A budget
  outside 64 bits is `invalid_cap` here (`invalid_input` in the reference);
  `iat` / `exp` outside 64 bits in a token make it `token_invalid` (malformed
  claims); `max_ttl` outside 64 bits in `roles.json` is `roles_parse`; `now`
  and `n` are clamped to the 64-bit range (the reference computes with the
  big number; `ttl` gives the same result in both). In a `context` and in
  entity attributes such integers are refused by both.
- **JSON text.** Results are written with keys sorted, and non-ASCII
  characters as themselves (the reference keeps insertion order and its daemon
  writes `\uXXXX`). Both are the same JSON values. Token claims are signed in
  sorted key order. An escaped lone surrogate (`"\ud800"`) in a request
  becomes U+FFFD here; the reference keeps it and fails with `internal` when
  it has to write it.
- **Nesting.** This port's parser refuses more than 1000 levels of nesting.
  The reference's limit comes from Python's recursion limit and is not a fixed
  number; requests nested between a few hundred and 1000 levels may be
  answered differently (both refuse 100000 levels with the same 400).
- **Daemon edges.** A body over 8 MiB is refused with the same 400, but up to
  32 MiB of it is read and discarded first so that the client can read the
  answer (the reference answers at once, and a client still sending may see a
  connection reset). A malformed `Content-Length` and methods other than GET
  and POST are answered by Go's HTTP server (400 / 501 with a text body), not
  with the reference's bodies. Chunked request bodies are ignored, as in the
  reference.
- **RSA keys under 1024 bits** in a JWKS are refused by Go 1.24's `crypto/rsa`.
  What the reference does with such a key was not compared.
- **After `Close`**, an engine with a state directory answers `state_io`.

## Not included

- The HTTP proxy (`http-proxy`) and the MCP proxy (`mcp-proxy`).
- The in-process helpers of the Python package: `Guard`, `SqlGuard`.
- `init` (example bundle), `bench`.
- `bundle compile`: no port other than Rust parses Cedar text. This port loads
  `policies.json` and refuses a bundle whose `.cedar` sources do not match it.
- Cedar schema validation, and Cedar outside the portable subset
  (`spec/POLICY_SUBSET.md`): refused at load with `policy_parse`.
- TLS in the daemon.

## Not tested

- Any Go version other than 1.24.7. `go.mod` says `go 1.21` and the code uses
  no newer language feature, but it was not compiled with 1.21 to 1.23.
- Windows, macOS and the BSDs: `go build` and `go vet` pass for
  `GOOS=windows`, `darwin` and `freebsd`; nothing was run there. The Windows
  lock in particular has never been exercised.
- This port's own tests compare it with the Python reference only. Interoperability with the Java, Node, PHP and Rust
  ports, and a state directory shared with Python, Rust and PHP, are checked by
  `ports/conformance/matrix.py`, not by `go test`.
- Performance. There is no benchmark.
- Long-running use: log rotation, very large audit logs or state files.
