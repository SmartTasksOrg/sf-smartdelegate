# Ports

The reference implementation is the Python package in `src/sf_smartdelegate`.
Each directory here is an independent implementation in another language,
except `js`, which is a REST client, and `conformance`, which holds the
cross-port tests. Every engine port reads the same bundle, state directory,
token, signature and audit formats (`spec/PORTING.md`).

| Port | Directory | Kind | Daemon | CLI | State directory can be shared with | Requirements | Its own tests |
|---|---|---|---|---|---|---|---|
| Python (reference) | `src/sf_smartdelegate` | engine | yes, plus HTTP and MCP proxy | `python3 -m sf_smartdelegate` | Rust, Go, PHP (`flock`) | Python 3.10+, `cryptography` | `cd tests && python3 -m unittest` |
| Rust | `ports/rust` | engine, embeds real Cedar, C ABI | yes, plus HTTP and MCP proxy | `target/release/smartdelegate` | Python, Go, PHP (`flock`) | Rust 1.89+; a C compiler for the C ABI check | `cargo test --release`; `./run_conformance.sh` |
| Go | `ports/go` | engine | yes | `go build ./cmd/smartdelegate-go` | Python, Rust, PHP (`flock`) | Go 1.21+ | `go vet ./... && go test ./...`; `./run_conformance.sh` |
| PHP | `ports/php` | engine | yes (`serve`, or `public/index.php`) | `php bin/smartdelegate-php` | Python, Rust, Go (`flock`) | PHP 8.1+ with `sodium`, `openssl`, `json`, `mbstring` | `php test/run.php`; `./run_conformance.sh` |
| Node.js | `ports/node` | engine | yes | `node bin/cli.mjs` | other Node.js engines only (own lock file `lock.node`) | Node 18+ | `npm test`; `./run_conformance.sh` |
| Java | `ports/java` | engine and REST client | yes | `./build.sh`, then `bin/smartdelegate-java` | other Java engines only (JVM file lock) | JDK 17+ | `./run_conformance.sh` |
| JavaScript client | `ports/js` | REST client only; decisions are made by a daemon | no | no | not applicable | Node 18+ | `node --test test/*.test.mjs` |

Notes on the table:

- "Can be shared" means several processes may use one state directory at the
  same time. Any two engine ports can use one directory one after the other.
- The versions are the ones each port's README states. Those READMEs also say
  which versions and platforms were actually run.
- The interoperability tests of a port, and the whole Java harness, start the
  Python reference, so they also need Python 3.10+ with `cryptography`.
- `./run_conformance.sh` (no arguments, in each engine port's directory) runs
  the two shared suites against that port: the policy evaluation cases
  (`spec/conformance/eval/cases.json`) and the engine conformance vectors
  (`spec/conformance/vectors`). The Java script runs the whole Java harness;
  the two suites alone are `bin/smartdelegate-java conformance` after `./build.sh`.
  The Rust script exits with status 3 when cargo is not installed.

## The shared suites against every port: `conformance/run.sh`

```
ports/conformance/run.sh             # all ports
ports/conformance/run.sh go php      # only these
ports/conformance/run.sh -v          # with each port's full output
```

It runs every port whose toolchain is installed and prints one line per port
and a summary:

```
python: PASS (<N> eval, <M> conformance)
java: SKIP (a JDK (javac, jar, java) is not installed)
...
summary: pass=5 fail=0 skip=1
```

The numbers are read from the port's output. A port without its toolchain is
SKIP, never PASS and never FAIL. A port that exits with 0 but does not report
both suites, or reports zero cases, is FAIL. The exit status is 1 if any port
failed. The Go binary is built in a temporary directory; the Java and Rust
scripts build into their ignored directories (`ports/java/build`,
`ports/rust/target`).

## Ports against each other: `conformance/matrix.py`

```
python3 ports/conformance/matrix.py
python3 ports/conformance/matrix.py --report matrix.json     # also write the results as JSON
python3 ports/conformance/matrix.py --ports python,go --checks a,e --keep
```

Python 3.10+, standard library only. It drives each engine port through its
command line (`call <op> --input -`, `bundle keygen`, `bundle sign`,
`audit verify`), one process per operation. The Java port is built with its
own `ports/java/build.sh` and driven through `bin/smartdelegate-java`.

For every ordered pair of ports (issuer A, verifier B, A != B), with separate
state directories, the same `issuer`, and B configured with `verify_only` and
`trusted_keys` = A's public key:

| Check | What |
|---|---|
| a | A issues a role token with live groups (user `dave`, agent `support-bot`, role `support-agent`, groups `["support"]`, a task). B's `inspect_token` says valid with the same claims; B's `authorize` allows with `principal.role`; B's `filter` of a record with `ssn`, `notes` and `card` returns the same `data`, `masked`, `obligations`, `effect`, `reason`, `rule`, `policies` and `rows_dropped` as A's own |
| b | A exchanges the token to a sub-agent with a narrower cap. B accepts the child, and denies an action and a resource outside the child's cap with the same `reason` and `rule` as A |
| c | The token with one payload character changed, and the token followed by `!!!!`, are `token_invalid` on B (`inspect_token` and `authorize`) |
| d | A makes a key pair and signs a copy of the conformance bundle. B loads it with `bundle_public_key` and reports the same `policy_version`, signing key id and roles. After `roles.json` is edited in the copy, B refuses to load it with `bundle_signature` |
| e | A writes an audit log (issue with a task containing U+2028, U+2029 and U+0085, filter, a deny, exchange, revoke, a deny after revocation). B's `audit verify` on a copy of A's state directory gives the same record count and head hash as A's. After one byte of the copy is flipped, B reports `audit_broken` |

JSON results are compared as values: member order is ignored, `1` and `true`
and `1.0` are different. All six engine ports are issuer and verifier in
every check.

Then the ports that lock the state directory with `flock` (Python, Rust, Go,
PHP) take turns on one state directory with one signing key:

- spend against one budget, each spend from a different port: the total is enforced
- a token issued by one port, exchanged by a second and revoked by a third is
  `token_revoked`, with its child, on all of them
- an approval is requested, listed, refused for the user herself, granted and
  used in different ports, and is single use
- five processes per port spend at the same time against a budget that covers
  half of them: exactly half are allowed
- each port's `audit verify` gives the same record count and head hash

Node.js and Java are left out of that part: they use their own locks. It is
skipped on Windows.

Output: one table per check (issuer rows, verifier columns; `PASS`, `FAIL`,
`-` on the diagonal), the shared-directory results, and for every
failure what differed and the commands that were run, in order. The commands
refer to a temporary directory; `--keep` keeps it so that they can be re-run.
A port whose toolchain is missing is left out with a `SKIP` line. Exit status:
0 without a failure, 1 with one, 2 for a usage or build error. Every command
has a time limit (`--timeout`, default 120 s). Keys, state, bundle copies and
the Go binary go to the temporary directory, never into the repository; the
Java and Rust ports are built into their own ignored directories
(`ports/java/build`, `ports/rust/target`).

## Everything

`./test_all.sh` at the repository root runs the reference's tests, every
port's own suite, the JavaScript client against the reference and the Rust
daemon, the reference's daemon conformance test against the Node.js, Go, Java
and PHP daemons, and the matrix. `./test_all.sh --quick` runs only
`ports/conformance/run.sh`. `./test_all.sh --live` adds the live suites
(`live/idp/run.sh`, `live/run.sh all --quick`), which start real services; a
live suite that exits with 3 could not run and is reported as SKIP.
`test_all.ps1` is the Windows counterpart; its header says what of it has
been run and where.

## Adding a port

`spec/PORTING.md` has the order of work, the formats that must match byte for
byte, and the rules that are easy to get wrong. To join the cross-port tests:

1. Give the port a `run_conformance.sh` that takes no arguments, runs the
   eval cases and the conformance vectors, prints `eval: N cases, F failed`
   and `conformance: N cases, F failed`, and exits non-zero on a failure.
2. Add it to `ports/conformance/run.sh`: a `run_<port>` function that skips
   when the toolchain is missing, and its name in `all_ports`.
3. Give it the command line of the other ports (`call <op> --input -`,
   `--config FILE`, `bundle keygen`, `bundle sign`, `audit verify`; JSON
   result on stdout; `smartdelegate: <code>: <message>` on stderr and exit
   status 1 when the engine cannot be built) and add it in `discover()` of
   `ports/conformance/matrix.py`. Add it to `FLOCK_PORTS` there only if it
   takes `flock` on `<state>/lock`.
4. Add its own test suite to `test_all.sh` and `test_all.ps1`, and a row to
   the table above and to `spec/PORTING.md`.
