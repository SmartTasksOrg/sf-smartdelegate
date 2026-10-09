# SmartDelegate for PHP

A native PHP port of the SmartDelegate engine: capability tokens (EdDSA JWTs
with an RFC 8693 `act` chain), narrowing-only delegation, Cedar policy
evaluated from compiled JSON, field masking, budgets, human approval, a
hash-chained audit log and role-scoped task tokens.

The Python package in `src/sf_smartdelegate` is the reference. This port is held
to the same suites (`spec/conformance`) and is additionally compared with the
reference result by result (see "Tests").

Included: the engine, a command line, a REST daemon, a front controller for a
web server, a REST client. Not included: the HTTP and MCP proxies (see the end).

## Requirements

- PHP 8.1 or later (CLI for the command line and the daemon)
- extensions: `sodium` (Ed25519), `openssl` (RSA / ECDSA ID tokens), `json`, `mbstring`
- optional: `pcntl` (the daemon then stops cleanly on SIGINT / SIGTERM)
- no Composer packages. `composer.json` is there for metadata and autoloading;
  without Composer, `require 'src/autoload.php';` does the same.

Developed and run on PHP 8.4.21 on Linux. It is written for 8.1+, but it has
not been run on 8.1, 8.2 or 8.3, nor on Windows or macOS.

## Using the engine

```php
require 'ports/php/src/autoload.php';

use SmartDelegate\Engine;
use SmartDelegate\Json;

$iam = new Engine(['bundle_dir' => 'spec/conformance/bundle', 'state_dir' => '/var/lib/smartdelegate']);

// alice lends the agent her role "support-agent" for one task
$t = $iam->call('issue_token', ['user' => 'alice', 'agent' => 'support-bot', 'role' => 'support-agent', 'task' => 'ticket-4711']);
if ($t['ok'] !== true) {
    throw new RuntimeException($t['error']['code'] . ': ' . $t['error']['message']);
}

$request = ['token' => $t['token'], 'action' => 'read', 'resource' => ['path' => 'crm.customer', 'id' => 'c-1']];
$d = $iam->call('authorize', $request);
echo $d['effect'], ' ', $d['rule'], ' role=', $d['principal']['role'], "\n";   // allow DELEGATE-POLICY-PERMIT role=support-agent
echo implode(',', $d['obligations']['fields']['deny']), "\n";                   // addresses[].geo,card.number,notes,ssn

$rows = [
    ['id' => 'c-1', 'name' => 'Ann', 'ssn' => '123-45-6789', 'region' => 'EU', 'card' => ['last4' => '4242', 'number' => '4111111111111111']],
    ['id' => 'c-2', 'name' => 'Bob', 'region' => 'US'],
];
$f = $iam->call('filter', $request + ['data' => $rows]);
echo Json::compact($f['data']), ' masked=', implode(',', $f['masked']), ' dropped=', $f['rows_dropped'], "\n";
// [{"id":"c-1","name":"Ann","region":"EU","card":{"last4":"4242","number":"[REDACTED]"}}] masked=card.number,ssn dropped=1
$iam->close();
```

`Engine::call(string $op, mixed $payload): array` takes every operation of
`spec/API.md`. It never throws: a failure is
`['ok' => false, 'error' => {code, message, rule}]`, and a deny is a normal
result with `effect` `deny`. The constructor does throw (`EngineError`) when
the configuration, the bundle or the state directory is unusable.
`Engine::callJson(string $op, string $json): string` is the same with JSON
text on both sides. `SmartDelegate\Client` has the same `call()` and talks to a
daemon (this port's or any other); it throws `EngineError`
`daemon_unreachable` when there is no answer, because an unreachable decision
point must never be taken for an allow.

### JSON in PHP: read this once

PHP arrays cannot represent JSON faithfully, and this engine depends on the
difference between `{}` and `[]`, between `1` and `1.0`, and on key order by
code point. So the port has its own JSON model (`src/Json.php`; `json_decode`
and `json_encode` are not used anywhere in the engine):

| JSON | In this port |
|---|---|
| object | `SmartDelegate\JsonObject` (array access, iteration with string keys, `count()`, `json_encode()`-able) |
| list | PHP list array |
| integer | `int`; beyond 64 bits a `SmartDelegate\BigInt` (exact digits, never a float, never a string) |
| other number | `float`, written back the way Python writes it (`1.0`, `1e+16`) |

What that means when you call the engine from PHP:

- **Results.** `call()` returns the result object as a PHP array; every
  object nested in it is a `JsonObject`, every list a PHP list. `$r['cap']['budget']`
  works either way; `json_encode($r)` and `Json::encode($r)` keep `{}` and `[]`
  apart. `Json::toNative()` gives plain arrays when you do not care.
- **Requests.** An associative array or a `stdClass` is an object, a list
  array is a list. **An empty PHP array is an empty list.** Write
  `new \stdClass` (or `new JsonObject`) where you mean `{}`, or leave the key
  out: `'context' => []` is refused with `invalid_context`, exactly as the JSON
  `"context": []` is. The one exception is the request itself: `call('info', [])`
  is read as `{}`, because a request can only be an object.
- **Integers.** A PHP float is a float even when it is whole: `'amount' => 100.0`
  is refused where the reference refuses `100.0`. Pass integers.
- **From JSON text** (the daemon, the command line, `callJson()`), nothing is
  ambiguous and nothing above needs thought.

Arithmetic on caller-supplied integers (clock, lifetimes, budgets, spend) is
exact beyond 64 bits (`src/Num.php`), as in Python. Inside Cedar policies
integers are 64-bit and overflow is an evaluation error, as in Cedar.

## Command line

```
php bin/smartdelegate-php help
php bin/smartdelegate-php conformance                       # eval cases + vectors of this repository
php bin/smartdelegate-php info --bundle DIR [--state DIR]
php bin/smartdelegate-php token issue --user alice --agent support-bot --role support-agent --raw --config smartdelegate.json
php bin/smartdelegate-php authorize --token T --action read --resource crm.customer/c-1 --config smartdelegate.json
php bin/smartdelegate-php serve --config smartdelegate.json --listen 127.0.0.1:8181
```

Commands: `info`, `policy check`, `policy test`, `bundle keygen <prefix>`,
`bundle sign --key <file>`, `token issue|exchange|inspect|revoke`, `authorize`,
`explain`, `approvals`, `approve <id> --by USER`, `audit verify`, `audit tail [-n N]`,
`call <op> [--input JSON|@file|-]`, `conformance [<vectors dir> <bundle dir>]`,
`serve [--listen host:port]`, `version`. Flags, configuration lookup
(`--config`, else `SMARTDELEGATE_CONFIG`, else `./smartdelegate.json`; `--bundle`,
`--state`, `--shadow`; relative `bundle_dir`, `state_dir` and `idp.jwks_file`
in a config file are relative to that file) and exit codes (0 allow / ok,
2 deny, 1 error) are those of the reference CLI.

## REST

Same routes, keys (`admin_key`, `pep_key`, bearer, constant-time comparison),
status codes and 8 MiB body limit as the reference daemon; see `spec/openapi.yaml`.

### `serve`: one PHP CLI process

`php bin/smartdelegate-php serve` needs nothing but the PHP CLI. It prints
`smartdelegate daemon listening on http://HOST:PORT` on stderr once bound
(`--listen 127.0.0.1:0` picks a free port). It is a single process with one
engine: requests are answered one at a time, in arrival order; connections are
multiplexed, so a client that stalls mid-request does not block the others
(it is dropped after 30 s). Every response carries `Connection: close`. No TLS:
bind to loopback or put a proxy in front. It raises PHP's `memory_limit` to 1G
when it is lower, because a fatal out-of-memory error would end the process;
if the process dies, clients get no answer, which `Client` reports as an error.

### `public/index.php`: php-fpm, Apache, `php -S`

```
SMARTDELEGATE_CONFIG=/etc/smartdelegate.json php -S 127.0.0.1:8181 public/index.php
```

Mount it at the web root (or strip the prefix in the web server). It builds a
fresh engine for every request. That has consequences; they come from where
the reference keeps its state, not from this port:

**Works across requests** (kept in the state directory, read under the lock on
every call): the signing key, revocations, pending and granted approvals, the
spend ledger and budgets of ancestor tokens, revoked users, the audit chain. Several workers,
and the Python or Rust engine, can share that directory.

**Does not work:**

- **Rate limits (`@rate_limit`).** The reference keeps rate-limit windows in
  the memory of the engine object (`Engine._rate`): per process, not shared
  between processes that share a state directory, gone on restart. This port
  does the same. With a fresh engine per request the window is always empty:
  `obligations.rate_limit.used` is always `0` and **a `@rate_limit` policy
  never denies**. If a policy relies on a rate limit, run `serve` (one
  long-lived process; counters are still lost when it restarts, as in the
  reference), not php-fpm. The test suite shows this: of the 78 conformance
  cases run through `index.php`, the one that expects `rate_limited` differs.
- **Decision ids can repeat.** A decision id is a hash of the request, the
  second, a per-engine counter and the process id. With a fresh engine the
  counter is always 1, so the same request answered twice in the same second by
  the same worker process gets the same `decision_id` (and two audit records
  carry it).
- **Cost.** Every request loads and checks the bundle and re-verifies the
  whole audit log before answering, so latency grows with the log.
- `reload` is meaningless (every request loads the bundle and `idp.jwks_file`
  anyway; it still writes its audit record).

Tested with `php -S` only. Not run under php-fpm or Apache; there,
`Authorization` must reach PHP (`HTTP_AUTHORIZATION`), and a body larger than
`post_max_size` is refused by PHP before `index.php` sees it.

## State directory and locking

`state.json` (`revoked`, `approvals`, `pending`, `ledger`, `limits`, `revoked_users`; an empty section is always written `{}`), `audit.jsonl`, `signing_key.pk8.b64` (mode 0600),
`signing_key.pub.b64`, `lock`. Every operation takes an exclusive `flock()` on
`lock` and re-reads `state.json`. On Linux PHP's `flock()` is flock(2), the
same lock the Python reference and the Rust port take, so one state directory
can be shared with them (tested against the reference: alternating operations,
one audit chain, each side waits for the other's lock). Do not share a state
directory with the Java port (different lock), and do not put it on a
filesystem where flock is not honoured.

## Tests

```
php test/run.php            # everything; --only=1,5 for sections, --verbose for every check
./run_conformance.sh        # the two official suites only
```

`test/run.php` has no dependencies and removes its temporary directories.

| Section | What |
|---|---|
| 1 | the 95 policy-evaluation cases |
| 2 | the 78 conformance cases (327 steps), in-process |
| 3 | the same 78 cases over REST: own daemon, own client; plus the HTTP rules (keys, 401/404/400/501, body limit) |
| 4 | interoperability with the Python reference: tokens both ways (incl. role + `grp`), signed bundles both ways and identical versions, audit logs both ways incl. tampering, one shared state directory with one signing key (spend, token revocation and revoke-by-user each seen by the other side) and the lock in both directions; an ancestor's budget enforced from the `lim` claim by a verify-only engine with its own state directory, in both directions; then about 300 requests run through both engines with the results, the state file and every audit record compared; the HTTP rules against both daemons; ID tokens with `azp`, several audiences, `iat` against the revoke cut-off and a nested group claim, each compared with the reference; approval ids for requests with and without resource attributes identical in both; canonical JSON byte for byte |
| 5 | JSON fidelity: `{}` vs `[]`, int vs float, integers beyond 64 bits, Cedar overflow, canonical form, numeric string keys |
| 6 | the 78 cases through `public/index.php` under `php -S`, and what does and does not survive between requests |
| 7 | key formats (RFC 8032 vector), every token check, ID tokens with RS256/384/512, ES256/384 and EdDSA (cross-checked with the reference), corrupt state and audit files, bundles that must not load, every rule of "Strictness (0.3)" in `spec/PORTING.md`, the command line |

Section 4 and the ID-token cross-check in section 7 need `python3` with the
`cryptography` package; without it they are skipped with a message and the
rest still runs.

The reference's own daemon test passes against this port's command line:

```
cd tests && SMARTDELEGATE_TEST_CLI='["php","'$ROOT'/ports/php/bin/smartdelegate-php"]' python3 -m unittest test_conformance.DaemonConformance
```

## Where this port differs from the reference

Error codes, reasons and every other output are meant to be identical, and
are compared in the tests (reference 0.3.0, including the "Strictness (0.3)"
rules of `spec/PORTING.md`, each of which has its own test in section 7).
Remaining differences, each re-checked against the current reference:

- `info` reports implementation `php`.
- Message texts are the reference's almost everywhere, but are not guaranteed.
- JSON text: nesting deeper than 512 is refused (the reference fails
  somewhere between a few hundred and a thousand levels, depending on the
  Python version), and an unpaired UTF-16 surrogate escape is refused (Python
  accepts it). `NaN` and `Infinity` are read and written, as Python does.
- Private keys: only the 48-byte PKCS#8 version 1 form of `spec/PORTING.md` is
  read. The reference reads any PKCS#8 Ed25519 key.
- Ed25519 verification is libsodium's, which also refuses small-order public
  keys; the reference uses OpenSSL.
- `@row_filter` / `@rate_limit` annotations: numbers must be ASCII digits
  (Python's regular expressions also accept other Unicode decimal digits).
- When a long-lived engine re-reads the last audit record after another
  process appended, `seq` must be an integer and `hash` a string; the
  reference converts other types with `int()` / `str()`. Both only matter for
  a log that is already damaged.
- The daemon answers requests one at a time and closes every connection; the
  body of a `501` is JSON, not the HTML page of Python's `http.server`.

## Not included / not tested

- `http-proxy` and `mcp-proxy`, `init`, `bench`, `bundle compile` (needs the
  Cedar toolchain: use the Rust port). The `Guard` and `SqlGuard` helpers of
  the Python package have no counterpart.
- No typed convenience methods (`authorize()`, `filter()`, ...): only `call()`.
- Not run on PHP 8.1 to 8.3, on Windows (PHP's `flock()` is a different lock
  there) or on macOS; not run under php-fpm or Apache.
- TLS, and any authentication beyond the two static keys.
- Throughput and latency were not measured.
