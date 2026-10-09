# AGENTS.md

Instructions for a coding or operations agent working **in this repository**.
To *use* or *operate* SmartDelegate, read [`skills/`](skills/) instead; to
*integrate* it, [`docs/INTEGRATE.md`](docs/INTEGRATE.md).

SmartDelegate is identity and access management for LLM agents: a human lends
an agent one role they hold, for one task; the token can only narrow; every
call is decided by policy; denied fields are removed; every decision is in a
hash-chained log. Build 0.3.0, no independent security review.

## Layout

| Path | What it is |
|---|---|
| `spec/` | the specification: `API.md` (operations), `ROLES.md`, `PORTING.md` (byte formats), `POLICY_SUBSET.md`, `openapi.yaml`, and `conformance/` (bundle, vectors, policy evaluation cases, test identity provider) |
| `src/sf_smartdelegate/` | **the reference implementation** (Python; one dependency, `cryptography`): engine, CLI, REST daemon, HTTP proxy, MCP proxy, SQL guard, `bridges/` |
| `ports/` | independent engines in Java, Node.js, Go, PHP, Rust; `js` is a REST client; `conformance/` holds the cross-port runners |
| `integrations/` | `adapter.py` and the wrappers built on it (LangChain, LlamaIndex, function calling), the MCP server, CI and editor integrations |
| `interfaces/` | what an adopter implements: typed contracts, reference implementations, the contract test kit |
| `skills/`, `agents/` | agent-facing files: Agent Skills, two agent definitions, their example bundle fragment |
| `tests/` | the reference's unit tests (`unittest`, standard library) |
| `docs/` | `LIMITATIONS.md`, `THREAT_MODEL.md`, `BRIDGES.md`, `SCOPE.md`, `COVERAGE.md`, `BUILD.md`, `INTEGRATE.md`, `FRAMEWORK.md` |
| `examples/`, `demo/`, `site/` | example bundles and stand-in upstreams, the scripted demo, the browser playground |
| `harness/`, `live/`, `scripts/`, `docker/` | the scenario harness, suites against real services, build scripts, container files |

## Build and test

Python 3.10 or later. From a clone, without installing:

```bash
PYTHONPATH=src python3 -m sf_smartdelegate --demo            # nine scripted steps on the bundled example
cd tests && python3 -m unittest                           # the reference's unit tests
cd tests && python3 -m unittest test_interfaces test_agent_surface -v
ports/conformance/run.sh                                  # the two shared suites against every port whose toolchain is installed
ports/conformance/run.sh python                           # only the reference
PYTHONPATH=src python3 skills/validate.py --run           # the skills in skills/
PYTHONPATH=src:. python3 -m interfaces.contract --reference   # the contract kit against the reference implementations
```

One command for a fresh clone (virtual environment, every port with an
installed toolchain, a quick verification): `./bootstrap.sh` on Linux and
macOS, `.\bootstrap.ps1` on Windows. The scenario harness: `python -m harness run`.
`docs/BUILD.md` has the details. A missing toolchain is reported as SKIP,
never as PASS.

Run when this file was written, on Linux with Python 3.11: every command in
the block above except the full `ports/conformance/run.sh`, which was run for
the reference only (`ports/conformance/run.sh python`). Not run then:
`./bootstrap.sh`, `.\bootstrap.ps1` and `python -m harness run` (they were being
changed at the time).

After a change, run at least the unit tests of what you touched and
`ports/conformance/run.sh python`. After a change to `src/sf_smartdelegate/` that
affects an operation, a byte format or a decision: every installed port
(`ports/conformance/run.sh`) and `ports/conformance/matrix.py`.

## Rules that must not be broken

1. **Never weaken a conformance vector.** `spec/conformance/vectors/*.json`
   and `spec/conformance/eval/cases.json` are the definition of correct. Do
   not delete, loosen or special-case one to make an implementation pass. A
   vector that is wrong is fixed in the specification first, with the reason,
   and then in every engine.
2. **The reference is `src/`.** When the specification and the reference
   disagree, the vectors decide and the loser is fixed
   (`spec/PORTING.md`). A behaviour change starts in the specification and
   the reference, gets a vector, and then goes to every port. Never change a
   port alone to behave differently from the reference.
3. **Byte formats match exactly** across all engines: canonical JSON, key
   encodings, the capability token, the bundle version and signature, the
   audit record, the state directory (`spec/PORTING.md`, "Formats that must
   match byte for byte" and "Strictness"). One token has one spelling; audit
   lines end at `\n` and nowhere else.
4. **Policies are compiled by the Rust port.** `policies.json` is produced
   from `policies/*.cedar` by `smartdelegate bundle compile` in `ports/rust`
   (the real Cedar library). Never write or edit `policies.json` by hand; an
   engine refuses a bundle whose `.cedar` files changed since compilation
   (`bundle_stale`). The policy evaluation cases carry the real Cedar
   engine's answers; never edit an expected answer by hand.
5. **No secrets, keys or state in the repository.** Nothing named
   `state.json`, `audit.jsonl`, `signing_key.*`, `*.key`, `*.pem`,
   `bundle.sig.json`, `.env`; no capability token or ID token outside the
   test fixtures that already hold throwaway ones; no cloud credential. Keys
   and tokens for tests are made in a temporary directory at run time.
   `.gitignore` lists the names.
6. **Fail closed.** A request that cannot be decided is refused: a malformed
   input, an unreadable state file, an audit log that cannot be written, a
   bundle that does not verify, an erroring forbid, an unreachable daemon, an
   unknown key in a configuration, routes or roles file. Never add a default
   that allows, a fallback that skips a check, or an `except` that turns an
   error into an allow or into an empty result.
7. **Say what was tested and what was not.** Do not write that something
   works on a platform, against a provider or at a scale it was not run on.
   `docs/LIMITATIONS.md` and the "UNVERIFIED" list in `docs/BRIDGES.md` are
   kept true; update them in the same change.
8. **Do not widen authority in examples or defaults.** Test switches
   (`allow_test_clock`, `trust_caller_chain`) stay off by default; example
   roles keep `max_ttl`; an integration never receives the admin key where
   the pep key is enough.

## Conventions

- Python: standard library plus `cryptography`; no new runtime dependency
  without a decision by the maintainers. Tests are `unittest`; a test that
  needs something that is not installed is skipped with the reason.
- Every refusal has a reason and a rule id, `DELEGATE-` plus the reason in
  upper case with dashes. A new reason is added to `spec/API.md` and gets a vector.
- Error and audit texts never contain a token, a key or a field value.
- Documentation is plain technical English: no marketing adjectives, no
  numbers that were not measured.
- A change to an operation updates `spec/API.md`, `spec/openapi.yaml`, the
  vectors and each port in the same piece of work, or says which port lags.

## Where things are specified

| Question | File |
|---|---|
| What an operation takes and returns | `spec/API.md`, `spec/openapi.yaml` |
| Roles, ceilings, issuance order | `spec/ROLES.md` |
| Token, bundle, audit, state formats | `spec/PORTING.md`, `docs/SCOPE.md` section 8 |
| The Cedar subset | `spec/POLICY_SUBSET.md` |
| Decision order and reasons | `docs/SCOPE.md` section 7 |
| What the system does not do | `docs/LIMITATIONS.md`, `docs/THREAT_MODEL.md` |
| Identity providers and clouds | `docs/BRIDGES.md` |
| Adopter interfaces | `interfaces/README.md`, `interfaces/docs/` |
| Place in a governance framework | `docs/FRAMEWORK.md`, `spec/iaiso-map.json` |

## Working on the engine while it is in use

If you are also *operating* an engine (not only editing code), the operating
rules of [`skills/`](skills/) apply: never mint authority, widen a role,
approve, revoke a user or change policy without a human.
