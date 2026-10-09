# Changelog

## Unreleased

### Security
- Install instructions no longer name packages the maintainers have not
  published. Until the first release, install from a clone (README, "Install").
- New `SECURITY.md` (private vulnerability reporting), `names.json` (the only
  official package names) and a CI check that fails when a document names any
  other package.
- Releases are built and published only by `.github/workflows/release.yml`
  through PyPI trusted publishing, with provenance attestations.

### Changed
- **Renamed (breaking), `sf-` = Smart Family:** repository `SmartTasksOrg/sf-smartdelegate`, PyPI package `sf-smartdelegate`, command `sf-smartdelegate`, import package `sf_smartdelegate`, MCP server `io.github.smarttasksorg/sf-smartdelegate`. The unprefixed names are not used any more, so nobody can be sent to a look-alike.
- New `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `MAINTAINERS.md`; README "Install" and "Status" sections.
- `pyproject.toml`: SPDX licence, `NOTICE` in the wheel, "3 - Alpha" classifier, Source/Issues/Security/Changelog URLs.
- CI (`.github/workflows/ci.yml`): tests, scenario harness, skills check and the install-line check on every push and pull request.
- The release workflow publishes the Python package to PyPI by trusted publishing. It no longer builds the other artifacts of `make dist`; build those from a clone (`docs/BUILD.md`).
- npm (`sf-smartdelegate`, `sf-smartdelegate-client`) and Composer (`smarttasksorg/sf-smartdelegate`) package names and the Go module path follow the `sf-` names; none is published.
- The GitHub Action pins `actions/setup-python` by commit and installs `sf-smartdelegate` by default.
- Scenario 10 of the harness issues its token for the company tenant `kestrel`, as the example company says, so the cross-tenant read is refused for the reason the scenario names (`tenant_mismatch`).
- The nightly soak workflow is no longer in this repository; it used third-party actions that the organisation does not allow.
- Leftover files of the private simulation harness and `MARKETING.md` are no longer in this repository.

## 0.3.0 — SmartDelegate: roles, bridges, six engines
- **Renamed** from the working name AgentIAM to SmartDelegate and laid out as a Smart* family repository. Token audience, default issuer, environment variables (`SMARTDELEGATE_*`), Java package (`dev.smartdelegate`) and C ABI symbols changed with the name; 0.2 tokens are not accepted.
- **Role-scoped task tokens** ([spec/ROLES.md](spec/ROLES.md)): `roles.json` in the bundle; `issue_token` with `role`; the human must hold the role, the token cannot exceed its ceiling, sub-agents inherit it; `context.iam.role` in policy; `require_role`.
- **Live membership**: `groups` at issuance and `idp.groups_claim` for OIDC ID tokens replace the stored membership of that user for that token.
- **Offboarding**: `revoke {"user"}` ends every token already issued for a human.
- **Rule ids**: every decision carries `rule`, every error `error.rule`, as `DELEGATE-*`.
- **IAM bridges** (`smartdelegate.bridges`, `smartdelegate bridge ...`): directory sync from SCIM, Okta, Entra ID, Keycloak, Google and AWS Identity Center; claim mapping; role ceilings from AWS, GCP and Azure permissions; AWS session policies, GCP access boundaries, Azure On-Behalf-Of scopes. Tested against fakes only.
- **New native engines**: Node, Go and PHP, each with a CLI and REST daemon. Java and Rust brought to 0.3.
- **Cross-port matrix** (`ports/conformance/matrix.py`) and `ports/conformance/run.sh`.
- **Strictness** found by running the ports against each other and fixed in the reference: audit lines split at `\n` only, strict base64url, full-match type names, `containsAll`/`containsAny` operand checks, policy JSON shapes, non-UTF-8 files, signing-key creation race.
- **Example company** ([examples/company/](examples/company/)): a bundle for a seven-unit company (35 people, 18 roles, 115 policies, 63 policy tests), used by the scenario harness and the live suites.
- **Scenario harness** ([harness/](harness/)): six business scenarios of that company with scripted agents, in process or against a daemon by URL, with five checks and an HTML report.
- **Simulation testing.** A larger harness, not part of this repository, ran 16 scenarios with many simulated agents (scripted and deliberately misbehaving) against every engine and compared the answers with an independent model of the company's rules. It found three engine issues, fixed in every engine: ancestor budgets were not enforced by a verify-only engine with its own state (now carried in the token's `lim` claim), a user cut-off could move back, and an approval was not bound to resource attributes.
- **Bootstrap, build and CI**: `bootstrap.sh` / `bootstrap.ps1` (fresh clone to built and checked), `scripts/doctor.py`, `make` / `make.ps1` targets, `make dist` (wheel, jar, npm tarballs, Go binaries for four platforms, PHP archive and phar, Rust binary, spec tarball, checksums), Docker files and a compose topology (not run), GitHub workflows for Linux, macOS and Windows (not run). [docs/BUILD.md](docs/BUILD.md).
- **Live suites** ([live/](live/)): a real Keycloak, a real PostgreSQL-backed upstream behind both proxy implementations, a kernel network-namespace boundary test, load and soak. They led to: `azp` check on ID tokens, ID tokens from before a user's revoke refused, `reload` re-reading the provider's keys, nested group claims, strict query parsing and record lookups in the proxies (`attrs_from_record`), strict validation of proxy configuration, request-framing rules, SqlGuard masking inside JSON columns, and in the Rust port a new HTTP server, no head-of-line blocking and `TCP_NODELAY`.
- **Java**: command line and REST daemon; Java is now in the cross-port matrix and the load suite.
- **Breaking for proxy users**: routes and tools files are validated strictly at start. Constants in `id` and `spend` are written `{"literal": ...}`; attributes taken from the request must be declared under `attrs_from_request`.
- **Family surface**: `smartdelegate.core` (`delegate`, `narrow`, `check`), `smartdelegate.models`, `smartdelegate --demo`, integrations, playground.
- Conformance: 95 policy-evaluation cases, 78 engine cases (327 steps) in 12 files.

## 0.2.0 — Python reference, Java port (as AgentIAM)
- Python became the reference; Java native port; Rust moved under `ports/`; policies compiled to Cedar JSON.

## 0.1.0 — first build (as AgentIAM)
- Rust core: capability tokens, delegation, Cedar policy, field masking, budgets, approval, audit.
