# Building and testing SmartDelegate

From a fresh clone to "everything built and tested" is one command:

| System | Command |
|---|---|
| Linux, macOS | `./bootstrap.sh` |
| Windows (PowerShell 5.1 or 7) | `.\bootstrap.ps1` |

Only Python 3.10+ is required. Every other toolchain is optional: a port
whose toolchain is missing is reported as `SKIPPED (reason)`, never as built
and never as passed.

**What was run where.** Everything in this document was run on one Linux
machine (Ubuntu 24.04, x86_64, 2 cores). Nothing was run on Windows or macOS.
The PowerShell scripts were run with PowerShell 7.5 **on Linux**. Docker files
were written without a Docker daemon and have never been built. The GitHub
workflows have never been executed by a runner. The table at the end,
[Verified here / written but not run](#verified-here--written-but-not-run),
lists every file; [Windows: untested, check these first](#windows-untested-check-these-first)
says what to try first on a Windows machine.

## Requirements

`python3 scripts/doctor.py` (Python 3.8+, standard library) prints this table
for the machine it runs on, with the versions it found and the install
command for what is missing. `--json` is the same for machines;
`--platform windows|macos|apt|dnf` shows another platform's commands.
It exits 0 when the reference requirement (Python 3.10+ with the `venv`
module) is met.

| Tool | Minimum | Enables |
|---|---|---|
| Python **(required)** | 3.10, with the `venv` module | the reference engine, CLI, daemon, proxies, harness, every test runner |
| Python package `cryptography` | 41 | Ed25519 and ID-token signatures; the bootstrap installs it into `.venv` |
| JDK (`java`, `javac`, `jar`) | 17 | `ports/java`: engine, command line, daemon. A Java 17 or 21 runtime also runs Keycloak for `live/idp` |
| Node.js | 18 | `ports/node`, `ports/js`, the Flowise and playground tests |
| npm | any | `npm test` in `ports/node`, `npm pack` for `dist` |
| Go | 1.21 | `ports/go`, the cross-compiled `dist` binaries |
| PHP with `sodium`, `openssl`, `json`, `mbstring` | 8.1 | `ports/php` |
| Rust (`cargo`, `rustc`) | 1.89 | `ports/rust`: real Cedar, HTTP and MCP proxy, C ABI, `bundle compile`. The first build downloads crates from crates.io |
| A C compiler | any | the C ABI check of `ports/rust` (not run on Windows); on Windows, MSVC is what Rust links with |
| Docker with Compose v2 | | `make docker-build`, `make docker-test` |
| PostgreSQL server (`pg_ctl`, `initdb`) | any (developed with 16) | `live/run.sh upstream` and `boundary`, or attach with `SD_PG_DSN` |
| PowerShell | 5.1 | `bootstrap.ps1`, `make.ps1`, `test_all.ps1` (Windows) |
| bash | any | `bootstrap.sh`, `test_all.sh`, `ports/conformance/run.sh`, `live/*.sh` |

The minimum versions are the ones the port READMEs state. The versions this
was developed and run with: Python 3.11, OpenJDK 21, Node 22, Go 1.24,
PHP 8.4, Rust 1.95, PostgreSQL 16.

Install commands, as `doctor.py` prints them. Where each name was checked:
winget ids in the manifests of `microsoft/winget-pkgs`; Homebrew formulae and
casks in `Homebrew/homebrew-core` and `homebrew-cask`; apt packages with
`apt-cache policy` on Ubuntu 24.04. **The dnf names were not verified**: no
Fedora machine or package index was reachable.

| Tool | Windows (`winget install -e --id ...`) | macOS (`brew install ...`) | Debian / Ubuntu (`apt-get install -y ...`) | Fedora (`dnf install -y ...`, not verified) |
|---|---|---|---|---|
| Python | `Python.Python.3.12` | `python@3.12` | `python3 python3-venv python3-pip` | `python3 python3-pip` |
| JDK | `EclipseAdoptium.Temurin.21.JDK` | `openjdk@21` (keg-only: add its `bin` to `PATH`) | `openjdk-21-jdk-headless` | `java-21-openjdk-devel` |
| Node.js, npm | `OpenJS.NodeJS.LTS` | `node` | `nodejs npm` (Node 18 on Ubuntu 24.04) | `nodejs npm` |
| Go | `GoLang.Go` | `go` | `golang-go` | `golang` |
| PHP | `PHP.PHP.8.4`, then enable the extensions in `php.ini` (see below) | `php` | `php-cli php-mbstring` | `php-cli php-mbstring php-sodium` |
| Rust | `Rustlang.Rustup`, then `rustup default stable` | `rustup`, then `rustup default stable` | `rustup`, then `rustup default stable` (the distribution's own `cargo` 1.75 is too old) | `rustup`, then `rustup-init -y` |
| C compiler | `Microsoft.VisualStudio.2022.BuildTools` with the C++ workload (the `--override` arguments `doctor.py` prints are from Microsoft's documentation and were not run) | `xcode-select --install` | `build-essential` | `gcc` |
| Docker | `Docker.DockerDesktop` | `--cask docker-desktop` | `docker.io docker-compose-v2` | `moby-engine docker-compose` |
| PostgreSQL | `PostgreSQL.PostgreSQL.16` (add its `bin` to `PATH`, or set `SD_PG_BIN`) | `postgresql@16` (keg-only) | `postgresql` | `postgresql-server` |
| PowerShell 7 | `Microsoft.PowerShell` | `powershell` | Microsoft's package repository or `snap install powershell --classic` | Microsoft's package repository |
| bash | `Git.Git` (Git Bash; only for running the `.sh` files natively) | present | present | present |

PHP from winget ships without a `php.ini`: copy `php.ini-development` to
`php.ini` next to `php.exe` and uncomment `extension=sodium`,
`extension=openssl` and `extension=mbstring`. `doctor.py` says which are
missing.

`--install` (`./bootstrap.sh --install`, `.\bootstrap.ps1 -Install`) runs
those commands for whatever is missing. It is opt-in: without the flag
nothing is installed outside the repository. Each command is printed before
it runs. `sudo` is put in front of `apt-get` and `dnf` only when you are not
root, with a line saying so, and asks for the password itself. On this
machine only `--install --dry-run` and the nothing-is-missing path were run;
**no package was installed through it**.

## The bootstrap

```
./bootstrap.sh                      .\bootstrap.ps1
./bootstrap.sh --full               .\bootstrap.ps1 -Full
./bootstrap.sh --only python,go     .\bootstrap.ps1 -Only python,go
./bootstrap.sh --install            .\bootstrap.ps1 -Install
./bootstrap.sh --offline            .\bootstrap.ps1 -Offline
./bootstrap.sh --clean              .\bootstrap.ps1 -Clean
./bootstrap.sh --require java,go    .\bootstrap.ps1 -Require java,go
./bootstrap.sh --no-verify          .\bootstrap.ps1 -NoVerify
./bootstrap.sh -v                   .\bootstrap.ps1 -ShowOutput
```

`bootstrap.ps1` also takes the bash spellings (`.\bootstrap.ps1 --full --only python,go`).

What it does, in order:

1. Finds a Python (3.8+ runs the driver; 3.10+ is needed for the virtualenv).
2. Creates the virtualenv `.venv`, installs the package editable
   (`pip install -e .`, which brings `cryptography`), then the optional
   extras of `scripts/requirements-dev.txt` (`build` for `dist`,
   `psycopg2-binary` for the PostgreSQL tests, `PyYAML` for the syntax check
   of two deployment files in `live/boundary`). If the extras cannot be installed, that is a `SKIPPED`
   line, not a failure.
3. Prints the doctor's table.
4. Builds every port whose toolchain is present (table below).
5. Writes uniform launchers into `build/bin/` and runs `<launcher> version`
   for each.
6. Quick verification: `sf-smartdelegate --demo`; the two shared suites against
   every built port (`ports/conformance/run.sh`; without bash, the same
   suites started directly); the example company's policy tests and
   `python -m harness run`.
7. With `--full`: `test_all.sh` (`test_all.ps1` on Windows), the cross-port
   matrix, and the live suites: `live/idp/run.sh` and
   `live/run.sh all --quick`.
8. Prints one line per component, `BUILT`, `PASS`, `SKIPPED (reason)` or
   `FAILED`, then the next commands. Exit status 1 if anything failed.

| Component | What "build" means | Where the result is |
|---|---|---|
| `python` | virtualenv, editable install | `.venv/` |
| `java` | `ports/java/build.sh` (`build.cmd` on Windows): `javac` and `jar`, no Maven | `ports/java/build/smartdelegate.jar`; `build/bin/smartdelegate-java` runs it through the port's own `bin/smartdelegate-java` |
| `node`, `js` | nothing to build: no dependencies | |
| `go` | `go build ./cmd/smartdelegate-go` | `build/bin/smartdelegate-go` (`.exe`) |
| `php` | nothing to build: no Composer packages | |
| `rust` | `cargo build --release --locked` | `ports/rust/target/release/smartdelegate` |

Launchers in `build/bin/`, the same command line for every engine
(`<launcher> version`, `call <op> --input ...`, `serve`, ...):
`smartdelegate` (the reference, through `.venv`), `smartdelegate-java`,
`smartdelegate-node`, `smartdelegate-go` (the binary itself),
`smartdelegate-php`, `smartdelegate-rust`. On Windows they are `.cmd` files.
They locate the repository relative to themselves, so the clone can be moved.

Everything written is git-ignored: `.venv/`, `build/` (launchers, `logs/`,
`reports/`), `dist/`, and the ports' own build directories
(`ports/java/build`, `ports/rust/target`). No key, token or password is
written anywhere; state and keys of the tests live in temporary directories.

**Idempotent.** A second run keeps the virtualenv (a stamp records the hash
of `pyproject.toml` and the requirements file), the Java jar when it is newer
than its sources, and whatever `go` and `cargo` consider up to date. Here: a
first run in a clean copy took 60 s on a quiet machine (24 s of it the
conformance suites) and up to 159 s on a busy one; a second run with
`--no-verify` took 2 s (about 20 s when the Rust conformance test ran in
between: after `cargo test -p smartdelegate-core`, cargo builds the command
line again). Those first runs had warm pip, Go and cargo caches and an
already compiled `ports/rust/target`: a cold Rust build compiles Cedar ("a
few minutes" in the Rust port's README) and was not timed here.

**`--offline`.** No network is used. The virtualenv is created with
`--system-site-packages` and `src/` is put on its path with a `.pth` file
(an editable install needs an index for its build environment); if
`cryptography` is not installed for the base Python, that step fails at once
and says so. `cargo build` runs with `--offline`; when there is no crate
cache at all, the Rust build is not even started and the message says to run
once online or `cargo fetch --locked`. `--offline` cannot be combined with
`--install`. `dist --offline` skips the Python sdist and wheel, because
`python -m build` downloads `setuptools` into an isolated environment.

**`--clean`** removes `.venv`, `build/`, `dist/`, `ports/java/build` and the
Python caches first. It keeps `ports/rust/target`, which takes several
minutes to rebuild; `make clean ARGS=--deep` removes that too.

**`--require a,b`** (or the environment variable `SD_REQUIRE`) turns a
`SKIPPED` for one of the named parts into `FAILED`. CI uses it: on a runner
where every toolchain is installed, a skip is a mistake. Names: the
components, and `live`, `harness`, `conformance`, `test_all`, `docker`.

**Time limits and leftovers.** Every command the driver starts is the
leader of a session of its own and has a time limit; when it runs over,
every process of that session is stopped, by PID and never by name (a
process group is not enough: `timeout`, which the repository's scripts use,
moves its child into another group). When a test step ends normally, what it
left running in its session is stopped as well and named in the output; for
a live suite that is a failure of its own (`FAILED live leftovers`), and so
is a private PostgreSQL the suite started and did not stop. A daemon that
detached on purpose (its own session, like the Keycloak of
`live/idp/keycloak.sh`) is left to the script that owns it. Defaults in
seconds, each overridable as `SD_TIMEOUT_<NAME>`: `PIP` 900, `JAVA` 600,
`GO` 900, `RUST` 3600, `CONFORMANCE` 1800 per port, `HARNESS` 900,
`MATRIX` 3600, `TEST` 1800, `TEST_ALL` 5400, `LIVE` 4500, `DOCKER` 7200.

The work is done by `scripts/sd.py` (Python 3.8+, standard library). The
shell and PowerShell files only parse their options, find a Python and call
it, so Linux, macOS and Windows run the same code. `SD_NATIVE=1` makes the
driver take the paths it takes on Windows (no bash scripts: the conformance
suites started directly, `test_all.ps1` instead of `test_all.sh`, `javac`
and `jar` called directly) on any system that has PowerShell.

## Make targets

`make <target>` on Linux and macOS, `.\make.ps1 <target>` on Windows. Extra
options: `make conformance ARGS="--only go,php"`, `.\make.ps1 conformance --only go,php`.

| Target | What it runs |
|---|---|
| `bootstrap` | `./bootstrap.sh` (`bootstrap.ps1`) |
| `doctor` | `scripts/doctor.py` |
| `build` | builds every port whose toolchain is here and writes the launchers. (It used to be `python -m build`; that is part of `dist` now.) |
| `test` | the reference's unit tests: `cd tests && python -m unittest` |
| `conformance` | the two shared suites against every installed port: `ports/conformance/run.sh` |
| `matrix` | every port against every other: `ports/conformance/matrix.py`, report in `build/reports/matrix.json` |
| `harness` | `sf-smartdelegate policy test --bundle examples/company`, then `python -m harness run`: the scenarios of `harness/scenarios/` on the reference engine; report in `build/reports/harness/` |
| `live` | `live/idp/run.sh`, then `live/run.sh all`. `ARGS=--quick` for the short form, `ARGS="idp upstream"` to pick parts (`idp`, `upstream`, `boundary`, `load`) |
| `load` | load and soak in the full form, gated: `python -m live.load --targets python,rust --duration 12 --warmup 2 --soak 20000 --overload --check live/load/thresholds.json`, report in `build/reports/load` |
| `all` | `bootstrap --full` |
| `dist` | release artifacts and `SHA256SUMS` in `dist/` |
| `clean` | removes `.venv`, `build/`, `dist/`, caches (`ARGS=--deep`: also `ports/rust/target`) |
| `docker-build` | builds `docker/Dockerfile.dev` and `docker/Dockerfile.daemon` (not tested) |
| `docker-test` | the live topology of `docker/docker-compose.yml` (not tested) |

`make demo` and `make all-tests` (`./test_all.sh`) are kept from before.

On Windows, `.\make.ps1 live` and `.\make.ps1 load` report every part as
`SKIPPED`: the live suites are bash scripts that start Keycloak and
PostgreSQL, and the boundary test needs Linux network namespaces and root.
Run them under WSL (`wsl bash -lc "./bootstrap.sh && make live"`) or against
containers (`.\make.ps1 docker-test`).

## The test pyramid

Each layer assumes the ones below it. Times are from this machine (2 cores),
with every toolchain installed.

| Layer | What it proves | Command | Time here |
|---|---|---|---|
| 1. Unit | the reference: policy evaluator against real Cedar's recorded answers, engine, strictness rules, proxies, SQL guard, bridges, integrations | `make test` | 34 s (265 tests) |
| 1. Unit, per port | each port's own suite (and its interoperability with the reference); the reference's daemon test against the Rust, Node, Go, Java and PHP daemons | `npm test`, `go vet ./... && go test ./...`, `php test/run.php`, `cargo test --release`, `ports/java/run_conformance.sh` | part of `test_all.sh` |
| 2. Conformance | every port gives the specified answer: 95 policy evaluation cases and 78 engine cases (327 steps, 12 vector files), the same files for all | `make conformance` | 24 s on a quiet machine, up to 109 s on a busy one |
| 3. Cross-port matrix | ports accept each other's tokens, sub-agent tokens, signed bundles and audit logs; tampering is refused; one state directory shared by the `flock` ports. Java takes part through its own command line | `make matrix` | 38 to 84 s |
| 4. Harness | six business scenarios of the example company end the way its rules require: no denied field in returned data, spend within budget, revoked tokens refused, an audit record for every decision. In process, or against any port's daemon by URL | `make harness` | under 1 s |
| 5. Live: idp | the bridges and the daemon against a real Keycloak (downloaded, started on a loopback port) | `live/idp/run.sh` | 78 s (45 tests), plus a 150 MB download the first time |
| 5. Live: upstream | the HTTP proxy, the MCP proxy and the SQL guard in front of a real PostgreSQL, a REST API in its own process and an MCP server | `live/run.sh upstream` | 43 s in the quick form (97 tests, 2 of them skipped) |
| 5. Live: boundary | the proxy is the only way out of a kernel network namespace (Linux, root) | `sudo -E live/run.sh boundary` | 25 s (4 tests), as root |
| 5. Live: load | throughput, latency and wrong-allow count against thresholds (`live/load/thresholds.json`) | `live/run.sh load --quick`, `make load` | about 40 s in the quick form; the full form: 12 min 41 s (`make load`) |

`./test_all.sh` runs layers 1 to 4 in one go (5 to 8 minutes here; its own summary was `pass=18 skip=4 fail=0`, the skips being tests that need `langchain_core`, `llama_index` or `SMARTDELEGATE_PG_DSN`, and the live suites it runs only with `--live`); with `--live`
it also runs layer 5. `./bootstrap.sh --full` runs `test_all.sh`, then the
matrix once more on its own (for the JSON report),
`live/idp/run.sh` and `live/run.sh all --quick`: 11 min 29 s here as root, with
every toolchain. `make dist` took 18 s with warm caches (about 2 minutes the first time: the Go cross-builds).

Line endings are checked separately: `python scripts/check_crlf.py` (4 s)
converts a copy of the conformance bundle to CRLF and proves, for every
installed engine, that it loads with the same `policy_version`, passes the
`bundle_stale` check, and that a bundle signed with one kind of line ending
verifies after conversion to the other. `.gitattributes` makes git check
every text file out with LF on every platform (`.cmd` and `.bat` with CRLF),
so a Windows clone has the same bytes as a Linux one.

## Run the scenario harness

The harness (`harness/README.md`) plays six business scenarios of the example
company (`examples/company`) against an engine and checks every step: the
outcome the company's rules require, no denied field in returned data, spend
within the budget of a token and of its ancestors, nothing allowed for a
revoked or offboarded human's token, and an audit record for every decision.
It is small on purpose: scripted agents, one scenario instance at a time, the
standard library and the `smartdelegate` package. After the bootstrap it
needs nothing else. Run everything below from the repository root.

The project is also tested with a larger simulation harness (many concurrent
agents, agents that misbehave on purpose, an independent model of the
company's rules, deliberately broken engines that the checks must catch, the
same workload compared across every port). That harness is not part of this
repository; `README.md` states the results obtained with it.

**Linux, macOS**

```bash
. .venv/bin/activate

# 1. in this process, the reference engine: each scenario once (under 1 s)
python -m harness run --out build/reports/harness

# 2. some scenarios, more instances; --seed chooses which people of the company play them
python -m harness run --scenarios 01,07,11 --instances 30 --seed 3

# 3. against a daemon you started yourself, here through a launcher in build/bin.
#    The keys exist in these two variables only.
export SMARTDELEGATE_ADMIN_KEY="$(python -c 'import secrets; print(secrets.token_hex(20))')"
export SMARTDELEGATE_PEP_KEY="$(python -c 'import secrets; print(secrets.token_hex(20))')"
mkdir -p build/harness-daemon
cat > build/harness-daemon/config.json <<'JSON'
{"bundle_dir": "../../examples/company", "state_dir": "state", "mode": "enforce", "allow_test_clock": true, "max_depth": 3}
JSON
build/bin/smartdelegate-go serve --config build/harness-daemon/config.json --listen 127.0.0.1:8181 &
python -m harness run --backend url:http://127.0.0.1:8181 --out build/reports/harness-url
kill %1                                  # stop the daemon you started
rm -rf build/harness-daemon/state        # the state holds that daemon's signing key and audit log
```

**Windows PowerShell** (not run on Windows; the harness itself has only run
on Linux)

```powershell
.\.venv\Scripts\Activate.ps1

python -m harness run --out build\reports\harness
python -m harness run --scenarios 01,07,11 --instances 30 --seed 3

# a daemon you start yourself: in a second PowerShell window, with the same two variables set
$env:SMARTDELEGATE_ADMIN_KEY = python -c "import secrets; print(secrets.token_hex(20))"
$env:SMARTDELEGATE_PEP_KEY = python -c "import secrets; print(secrets.token_hex(20))"
New-Item -ItemType Directory -Force build\harness-daemon | Out-Null
'{"bundle_dir": "../../examples/company", "state_dir": "state", "mode": "enforce", "allow_test_clock": true, "max_depth": 3}' |
  Set-Content -Encoding ascii build\harness-daemon\config.json
build\bin\smartdelegate-java.cmd serve --config build\harness-daemon\config.json --listen 127.0.0.1:8181    # second window
python -m harness run --backend url:http://127.0.0.1:8181 --out build\reports\harness-url                    # first window
# stop the daemon with Ctrl-C in its window, then: Remove-Item -Recurse build\harness-daemon\state
```

Without the virtualenv, set `PYTHONPATH=src` (PowerShell:
`$env:PYTHONPATH = "src"`) and use `python3` or `python`.

Any launcher works in step 3 (`smartdelegate`, `smartdelegate-java`,
`smartdelegate-node`, `smartdelegate-go`, `smartdelegate-php`,
`smartdelegate-rust`; `.cmd` on Windows except the Go `.exe`). The daemon
must be given the company bundle (`examples/company`), `mode: enforce` and
`max_depth: 3`. With `allow_test_clock: true` every scenario runs; without
it the two scenarios that move the clock are reported as `SKIP`. `make
harness` is the bundle's policy tests and step 1.

**Where the reports land.** In the directory given with `--out`; without
it, in a new temporary directory whose path is printed at the end.
`build/` is git-ignored. Two files: `report.html` (open this one: what ran,
pass or fail per scenario, a swimlane per scenario, every violation with its
request and answer) and `report.json` (for machines, with every recorded
step). No capability token is written to a report.

**How to read the result.** Every run ends with these lines:

```text
backend inprocess (python engine): 6 instances, 117 requests, 75 decisions in 0.2 s; audit records: 109 (74 decisions matched)
violations: 0; harness errors: 0
verdict: PASS
```

| Verdict | Exit status | Meaning |
|---|---|---|
| `PASS` | 0 | every step had the outcome the company's rules require and none of the five checks found anything |
| `FAIL` | 1 | at least one violation: a step with an unexpected outcome, a denied field in returned data, spend over a budget, a dead token that worked, or an audit log that does not verify or misses a decision. Each is printed with its scenario and step |
| `ERROR` | 2 | the harness itself could not run (no backend, a request without an answer, a scenario that names nobody in the bundle). This says nothing about the engine |

A scenario shown as `SKIP` did not run; it is not a pass.

What was run here: steps 1 to 3 on Linux, each ending in `verdict: PASS`
(step 3 with the Go and the Java launcher in turn).

## What used to be "not covered", and what covers it now

Earlier versions of this repository said, for each of these, that nothing
tested it. This is what does now, how to run it, and what is still open.

| Was not covered | Covered by | Run it | Still open |
|---|---|---|---|
| A real identity provider | `live/idp`: the daemon, the bridges and the sync against a real Keycloak, 26.0.7 and 26.8.0 (ID tokens, `azp`, group mappers, key rotation with `idp.jwks_file` and reload, offboarding) | `live/idp/run.sh` (`SD_KEYCLOAK_VERSION=26.8.0` for the other version); part of `make live` and `--full` | **Only Keycloak.** Okta, Entra, Google, AWS Identity Center, Auth0 and generic SCIM are still tested against hand-written fakes |
| A real upstream | `live/upstream`: a PostgreSQL database, a REST API in a separate process with its own key, and an MCP server, behind the HTTP proxy, the MCP proxy and the SQL guard; results checked by an oracle that imports nothing from the engine | `live/run.sh upstream` | Open findings are listed in `live/FINDINGS.md`; their tests are expected failures |
| The proxy as a network boundary | `live/boundary`: an agent process in a kernel network namespace whose only way out is the proxy | `sudo -E live/run.sh boundary` (Linux, root) | `live/boundary/deploy-compose.yml` and `deploy-networkpolicy.yaml` are only parsed, never deployed; so is `docker/docker-compose.yml` here. Nothing on macOS or Windows |
| Load | `live/load`: steady state, overload and soak against the reference and the Rust daemon (other daemons with `--targets`), gated by `live/load/thresholds.json`; one set of numbers in `live/load/RESULTS.md` | `live/run.sh load --quick`; `make load` for the full form | One small shared machine, client and server together: indicative numbers, not a datasheet |
| Windows | `bootstrap.ps1`, `make.ps1` and `test_all.ps1` exist and were executed with PowerShell 7 **on Linux**; a `windows-latest` CI job is written | `.\bootstrap.ps1`, then the list in [Windows: untested, check these first](#windows-untested-check-these-first) | **Never run on Windows.** The CI job has never run. Windows PowerShell 5.1, `.cmd` launchers, file locking and code pages are unexercised |
| A Java backend | the Java port has a command line and a daemon (`ports/java/build.sh`, `bin/smartdelegate-java`); it is in the conformance script, the cross-port matrix (through its own CLI) and the load suite (`--targets java`); the reference's daemon test runs against it, and the scenario harness by URL | `make conformance`, `make matrix`, `python -m harness run --backend url:...` against `smartdelegate-java serve`, `python -m live.load --targets java --quick` | Java shares a state directory only with other Java engines (its own lock); never run on Windows (`build.cmd`, `smartdelegate-java.cmd`) |

## The live suites

Natively (Linux; macOS not tried):

```
make live                      # live/idp/run.sh, then live/run.sh all (upstream, boundary when root, load)
make live ARGS=--quick         # the short form: what ./bootstrap.sh --full and ./test_all.sh --live run
sudo -E env "PATH=$PATH" make live ARGS=boundary
make load                      # python -m live.load ... --check live/load/thresholds.json, report in build/reports/load
live/idp/run.sh                # or the scripts themselves
live/run.sh all --quick
```

Each script starts what it needs (Keycloak into `~/.cache/smartdelegate`, a
private PostgreSQL cluster under `/var/tmp`), stops it by PID, and checks at
its end that nothing it started is still alive. Exit status of both
scripts: 0 something ran and nothing failed, 1 a failure, 3 nothing ran.
`live/run.sh` prints one line per part (`upstream  PASS ...`,
`boundary  SKIP needs root ...`); the driver reads those lines, so a part
that was skipped inside a run that passed as a whole is reported as
`SKIPPED`, never as `PASS`.

The driver keeps a safety net of its own: after a live script ends, any
process still running in its session, and a private PostgreSQL the script
started and did not stop, is stopped and reported as
`FAILED live leftovers (...)` under a banner. With the scripts as they are
this did not trigger in any run here.

Two things about where the checkout lives. The boundary test drops to an
unprivileged user and starts `.venv/bin/python3` as that user, and
PostgreSQL, when the suite runs as root, is started as the `postgres` user:
both need every directory above the repository (and `SD_LIVE_HOME`, where the
private cluster goes) to be enterable by other users. Under a `0700`
directory the boundary test fails with `PermissionError`.

To attach to services that already run, set the variables the scripts
document (`live/README.md`, `live/idp/README.md`):

| Variables | Attach to |
|---|---|
| `SD_KEYCLOAK_URL`, `SD_KEYCLOAK_ADMIN`, `SD_KEYCLOAK_ADMIN_PASSWORD` | a Keycloak |
| `SD_PG_DSN` | a PostgreSQL |
| `SD_UPSTREAM_URL`, `SD_UPSTREAM_KEY` | a company API |
| `SD_DAEMON_URL`, `SD_ADMIN_KEY`, `SD_PEP_KEY`, `SD_PROXY_URL` | a decision daemon and its HTTP proxy |

Through Docker Compose (**not tested**, see the next section):

```
cp docker/.env.example docker/.env      # then fill in every value; the file is git-ignored
make docker-test
```

That starts the whole topology and runs the `tests` service, which is
`scripts/sd.py live idp upstream load --quick --require live` with the
variables above pointing at the other containers. Without a `docker/.env`,
`make docker-test` invents throwaway keys for the one run and keeps them in
memory only. The services publish their ports on `127.0.0.1`, so the native
scripts can also be pointed at the containers with the same variables.

## Docker

**Untested.** There was no Docker daemon where these files were written.
What was checked: `docker compose -f docker/docker-compose.yml config`
accepts the file (Compose 5.1.3) and refuses to start without the keys; the
base image tags exist in the official image manifests
(`docker-library/official-images`); the pieces that are not Docker were run
on Linux outside a container (below). Nothing was built, nothing was
started. `quay.io` was not reachable, so the Keycloak tag (`26.0.7`, the
version `live/idp/keycloak.sh` downloads and the live suite was verified
with) was not checked at the registry.

| File | What |
|---|---|
| `docker/Dockerfile.dev` | every toolchain and the repository; builds all ports at image build; `docker run` runs `./bootstrap.sh --full`. Base `php:8.4-cli-bookworm`, with Node from `node:22-bookworm-slim`, Go from `golang:1.26-bookworm`, the JDK from `eclipse-temurin:21-jdk-jammy`, Rust from `rust:1.99-slim-bookworm`, Python 3.11 and PostgreSQL 15 from Debian. Go and Rust are newer there than what was run natively (1.24, 1.95) |
| `docker/Dockerfile.daemon` | runtime image for `sf-smartdelegate serve` on `python:3.12-slim-bookworm`: uid 10001, state in the volume `/state`, bundle mounted read-only at `/bundle`, health check on `/healthz`, works with a read-only root file system |
| `docker/Dockerfile.upstream` | the plain-Python fixtures: `live/upstream/company_api.py`, `seed.py`, and `docker/idp_init.py` |
| `docker/docker-compose.yml` | `keycloak` (dev mode), `idp-init`, `postgres`, `db-seed`, `company-api`, `smartdelegate` (daemon), `http-proxy` (holds the upstream key), `agent` (on an `internal: true` network, reaches only the proxy; `agent_check.py` verifies that and exits), `tests`; `idp-jwks` on demand |
| `docker/idp_init.py` | creates the test realm with `live/idp/provision.py` and writes the daemon's config with its `idp` section and the JWKS file |
| `docker/.env.example` | template for `docker/.env`; no real secrets |

The daemon image is configured as the reference is (`load_config` in
`src/sf_smartdelegate/cli.py`): `SMARTDELEGATE_CONFIG` names the config file
(default in the image: `/etc/smartdelegate/smartdelegate.json` with
`bundle_dir` `/bundle`, `state_dir` `/state`, `listen` `0.0.0.0:8181`);
`SMARTDELEGATE_ADMIN_KEY` and `SMARTDELEGATE_PEP_KEY` are the two API keys
(16+ characters; `serve` refuses to start without them). The entrypoint also
reads `SMARTDELEGATE_ADMIN_KEY_FILE` and `SMARTDELEGATE_PEP_KEY_FILE`, for
secrets mounted as files. Keep the `/state` volume: it holds the signing key
and the audit log.

The live fixtures need no adapters any more: `company_api.py` takes its
address from `COMPANY_API_HOST` and `COMPANY_API_PORT`, and
`live/upstream/routes.json` names the upstream as `env:COMPANY_API_URL` and
its key as `env:COMPANY_API_KEY`, which the `http-proxy` service sets. The
proxies validate such files strictly when they start. Checked here with the
reference and with the Rust binary: `routes.json` loads with both variables
set and is refused by both ("the routes file is refused") with one unset;
`docker/daemon.json` and `docker/compose-daemon.json` load in both engines.

**The identity provider in Compose** follows the operator guidance of
`live/idp/README.md`. `idp-init` provisions the realm and writes, into a
volume the daemon mounts read-only, `jwks.json` and a `smartdelegate.json`
whose `idp` section has the issuer (the exact `iss` of the tokens, which
contains the host name users sign in through: `http://keycloak:8080/...`
inside the Compose network; `idp_init.py --public-url` for another), the
audience `sd-engine` (the engine checks `azp` against it; send the ID token,
never the access token), `jwks_file`, `user_claim: preferred_username`,
`groups_claim: groups` and the `group_map`. The provisioning record with
the test passwords stays in a volume only `idp-init` mounts. Rotating
Keycloak's signing key needs a reload, not a restart:

```
# 1. add the new key in Keycloak as passive, then
docker compose -f docker/docker-compose.yml --env-file docker/.env run --rm idp-jwks     # rewrites jwks.json
curl -X POST -H "Authorization: Bearer $SD_ADMIN_KEY" http://127.0.0.1:8181/v1/admin/reload
# 4. make the new key active in Keycloak
```

Run here without containers, against a real Keycloak 26.0.7 that
`live/idp/keycloak.sh` started: `idp_init.py` provisioned the realm and
wrote both files (2 keys, 19 mapped groups, no secret in either); with that
config the reference daemon and the Rust daemon each issued a role token
from a real ID token with no API key on the request, refused
`/v1/admin/reload` without the admin key, and after `--jwks-only` and a
reload with the admin key accepted the same sign-in again.

`docker run --privileged` is needed for the boundary test inside
`Dockerfile.dev` (it creates a network namespace). In Compose the boundary
is the `agent` service on the internal network instead.

## CI

Two workflows run on GitHub. Every action is a GitHub-owned action pinned to
a commit (the comment names the tag and the day it was read); Rust and PHP come
from the runner image, so no third-party action is used.

| Workflow | Trigger | Jobs |
|---|---|---|
| `ci.yml` | push to `master`, pull request | `test` (Python 3.10 and 3.12: `tests/`, the scenario harness, the skills check), `install-lines` (`scripts/check_install_lines.py` against `names.json`), `ports` (`ports/conformance/run.sh` against all six engines; shown, not yet a required check) |
| `release.yml` | tag `v*` | build and check the Python sdist and wheel, attest them, upload to PyPI by trusted publishing after a second maintainer approves the `pypi` environment, then a GitHub release with the same files and `SHA256SUMS` |

`test` and `install-lines` are required checks on `master`. The full layer
pyramid, the live suites (Keycloak, PostgreSQL, the network boundary, load)
and the other operating systems run from a clone with `./bootstrap.sh --full`
(`.\bootstrap.ps1 -Full` on Windows), as described above; they are not run on
GitHub. The other artifacts of `make dist` (jar, npm tarballs, Go, PHP and Rust
binaries) are built the same way and are not published.

## Cutting a release

1. Set the version everywhere it is written (`pyproject.toml`,
   `src/sf_smartdelegate/_version.py`, `.smart.json`, `spec/iaiso-map.json`,
   `publish/server.json`, `ports/node/package.json`, `ports/js/package.json`,
   `ports/rust/Cargo.toml`, `CHANGELOG.md`).
2. `./bootstrap.sh --full` must end without `FAILED`.
3. `make dist`, and read its summary. It builds into `dist/` and runs what it
   built:

   | Artifact | How it is checked |
   |---|---|
   | `sf_smartdelegate-X.tar.gz`, `sf_smartdelegate-X-py3-none-any.whl` (`python -m build` in `.venv`) | the wheel is installed into a fresh virtualenv and `sf-smartdelegate --demo` is run there |
   | `smartdelegate-java-X.jar` (from `ports/java/build.sh`) | `java -jar ... version` |
   | `smartdelegate-java-X.zip`: that jar as `build/smartdelegate.jar` with the port's launchers `bin/smartdelegate-java` and `bin/smartdelegate-java.cmd` | unzipped; `bin/smartdelegate-java version` and `conformance --root` (the `.cmd` is not run) |
   | `sf-smartdelegate-X.tgz` (`ports/node`), `sf-smartdelegate-client-X.tgz` (`ports/js`), from `npm pack` | unpacked; the CLI is run, the client is imported |
   | `smartdelegate-go-X-{linux-amd64,linux-arm64,darwin-arm64,windows-amd64.exe}` (`GOOS`/`GOARCH`, `CGO_ENABLED=0`) | the binary for the build machine runs `conformance`; the others are only compiled |
   | `smartdelegate-php-X.zip` (`bin/`, `src/` with `autoload.php`, `public/`, `composer.json`) | unzipped, `php bin/smartdelegate-php version` |
   | `smartdelegate-php-X.phar` | `php x.phar version` and `conformance`. Writing a phar needs `phar.readonly=0`; `php.ini` leaves it at 1, so it is built with `php -d phar.readonly=0`. If that does not work on a PHP, the phar is skipped and the summary says so |
   | `smartdelegate-rust-X-<host triple>` | `version`. Only the build machine's target; see below |
   | `smartdelegate-spec-X.tar.gz`: `spec/` with the conformance bundle, vectors and eval cases, for port authors | the listing is checked |
   | `SHA256SUMS` | `sha256sum -c` |

   Rust for other targets is not cross-compiled here: Cedar's dependencies
   need the target's linker. Either build on the target, or
   `rustup target add <triple>` and
   `cargo build --release --locked --target <triple>` with a linker for it
   (for example `aarch64-linux-gnu-gcc` and
   `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER`), or use `cross`. None of
   these was run.
   A tool that scans the working tree for key material will find
   third-party files in `.venv` (a CA bundle, test keys inside
   `cryptography`). Run `make clean` before such a scan, or keep the
   virtualenv outside the repository: `SD_VENV=~/.venvs/smartdelegate ./bootstrap.sh`
   (the same variable for every later command).
4. Tag `vX` (the tag must equal the version; `release.yml` checks) and push
   the tag. Only organisation owners can create release tags. The workflow
   builds and checks the Python sdist and wheel on a runner, attests them,
   waits for a second maintainer to approve the `pypi` environment, uploads
   them to PyPI by trusted publishing (no token exists) and attaches the same
   files and `SHA256SUMS` to a GitHub release.
5. The other `make dist` artifacts are not published. npm, crates.io and
   Packagist have no publisher for this repository; the names in
   `names.json` say which names would be ours.

## Windows: untested, check these first

**First run on a real Windows machine: 2026-10-06** (Windows 11, PowerShell 7.4,
Python 3.13.5, JDK 25.0.2, Node 24.14; no Go, PHP, Rust or PostgreSQL), from an
unzipped copy on drive `I:`. `.\bootstrap.ps1` needed
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first (the files
came from a downloaded zip). Result, 66 s: the virtualenv, the editable
install, `ports\java\build.cmd`, the demo, conformance for Python, Java and
Node (95 evaluation and 78 conformance cases each), the harness run and the
self-test of the larger harness (in the checkout at the time) all passed. One failure:
`build\bin\smartdelegate-java.cmd version` exited 1 with `LinkageError
occurred while loading main class`. The launcher preferred `JAVA_HOME` over
`PATH` while the build used `PATH`; it now uses `PATH` first, and the
class-data archive is opt-in. That fix has not been re-run on Windows yet.
Everything else in this list is still unrun there.

Nothing here has run on Windows. The PowerShell scripts were executed with
PowerShell 7.5 on Linux, which exercises their logic but none of: Windows
PowerShell 5.1, `winget`, `.cmd` launchers, `.exe` names, backslash paths,
Windows file locking, the ANSI code page. The list below is ordered by how
likely each is to bite, with the command that exercises it. `$R` is the
repository root.

1. **The scripts themselves.** Start small:
   `.\bootstrap.ps1 -Only python -NoVerify`, then `.\bootstrap.ps1`, then
   `.\bootstrap.ps1 -Full`. If scripts are blocked:
   `powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1`. If `python`
   opens the Microsoft Store, that is the placeholder alias; the scripts
   probe each candidate (`py -3`, `python`, `python3`) and skip it, but only
   the logic was run, not the alias.
2. **Text through pipes is not UTF-8.** A Python whose stdin or stdout is a
   pipe uses the ANSI code page on Windows. `sf-smartdelegate call <op> --input -`
   then misreads non-ASCII JSON without an error (on Linux, forcing
   `PYTHONIOENCODING=cp1252` turned the task `t-Zoë-日` into mojibake inside
   the token and the audit record), and `ports/conformance/matrix.py` pipes
   exactly such JSON (`subprocess` in text mode, U+2028 in check e).
   `scripts/sd.py` therefore sets `PYTHONUTF8=1` for everything it starts on
   Windows, and `build\bin\smartdelegate.cmd` sets it too. To see the
   behaviour without that:
   `$env:PYTHONUTF8 = "0"; python ports\conformance\matrix.py --ports python,node --checks a,e`
   and
   `'{"user":"alice","agent":"support-bot","role":"support-agent","task":"t-Zoë-日"}' | python -m sf_smartdelegate call issue_token --bundle spec\conformance\bundle --state $env:TEMP\sd-enc --input -`
   (in Windows PowerShell 5.1, `$OutputEncoding` is ASCII by default, which
   replaces those characters before Python sees them). `--input @file.json`
   reads UTF-8 whatever the console is.
3. **File locking, reference** (`src/sf_smartdelegate/engine.py`, the `msvcrt`
   branch, never executed). `msvcrt.locking(..., LK_LOCK, 1)` retries for
   about 10 seconds and then raises, which the engine reports as
   `state_io: cannot lock the state directory`; `flock` on Linux waits
   without limit. Under contention this can fail where Linux does not.
   `cd tests; python -m unittest -v test_engine test_strictness`
   (`test_two_processes_write_one_valid_audit_chain`,
   `test_spend_is_shared_between_processes`,
   `test_racing_to_create_the_signing_key`), then
   `python -m harness run --instances 60`.
4. **Replacing `state.json`.** `state.py` writes `state.json.tmp` and calls
   `os.replace`. On Windows that fails with a sharing violation while any
   other process has `state.json` open (another engine reading it, a virus
   scanner, the search indexer). Same commands as 3; a failure shows as
   `state_io`.
5. **File locking, ports.** Go: `lock_windows.go` (`LockFileEx` on the first
   byte, the byte the reference locks) compiles for `GOOS=windows` and has
   never run: `cd ports\go; go test -run "Concurrent|Interop" ./...`.
   Node: its own lock file with a PID check that has no `/proc` on Windows:
   `cd ports\node; node --test test\lock.test.mjs`. PHP: `flock()` on Windows
   is a mandatory lock: `cd ports\php; php test\run.php --only=4`. Java:
   `FileLock`, a mandatory lock on Windows; on Linux Java and the `flock`
   ports do not exclude each other, on Windows they may, which nobody has
   looked at. The Java command line and daemon are started on Windows by
   `ports\java\build.cmd` and `bin\smartdelegate-java.cmd`, neither of which
   has ever run: `.\make.ps1 build --only java`, then
   `build\bin\smartdelegate-java.cmd version`,
   `.\make.ps1 conformance --only java` and the scenario harness against
   `build\bin\smartdelegate-java.cmd serve` (the PowerShell block above).
   `matrix.py` leaves its shared-state-directory part out on Windows by itself.
6. **The signing key file.** It is created through a temporary file and
   `os.link` (hard link), with a fallback to exclusive create when the file
   system has no hard links. NTFS has them; exFAT, FAT, some network shares
   and older ReFS do not, so the fallback is what runs there, untested on
   Windows. Put the state directory on such a volume and run
   `python -m sf_smartdelegate call info --bundle spec\conformance\bundle --state E:\sd-state`
   from two consoles at once; both must print the same `key_id`.
7. **`0600` means nothing.** The key file is created with mode `0o600`
   (Python, Go, Node, PHP, Java alike); Windows ignores it and the file
   inherits the directory's ACL. Look: `icacls <state>\signing_key.pk8.b64`.
   Restrict: `icacls <state> /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F"`.
   The same holds for `<prefix>.key` from `bundle keygen`.
8. **Path separators in bundle manifests.** By reading the sources: the
   manifest keys are the four fixed file names, and the `sources` keys of
   `policies.json` are built as `"policies/" + name` in every port (Python,
   Rust, Go, Node, PHP, Java), never with the platform separator. To see it:
   `python scripts\check_crlf.py`, and after
   `ports\rust\target\release\smartdelegate.exe bundle compile --bundle spec\conformance\bundle`
   the command `git diff --stat spec/conformance/bundle` must show nothing.
9. **CRLF.** `git ls-files --eol | findstr /v "w/lf"` should list only
   `.cmd` files (`w/crlf`). `python scripts\check_crlf.py` must pass for
   every engine. On Linux it passed for all six, and a clone made with
   `core.autocrlf=true` had LF in the bundle, the shell scripts and the
   `.ps1` files and CRLF in `ports/java/build.cmd`.
10. **JDK 17 reads sources in the ANSI code page.** `ports/java/build.sh`,
    `build.cmd` and `run_conformance.sh` pass `-encoding UTF-8`, and the
    matrix builds Java through `build.cmd`, so this should not
    bite any more; `scripts/sd.py` still sets
    `JDK_JAVAC_OPTIONS=-encoding UTF-8` for everything it starts. The JVM's
    own default charset is another matter: the launchers pass
    `-Dfile.encoding=UTF-8`; a bare `java -jar ...smartdelegate.jar` on JDK 17
    does not.
11. **`.cmd` launchers and JSON arguments.** `cmd.exe` rewrites `%`, `^`,
    `&` and quotes in `%*`. `build\bin\smartdelegate-node.cmd call info --input "{}"`
    works; anything with nested quotes should go through `--input @file.json`
    or `--input -`. Do not give a `.cmd` launcher to `SMARTDELEGATE_TEST_CLI`:
    stopping it kills `cmd.exe` and leaves the daemon behind; name the real
    executable (`python -m sf_smartdelegate`, `node ...\cli.mjs`, the `.exe`).
12. **`tests/test_integrations.py`, the GitHub Action test.** When a `bash`
    is on `PATH` (Git Bash, or WSL's `bash.exe`), it writes a `/bin/sh` shim
    with a Windows path in it and calls `os.symlink`, which needs Developer
    Mode or an elevated console: `cd tests; python -m unittest -v test_integrations`.
13. **PHP.** winget's PHP has no `php.ini`, so `sodium`, `openssl` and
    `mbstring` are off until enabled (`php -m`); there is no `pcntl`, so
    `smartdelegate-php serve` cannot stop cleanly on a signal.
14. **Long paths.** The longest paths below the repository are about 150
    characters (`.venv` with Python 3.11's bundled setuptools; cargo's
    `target\debug\incremental`). Keep the clone's own path under about 100
    characters, or enable long paths
    (`git config --system core.longpaths true` and the `LongPathsEnabled`
    registry value).
15. **Rust.** Needs the MSVC build tools; the first build compiles Cedar
    and takes several minutes; real-time virus scanning of
    `ports\rust\target` slows it considerably. The C ABI check is not run on
    Windows by any script.
16. **`test_all.ps1`.** Run on Linux with PowerShell 7 (results in the
    table below); never on Windows and never with PowerShell 5.1. It has no
    time limit per step; `bootstrap.ps1 -Full` puts one on the whole run. On
    Windows `-Live` reports the live suites as SKIP.

## Verified here / written but not run

"Run here" means on the Linux machine described at the top, as root, from a
clean copy of the repository in `/var/tmp` (with an already compiled
`ports/rust/target/release` copied in, so no cold Rust build).

| File | Run here | Not run |
|---|---|---|
| `scripts/doctor.py` | full table, `--json`, `--markdown`, `--platform` for all four, `--require`, `--install --dry-run`, with `PATH` cut down to Python, PHP and Go; under Python 3.8.20 (an earlier revision) and 3.11 | on Windows and macOS; a real `--install` |
| `scripts/sd.py` | `bootstrap` (plain 60 s; `--full` 11 min 29 s, `built=7 pass=22`; `--only`, `--offline`, `--clean`, `--require`, `--no-verify`), `build`, `test`, `conformance` (bash and `SD_NATIVE=1`), `matrix`, `harness`, `live` (`idp`, and `live/run.sh all --quick` as root: upstream, boundary and load all ran), `load` (12 min 41 s, within the thresholds), `dist`, `clean`; the time limit stopping a whole session; the leftover check, with a fake script that leaves a process (reported as `FAILED live leftovers`) | its Windows branches: `.cmd` launchers (their text was generated and read, not executed), `taskkill`, `PYTHONUTF8`, `build.cmd`; `docker-build` and `docker-test` beyond their "no daemon" message; `live/run.sh all` in its full form through `make live` (its parts ran: `--quick`, and the full load) |
| `scripts/check_crlf.py` | all six engines, 26 checks | on Windows |
| `scripts/requirements-dev.txt` | installed by the bootstrap | |
| `scripts/find-python.ps1` | PowerShell 7.5 on Linux | Windows, PowerShell 5.1, `py -3`, the Store alias |
| `bootstrap.sh` | all flags; `--install` only where nothing was missing | on macOS (bash 3.2); a real install |
| `bootstrap.ps1` | PowerShell 7.5 on Linux: parsing, both option spellings, `-Only`, `-Require`, `-NoVerify`, `-Help`, usage errors, and `-Full` with `SD_NATIVE=1` from `/var/tmp`: `built=7 pass=22`, `test_all.ps1` inside it `pass=19 skip=2 fail=0`, the live suites including the boundary test, 10 min 30 s | Windows, PowerShell 5.1, `-Install` (winget), the PATH refresh |
| `make.ps1` | PowerShell 7.5 on Linux: `conformance` with `SD_NATIVE=1` (six ports pass without bash, Java through its jar), `build`, `doctor --json`, `help`, unknown target | Windows, PowerShell 5.1 |
| `Makefile` | `bootstrap`, `doctor`, `dist`, `clean`, `help`, `load`; the others through `scripts/sd.py` directly | `docker-build`, `docker-test` |
| `test_all.ps1` | PowerShell 7.5 on Linux: `-Quick` (`pass=11 skip=0 fail=0`), the full run (`pass=19 skip=2 fail=0`, with the "java daemon" step; the skips are the C ABI check, which it never runs, and the live suites without `-Live`), and `-Live` (as root: `pass=21 skip=1 fail=0`, both live steps passing, 9 minutes) | Windows, PowerShell 5.1 |
| `.gitattributes` | `git check-attr`; a clone with `core.autocrlf=true` | a real Windows checkout |
| `.gitignore`, `.dockerignore` | read | |
| `docker/Dockerfile.dev`, `Dockerfile.daemon`, `Dockerfile.upstream` | base image tags checked against the official manifests | never built |
| `docker/docker-compose.yml`, `.env.example` | `docker compose config` (valid; refuses empty keys) | never started |
| `docker/daemon.json`, `compose-daemon.json`; `live/upstream/routes.json` as the `http-proxy` service gets it | loaded by the reference and by the Rust binary; the routes file refused by both with `COMPANY_API_URL` unset | in a container |
| `docker/idp_init.py` | against a real Keycloak 26.0.7 outside a container; the reference and the Rust daemon then ran with its output (sign-in with a real ID token, `--jwks-only`, reload) | in a container; Keycloak 26.8.0; `--public-url` |
| `docker/daemon-entrypoint.sh`, `agent_check.py` | on Linux outside a container: the entrypoint with key files; `agent_check.py` against a real `sf-smartdelegate http-proxy` and closed ports | in a container |
| `.github/workflows/ci.yml`, `release.yml` | `actionlint`; every `run:` step of `ci.yml` executed as written on Linux | not yet executed on GitHub |
| `dist` artifacts | built; wheel, jar, the Java launcher archive (its `bin/smartdelegate-java` ran `version` and `conformance`), npm tarballs, linux/amd64 Go binary, PHP zip and phar, Rust binary, spec tarball and checksums each run or checked | the linux/arm64, darwin/arm64 and windows/amd64 Go binaries were compiled, not run; `bin/smartdelegate-java.cmd` |
