# Runs every test suite on Windows. PowerShell 5.1 or PowerShell 7.
#
# NOTE: THIS SCRIPT HAS NEVER BEEN RUN ON WINDOWS. It was run with PowerShell
# 7.5 on Linux (all steps, see docs/BUILD.md), which exercises its logic but
# not Windows: no .exe names, no backslash paths, no Windows file locking, no
# PowerShell 5.1. test_all.sh is the script that is executed regularly, on
# Linux; this one follows the same steps. If a step fails on Windows, check
# first whether the step itself (not the code under test) is wrong, and
# report it. docs/BUILD.md lists what to check first on Windows.
#
# There is no time limit per step here. `.\bootstrap.ps1 -Full` and
# `.\make.ps1 all` run this script with a limit on the whole run.
# Unlike test_all.sh, tests that a suite skips by itself are not listed as
# SKIP lines; read the step's output for them.
#
#   .\test_all.ps1            everything
#   .\test_all.ps1 -Quick     only the two shared suites (policy evaluation
#                             cases, engine conformance vectors) against every
#                             installed port; what ports/conformance/run.sh
#                             does on Linux and macOS
#   .\test_all.ps1 -Live      also the live suites (live/idp/run.sh, live/run.sh
#                             all --quick). They are bash scripts that start
#                             real services: on Windows they are reported as
#                             SKIP (run test_all.sh --live under WSL or Linux).
#                             An exit code of 3 means nothing could run: SKIP.
#
# The "java daemon" step and -Live were run the same way, with PowerShell 7.5
# on Linux (-Live as root: pass=21 skip=1 fail=0). On Windows -Live only
# reports SKIP, and the "java daemon" step uses build.cmd and
# smartdelegate-java.cmd, which have never run.
#
#   required: Python 3.10+ with `cryptography`  (src\sf_smartdelegate, the reference)
#   optional: JDK 17+ (ports\java), Node 18+ (ports\node, ports\js), Go 1.21+
#             (ports\go), PHP 8.1+ with sodium (ports\php), Rust 1.89+ (ports\rust)
#
# A step whose toolchain is missing is reported as SKIP, never as PASS.
# Not run on Windows, each reported as SKIP:
#   - the C ABI check of the Rust port (run test_all.sh under WSL or Linux)
#   - sharing one state directory between ports: that relies on flock(2);
#     ports\conformance\matrix.py leaves that part out on Windows by itself
# Exit code 1 if any step failed.
param([switch]$Quick, [switch]$Live)

$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot
$root = (Get-Location).Path
$results = @()
# $IsWindows does not exist in Windows PowerShell 5.1, which only runs on Windows.
$onWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
$exe = ""
if ($onWindows) { $exe = ".exe" }

# A path below the repository, written with forward slashes, in this platform's form.
function RepoPath([string]$Relative) {
  return [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($root, $Relative))
}

function Have([string]$Name) {
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# Step <name> { commands }: PASS when the last native command of the block left
# exit code 0. A block with several commands must stop at the first failure:
#   first; if ($LASTEXITCODE -ne 0) { return }; second
function Step([string]$Name, [scriptblock]$Body) {
  Write-Host ""
  Write-Host "=== $Name"
  $global:LASTEXITCODE = 0
  try {
    & $Body | Out-Host
  } catch {
    Write-Host $_
    $global:LASTEXITCODE = 1
  }
  $outcome = "PASS"
  if ($LASTEXITCODE -ne 0) { $outcome = "FAIL" }
  $script:results += [pscustomobject]@{ Result = $outcome; Step = $Name }
}

function Skip([string]$Name) {
  $script:results += [pscustomobject]@{ Result = "SKIP"; Step = $Name }
}

# LiveStep <name> { command }: like Step, but exit code 3 means that the suite
# could not run at all (it prints why), which is a SKIP and not a failure.
function LiveStep([string]$Name, [scriptblock]$Body) {
  Write-Host ""
  Write-Host "=== $Name"
  $global:LASTEXITCODE = 0
  try {
    & $Body | Out-Host
  } catch {
    Write-Host $_
    $global:LASTEXITCODE = 1
  }
  $outcome = "PASS"
  $label = $Name
  if ($LASTEXITCODE -eq 3) {
    $outcome = "SKIP"
    $label = "$Name (exit 3, nothing ran: the reason is in its output above)"
  } elseif ($LASTEXITCODE -ne 0) {
    $outcome = "FAIL"
  }
  $script:results += [pscustomobject]@{ Result = $outcome; Step = $label }
}

# InDir <directory> { commands }: runs the block there and always comes back.
function InDir([string]$Directory, [scriptblock]$Body) {
  Push-Location $Directory
  try { & $Body } finally { Pop-Location }
}

# A command line as the JSON array that SMARTDELEGATE_TEST_CLI and
# SMARTDELEGATE_CLI expect (backslashes in Windows paths are escaped).
function CliJson([string[]]$Command) {
  return (ConvertTo-Json -Compress -InputObject @($Command))
}

# The reference's daemon conformance test against another port's command line.
function DaemonConformance([string[]]$Command) {
  $env:SMARTDELEGATE_TEST_CLI = CliJson $Command
  try {
    InDir (RepoPath "tests") { & $python -m unittest test_conformance.DaemonConformance }
  } finally {
    Remove-Item Env:SMARTDELEGATE_TEST_CLI -ErrorAction SilentlyContinue
  }
}

# ---- Python: required
$python = $null
foreach ($candidate in @("python", "python3")) {
  # the Microsoft Store placeholder python.exe exists on PATH but is not Python: ask it
  if (-not $python -and (Have $candidate)) {
    & $candidate -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $python = $candidate }
  }
}
if (-not $python) {
  Write-Host "Python 3.10+ is required: it is the reference implementation."
  exit 1
}
& $python -c "import cryptography" 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Install the one dependency first:  $python -m pip install cryptography"
  exit 1
}

$separator = [System.IO.Path]::PathSeparator
if ($env:PYTHONPATH) {
  $env:PYTHONPATH = (RepoPath "src") + $separator + $env:PYTHONPATH
} else {
  $env:PYTHONPATH = RepoPath "src"
}
if (-not $env:GOTOOLCHAIN) { $env:GOTOOLCHAIN = "local" }

$vectors = RepoPath "spec/conformance/vectors"
$bundle = RepoPath "spec/conformance/bundle"
$rust = RepoPath ("ports/rust/target/release/smartdelegate" + $exe)
$nodeCli = RepoPath "ports/node/bin/cli.mjs"
$phpCli = RepoPath "ports/php/bin/smartdelegate-php"
$goExe = $null
# the Java port's launcher; it runs ports/java/build/smartdelegate.jar, which build.sh / build.cmd make
$javaCli = RepoPath "ports/java/bin/smartdelegate-java"
if ($onWindows) { $javaCli = RepoPath "ports/java/bin/smartdelegate-java.cmd" }

$hasJava = (Have "javac") -and (Have "java")
$hasNode = Have "node"
$hasGo = Have "go"
$hasPhp = Have "php"
$hasCargo = Have "cargo"

# Build output that is not a port's own ignored directory goes here.
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("smartdelegate-test-all-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
  # ---- builds
  if ($hasCargo) {
    Step "rust port: build" { InDir (RepoPath "ports/rust") { cargo build --release } }
  } else {
    Skip "rust port (no cargo): build, cargo tests, daemon and proxy tests, JavaScript client against the Rust daemon"
    if (-not (Test-Path $rust)) { Skip "python: tests\test_interop.py, the reference against the Rust port (no Rust binary)" }
  }
  $hasRust = $hasCargo -and (Test-Path $rust)

  if ($hasGo) {
    $goExe = Join-Path $tmp ("smartdelegate-go" + $exe)
    Step "go port: build into a temporary directory" {
      InDir (RepoPath "ports/go") { go build "-buildvcs=false" -o $goExe ./cmd/smartdelegate-go }
    }
    if (-not (Test-Path $goExe)) { $goExe = $null }
  }

  $javaBuild = Join-Path $tmp "java"
  $javaBuilt = $false
  if ($hasJava) {
    New-Item -ItemType Directory -Path $javaBuild | Out-Null
    $javaSources = @(Get-ChildItem -Recurse -Path (RepoPath "ports/java/src") -Filter *.java | ForEach-Object { $_.FullName })
    # -encoding: JDK 17 on Windows reads sources in the ANSI code page otherwise
    Step "java port: build into a temporary directory" { javac -nowarn -encoding UTF-8 -d $javaBuild $javaSources }
    $javaBuilt = Test-Path ([System.IO.Path]::Combine($javaBuild, "dev", "smartdelegate", "Conformance.class"))
  }

  if ($Quick) {
    # ---- the two shared suites against every installed port
    Step "python (reference): conformance vectors" { & $python -m sf_smartdelegate conformance $vectors $bundle }
    Step "python (reference): policy evaluation cases" { InDir (RepoPath "tests") { & $python -m unittest test_cedar_eval } }
    if ($javaBuilt) {
      Step "java port: its harness (eval, conformance, interop with the reference, strictness, REST client)" {
        java -cp $javaBuild dev.smartdelegate.Conformance $root $python -m sf_smartdelegate
      }
    } else { Skip "java port (no javac / java, or the build failed)" }
    if ($hasNode) { Step "node port: eval cases and conformance vectors" { node $nodeCli conformance $vectors $bundle } } else {
      Skip "node port (no node)"
    }
    if ($goExe) { Step "go port: eval cases and conformance vectors" { & $goExe conformance --root $root } } else {
      Skip "go port (no go, or the build failed)"
    }
    if ($hasPhp) { Step "php port: eval cases and conformance vectors" { php $phpCli conformance $vectors $bundle } } else {
      Skip "php port (no php)"
    }
    if ($hasRust) {
      Step "rust port: conformance vectors" { & $rust conformance $vectors $bundle }
      Step "rust port: cargo conformance test (vectors, eval cases against real Cedar)" {
        InDir (RepoPath "ports/rust") { cargo test --release -p smartdelegate-core --test conformance }
      }
    }
  } else {
    # ---- the reference
    Step "python (reference): unit tests" { InDir (RepoPath "tests") { & $python -m unittest } }
    Step "python (reference): bundle policy tests" { & $python -m sf_smartdelegate policy test --bundle $bundle }
    # The scenario harness (harness\README.md). Like the rest of this script, this step was
    # written without being run: the harness itself has only been run on Linux.
    Step "scenario harness (harness\): example company policy tests, 24 scenario instances on the reference engine" {
      & $python -m sf_smartdelegate policy test --bundle (RepoPath "examples/company"); if ($LASTEXITCODE -ne 0) { return }
      & $python -m harness run --scenarios all --instances 24 --seed 1 --out (Join-Path $tmp "harness-report")
    }

    # ---- each port's own full suite
    if ($javaBuilt) {
      Step "java port: eval, conformance, interop with the reference, strictness, REST client" {
        java -cp $javaBuild dev.smartdelegate.Conformance $root $python -m sf_smartdelegate
      }
    } else { Skip "java port (no javac / java, or the build failed)" }

    if ($hasNode) {
      Step "node port: node --test test/" { InDir (RepoPath "ports/node") { node --test test/ } }
    } else { Skip "node port (no node)" }

    if ($hasGo) {
      Step "go port: go vet, go test" {
        InDir (RepoPath "ports/go") {
          go vet ./...
          if ($LASTEXITCODE -ne 0) { return }
          go test ./...
        }
      }
    } else { Skip "go port (no go)" }

    if ($hasPhp) {
      Step "php port: test\run.php" { InDir (RepoPath "ports/php") { php test/run.php } }
    } else { Skip "php port (no php)" }

    if ($hasRust) {
      Step "rust port: cargo test (conformance, eval cases re-checked against real Cedar, strictness)" {
        InDir (RepoPath "ports/rust") { cargo test --release }
      }
      Step "rust port: daemon, HTTP proxy and MCP proxy (the reference's tests against the Rust binary)" {
        $env:SMARTDELEGATE_TEST_CLI = CliJson @($rust)
        try {
          InDir (RepoPath "tests") { & $python -m unittest test_proxies test_conformance.DaemonConformance }
        } finally {
          Remove-Item Env:SMARTDELEGATE_TEST_CLI -ErrorAction SilentlyContinue
        }
      }
    }
    Skip "rust port: C ABI (not run by test_all.ps1: run test_all.sh under WSL or Linux)"

    # ---- the REST-only JavaScript client
    if ($hasNode) {
      $jsTests = @(Get-ChildItem -Path (RepoPath "ports/js/test") -Filter *.test.mjs | ForEach-Object { $_.FullName })
      Step "javascript client (ports\js) against the reference daemon" {
        InDir (RepoPath "ports/js") { node --test $jsTests }
      }
      if ($hasRust) {
        Step "javascript client (ports\js) against the rust daemon" {
          $env:SMARTDELEGATE_CLI = CliJson @($rust)
          try {
            InDir (RepoPath "ports/js") { node --test $jsTests }
          } finally {
            Remove-Item Env:SMARTDELEGATE_CLI -ErrorAction SilentlyContinue
          }
        }
      }
    } else { Skip "javascript client (no node)" }

    # ---- the reference's daemon conformance test against the other daemons
    if ($hasNode) { Step "node daemon: the reference's DaemonConformance" { DaemonConformance @("node", $nodeCli) } } else {
      Skip "node daemon: the reference's DaemonConformance (no node)"
    }
    if ($goExe) { Step "go daemon: the reference's DaemonConformance" { DaemonConformance @($goExe) } } else {
      Skip "go daemon: the reference's DaemonConformance (no go, or the build failed)"
    }
    if ($hasJava -and (Have "jar")) {
      Step "java daemon: the reference's DaemonConformance" {
        InDir (RepoPath "ports/java") {
          if ($onWindows) { cmd /c build.cmd } else { sh build.sh }
        }
        if ($LASTEXITCODE -ne 0) { return }
        DaemonConformance @($javaCli)
      }
    } else {
      Skip "java daemon: the reference's DaemonConformance (no JDK)"
    }
    if ($hasPhp) { Step "php daemon: the reference's DaemonConformance" { DaemonConformance @("php", $phpCli) } } else {
      Skip "php daemon: the reference's DaemonConformance (no php)"
    }

    # ---- all ports against each other
    Step "cross-port matrix (ports\conformance\matrix.py): tokens, sub-agents, tampering, signed bundles, audit logs" {
      & $python (RepoPath "ports/conformance/matrix.py")
    }
    if ($onWindows) { Skip "cross-port matrix: one state directory shared between ports (needs flock; matrix.py leaves it out on Windows)" }

    # ---- live suites: real services, only with -Live
    if (-not $Live) {
      Skip "live suites (live/idp/run.sh, live/run.sh): not requested, pass -Live"
    } elseif ($onWindows -or -not (Have "bash")) {
      Skip "live suites (live/idp/run.sh, live/run.sh): bash scripts, not run here; run test_all.sh --live under WSL or Linux"
    } else {
      $liveIdp = RepoPath "live/idp/run.sh"
      $liveAll = RepoPath "live/run.sh"
      if (Test-Path $liveIdp) {
        LiveStep "live: identity provider (live/idp/run.sh, a real Keycloak)" { bash $liveIdp }
      } else {
        Skip "live: identity provider (live/idp/run.sh is not in this checkout)"
      }
      if (Test-Path $liveAll) {
        LiveStep "live: upstream, boundary, load (live/run.sh all --quick)" { bash $liveAll all --quick }
      } else {
        Skip "live: upstream, boundary, load (live/run.sh is not in this checkout)"
      }
    }
  }
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "================ summary"
foreach ($wanted in @("PASS", "SKIP", "FAIL")) {
  foreach ($r in $results) {
    if ($r.Result -eq $wanted) { Write-Host ("  " + $r.Result + "  " + $r.Step) }
  }
}
$passed = @($results | Where-Object { $_.Result -eq "PASS" }).Count
$skipped = @($results | Where-Object { $_.Result -eq "SKIP" }).Count
$failed = @($results | Where-Object { $_.Result -eq "FAIL" }).Count
Write-Host "  pass=$passed skip=$skipped fail=$failed"
if ($failed -gt 0) { exit 1 }
exit 0
