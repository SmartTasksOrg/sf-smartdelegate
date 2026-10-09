<#
.SYNOPSIS
The Makefile's targets for Windows. PowerShell 5.1 or 7.   .\make.ps1 <target> [options]

.DESCRIPTION
NOT RUN ON WINDOWS: written on Linux and run there with PowerShell 7.5 only.
See docs/BUILD.md, "Windows: untested, check these first".

  .\make.ps1 bootstrap        fresh clone -> .venv, every port built, launchers in build\bin, quick verification
  .\make.ps1 doctor           which toolchains are here, what each enables, how to install the rest
  .\make.ps1 build            build every port whose toolchain is here; write the launchers
  .\make.ps1 test             the reference's unit tests (tests\)
  .\make.ps1 conformance      the two shared suites against every installed port
  .\make.ps1 matrix           every port against every other (ports\conformance\matrix.py)
  .\make.ps1 harness          the example company's policy tests and the scenario harness (harness\README.md)
  .\make.ps1 live             suites against real services (live/idp/run.sh, live/run.sh all). They are bash
                              scripts that start Keycloak and PostgreSQL, and the boundary test needs Linux
                              network namespaces and root: on Windows each part is reported as SKIPPED.
                              Run them under WSL:
                                  wsl bash -lc "./bootstrap.sh && make live"
                              or against containers:  .\make.ps1 docker-test
  .\make.ps1 load             load and soak with thresholds (python -m live.load): only ever run on Linux;
                              SKIPPED on Windows, as above
  .\make.ps1 all              bootstrap -Full: all of the above plus test_all.ps1
  .\make.ps1 dist             release artifacts and SHA256SUMS in dist\
  .\make.ps1 clean            remove .venv, build\, dist\, caches (--deep: also ports\rust\target)
  .\make.ps1 docker-build     build docker\Dockerfile.dev and docker\Dockerfile.daemon   (not tested)
  .\make.ps1 docker-test      the live topology of docker\docker-compose.yml             (not tested)

Options after the target go to scripts\sd.py unchanged, in its spelling:
  .\make.ps1 conformance --only go,php
  .\make.ps1 bootstrap --offline
  .\make.ps1 clean --deep
#>
param(
  [Parameter(Position = 0)]
  [string]$Target = "help",
  [Parameter(ValueFromRemainingArguments = $true)]
  [object[]]$Rest = @()
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
. (Join-Path $PSScriptRoot "scripts\find-python.ps1")

# An unquoted a,b arrives as an array; sd.py wants the one word a,b after --only and --require.
$passed = @()
foreach ($item in $Rest) {
  if ($item -is [array]) { $passed += (@($item | ForEach-Object { "$_" }) -join ",") } else { $passed += "$item" }
}

$targets = @("bootstrap", "doctor", "build", "test", "conformance", "matrix", "harness",
             "live", "load", "all", "dist", "clean", "docker-build", "docker-test")
if ($Target -in @("help", "-h", "--help", "-?")) {
  # the comment block at the top of this file (Get-Help reformats it and prints nothing where the help system is absent)
  $inside = $false
  foreach ($line in [System.IO.File]::ReadAllLines($PSCommandPath)) {
    if ($line.StartsWith("#>")) { break }
    if ($inside) { Write-Host $line }
    if ($line.StartsWith("<#")) { $inside = $true }
  }
  exit 0
}
if ($targets -notcontains $Target) {
  Write-Host "make.ps1: unknown target '$Target'. Targets: $($targets -join ', ')"
  exit 2
}

if ($Target -eq "bootstrap") {
  & (Join-Path $PSScriptRoot "bootstrap.ps1") @passed
  exit $LASTEXITCODE
}
if ($Target -eq "all") {
  & (Join-Path $PSScriptRoot "bootstrap.ps1") --full @passed
  exit $LASTEXITCODE
}

$python = Find-SdPython
if (-not $python) {
  Write-Host "make.ps1: no Python 3.8+ found. Run .\bootstrap.ps1 first (it says how to install one)."
  exit 1
}
$pythonExe = $python[0]
$pythonArgs = @()
if ($python.Length -gt 1) { $pythonArgs = @($python[1..($python.Length - 1)]) }

$env:SD_POWERSHELL = Get-SdPowerShell
if ($Target -eq "doctor") {
  & $pythonExe @pythonArgs "scripts/doctor.py" @passed
} else {
  & $pythonExe @pythonArgs "scripts/sd.py" $Target @passed
}
exit $LASTEXITCODE
