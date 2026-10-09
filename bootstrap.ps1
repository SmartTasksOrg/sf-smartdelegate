<#
.SYNOPSIS
From a fresh clone to "everything built and tested", on Windows. PowerShell 5.1 or 7.
(Linux and macOS: bootstrap.sh.)

.DESCRIPTION
NOT RUN ON WINDOWS. This script was written on Linux and run there with
PowerShell 7.5 only (the parameter handling, the search for Python, and the
whole of scripts/sd.py behind it). The Windows-only lines (winget, the PATH
refresh from the registry, the .cmd launchers sd.py writes, test_all.ps1's
steps) have never been executed. If something fails, check the script before
the code under test, and see docs/BUILD.md, "Windows: untested, check these
first".

  .\bootstrap.ps1                    virtualenv in .venv, the package installed editable, every
                                     port built whose toolchain is here, launchers (.cmd) in
                                     build\bin, then the quick verification (demo, the two shared
                                     suites against every built port, the scenario harness)
  .\bootstrap.ps1 -Full              also test_all.ps1 and the cross-port matrix. The live
                                     suites are bash scripts for Linux: they are reported as
                                     SKIPPED here, with the WSL command to run them
  .\bootstrap.ps1 -Only python,go    only these components (python java node js go php rust)
  .\bootstrap.ps1 -Install           first install the missing toolchains with winget. Every
                                     command is printed before it runs. Without this switch
                                     nothing is ever installed outside the repository
  .\bootstrap.ps1 -Offline           no network: parts that need one fail at once and say why
  .\bootstrap.ps1 -Clean             remove .venv, build\ and dist\ first
  .\bootstrap.ps1 -Require java,go   a skipped part named here is a failure (for CI)
  .\bootstrap.ps1 -NoVerify          build only
  .\bootstrap.ps1 -ShowOutput        show each step's output while it runs

The bash spellings work too: .\bootstrap.ps1 --full --only python,go

If scripts are blocked:  powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1

A part whose toolchain is missing is SKIPPED with the reason, never reported
as built or passed. Exit code: 0 nothing failed, 1 something failed, 2 usage.
Everything written is git-ignored (.venv\, build\, dist\, the ports' build
directories). No key, token or password is written anywhere. The work is done
by scripts\sd.py, the same code bootstrap.sh runs.
#>
param(
  [switch]$Install,
  [string[]]$Only = @(),
  [switch]$Full,
  [switch]$Offline,
  [switch]$Clean,
  [string[]]$Require = @(),
  [switch]$NoVerify,
  [switch]$ShowOutput,
  [switch]$Help,
  [Parameter(ValueFromRemainingArguments = $true)]
  [object[]]$Rest = @()
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
. (Join-Path $PSScriptRoot "scripts\find-python.ps1")

# ---- the bash spellings (--full, --only a,b, --only=a,b, -v)
$Rest = @($Rest | ForEach-Object { $_ })      # an unquoted a,b arrives as an array: flatten it
$i = 0
while ($i -lt $Rest.Count) {
  $arg = [string]$Rest[$i]
  $takesList = $null
  switch -Regex ($arg) {
    '^--install$'    { $Install = $true; break }
    '^--full$'       { $Full = $true; break }
    '^--offline$'    { $Offline = $true; break }
    '^--clean$'      { $Clean = $true; break }
    '^--no-verify$'  { $NoVerify = $true; break }
    '^(-v|--verbose)$' { $ShowOutput = $true; break }
    '^(-h|--help)$'  { $Help = $true; break }
    '^--only=(.*)$'    { $Only += $Matches[1]; break }
    '^--require=(.*)$' { $Require += $Matches[1]; break }
    '^--only$'       { $takesList = "only"; break }
    '^--require$'    { $takesList = "require"; break }
    default {
      Write-Host "bootstrap.ps1: unknown option '$arg' (try -Help)"
      exit 2
    }
  }
  if ($takesList) {
    $got = 0
    while (($i + 1) -lt $Rest.Count -and -not ([string]$Rest[$i + 1]).StartsWith("-")) {
      $i++
      if ($takesList -eq "only") { $Only += [string]$Rest[$i] } else { $Require += [string]$Rest[$i] }
      $got++
    }
    if ($got -eq 0) { Write-Host "bootstrap.ps1: --$takesList needs a list, for example --$takesList python,go"; exit 2 }
  }
  $i++
}

if ($Help) {
  # the comment block at the top of this file (Get-Help reformats it and prints nothing where the help system is absent)
  $inside = $false
  foreach ($line in [System.IO.File]::ReadAllLines($PSCommandPath)) {
    if ($line.StartsWith("#>")) { break }
    if ($inside) { Write-Host $line }
    if ($line.StartsWith("<#")) { $inside = $true }
  }
  exit 0
}
if ($Install -and $Offline) {
  Write-Host "bootstrap.ps1: -Install needs the network; it cannot be combined with -Offline"
  exit 2
}

$onWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
$onlyList = (@($Only | ForEach-Object { "$_".Split(",") } | Where-Object { $_ }) -join ",")
$requireList = (@($Require | ForEach-Object { "$_".Split(",") } | Where-Object { $_ }) -join ",")

# After winget installed something, this session's PATH is stale: read it again from the registry.
function Update-SdPath {
  if (-not $onWindows) { return }
  $machine = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
  $user = [System.Environment]::GetEnvironmentVariable("Path", "User")
  $env:Path = (@($machine, $user, $env:Path) | Where-Object { $_ }) -join ";"
}

$python = Find-SdPython
if (-not $python) {
  if ($Install) {
    if ($onWindows -and (Get-Command winget -ErrorAction SilentlyContinue)) {
      Write-Host "bootstrap.ps1: no Python 3.8+ found; installing one (-Install was given)"
      $cmd = @("winget", "install", "-e", "--id", "Python.Python.3.12", "--accept-source-agreements", "--accept-package-agreements")
      Write-Host ("+ " + ($cmd -join " "))
      & $cmd[0] $cmd[1..($cmd.Length - 1)]
      Update-SdPath
      $python = Find-SdPython
    } else {
      Write-Host "bootstrap.ps1: no Python found and no winget to install it with"
    }
  }
  if (-not $python) {
    Write-Host "bootstrap.ps1: Python 3.10 or newer is required (it is the reference implementation,"
    Write-Host "and it runs this bootstrap). Install it, open a new PowerShell, and run .\bootstrap.ps1 again:"
    Write-Host "  winget install -e --id Python.Python.3.12"
    Write-Host "or let the bootstrap do it:  .\bootstrap.ps1 -Install"
    Write-Host "(If 'python' opens the Microsoft Store: that is a placeholder, not Python. Install Python as"
    Write-Host " above, or turn the alias off in Settings > Apps > Advanced app settings > App execution aliases.)"
    exit 1
  }
}
$pythonExe = $python[0]
$pythonArgs = @()
if ($python.Length -gt 1) { $pythonArgs = @($python[1..($python.Length - 1)]) }

if ($Install) {
  # Only what the doctor reports as missing; doctor.py prints each command before it runs.
  $doctorArgs = @("scripts/doctor.py", "--install")
  if ($onlyList) {
    $rows = (@($onlyList.Split(",") | ForEach-Object { if ($_ -eq "js") { "node" } else { $_ } }) + "venv") -join ","
    $doctorArgs += @("--only", $rows)
  }
  & $pythonExe @pythonArgs @doctorArgs
  if ($LASTEXITCODE -ne 0) { Write-Host "bootstrap.ps1: some installs failed; continuing with what is here" }
  Update-SdPath
}

$sdArgs = @("scripts/sd.py", "bootstrap")
if ($Full) { $sdArgs += "--full" }
if ($Offline) { $sdArgs += "--offline" }
if ($Clean) { $sdArgs += "--clean" }
if ($NoVerify) { $sdArgs += "--no-verify" }
if ($ShowOutput) { $sdArgs += "-v" }
if ($onlyList) { $sdArgs += @("--only", $onlyList) }
if ($requireList) { $sdArgs += @("--require", $requireList) }

$env:SD_POWERSHELL = Get-SdPowerShell
& $pythonExe @pythonArgs @sdArgs
exit $LASTEXITCODE
