# Dot-sourced by bootstrap.ps1 and make.ps1. PowerShell 5.1 and 7.
#
# NOT RUN ON WINDOWS. It was run with PowerShell 7 on Linux only (see
# docs/BUILD.md, "Windows: untested, check these first").
#
# Find-SdPython: the command line (an array) of a Python 3.8+ that can run
# scripts/sd.py, or $null. sd.py itself then looks for a 3.10+ to make the
# virtualenv with. The Microsoft Store placeholder python.exe (it prints
# nothing and exits with 9009) is skipped because it fails the version probe.

function Test-SdPython([string[]]$Command) {
  $exe = $Command[0]
  if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { return $false }
  $rest = @()
  if ($Command.Length -gt 1) { $rest = $Command[1..($Command.Length - 1)] }
  try {
    $out = & $exe @rest -c "import sys; print('sd-python-ok' if sys.version_info >= (3, 8) else 'too-old')" 2>$null
  } catch {
    return $false
  }
  return ($LASTEXITCODE -eq 0) -and ("$out".Trim() -eq "sd-python-ok")
}

function Find-SdPython {
  $candidates = @(@("python3"), @("python"), @("python3.13"), @("python3.12"), @("python3.11"), @("python3.10"))
  $onWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
  if ($onWindows) { $candidates = @(@("py", "-3"), @("python"), @("python3")) }
  foreach ($c in $candidates) {
    if (Test-SdPython $c) { return ,$c }
  }
  return $null
}

# The PowerShell that is running this script, so that sd.py starts test_all.ps1 with the same one.
function Get-SdPowerShell {
  try { return (Get-Process -Id $PID).Path } catch { return $null }
}
