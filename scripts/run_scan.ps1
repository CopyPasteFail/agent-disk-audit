param(
  [string]$Config = "config/defaults.json",
  [string]$OutputDir = "",
  [switch]$NoOpenReport
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvHelper = Join-Path $PSScriptRoot "_venv.ps1"
. $venvHelper
$python = Get-VenvPython -RepoRoot $repoRoot
$env:PYTHONPATH = (Join-Path $repoRoot "src")

Push-Location $repoRoot
try {
  $args = @("-m", "codex_disk_audit.cli", "scan", "--config", $Config)
  if ($OutputDir) {
    $args += @("--output-dir", $OutputDir)
  }
  if ($NoOpenReport) {
    $args += "--no-open-report"
  }
  & $python @args
}
finally {
  Pop-Location
}
