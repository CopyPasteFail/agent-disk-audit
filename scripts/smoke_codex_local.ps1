param(
  [string]$Config = "config/defaults.json",
  [string]$OutputDir = "output/codex-local-smoke"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvHelper = Join-Path $PSScriptRoot "_venv.ps1"
. $venvHelper
$python = Get-VenvPython -RepoRoot $repoRoot
$env:PYTHONPATH = (Join-Path $repoRoot "src")

Push-Location $repoRoot
try {
  & $python -m codex_disk_audit.cli codex-local-smoke --config $Config --output-dir $OutputDir
}
finally {
  Pop-Location
}
