param(
  [string]$Config = "config/demo.json",
  [string]$InputFindings = "sample_data/demo_findings.json",
  [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvHelper = Join-Path $PSScriptRoot "_venv.ps1"
. $venvHelper
$python = Get-VenvPython -RepoRoot $repoRoot
$env:PYTHONPATH = (Join-Path $repoRoot "src")

Push-Location $repoRoot
try {
  $args = @("-m", "codex_disk_audit.cli", "report", "--config", $Config, "--input-findings", $InputFindings)
  if ($OutputDir) {
    $args += @("--output-dir", $OutputDir)
  }
  & $python @args
}
finally {
  Pop-Location
}
