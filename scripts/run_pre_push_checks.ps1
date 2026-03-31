$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvHelper = Join-Path $PSScriptRoot "_venv.ps1"
. $venvHelper
$python = Get-VenvPython -RepoRoot $repoRoot
$env:PYTHONPATH = (Join-Path $repoRoot "src")

Push-Location $repoRoot
try {
  & $python -m compileall src tests scripts
  & $python -m unittest discover -s tests -v
}
finally {
  Pop-Location
}
