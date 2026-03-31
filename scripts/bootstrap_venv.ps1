param(
  [switch]$WithOpenAI
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$basePython = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }

Push-Location $repoRoot
try {
  if (-not (Test-Path ".venv\Scripts\python.exe")) {
    if ($basePython -eq "py") {
      & py -3 -m venv .venv
    }
    else {
      & python -m venv .venv
    }
  }

  $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
  & $venvPython -m pip install --upgrade pip setuptools
  if ($WithOpenAI) {
    & $venvPython -m pip install -r requirements.lock
  }
  & $venvPython -m pip install -e .
}
finally {
  Pop-Location
}
