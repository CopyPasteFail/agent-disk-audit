function Get-VenvPython {
  param(
    [string]$RepoRoot
  )

  $venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
  if (-not (Test-Path $venvPython)) {
    throw "Missing virtual environment at `"$venvPython`". Run .\scripts\bootstrap_venv.ps1 first."
  }

  return $venvPython
}
