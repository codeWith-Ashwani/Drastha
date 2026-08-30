$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonCandidates = @(
    (Join-Path $ProjectRoot ".venv\Scripts\python.exe"),
    (Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
    (Get-Command py -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
) | Where-Object { $_ -and (Test-Path $_) }

if (-not $PythonCandidates) {
    throw "Python 3.11+ was not found. Create .venv or install Python, then run this script again."
}

$PythonExecutable = @($PythonCandidates)[0]
$env:PYTHONPATH = Join-Path $ProjectRoot "src"
Set-Location $ProjectRoot

Write-Host "Checking the Drastha demo..." -ForegroundColor Cyan
& $PythonExecutable -m aegisflow.cli demo-preflight
if ($LASTEXITCODE -ne 0) { throw "Demo preflight failed." }

Write-Host "Starting Drastha at http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "Keep this window open during the demonstration." -ForegroundColor DarkGray
Start-Job -ScriptBlock {
    param($DashboardUrl)
    Start-Sleep -Seconds 2
    Start-Process $DashboardUrl
} -ArgumentList "http://127.0.0.1:8000" | Out-Null
& $PythonExecutable -m aegisflow.cli demo-serve --root $ProjectRoot --fresh
