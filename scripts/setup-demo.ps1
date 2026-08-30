$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$SystemPython = @(
    (Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
    (Get-Command py -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $SystemPython) {
    throw "Python 3.11+ is required. Install Python, enable 'Add Python to PATH', then rerun setup-demo.ps1."
}

Write-Host "[1/4] Creating the local Python environment..." -ForegroundColor Cyan
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    & $SystemPython -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Could not create the Python virtual environment." }
}
$PythonExecutable = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

Write-Host "[2/4] Installing Drastha API dependencies..." -ForegroundColor Cyan
& $PythonExecutable -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Could not upgrade pip. Check the internet connection." }
& $PythonExecutable -m pip install -e ".[api]"
if ($LASTEXITCODE -ne 0) { throw "Could not install the Drastha API dependencies." }

$PnpmCommand = Get-Command pnpm -ErrorAction SilentlyContinue
$CorepackCommand = Get-Command corepack -ErrorAction SilentlyContinue
if (-not $PnpmCommand -and -not $CorepackCommand) {
    throw "Node.js with pnpm or Corepack is required to build the dashboard."
}

Write-Host "[3/4] Building the dashboard..." -ForegroundColor Cyan
Push-Location (Join-Path $ProjectRoot "web")
try {
    if ($PnpmCommand) {
        & $PnpmCommand.Source install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { throw "Could not install dashboard dependencies." }
        & $PnpmCommand.Source run build
        if ($LASTEXITCODE -ne 0) { throw "Could not build the dashboard." }
    } else {
        & $CorepackCommand.Source pnpm install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { throw "Could not install dashboard dependencies." }
        & $CorepackCommand.Source pnpm run build
        if ($LASTEXITCODE -ne 0) { throw "Could not build the dashboard." }
    }
} finally {
    Pop-Location
}

Write-Host "[4/4] Rehearsing the complete demo twice..." -ForegroundColor Cyan
$env:PYTHONPATH = Join-Path $ProjectRoot "src"
& $PythonExecutable -m aegisflow.cli demo-rehearse --root $ProjectRoot --evaluation-iterations 50
if ($LASTEXITCODE -ne 0) { throw "Demo rehearsal failed. Check output/drastha_demo_rehearsal.json." }

Write-Host "Drastha is ready. Run scripts\start-demo.ps1 on presentation day." -ForegroundColor Green
