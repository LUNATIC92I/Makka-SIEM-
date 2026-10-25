<#
.SYNOPSIS
  Build complet de MAKKADi pour Windows : tests, frontend, backend PyInstaller, installateur Electron.
.DESCRIPTION
  Prérequis : Windows 10/11 x64, Python 3.12 (python.org, "Add to PATH"), Node.js 22 LTS, Git.
  Exécution (PowerShell, depuis la racine du dépôt) :
      Set-ExecutionPolicy -Scope Process Bypass
      .\scripts\build_windows.ps1
  Résultats :
      desktop\dist\MAKKADi-<version>-x64-nsis.exe      (installateur)
      desktop\dist\MAKKADi-<version>-x64-portable.exe  (exécutable portable)
      backend\dist\makkadi-backend\makkadi-backend.exe (serveur seul, utilisable sans Electron)
#>
param(
  [switch]$SkipTests,
  [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

Step "Environnement Python (backend\.venv)"
Push-Location "$Root\backend"
if (-not (Test-Path ".venv")) { & $Python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
if (-not $SkipTests) {
  Step "Tests backend (pytest)"
  & .\.venv\Scripts\python.exe -m pytest -q
  if ($LASTEXITCODE -ne 0) { throw "Tests backend en échec" }
  Step "Audit des dépendances Python (pip-audit)"
  & .\.venv\Scripts\python.exe -m pip_audit -r requirements.txt
}
Pop-Location

Step "Frontend (npm ci + build)"
Push-Location "$Root\frontend"
npm ci
if (-not $SkipTests) { npm test; if ($LASTEXITCODE -ne 0) { throw "Tests frontend en échec" } }
npm run build
if ($LASTEXITCODE -ne 0) { throw "Build frontend en échec" }
Pop-Location

Step "Backend autonome (PyInstaller)"
Push-Location "$Root\backend"
& .\.venv\Scripts\pyinstaller.exe --noconfirm makkadi-backend.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller en échec" }
Step "Test de fumée du backend compilé"
$data = Join-Path $env:TEMP "makkadi-smoke-$(Get-Random)"
$proc = Start-Process -FilePath ".\dist\makkadi-backend\makkadi-backend.exe" -ArgumentList "--port","8799","--data-dir",$data -PassThru -WindowStyle Hidden
try {
  $ok = $false
  for ($i = 0; $i -lt 60; $i++) {
    try { $r = Invoke-RestMethod "http://127.0.0.1:8799/api/v1/health" -TimeoutSec 2; if ($r.status -eq "ok") { $ok = $true; break } } catch { Start-Sleep -Milliseconds 500 }
  }
  if (-not $ok) { throw "Le backend compilé ne répond pas" }
  Write-Host "Backend compilé OK : $($r.app_name) $($r.version)" -ForegroundColor Green
} finally { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Pop-Location

Step "Application de bureau (Electron + electron-builder)"
Push-Location "$Root\desktop"
if (Test-Path "resources\backend") { Remove-Item -Recurse -Force "resources\backend" }
New-Item -ItemType Directory -Force "resources\backend" | Out-Null
Copy-Item -Recurse "$Root\backend\dist\makkadi-backend" "resources\backend\"
npm ci
npm run dist:win
if ($LASTEXITCODE -ne 0) { throw "electron-builder en échec" }
Get-ChildItem dist\*.exe | ForEach-Object {
  $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
  Write-Host ("{0}  {1}" -f $h, $_.Name) -ForegroundColor Green
}
Pop-Location
Write-Host "`nBuild terminé. Les exécutables ne sont pas signés : voir docs/WINDOWS_BUILD.md (signature de code)." -ForegroundColor Yellow
