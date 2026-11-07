# Arranque de un comando (Windows): prepara el entorno la primera vez y audita.
#   powershell -ExecutionPolicy Bypass -File iniciar.ps1 ejemplo.com.co
#   powershell -ExecutionPolicy Bypass -File iniciar.ps1 ejemplo.com.co --json
#   powershell -ExecutionPolicy Bypass -File iniciar.ps1 --lote casos.txt --json
# La llave va en la variable RETO_KEY o en el archivo .env (ver .env.example). Nunca en el repositorio.
Set-Location $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if (-not (Test-Path "venv\Scripts\python.exe")) {
    Write-Host "Preparando el entorno (solo la primera vez)..."
    python -m venv venv
    if ($LASTEXITCODE -ne 0) { Write-Host "No se pudo crear el entorno: instale Python 3.12 o superior."; exit 2 }
    & .\venv\Scripts\python.exe -m pip install --quiet --disable-pip-version-check -r requirements.txt
    if ($LASTEXITCODE -ne 0) { Write-Host "No se pudieron instalar las dependencias."; exit 2 }
}

& .\venv\Scripts\python.exe -m auditor auditar @args
exit $LASTEXITCODE
