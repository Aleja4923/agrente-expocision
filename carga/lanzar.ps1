# Lanza la corrida del S4 y la relanza sola si el proceso de Python se cae.
# Uso, desde la carpeta del proyecto:  powershell -ExecutionPolicy Bypass -File carga\lanzar.ps1 -Lote s4-carga
# Termina cuando la cola se acaba (código 0) o cuando frena por gasto (código 3).
param([string]$Lote = "s4-carga", [int]$Hilos = 2)

Set-Location (Split-Path $PSScriptRoot -Parent)
$env:PYTHONIOENCODING = "utf-8"
New-Item -ItemType Directory -Force "carga\$Lote" | Out-Null
$log = "carga\$Lote\consola.log"

function Anotar([string]$texto) {
    Write-Host $texto
    Add-Content -Path $log -Value $texto -Encoding utf8
}

$arranque = 0
while ($true) {
    $arranque++
    Anotar "== arranque $arranque $(Get-Date -Format o)"
    & .\venv\Scripts\python.exe -u -m carga.correr --lote $Lote --hilos $Hilos 2>&1 | ForEach-Object { Anotar "$_" }
    $codigo = $LASTEXITCODE
    if ($codigo -eq 0 -or $codigo -eq 3) {
        Anotar "== fin del corredor (código $codigo) $(Get-Date -Format o)"
        break
    }
    if ($arranque -ge 20) {
        Anotar "== 20 arranques sin terminar: se detiene para revisar"
        break
    }
    Anotar "== el corredor salió con código $codigo; se relanza en 60 s"
    Start-Sleep -Seconds 60
}
