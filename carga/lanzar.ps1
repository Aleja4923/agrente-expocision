# Lanza la corrida del S4 y la relanza sola si el proceso de Python se cae.
# Uso, desde la carpeta del proyecto:  powershell -ExecutionPolicy Bypass -File carga\lanzar.ps1 -Lote s4-carga
# Termina cuando la cola se acaba (codigo 0) o cuando frena por gasto (codigo 3). Con cualquier otro codigo
# (4 = quedaron tareas sin linea, 1 = Python se cayo) espera 60 s y relanza; la cola se retoma donde quedo.
param([string]$Lote = "s4-carga", [int]$Hilos = 2)

Set-Location (Split-Path $PSScriptRoot -Parent)
$env:PYTHONIOENCODING = "utf-8"
# Python escribe en UTF-8; sin esto PowerShell 5.1 lo lee con la pagina de codigos de la consola (salen simbolos raros).
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
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
        Anotar "== fin del corredor (codigo $codigo) $(Get-Date -Format o)"
        break
    }
    if ($arranque -ge 20) {
        Anotar "== 20 arranques sin terminar: se detiene para revisar"
        break
    }
    Anotar "== el corredor salio con codigo $codigo; se relanza en 60 s"
    Start-Sleep -Seconds 60
}
