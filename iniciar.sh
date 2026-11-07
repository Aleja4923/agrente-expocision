#!/usr/bin/env bash
# Arranque de un comando (Linux y macOS): prepara el entorno la primera vez y audita.
#   ./iniciar.sh ejemplo.com.co
#   ./iniciar.sh ejemplo.com.co --json
#   ./iniciar.sh --lote casos.txt --json
# La llave va en la variable RETO_KEY o en el archivo .env (ver .env.example). Nunca en el repositorio.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x venv/bin/python ]; then
    echo "Preparando el entorno (solo la primera vez)..." >&2
    python3 -m venv venv
    venv/bin/python -m pip install --quiet --disable-pip-version-check -r requirements.txt
fi

exec venv/bin/python -m auditor auditar "$@"
