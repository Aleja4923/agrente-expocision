"""Resume las auditorías de la bitácora (pasos, costo, duración) desde una fecha.

Uso: venv\\Scripts\\python.exe scripts\\resumen_bitacora.py [--desde 2026-10-24T18:00:00+00:00]
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auditor.config import RUTA_LOGS  # noqa: E402
from auditor.metricas import agregado, leer_eventos, resumir  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--desde", help="Solo auditorías iniciadas desde este instante ISO 8601 (UTC)")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    filas = resumir(leer_eventos(sorted(RUTA_LOGS.glob("bitacora-*.jsonl"))), args.desde)
    for f in filas:
        print(f"{f['dominio']:34} pasos {f['pasos']:>2}  USD {f['costo_usd']:.4f}  {f['segundos']} s  "
              f"{f['motivo_cierre']}  herramientas {f['llamadas_herramientas']} ({f['herramientas_distintas']} "
              f"distintas)  rechazos {f['rechazos']}")
    print(json.dumps(agregado(filas), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
