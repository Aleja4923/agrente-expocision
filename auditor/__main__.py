"""CLI: python -m auditor auditar <dominio> [--objetivo TEXTO] [--modelo M] [--verbose]

Audita un dominio de principio a fin, sin intervención: guarda el informe para el dueño
en salidas/, registra la auditoría en SQLite y deja cada paso en la bitácora.
Códigos de salida: 0 bien, 1 dominio inválido, 2 falta configuración (llave o modelo).
"""

import argparse
import sys
import uuid
from datetime import datetime

from auditor.agent import auditar
from auditor.config import RUTA_DB, RUTA_SALIDAS, modelo_elegido
from auditor.report import dominio_no_existe, guardar_informe
from auditor.store import guardar_auditoria
from auditor.tools.base import DominioInvalido, normalizar_dominio


def _argumentos(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m auditor",
                                     description="Auditor de exposición digital para pymes (revisión pasiva).")
    sub = parser.add_subparsers(dest="comando", required=True)
    a = sub.add_parser("auditar", help="Audita un dominio y genera el informe para el dueño.")
    a.add_argument("dominio", help="Dominio a revisar, por ejemplo ejemplo.com.co")
    a.add_argument("--objetivo", help="Objetivo en texto libre (por defecto: exposición a suplantación y fraudes)")
    a.add_argument("--modelo", help="Modelo de Grok permitido por el reto (por defecto grok-4.7)")
    a.add_argument("--verbose", action="store_true", help="Muestra en vivo cada decisión de Grok")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    args = _argumentos(argv)

    try:
        dominio = normalizar_dominio(args.dominio)
    except DominioInvalido:
        print(f"Dominio inválido: {args.dominio!r}. Escriba solo el dominio, por ejemplo ejemplo.com.co.",
              file=sys.stderr)
        return 1
    try:
        modelo = modelo_elegido(args.modelo)
        lote_id = f"cli-{datetime.now():%Y%m%d-%H%M%S}"
        auditoria_id = f"{dominio}-{uuid.uuid4().hex[:8]}"
        estado = auditar(dominio, args.objetivo, lote_id=lote_id, auditoria_id=auditoria_id, modelo=modelo,
                         observador=print if args.verbose else None)
    except SystemExit as e:  # config.py sale con un mensaje claro si falta la llave o el modelo no es válido
        print(e, file=sys.stderr)
        return 2

    ruta = guardar_informe(estado, RUTA_SALIDAS)
    guardar_auditoria(estado, ruta, RUTA_DB)
    resultado = ("El dominio no existe" if dominio_no_existe(estado)
                 else f"Riesgo: {estado.nivel_riesgo.value.upper()} · Hallazgos: {len(estado.hallazgos)}")
    print(f"\nInforme: {ruta}")
    print(f"{resultado} · Pasos: {estado.pasos} · Costo: USD {estado.costo_usd:.4f} · "
          f"Cierre: {estado.motivo_cierre.value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
