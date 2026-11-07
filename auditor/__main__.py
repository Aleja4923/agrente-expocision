"""CLI: python -m auditor auditar <dominio> [--objetivo TEXTO] [--modelo M] [--verbose] [--json]
     python -m auditor auditar --lote dominios.txt [--modelo M] [--json]

Audita uno o varios dominios de principio a fin, sin intervención: guarda el informe para el dueño
en salidas/, registra la auditoría en SQLite y deja cada paso en la bitácora.

- `--json` imprime el resultado estructurado (una línea JSON por dominio) para que otro programa lo lea.
- `--lote` lee un dominio por línea; opcionalmente `dominio;objetivo`. Las líneas vacías o con # se saltan.
  Un dominio inválido no detiene el lote: su línea sale con "error".

Códigos de salida: 0 bien, 1 dominio inválido (o algún dominio inválido en el lote), 2 falta configuración
(llave o modelo).
"""

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from auditor.agent import auditar
from auditor.config import RUTA_DB, RUTA_SALIDAS, modelo_elegido
from auditor.modelos import EstadoAuditoria
from auditor.report import contenido, dominio_no_existe, guardar_informe, nivel_provisional
from auditor.store import guardar_auditoria
from auditor.tools.base import DominioInvalido, normalizar_dominio


def _argumentos(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m auditor",
                                     description="Auditor de exposición digital para pymes (revisión pasiva).")
    sub = parser.add_subparsers(dest="comando", required=True)
    a = sub.add_parser("auditar", help="Audita un dominio (o una lista) y genera el informe para el dueño.")
    a.add_argument("dominio", nargs="?", help="Dominio a revisar, por ejemplo ejemplo.com.co")
    a.add_argument("--lote", type=Path, help="Archivo con un dominio por línea (opcional: dominio;objetivo)")
    a.add_argument("--objetivo", help="Objetivo en texto libre (por defecto: exposición a suplantación y fraudes)")
    a.add_argument("--modelo", help="Modelo de Grok permitido por el reto (por defecto grok-4.7)")
    a.add_argument("--verbose", action="store_true", help="Muestra en vivo cada decisión de Grok")
    a.add_argument("--json", action="store_true", help="Imprime el resultado como JSON (una línea por dominio)")
    args = parser.parse_args(argv)
    if (args.dominio is None) == (args.lote is None):
        parser.error("indique un dominio o --lote ARCHIVO (uno de los dos)")
    return args


def leer_lote(ruta: Path) -> list[tuple[str, str | None]]:
    """(dominio, objetivo) por línea; se saltan las vacías y los comentarios."""
    filas = []
    for linea in ruta.read_text(encoding="utf-8-sig").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        dominio, _, objetivo = linea.partition(";")
        filas.append((dominio.strip(), objetivo.strip() or None))
    return filas


def resultado_json(estado: EstadoAuditoria, ruta: Path) -> dict[str, Any]:
    """Lo que dice el informe, en datos: lo mismo que ve el dueño, para que otro programa lo evalúe."""
    c = contenido(estado)
    return {
        "dominio": estado.dominio, "existe": not c.no_existe,
        "nivel": c.nivel.value if c.nivel else None, "provisional": nivel_provisional(estado),
        "hallazgos": [{"id": h.id, "severidad": h.severidad.value, "titulo": h.titulo, "evidencia": h.evidencia}
                      for h in c.hallazgos],
        "acciones": [{"orden": a.n, "hallazgo_id": a.id, "recomendacion": a.recomendacion} for a in c.acciones],
        "resumen": c.resumen, "limitaciones": c.limitaciones,
        "motivo_cierre": estado.motivo_cierre.value, "informe_de_respaldo": estado.informe_de_respaldo,
        "pasos": estado.pasos, "costo_usd": round(estado.costo_usd, 6), "modelo": estado.modelo,
        "auditoria_id": estado.auditoria_id, "informe_md": str(ruta), "informe_html": str(ruta.with_suffix(".html")),
    }


def _texto(estado: EstadoAuditoria, ruta: Path) -> str:
    resultado = ("El dominio no existe" if dominio_no_existe(estado)
                 else f"Riesgo: {estado.nivel_riesgo.value.upper()}{' (provisional)' if nivel_provisional(estado) else ''}"
                      f" · Hallazgos: {len(estado.hallazgos)}")
    return (f"\nInforme: {ruta}\nInforme imprimible: {ruta.with_suffix('.html')}\n"
            f"{resultado} · Pasos: {estado.pasos} · Costo: USD {estado.costo_usd:.4f} · "
            f"Cierre: {estado.motivo_cierre.value}")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    args = _argumentos(argv)
    filas = leer_lote(args.lote) if args.lote else [(args.dominio, args.objetivo)]
    # Con --json, stdout queda solo para el JSON: el modo --verbose va a stderr.
    observador = (lambda linea: print(linea, file=sys.stderr if args.json else sys.stdout)) if args.verbose else None
    lote_id = f"cli-{datetime.now():%Y%m%d-%H%M%S}"
    codigo = 0
    try:
        modelo = modelo_elegido(args.modelo)
        for texto, objetivo in filas:
            try:
                dominio = normalizar_dominio(texto)
            except DominioInvalido:
                codigo = 1
                if args.json:
                    print(json.dumps({"dominio": texto, "error": "dominio_invalido"}, ensure_ascii=False), flush=True)
                else:
                    print(f"Dominio inválido: {texto!r}. Escriba solo el dominio, por ejemplo ejemplo.com.co.",
                          file=sys.stderr)
                continue
            estado = auditar(dominio, objetivo or args.objetivo, lote_id=lote_id,
                                auditoria_id=f"{dominio}-{uuid.uuid4().hex[:8]}", modelo=modelo,
                                observador=observador)
            ruta = guardar_informe(estado, RUTA_SALIDAS)
            guardar_auditoria(estado, ruta, RUTA_DB)
            print(json.dumps(resultado_json(estado, ruta), ensure_ascii=False) if args.json else _texto(estado, ruta),
                  flush=True)
    except SystemExit as e:  # config.py sale con un mensaje claro si falta la llave o el modelo no es válido
        print(e, file=sys.stderr)
        return 2
    return codigo


if __name__ == "__main__":
    sys.exit(main())
