"""Resumen de auditorías a partir de la bitácora: pasos, costo, duración y herramientas usadas.

Las cifras del README salen de aquí, no de cuentas a mano. Lee los eventos tal cual están en
logs/bitacora-*.jsonl; una auditoría sin evento "fin" (cortada, por ejemplo) se informa aparte.
"""

import json
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any


def leer_eventos(rutas: list[Path]) -> list[dict[str, Any]]:
    eventos = []
    for ruta in rutas:
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            if linea.strip():
                eventos.append(json.loads(linea))
    return eventos


def resumir(eventos: list[dict[str, Any]], desde: str | None = None) -> list[dict[str, Any]]:
    """Una fila por (auditoría, intento) con evento "inicio" posterior a `desde` (ISO 8601)."""
    grupos: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for e in eventos:
        if e.get("auditoria_id"):
            grupos.setdefault((e["auditoria_id"], e.get("intento", 1)), []).append(e)
    filas = []
    for (auditoria, intento), evs in grupos.items():
        inicio = next((e for e in evs if e["tipo"] == "inicio"), None)
        if inicio is None or (desde and inicio["ts"] < desde):
            continue
        fin = next((e for e in evs if e["tipo"] == "fin"), None)
        herramientas = [e["herramienta"] for e in evs if e["tipo"] == "herramienta"]
        filas.append({
            "auditoria_id": auditoria, "intento": intento, "dominio": inicio["dominio"],
            "pasos": max((e["paso"] for e in evs if e["tipo"] == "llm"), default=0),
            "costo_usd": round(sum(e["costo_usd"] for e in evs if e["tipo"] == "llm"), 6),
            "segundos": (round((datetime.fromisoformat(fin["ts"]) - datetime.fromisoformat(inicio["ts"]))
                               .total_seconds()) if fin else None),
            "motivo_cierre": fin["motivo_cierre"] if fin else None,
            "respaldo": (fin["ok"] is False) if fin else None,
            "llamadas_herramientas": len(herramientas), "herramientas_distintas": len(set(herramientas)),
            "rechazos": sum(1 for e in evs if e["tipo"] == "rechazo"),
        })
    return sorted(filas, key=lambda f: f["auditoria_id"])


def agregado(filas: list[dict[str, Any]]) -> dict[str, Any]:
    """Mínimo, mediana y máximo de costo, pasos y duración, y el total gastado."""
    def estad(clave):
        valores = [f[clave] for f in filas if f[clave] is not None]
        return {"min": min(valores), "mediana": median(valores), "max": max(valores)} if valores else None
    return {"auditorias": len(filas), "costo_total_usd": round(sum(f["costo_usd"] for f in filas), 4),
            "informe_entregado": sum(1 for f in filas if f["motivo_cierre"] == "informe_entregado"),
            "respaldo": sum(1 for f in filas if f["respaldo"]),
            "costo_usd": estad("costo_usd"), "pasos": estad("pasos"), "segundos": estad("segundos")}
