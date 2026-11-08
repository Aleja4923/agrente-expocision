"""Bitácora de consumo pública: cada llamada a Grok del proyecto, cruzada con el panel del reto (sin Grok ni llave).

El panel del reto solo muestra los últimos registros y los totales por modelo. Este módulo exporta la bitácora
completa del agente (`logs/`, privada) a `consumo/consumo.csv` y escribe `consumo/RESUMEN.md` con el cruce:
cuántas peticiones, tokens y costo por modelo según la bitácora y según el panel (`consumo/panel.json`).

Qué no se publica: el dominio, la justificación de Grok ni el id de auditoría de las corridas por la CLI, que llevan
el nombre real del dominio. Las corridas de evaluación (`evals-*`, seudonimizadas) y de carga (`s4-*`, públicas)
conservan su id.
"""

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from evals.correr import _leer_lineas

RAIZ = Path(__file__).resolve().parents[1]
RUTA_LOGS = RAIZ / "logs"
CARPETA = RAIZ / "consumo"
COLUMNAS = ["ts", "hito", "lote_id", "auditoria_id", "intento", "paso", "modelo", "tipo", "ok", "tokens_entrada",
            "tokens_cache", "tokens_salida", "tokens_razonamiento", "costo_usd", "latencia_ms", "error"]
LOTES_PUBLICOS = ("evals-", "s4-")


def hito(evento: dict[str, Any]) -> str:
    """El hito del reto al que pertenece una llamada, por su lote y, si no, por su fecha."""
    lote = evento.get("lote_id") or evento.get("run_id") or ""
    if lote.startswith("s4-") or lote == "evals-inyeccion":  # la verificación de la inyección abrió el S4
        return "S4"
    if lote.startswith("evals-"):
        return "S3"
    fecha = (evento.get("ts") or "")[:10]
    if fecha <= "2026-10-19":
        return "S1"
    if fecha <= "2026-10-28":
        return "S2"
    if fecha <= "2026-11-05":
        return "S3"
    return "Después del S4"


def es_peticion(evento: dict[str, Any]) -> bool:
    """Una petición que llegó al gateway: una respuesta (`llm`) o un intento que el cliente cortó por tiempo.

    El gateway cobra el intento cortado (siguió procesándolo), pero el cliente no recibió su `usage`: por eso
    queda en la bitácora con costo 0. Una desconexión o una llave inválida no llegan a ser petición.
    """
    if evento.get("tipo") == "llm":
        return True
    return evento.get("tipo") == "error" and evento.get("justificacion") == "reintento:APITimeoutError"


def _id_publico(evento: dict[str, Any]) -> str:
    aid = evento.get("auditoria_id") or ""
    lote = evento.get("lote_id") or ""
    if not aid or lote.startswith(LOTES_PUBLICOS):
        return aid
    return "a-" + hashlib.sha256(aid.encode()).hexdigest()[:8]  # el id de la CLI lleva el dominio real


def fila(evento: dict[str, Any]) -> dict[str, Any]:
    error = "" if evento.get("tipo") == "llm" else str(evento.get("justificacion") or "")[:60]
    return {"ts": evento.get("ts"), "hito": hito(evento), "lote_id": evento.get("lote_id") or evento.get("run_id"),
            "auditoria_id": _id_publico(evento), "intento": evento.get("intento"), "paso": evento.get("paso"),
            "modelo": evento.get("modelo"), "tipo": evento.get("tipo"), "ok": evento.get("ok"),
            **{k: evento.get(k) or 0 for k in ("tokens_entrada", "tokens_cache", "tokens_salida",
                                                "tokens_razonamiento")},
            "costo_usd": evento.get("costo_usd") or 0, "latencia_ms": evento.get("latencia_ms"), "error": error}


def leer_peticiones(ruta_logs: Path = RUTA_LOGS) -> list[dict[str, Any]]:
    """Todas las peticiones a Grok de la bitácora, en orden de tiempo."""
    eventos = [e for archivo in sorted(ruta_logs.glob("**/bitacora-*.jsonl")) for e in _leer_lineas(archivo)]
    return sorted((fila(e) for e in eventos if es_peticion(e)), key=lambda f: f["ts"] or "")


def totales(filas: list[dict[str, Any]], clave: str) -> dict[str, dict[str, Any]]:
    salida: dict[str, dict[str, Any]] = defaultdict(lambda: {"peticiones": 0, "cortadas": 0, "entrada": 0,
                                                              "salida": 0, "costo": 0.0})
    for f in filas:
        t = salida[f[clave]]
        t["peticiones"] += 1
        t["cortadas"] += f["tipo"] != "llm"
        t["entrada"] += f["tokens_entrada"]
        t["salida"] += f["tokens_salida"]
        t["costo"] += f["costo_usd"]
    return dict(salida)


def reporte(filas: list[dict[str, Any]], panel: dict[str, Any] | None) -> str:
    por_modelo = totales(filas, "modelo")
    por_hito = totales(filas, "hito")
    cortadas_47 = por_modelo.get("grok-4.7", {}).get("cortadas", 0)
    sin_linea = ((panel or {}).get("modelos", {}).get("grok-4.7", {}).get("peticiones", 0)
                 - por_modelo.get("grok-4.7", {}).get("peticiones", 0))
    r = ["# Bitácora de consumo", "",
         "Generado por `python -m carga.consumo` desde la bitácora del agente. El detalle, una fila por petición a "
         "Grok, está en `consumo.csv`.", "",
         "## Por modelo: bitácora del agente frente al panel del reto", ""]
    if panel:
        r += [f"Panel consultado el {panel['consultado']}.", "",
              "| Modelo | Peticiones (bitácora · panel) | Tokens entrada (bitácora · panel) | "
              "Tokens salida (bitácora · panel) | Costo USD (bitácora · panel) |", "|---|---|---|---|---|"]
        for modelo in sorted(set(por_modelo) | set(panel["modelos"]), key=str):
            b = por_modelo.get(modelo, {"peticiones": 0, "entrada": 0, "salida": 0, "costo": 0.0})
            p = panel["modelos"].get(modelo, {"peticiones": 0, "entrada": 0, "salida": 0, "costo": 0.0})
            r.append(f"| {modelo} | {b['peticiones']:,} · {p['peticiones']:,} | {b['entrada']:,} · {p['entrada']:,} | "
                     f"{b['salida']:,} · {p['salida']:,} | {b['costo']:.2f} · {p['costo']:.2f} |")
        r += ["", "**Cómo se lee la diferencia:**",
              "- Las peticiones de la bitácora incluyen las que el cliente cortó por tiempo (columna «cortadas» "
              "abajo). El gateway las procesó y las cobró, pero el cliente no recibió su consumo, así que en la "
              "bitácora tienen costo 0. Con grok-4.20 las peticiones cuadran exactas.",
              f"- Con grok-4.7 hay {cortadas_47} peticiones cortadas, casi todas en la tarde lenta del gateway durante el "
              "S3, cuando el tiempo máximo por respuesta era de 60 s. Su costo no se conoce desde la bitácora: es "
              "parte de la diferencia de costo con el panel.",
              f"- Quedan {sin_linea} peticiones de grok-4.7 en el panel sin línea en la bitácora. La causa más "
              "probable, no comprobada una por una, es la pérdida de líneas cuando escribían varios hilos o procesos "
              "a la vez durante el S3, un problema documentado que se corrigió para el S4. Las peticiones a grok-4.6 y sin modelo del panel tampoco están en la "
              "bitácora y no tienen costo.",
              ""]
    r += ["| Modelo | Peticiones | Cortadas por tiempo (costo no reportado) | Tokens entrada | Tokens salida | "
          "Costo USD |", "|---|---|---|---|---|---|"]
    r += [f"| {m} | {t['peticiones']:,} | {t['cortadas']:,} | {t['entrada']:,} | {t['salida']:,} | {t['costo']:.2f} |"
          for m, t in sorted(por_modelo.items(), key=lambda x: str(x[0]))]
    r += ["", "## Por hito", "", "| Hito | Peticiones | Costo USD |", "|---|---|---|"]
    orden = ["S1", "S2", "S3", "S4", "Después del S4"]
    r += [f"| {h} | {por_hito[h]['peticiones']:,} | {por_hito[h]['costo']:.2f} |" for h in orden if h in por_hito]
    total = sum(t["costo"] for t in por_modelo.values())
    r += [f"| **Total** | **{len(filas):,}** | **{total:.2f}** |", "",
          "> Todo el consumo está ligado a tareas reales del agente: auditorías por la CLI (S1 y S2), el set de "
          "evaluación (S3), la corrida de carga (S4) y las pruebas del gateway del S1. No se publica el dominio "
          "de las corridas por la CLI."]
    return "\n".join(r) + "\n"


def escribir(filas: list[dict[str, Any]], panel: dict[str, Any] | None, carpeta: Path = CARPETA) -> None:
    carpeta.mkdir(parents=True, exist_ok=True)
    with (carpeta / "consumo.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNAS)
        w.writeheader()
        w.writerows(filas)
    (carpeta / "RESUMEN.md").write_text(reporte(filas, panel), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    argparse.ArgumentParser(prog="python -m carga.consumo", description=__doc__.splitlines()[0]).parse_args(argv)
    ruta_panel = CARPETA / "panel.json"
    panel = json.loads(ruta_panel.read_text(encoding="utf-8")) if ruta_panel.exists() else None
    filas = leer_peticiones()
    escribir(filas, panel)
    print(reporte(filas, panel))


if __name__ == "__main__":
    main()
