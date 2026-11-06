"""`carga/<lote>/RESUMEN.md` desde la bitácora por tarea, sus eventos y la bitácora de Grok (sin Grok ni llave).

Publica solo agregados: el nivel y los hallazgos de cada empresa no salen de `docs/carga/`.
"""

import argparse
import json
import statistics
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from carga.correr import CARPETA, CARPETA_PRIVADA, escribir_csv
from evals.correr import _leer_lineas

RUTA_LOGS = CARPETA.parent / "logs"


def _pct(n: int, total: int) -> str:
    return f"{100 * n / total:.1f} % ({n}/{total})" if total else "—"


def _usd(x: float) -> str:
    return f"USD {x:.4f}"


def _percentil(valores: list[float], p: float) -> float:
    v = sorted(valores)
    return v[min(len(v) - 1, int(round(p * (len(v) - 1))))]


def gasto_en_bitacora(lote: str, ruta_logs: Path = RUTA_LOGS) -> float:
    """Costo de las llamadas a Grok del lote según la bitácora de eventos (los `fin` repiten el total)."""
    total = 0.0
    for archivo in sorted(ruta_logs.glob("bitacora-*.jsonl")):
        for e in _leer_lineas(archivo):
            if e.get("lote_id") == lote and e.get("tipo") == "llm":
                total += e.get("costo_usd") or 0
    return total


def pasadas(eventos: list[dict]) -> list[dict[str, Any]]:
    """Cada arranque del corredor con su fin (o el último evento, si se cayó) y su duración en horas."""
    salida = []
    for i, e in enumerate(eventos):
        if e["tipo"] != "inicio_corrida":
            continue
        siguientes = []
        for f in eventos[i + 1:]:
            if f["tipo"] == "inicio_corrida":
                break
            siguientes.append(f)
        fin = next((f for f in siguientes if f["tipo"] == "fin_corrida"), None)
        ultimo = fin or (siguientes[-1] if siguientes else e)
        horas = (datetime.fromisoformat(ultimo["ts"]) - datetime.fromisoformat(e["ts"])).total_seconds() / 3600
        salida.append({"inicio": e["ts"], "fin": ultimo["ts"], "horas": horas, "terminó": fin is not None,
                       "completadas_al_final": fin["completadas"] if fin else None})
    return salida


def metricas(tareas: list[dict], eventos: list[dict], privado: list[dict]) -> dict[str, Any]:
    completadas = [t for t in tareas if t["resultado"] == "completada"]
    fallidas = [t for t in tareas if t["resultado"] == "fallida"]
    costos = [t["costo_usd"] for t in tareas]
    total = sum(costos)
    inicios = [datetime.fromisoformat(t["inicio"]) for t in tareas]
    fines = [datetime.fromisoformat(t["fin"]) for t in tareas]
    corridas = [e for e in eventos if e["tipo"] == "inicio_corrida"]
    existentes = [p for p in privado if p.get("existe")]
    hallazgos = Counter(h for p in existentes for h in p["hallazgos"])
    entrada = sum(t["tokens_entrada"] for t in tareas)
    return {
        "n": len(tareas), "completadas": len(completadas), "fallidas": len(fallidas),
        "inexistentes": sum(1 for t in completadas if t["dominio_existe"] is False),
        "respaldos": Counter(t["motivo_cierre"] for t in completadas if t["respaldo"]),
        "recuperadas": sum(1 for t in completadas if t["intentos"] > 1),
        "horas": (max(fines) - min(inicios)).total_seconds() / 3600 if tareas else 0,
        "inicio": min(inicios).isoformat(timespec="minutes") if tareas else "—",
        "fin": max(fines).isoformat(timespec="minutes") if tareas else "—",
        "arranques": len(corridas),
        "pasadas": pasadas(eventos),
        "costo_total": total,
        "costo_por_completada": total / len(completadas) if completadas else 0,
        "costo_media": statistics.fmean(costos) if costos else 0,
        "costo_mediana": statistics.median(costos) if costos else 0,
        "costo_p90": _percentil(costos, 0.9) if costos else 0,
        "costo_max": max(costos, default=0),
        "duracion_mediana": statistics.median([t["duracion_s"] for t in tareas]) if tareas else 0,
        "pasos_mediana": statistics.median([t["pasos"] for t in completadas]) if completadas else 0,
        "tokens": {k: sum(t[f"tokens_{k}"] for t in tareas) for k in ("entrada", "cache", "salida", "razonamiento")},
        "cache_pct": sum(t["tokens_cache"] for t in tareas) / entrada if entrada else 0,
        "errores": Counter(e.split(":")[0] if e.startswith("gateway") else e for t in tareas for e in t["errores"]),
        "eventos": Counter(e["tipo"] for e in eventos),
        "niveles": Counter(p["nivel"] for p in existentes),
        "existentes": len(existentes),
        "hallazgos": hallazgos,
    }


def reporte(lote: str, m: dict[str, Any], gasto_bitacora: float | None) -> str:
    r = [f"# Resumen de la corrida `{lote}`", "",
         "Generado por `python -m carga.resumen` desde `tareas.jsonl`, `eventos.jsonl` y la bitácora de Grok.", "",
         "## Unidades de trabajo", "",
         "| | |", "|---|---|",
         f"| Tareas intentadas | {m['n']} |",
         f"| **Completadas** | **{m['completadas']}** |",
         f"| Fallidas (3 intentos sin éxito) | {m['fallidas']} |",
         f"| **Tasa de éxito** | **{_pct(m['completadas'], m['n'])}** |",
         f"| Dominios que no existen (completadas: el agente lo confirmó) | {m['inexistentes']} |",
         f"| Completadas con informe de respaldo | {sum(m['respaldos'].values())} "
         f"({', '.join(f'{k}: {v}' for k, v in m['respaldos'].most_common()) or '—'}) |",
         f"| Completadas tras reintentar | {m['recuperadas']} |",
         "", "## Duración", "",
         "| | |", "|---|---|",
         f"| Primera tarea → última (UTC) | {m['inicio']} → {m['fin']} |",
         f"| Horas | **{m['horas']:.1f}** |",
         f"| Arranques del corredor | {m['arranques']} (más de 1 = relanzado por `lanzar.ps1` o reanudado) |",
         f"| **Pasada más larga sin intervención** | **{max((x['horas'] for x in m['pasadas']), default=0):.1f} h** |",
         f"| Duración por tarea (mediana) | {m['duracion_mediana']:.0f} s |",
         "", "| Pasada | Inicio (UTC) | Fin (UTC) | Horas | Cómo terminó |", "|---|---|---|---|---|",
         *[f"| {i} | {x['inicio']} | {x['fin']} | {x['horas']:.1f} | "
           f"{'fin de la pasada' if x['terminó'] else 'se cortó (sin evento de fin)'} |"
           for i, x in enumerate(m["pasadas"], start=1)],
         "", "## Costo", "",
         "| | |", "|---|---|",
         f"| **Costo total** | **{_usd(m['costo_total'])}** |",
         f"| **Costo por tarea completada** (total / completadas) | **{_usd(m['costo_por_completada'])}** |",
         f"| Por tarea: promedio · mediana · p90 · máximo | {_usd(m['costo_media'])} · {_usd(m['costo_mediana'])} · "
         f"{_usd(m['costo_p90'])} · {_usd(m['costo_max'])} |",
         f"| Pasos de Grok por tarea (mediana) | {m['pasos_mediana']} |"]
    if gasto_bitacora is not None:
        r.append(f"| Gasto del lote en la bitácora de Grok | {_usd(gasto_bitacora)} (incluye intentos cortados "
                 "por una caída, que no dejan línea de tarea) |")
    t = m["tokens"]
    r += ["", "## Tokens", "",
          f"Entrada {t['entrada']:,} (en caché {t['cache']:,}, {100 * m['cache_pct']:.0f} %) · salida "
          f"{t['salida']:,} · razonamiento {t['razonamiento']:,}.", "",
          "## Errores y recuperación", "",
          "| Error | Tareas |", "|---|---|"]
    r += [f"| `{k}` | {v} |" for k, v in m["errores"].most_common()] or ["| — | 0 |"]
    r += ["", "| Evento de la corrida | Veces |", "|---|---|"]
    r += [f"| `{k}` | {v} |" for k, v in sorted(m["eventos"].items())]
    r += ["", "> Los errores de herramientas (`tls_certificado:sin_https`, `subdominios_ct:ct_no_responde`…) no "
          "son fallos de la tarea: el agente los declara como limitación y sigue. `gateway` cuenta las llamadas a "
          "Grok que fallaron después de los reintentos del cliente.",
          "", f"## Prevalencia agregada (dominios que existen, n={m['existentes']})", "",
          "Sobre dominios `.com.co` de la lista Tranco, no sobre \"pymes\". No se publica el resultado de ninguna "
          "empresa concreta.", "",
          "| Nivel de riesgo | Dominios |", "|---|---|"]
    r += [f"| {k} | {_pct(v, m['existentes'])} |" for k, v in m["niveles"].most_common()]
    r += ["", "| Hallazgo más frecuente | Dominios |", "|---|---|"]
    r += [f"| `{k}` | {_pct(v, m['existentes'])} |" for k, v in m["hallazgos"].most_common(15)]
    return "\n".join(r) + "\n"


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="python -m carga.resumen")
    p.add_argument("--lote", required=True)
    a = p.parse_args(argv)
    carpeta = CARPETA / a.lote
    tareas = _leer_lineas(carpeta / "tareas.jsonl")
    eventos = _leer_lineas(carpeta / "eventos.jsonl")
    privado_ruta = CARPETA_PRIVADA / f"{a.lote}-hallazgos.jsonl"
    privado = _leer_lineas(privado_ruta) if privado_ruta.exists() else []
    texto = reporte(a.lote, metricas(tareas, eventos, privado), gasto_en_bitacora(a.lote))
    (carpeta / "RESUMEN.md").write_text(texto, encoding="utf-8")
    escribir_csv(carpeta)
    print(texto)


if __name__ == "__main__":
    main()
