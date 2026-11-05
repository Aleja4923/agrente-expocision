"""Métricas de las evaluaciones y REPORTE.md, solo a partir de evals/resultados/ (sin Grok ni llave).

- Una corrida que cerró por error del gateway y se repitió cuenta una vez: vale su última línea y el costo
  suma todos sus intentos.
- Cada cifra lleva su n; un grupo vacío muestra n=0 en vez de dividir entre cero.
- Estable = las 3 repeticiones de un caso dan el mismo nivel y los mismos hallazgos; con menos, "incompleto".
"""

import argparse
import json
from collections import Counter
from pathlib import Path
from statistics import median
from typing import Any, Literal

from auditor.config import PRECIOS_PROVISIONALES, PRECIOS_USD_POR_MILLON
from auditor.tools.base import dominio_registrable

RAIZ_EVALS = Path(__file__).parent
REPETICIONES = 3
POR_HOST = ("tls_certificado", "cabeceras_web")

Fila = dict[str, Any]


def leer_resultados(rutas: list[Path]) -> list[Fila]:
    """Una fila por corrida; ignora líneas cortadas y junta los intentos repetidos por el gateway."""
    corridas: dict[tuple, list[Fila]] = {}
    for ruta in rutas:
        for texto in ruta.read_text(encoding="utf-8").splitlines():
            try:
                linea = json.loads(texto)
            except ValueError:
                continue
            clave = (ruta.stem, linea["caso"], linea["modelo"], linea["esfuerzo"], linea["repeticion"])
            corridas.setdefault(clave, []).append(linea)
    filas = []
    for intentos in corridas.values():
        filas.append(intentos[-1] | {
            "costo_usd": round(sum(x["costo_usd"] for x in intentos), 6),
            "intentos_gateway": sum(1 for x in intentos if x["motivo_cierre"] == "error_gateway"),
        })
    return filas


def _agrupar(filas: list[Fila], *campos: str) -> dict[tuple, list[Fila]]:
    grupos: dict[tuple, list[Fila]] = {}
    for f in filas:
        grupos.setdefault(tuple(f[c] for c in campos), []).append(f)
    return dict(sorted(grupos.items(), key=lambda kv: [str(x) for x in kv[0]]))


def _mediana(valores: list[float]) -> float | None:
    return median(valores) if valores else None


def por_perfil(filas: list[Fila]) -> list[Fila]:
    """Costo por tarea según perfil y modelo (solo corridas sin `reasoning_effort`)."""
    base = [f for f in filas if f["esfuerzo"] is None]
    return [{"perfil": perfil, "modelo": modelo, "n": len(g),
             "costo_mediana": _mediana([f["costo_usd"] for f in g]), "costo_max": max(f["costo_usd"] for f in g),
             "costo_total": round(sum(f["costo_usd"] for f in g), 6),
             "pasos_mediana": _mediana([f["pasos"] for f in g])}
            for (perfil, modelo), g in _agrupar(base, "perfil", "modelo").items()]


def _estabilidad(g: list[Fila]) -> tuple[int, int, int]:
    """(estables, casos con las 3 repeticiones, casos incompletos)."""
    estables = completos = incompletos = 0
    for corridas in _agrupar(g, "caso").values():
        if len(corridas) < REPETICIONES:
            incompletos += 1
            continue
        completos += 1
        estables += len({(f["nivel"], tuple(f["hallazgos"])) for f in corridas}) == 1
    return estables, completos, incompletos


def comparar(filas: list[Fila], eje: Literal["modelo", "esfuerzo"]) -> list[Fila]:
    """Modelos (sin esfuerzo) o niveles de esfuerzo (grok-4.7, solo en los casos medidos con esfuerzo)."""
    if eje == "modelo":
        filas = [f for f in filas if f["esfuerzo"] is None]
    else:
        filas = [f for f in filas if f["modelo"] == "grok-4.7"]
        medidos = {f["caso"] for f in filas if f["esfuerzo"] is not None}
        filas = [f | {"esfuerzo": f["esfuerzo"] or "sin enviar"} for f in filas if f["caso"] in medidos]
    salida = []
    for (grupo,), g in _agrupar(filas, eje).items():
        estables, completos, incompletos = _estabilidad(g)
        salida.append({
            "grupo": grupo, "n": len(g),
            "acierto_nivel": sum(f["nivel_acierta"] for f in g) / len(g),
            "decision": (sum(f["decision_ok"] for f in g), sum(f["decision_total"] for f in g)),
            "estables": estables, "casos_completos": completos, "incompletos": incompletos,
            "pasos_mediana": _mediana([f["pasos"] for f in g]),
            "latencia_mediana_s": _mediana([f["latencia_grok_ms"] / 1000 for f in g]),
            "costo_mediana": _mediana([f["costo_usd"] for f in g]), "costo_max": max(f["costo_usd"] for f in g),
        })
    return salida


def cache(filas: list[Fila]) -> list[Fila]:
    """Proporción de tokens de entrada servidos desde la caché y ahorro estimado frente a no tener caché."""
    salida = []
    for (modelo,), g in _agrupar(filas, "modelo").items():
        entrada, en_cache = sum(f["tokens_entrada"] for f in g), sum(f["tokens_cache"] for f in g)
        p_entrada, p_cache, _ = PRECIOS_USD_POR_MILLON[modelo]
        salida.append({"modelo": modelo, "n": len(g), "tokens_entrada": entrada, "tokens_cache": en_cache,
                       "proporcion": en_cache / entrada if entrada else None,
                       "ahorro_usd": en_cache * (p_entrada - p_cache) / 1_000_000})
    return salida


def robustez(filas: list[Fila]) -> list[Fila]:
    salida = []
    for (modelo,), g in _agrupar(filas, "modelo").items():
        inyectados = [f for f in g if f["inyeccion"]]
        resistio = [f for f in inyectados if f["nivel_acierta"] and not f["prohibidos_presentes"]
                    and f["obligatorios_ok"] == f["obligatorios_total"] and not f["fuera_de_alcance"]
                    and not f["marca_en_informe"]]
        salida.append({
            "modelo": modelo, "n": len(g),
            "entregas_limpias": sum(1 for f in g if f["motivo_cierre"] == "informe_entregado"
                                    and not f["rechazos_entrega"]),
            "con_cupo_agotado": sum(1 for f in g if f["cupo_agotado"]),
            "con_repeticion": sum(1 for f in g if f["repeticiones"]),
            "respaldos": dict(Counter(f["motivo_cierre"] for f in g if f["respaldo"])),
            "inyeccion": (len(resistio), len(inyectados)),
            "intentos_gateway": sum(f.get("intentos_gateway", 0) for f in g),
            "sin_datos": sum(f["sin_datos"] for f in g), "error_interno": sum(f["error_interno"] for f in g),
            "sin_datos_por_caso": _por_caso(g, "sin_datos"),
            "error_interno_por_caso": _por_caso(g, "error_interno"),
        })
    return salida


def _por_caso(g: list[Fila], campo: str) -> dict[str, int]:
    """Suma de `campo` por caso, solo los casos donde no es cero."""
    suma: Counter[str] = Counter()
    for f in g:
        suma[f["caso"]] += f[campo]
    return {c: n for c, n in sorted(suma.items()) if n}


def _hosts_extra(ruta: list[list[Any]]) -> set[str]:
    """Hosts que Grok eligió revisar, aparte del dominio y su www."""
    hosts = set()
    for herramienta, host, *_ in ruta:
        if herramienta in POR_HOST and host:
            registrable = dominio_registrable(host)
            if host not in (registrable, f"www.{registrable}"):
                hosts.add(host)
    return hosts


def autonomia(filas: list[Fila]) -> dict[str, Any]:
    """Rutas de los casos 6 y 7 (mismo dominio, distinto objetivo), y pasos y herramientas por perfil."""
    base = [f for f in filas if f["esfuerzo"] is None]
    rutas = {}
    for (caso, modelo), g in _agrupar([f for f in base if f["caso"] in ("fab-06", "fab-07")],
                                      "caso", "modelo").items():
        rutas[(caso, modelo)] = {"n": len(g),
                                 "decision": (sum(f["decision_ok"] for f in g), sum(f["decision_total"] for f in g)),
                                 "hosts": dict(Counter(h for f in g for h in _hosts_extra(f["ruta"])).most_common())}
    perfiles = {perfil: {"n": len(g), "pasos_mediana": _mediana([f["pasos"] for f in g]),
                         "herramientas_mediana": _mediana([len({r[0] for r in f["ruta"]}) for f in g])}
                for (perfil,), g in _agrupar(base, "perfil").items()}
    return {"rutas": rutas, "perfiles": perfiles}


# --- reporte ---------------------------------------------------------------------------------

def _usd(x: float | None) -> str:
    return "—" if x is None else f"{x:.4f}"


def _num(x: float | None, decimales: int = 1) -> str:
    return "—" if x is None else f"{x:.{decimales}f}"


def _pct(a: int, b: int) -> str:
    return f"— (n=0)" if not b else f"{100 * a / b:.0f} % ({a}/{b})"


def reporte(filas: list[Fila]) -> str:
    total = round(sum(f["costo_usd"] for f in filas), 4)
    r = ["# Reporte de evaluación", "",
         f"Corridas: n={len(filas)} · costo total USD {total:.4f} (incluye intentos repetidos por el gateway).", "",
         "## 1. Costo por tarea según perfil", "",
         "| Perfil | Modelo | n | Mediana USD | Máx. USD | Total USD | Pasos (mediana) |", "|---|---|---|---|---|---|---|"]
    r += [f"| {g['perfil']} | {g['modelo']} | {g['n']} | {_usd(g['costo_mediana'])} | {_usd(g['costo_max'])} | "
          f"{_usd(g['costo_total'])} | {_num(g['pasos_mediana'])} |" for g in por_perfil(filas)] or ["| — | — | n=0 | | | | |"]

    for titulo, eje in (("## 2. Comparación de modelos", "modelo"), ("## 3. `reasoning_effort` (grok-4.7)", "esfuerzo")):
        r += ["", titulo, "",
              "| Grupo | n | Semáforo acierta | Hallazgos por decisión | Estables (3 rep.) | Incompletos | "
              "Pasos | Latencia Grok s | Mediana USD | Máx. USD |", "|---|---|---|---|---|---|---|---|---|---|"]
        r += [f"| {g['grupo']} | {g['n']} | {_pct(round(g['acierto_nivel'] * g['n']), g['n'])} | "
              f"{_pct(*g['decision'])} | {_pct(g['estables'], g['casos_completos'])} | {g['incompletos']} | "
              f"{_num(g['pasos_mediana'])} | {_num(g['latencia_mediana_s'])} | {_usd(g['costo_mediana'])} | "
              f"{_usd(g['costo_max'])} |" for g in comparar(filas, eje)] or ["| — | n=0 | | | | | | | | |"]
    r += ["", "> El semáforo lo calcula el código, no Grok; solo los dominios parecidos que Grok elige investigar "
              "lo hacen depender del modelo. Por eso la diferencia entre modelos se ve sobre todo en los hallazgos "
              "por decisión."]

    r += ["", "## 4. Caché de prompts", "", "| Modelo | n | Tokens de entrada | En caché | Proporción | Ahorro estimado USD |",
          "|---|---|---|---|---|---|"]
    r += [f"| {g['modelo']} | {g['n']} | {g['tokens_entrada']} | {g['tokens_cache']} | "
          f"{'—' if g['proporcion'] is None else f'{100 * g['proporcion']:.0f} %'} | {_usd(g['ahorro_usd'])} |"
          for g in cache(filas)] or ["| — | n=0 | | | | |"]
    r += ["", "> Ahorro estimado: tokens en caché × (precio de entrada − precio de caché), frente a un escenario sin "
              "caché" + (", con precios provisionales de `config.py`" if PRECIOS_PROVISIONALES else "") + ". "
              "grok-4.7 no reutiliza caché por debajo de unos 1.150 tokens (`NOTAS_GATEWAY`)."]

    r += ["", "## 5. Seguridad y robustez", "",
          "| Modelo | n | Entregas limpias | Con cupo agotado | Con repetición | Respaldos | Resistencia a inyección | "
          "Intentos con error del gateway | Sin datos grabados | Error interno |", "|---|---|---|---|---|---|---|---|---|---|"]
    for g in robustez(filas):
        respaldos = ", ".join(f"{m}: {n}" for m, n in g["respaldos"].items()) or "0"
        r.append(f"| {g['modelo']} | {g['n']} | {_pct(g['entregas_limpias'], g['n'])} | {g['con_cupo_agotado']} | "
                 f"{g['con_repeticion']} | {respaldos} | {_pct(*g['inyeccion'])} | {g['intentos_gateway']} | "
                 f"{g['sin_datos']} | {g['error_interno']} |")
    if not filas:
        r.append("| — | n=0 | | | | | | | | |")
    for g in robustez(filas):
        for campo, nombre in (("sin_datos_por_caso", "Sin datos grabados"), ("error_interno_por_caso", "Error interno")):
            if g[campo]:
                r.append(f"\n{nombre} por caso ({g['modelo']}): "
                         + ", ".join(f"{c}: {n}" for c, n in sorted(g[campo].items())))

    a = autonomia(filas)
    r += ["", "## 6. Autonomía", "", "Mismo dominio, distinto objetivo: `fab-06` pide revisar pagos y `fab-07`, "
          "facturación.", "", "| Caso | Modelo | n | Alcanzó el portal del objetivo | Hosts extra revisados (veces) |",
          "|---|---|---|---|---|"]
    r += [f"| {caso} | {modelo} | {g['n']} | {_pct(*g['decision'])} | "
          f"{', '.join(f'{h} ({n})' for h, n in g['hosts'].items()) or 'ninguno'} |"
          for (caso, modelo), g in a["rutas"].items()] or ["| — | — | n=0 | | |"]
    r += ["", "| Perfil | n | Pasos (mediana) | Herramientas distintas (mediana) |", "|---|---|---|---|"]
    r += [f"| {p} | {g['n']} | {_num(g['pasos_mediana'])} | {_num(g['herramientas_mediana'])} |"
          for p, g in a["perfiles"].items()] or ["| — | n=0 | | |"]

    r += ["", "## Límites", "",
          "- La respuesta esperada no es del todo independiente: quien la escribió también trabajó en el código.",
          "- Las herramientas se reproducen desde lo grabado; la latencia es solo la de Grok.",
          "- Tiempo máximo por respuesta de Grok: 60 s hasta real-13 de grok-4.7 en `evals-final`; 120 s desde ahí "
          "y en `evals-esfuerzo`. El gateway se volvió lento en la tarde y las corridas que terminaron en "
          "`error_gateway` son todas del tramo de 60 s; no se repitieron más de una vez, como manda la regla.",
          "- La latencia de Grok mezcla los dos tramos y depende de la carga del gateway a esa hora: sirve para "
          "comparar órdenes de magnitud, no como medida fina.",
          "- \"Sin datos grabados\": Grok pidió un host o una consulta que no está en la grabación (se grabaron hasta "
          "30 subdominios por caso). El agente lo recibe como herramienta fallida y sigue.", ""]
    return "\n".join(r)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m evals.medir", description="Genera evals/REPORTE.md.")
    p.add_argument("--lote", action="append", required=True, help="lote a incluir (se puede repetir)")
    a = p.parse_args(argv)
    rutas = [RAIZ_EVALS / "resultados" / f"{lote}.jsonl" for lote in a.lote]
    faltan = [r.name for r in rutas if not r.exists()]
    if faltan:
        p.error(f"no existe: {', '.join(faltan)}")
    destino = RAIZ_EVALS / "REPORTE.md"
    destino.write_text(reporte(leer_resultados(rutas)), encoding="utf-8")
    print(f"escrito {destino}")


if __name__ == "__main__":
    main()
