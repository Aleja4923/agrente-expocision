"""Corre los casos con Grok de verdad y deja una línea pública por corrida en evals/resultados/.

- Cada corrida es una auditoría normal (`auditar`) con las herramientas reproducidas detrás de las guardas.
- Tokens, costo, latencia y rechazos se leen de la bitácora: las cifras tienen una sola fuente.
- La línea no guarda justificaciones ni el texto del informe, solo lo que se mide.
- El lote se puede reanudar: salta lo que ya tiene línea y repite una vez lo que cerró por error del gateway.
- Corre en un solo hilo: la bitácora pierde líneas si varios hilos escriben a la vez en Windows.
"""

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from auditor import agent
from auditor.config import MODELOS_PERMITIDOS, RUTA_LOGS
from auditor.llm import ClienteLLM
from auditor.metricas import leer_eventos
from evals.casos import Caso, cargar_casos
from evals.reglas import alcanzado
from evals.reproducir import SIN_DATOS, Reproductor

RUTA_RESULTADOS = Path(__file__).parent / "resultados"
REINTENTOS_GATEWAY = 1

Plan = list[tuple[Caso, str, str | None, int]]


def id_corrida(lote: str, caso_id: str, modelo: str, esfuerzo: str | None, repeticion: int,
               gateway: int = 0) -> str:
    """Un id por corrida; `-gN` marca la N-ésima repetición por error del gateway."""
    return f"{lote}-{caso_id}-{modelo}-{esfuerzo or 'base'}-r{repeticion}" + (f"-g{gateway}" if gateway else "")


def _host(herramienta: str, argumentos: dict[str, Any]) -> str | None:
    if herramienta == "investigar_parecido":
        return str(argumentos.get("parecido") or "") or None
    return agent._host(argumentos)


def _sin_datos(resultado) -> int:
    selectores = (resultado.datos or {}).get("selectores", []) if resultado.herramienta == "dkim_selector" else []
    return (resultado.error == SIN_DATOS) + sum(1 for s in selectores if s.get("error") == SIN_DATOS)


def correr_una(caso: Caso, modelo: str, esfuerzo: str | None, repeticion: int, lote: str, *,
               gateway: int = 0, cliente_llm=None, ruta_logs: Path = RUTA_LOGS) -> dict[str, Any]:
    """Una auditoría del caso y su comparación con la respuesta esperada."""
    auditoria_id = id_corrida(lote, caso.id, modelo, esfuerzo, repeticion, gateway)
    cliente = cliente_llm or ClienteLLM(lote, auditoria_id, modelo, dominio=caso.dominio, ruta_logs=ruta_logs,
                                        reasoning_effort=esfuerzo)
    estado = agent.auditar(caso.dominio, caso.objetivo, lote_id=lote, auditoria_id=auditoria_id, modelo=modelo,
                           cliente_llm=cliente, ejecutor=Reproductor(caso), ruta_logs=ruta_logs)

    eventos = [e for e in leer_eventos(sorted(ruta_logs.glob("bitacora-*.jsonl")))
               if e.get("auditoria_id") == auditoria_id]
    llm = [e for e in eventos if e["tipo"] == "llm"]
    rechazos = [e for e in eventos if e["tipo"] == "rechazo"]

    def suma(campo: str) -> int:
        return sum(e[campo] for e in llm)

    def rechazados(motivo: str) -> int:
        return sum(1 for e in rechazos if e["justificacion"] == motivo)

    e, h = caso.esperado, estado.hallazgos
    resultados = [r for _, r in estado.llamadas]
    return {
        "caso": caso.id, "perfil": caso.perfil, "modelo": modelo, "esfuerzo": esfuerzo, "repeticion": repeticion,
        "auditoria_id": auditoria_id,
        "nivel": estado.nivel_riesgo.value, "nivel_acierta": estado.nivel_riesgo == e.nivel_esperado,
        "hallazgos": sorted(h),
        "obligatorios_ok": sum(alcanzado(x, h) for x in e.hallazgos_obligatorios),
        "obligatorios_total": len(e.hallazgos_obligatorios),
        "decision_ok": sum(alcanzado(x, h) for x in e.hallazgos_por_decision),
        "decision_total": len(e.hallazgos_por_decision),
        "prohibidos_presentes": [x for x in e.hallazgos_prohibidos if alcanzado(x, h)],
        "motivo_cierre": estado.motivo_cierre.value,
        "cierre_acierta": estado.motivo_cierre.value == e.cierre_esperado,
        "respaldo": estado.informe_de_respaldo,
        "ruta": [[r.herramienta, _host(r.herramienta, a), r.ok, r.error] for a, r in estado.llamadas],
        "pasos": estado.pasos,
        "tokens_entrada": suma("tokens_entrada"), "tokens_cache": suma("tokens_cache"),
        "tokens_salida": suma("tokens_salida"), "tokens_razonamiento": suma("tokens_razonamiento"),
        "costo_usd": round(sum(e["costo_usd"] for e in llm), 6),
        "latencia_grok_ms": suma("latencia_ms"),
        "rechazos_entrega": sum(1 for e in rechazos if e["herramienta"] == "entregar_informe"),
        "cupo_agotado": rechazados("cupo_agotado"),
        "repeticiones": rechazados("repeticion"),
        "fuera_de_alcance": rechazados("fuera_de_alcance"),
        "sin_datos": sum(_sin_datos(r) for r in resultados),
        "error_interno": sum(1 for r in resultados if (r.error or "").startswith("error_interno")),
        "inyeccion": caso.marca_inyeccion is not None,
        "marca_en_informe": bool(caso.marca_inyeccion) and caso.marca_inyeccion in estado.informe.model_dump_json(),
    }


def planear(casos: list[Caso], modelos: list[str], repeticiones: int,
            esfuerzos: set[str | None] = frozenset({None})) -> Plan:
    return [(c, m, e, r) for c in casos for m in modelos for e in sorted(esfuerzos, key=str)
            for r in range(1, repeticiones + 1)]


def _leer_lineas(archivo: Path) -> list[dict[str, Any]]:
    """Líneas completas del lote; una línea cortada a mitad de escritura se ignora."""
    if not archivo.exists():
        return []
    lineas = []
    for texto in archivo.read_text(encoding="utf-8").splitlines():
        try:
            lineas.append(json.loads(texto))
        except ValueError:
            pass
    return lineas


def correr_lote(plan: Plan, lote: str, *, hilos: int = 1, ruta_resultados: Path = RUTA_RESULTADOS,
                fabrica_cliente: Callable[[Caso, str], Any] | None = None,
                ruta_logs: Path = RUTA_LOGS, avisar: Callable[[str], None] = lambda _: None) -> dict[str, Any]:
    """Corre el plan y agrega una línea por corrida a `{lote}.jsonl`; se puede cortar y reanudar."""
    if hilos != 1:
        raise ValueError("El lote corre en un hilo: la bitácora pierde líneas con varios hilos (registro_s3).")
    ruta_resultados.mkdir(parents=True, exist_ok=True)
    archivo = ruta_resultados / f"{lote}.jsonl"
    hechas: dict[str, list[dict[str, Any]]] = {}
    for linea in _leer_lineas(archivo):
        clave = id_corrida(lote, linea["caso"], linea["modelo"], linea["esfuerzo"], linea["repeticion"])
        hechas.setdefault(clave, []).append(linea)
    if archivo.exists() and archivo.stat().st_size and not archivo.read_bytes().endswith(b"\n"):
        with archivo.open("a", encoding="utf-8") as f:
            f.write("\n")  # aísla la línea cortada para que la siguiente no se pegue a ella

    resumen = {"hechas": 0, "saltadas": 0, "repetidas_gateway": 0, "costo_usd": 0.0}
    for caso, modelo, esfuerzo, repeticion in plan:
        previas = hechas.setdefault(id_corrida(lote, caso.id, modelo, esfuerzo, repeticion), [])
        if any(p["motivo_cierre"] != "error_gateway" for p in previas) or len(previas) > REINTENTOS_GATEWAY:
            resumen["saltadas"] += 1
            continue
        while len(previas) <= REINTENTOS_GATEWAY:
            gateway = len(previas)
            auditoria_id = id_corrida(lote, caso.id, modelo, esfuerzo, repeticion, gateway)
            cliente = fabrica_cliente(caso, auditoria_id) if fabrica_cliente else None
            linea = correr_una(caso, modelo, esfuerzo, repeticion, lote, gateway=gateway,
                               cliente_llm=cliente, ruta_logs=ruta_logs)
            with archivo.open("a", encoding="utf-8") as f:
                f.write(json.dumps(linea, ensure_ascii=False) + "\n")
            previas.append(linea)
            resumen["hechas"] += 1
            resumen["repetidas_gateway"] += gateway > 0
            resumen["costo_usd"] += linea["costo_usd"]
            avisar(f"{auditoria_id} · {linea['motivo_cierre']} · nivel {linea['nivel']} · "
                   f"{linea['pasos']} pasos · USD {linea['costo_usd']:.4f}")
            if linea["motivo_cierre"] != "error_gateway":
                break
    resumen["costo_usd"] = round(resumen["costo_usd"], 6)
    return resumen


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m evals.correr", description="Corre casos de evaluación con Grok.")
    p.add_argument("--lote", required=True, help="nombre del lote; empieza por evals-")
    p.add_argument("--casos", help="ids separados por coma (por defecto, todos)")
    p.add_argument("--modelos", default="grok-4.7")
    p.add_argument("--repeticiones", type=int, default=1)
    p.add_argument("--esfuerzo", help="reasoning_effort a enviar (por defecto, no se envía)")
    p.add_argument("--hilos", type=int, default=1)
    a = p.parse_args(argv)
    if not a.lote.startswith("evals-"):
        p.error("el lote debe empezar por evals- para separarlo en la bitácora")
    modelos = a.modelos.split(",")
    if not set(modelos) <= set(MODELOS_PERMITIDOS):
        p.error(f"modelos permitidos: {', '.join(MODELOS_PERMITIDOS)}")
    casos = cargar_casos()
    if a.casos:
        pedidos = a.casos.split(",")
        casos = [c for c in casos if c.id in pedidos]
        if len(casos) != len(pedidos):
            p.error("algún caso no existe en evals/casos/")
    plan = planear(casos, modelos, a.repeticiones, {a.esfuerzo})
    resumen = correr_lote(plan, a.lote, hilos=a.hilos, avisar=print)
    print(f"hechas {resumen['hechas']} · saltadas {resumen['saltadas']} · "
          f"repetidas por gateway {resumen['repetidas_gateway']} · USD {resumen['costo_usd']:.4f}")


if __name__ == "__main__":
    main()
