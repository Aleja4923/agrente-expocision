"""Corrida del S4: audita una cola de dominios reales, sola y sin supervisión, y deja una línea por tarea.

- Una **tarea** es la auditoría completa de un dominio. Es **completada** si cerró con informe (de Grok o de
  respaldo por un tope) o confirmó que el dominio no existe, y **fallida** si sus 3 intentos terminaron en error
  del gateway o en un error interno.
- La cola se puede cortar y reanudar: salta las posiciones que ya tienen su línea en `tareas.jsonl`.
- `carga/<lote>/tareas.jsonl` es público y **no lleva datos de riesgo**: el nivel y los hallazgos de cada empresa
  van a `docs/carga/` (privado) y solo se publican en agregado.
- Se recupera sola:
  - reintenta las tareas que fallan;
  - si el gateway se cae, pausa la cola (5, 10 y luego 20 minutos);
  - frena por gasto;
  - impide que Windows suspenda el equipo;
  - anota en `eventos.jsonl` todo lo que hizo.
"""

import argparse
import csv
import json
import os
import queue
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from auditor.modelos import EstadoAuditoria, MotivoCierre
from carga.dominios import leer_csv
from evals.correr import _candado, _leer_lineas

CARPETA = Path(__file__).resolve().parent
CARPETA_PRIVADA = CARPETA.parent / "docs" / "carga"
MODELO = "grok-4.20"
MAX_INTENTOS = 3
ESPERAS_ENTRE_INTENTOS = (30, 60)          # segundos antes del intento 2 y del 3
PAUSAS_GATEWAY = (300, 600, 1200)          # pausas de la cola si el gateway se cae (la última se repite)
CAIDAS_SEGUIDAS = 5                        # tareas fallidas seguidas por el gateway que activan la pausa
FRENO = (44.0, 46.5, 1030)                 # (freno suave USD, freno duro USD, completadas para el suave)
SALTO_RELOJ_SEGUNDOS = 600
# Mínimo entre el arranque de dos tareas: el reto exige 12 h seguidas, y una tarea tarda ~45 s. Con 1.150 tareas,
# 42 s dan unas 13,4 h. Si las tareas tardan más, no se espera nada extra.
RITMO_SEGUNDOS = 42.0

COLUMNAS = ["pos", "dominio", "inicio", "fin", "duracion_s", "resultado", "exito", "motivo_cierre", "respaldo",
            "dominio_existe", "intentos", "pasos", "tokens_entrada", "tokens_cache", "tokens_salida",
            "tokens_razonamiento", "costo_usd", "errores", "recuperacion", "lote_id", "auditoria_id"]


def _ahora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ContadorLLM:
    """Envuelve al cliente de Grok de un intento: suma tokens y anota los errores del gateway."""

    def __init__(self, cliente: Any):
        self.cliente = cliente
        self.tokens = {"entrada": 0, "cache": 0, "salida": 0, "razonamiento": 0}
        self.errores: list[str] = []

    def completar(self, *args, **kwargs):
        from auditor.llm import ErrorGateway
        try:
            r = self.cliente.completar(*args, **kwargs)
        except ErrorGateway as e:
            self.errores.append(f"gateway:{e.codigo}")
            raise
        for k in self.tokens:
            self.tokens[k] += getattr(r, f"tokens_{k}", 0) or 0
        return r


def _auditar_real(dominio, *, lote_id, auditoria_id, intento, modelo, cliente_llm) -> EstadoAuditoria:
    from auditor.agent import auditar
    return auditar(dominio, lote_id=lote_id, auditoria_id=auditoria_id, intento=intento, modelo=modelo,
                   cliente_llm=cliente_llm)


def _cliente_real(lote_id, auditoria_id, modelo, intento, dominio):
    from auditor.llm import ClienteLLM
    return ClienteLLM(lote_id, auditoria_id, modelo, intento=intento, dominio=dominio)


def _guardar_real(estado: EstadoAuditoria) -> None:
    """Informe en salidas/ y registro en SQLite, igual que la CLI (ambos privados)."""
    from auditor.config import RUTA_DB, RUTA_SALIDAS
    from auditor.report import guardar_informe
    from auditor.store import guardar_auditoria
    guardar_auditoria(estado, guardar_informe(estado, RUTA_SALIDAS), RUTA_DB)


def _existe(estado: EstadoAuditoria) -> bool:
    from auditor.report import dominio_no_existe
    return not dominio_no_existe(estado)


def _recuperacion(cierres: list[str], estado: EstadoAuditoria | None, completada: bool) -> str:
    partes = []
    for codigo, nombre in (("error_gateway", "error del gateway"), ("error_interno", "error interno")):
        n = cierres.count(codigo)
        if n:
            partes.append(f"{n} {'intento' if n == 1 else 'intentos'} con {nombre}")
    if not completada:
        return "; ".join(partes) + f" → fallida tras {len(cierres)} intentos"
    if estado.informe_de_respaldo:
        final = f"informe de respaldo ({estado.motivo_cierre.value})"
    else:
        final = "informe entregado"
    return f"{'; '.join(partes)} → {final}" if partes else ("" if not estado.informe_de_respaldo else final)


@contextmanager
def _despierto():
    """Windows no suspende el equipo mientras corre la cola (lección del S1, CONTEXT §10)."""
    if os.name != "nt":
        yield
        return
    import ctypes
    kernel = ctypes.windll.kernel32
    kernel.SetThreadExecutionState(0x80000000 | 0x00000001)  # ES_CONTINUOUS | ES_SYSTEM_REQUIRED
    try:
        yield
    finally:
        kernel.SetThreadExecutionState(0x80000000)


class _Cola:
    def __init__(self, lote, carpeta_lote, ruta_privada, previas):
        self.lote = lote
        self.candado = threading.Lock()
        self.tareas = carpeta_lote / "tareas.jsonl"
        self.eventos = carpeta_lote / "eventos.jsonl"
        self.privado = ruta_privada
        self.gasto = sum(t.get("costo_usd", 0) for t in previas)
        self.completadas = sum(1 for t in previas if t.get("resultado") == "completada")
        self.fallidas = sum(1 for t in previas if t.get("resultado") == "fallida")
        self.seguidas_gateway = 0
        self.pausa_n = 0
        self.frenada = False

    def _agregar(self, ruta: Path, dato: dict) -> None:
        with ruta.open("a", encoding="utf-8") as f:
            f.write(json.dumps(dato, ensure_ascii=False) + "\n")

    def evento(self, tipo: str, **campos) -> None:
        self._agregar(self.eventos, {"ts": _ahora(), "lote_id": self.lote, "tipo": tipo, **campos})


def correr_cola(lote: str, filas: list[tuple[int, str, str]], *, hilos: int = 2, modelo: str = MODELO,
                auditar_fn: Callable[..., EstadoAuditoria] | None = None,
                nuevo_cliente: Callable[..., Any] | None = None,
                guardar: Callable[[EstadoAuditoria], None] | None = None,
                carpeta: Path = CARPETA, carpeta_privada: Path = CARPETA_PRIVADA,
                dormir: Callable[[float], None] = time.sleep, freno: tuple[float, float, int] = FRENO,
                caidas_seguidas: int = CAIDAS_SEGUIDAS, limite: int | None = None, vigilar_reloj: bool = False,
                ritmo: float = 0.0, reloj: Callable[[], float] = time.monotonic,
                avisar: Callable[[str], None] = lambda _: None) -> dict[str, Any]:
    """Corre las filas pendientes de la cola y devuelve el resumen de esta pasada."""
    if auditar_fn is None:
        auditar_fn, nuevo_cliente = _auditar_real, nuevo_cliente or _cliente_real
        guardar = guardar or _guardar_real
    nuevo_cliente = nuevo_cliente or (lambda *a: None)
    guardar = guardar or (lambda e: None)
    carpeta_lote = carpeta / lote
    carpeta_lote.mkdir(parents=True, exist_ok=True)
    carpeta_privada.mkdir(parents=True, exist_ok=True)

    with _candado(carpeta_lote / "corrida.lock"), _despierto():
        ruta = carpeta_lote / "tareas.jsonl"
        if ruta.exists() and ruta.stat().st_size and not ruta.read_bytes().endswith(b"\n"):
            with ruta.open("a", encoding="utf-8") as f:  # una línea cortada por una caída queda sola (no se borra)
                f.write("\n")
        previas = _leer_lineas(ruta) if ruta.exists() else []
        hechas = {t["pos"] for t in previas if "pos" in t}
        pendientes = [f for f in filas if f[0] not in hechas][:limite]
        c = _Cola(lote, carpeta_lote, carpeta_privada / f"{lote}-hallazgos.jsonl", previas)
        c.evento("inicio_corrida", pid=os.getpid(), hilos=hilos, modelo=modelo, ritmo_s=ritmo, pendientes=len(pendientes),
                 hechas_antes=len(hechas), gasto_previo_usd=round(c.gasto, 4))
        trabajo: queue.Queue = queue.Queue()
        for f in pendientes:
            trabajo.put(f)
        parar = threading.Event()
        turno = threading.Lock()
        proxima = [reloj()]

        def esperar_turno() -> None:
            """Una tarea arranca como pronto `ritmo` segundos después de la anterior."""
            with turno:
                falta = proxima[0] - reloj()
                if falta > 0:
                    dormir(falta)
                proxima[0] = max(reloj(), proxima[0]) + ritmo

        def puede_seguir() -> bool:
            with c.candado:
                suave, duro, minimo = freno
                if c.gasto >= duro or (c.gasto >= suave and c.completadas >= minimo):
                    if not c.frenada:
                        c.frenada = True
                        c.evento("freno_gasto", gasto_usd=round(c.gasto, 4), completadas=c.completadas)
                    return False
                if c.seguidas_gateway >= caidas_seguidas:
                    segundos = PAUSAS_GATEWAY[min(c.pausa_n, len(PAUSAS_GATEWAY) - 1)]
                    c.evento("pausa_gateway", segundos=segundos, fallidas_seguidas=c.seguidas_gateway)
                    avisar(f"   … el gateway no responde: la cola espera {segundos // 60} min")
                    c.pausa_n += 1
                    c.seguidas_gateway = 0
                    dormir(segundos)  # con el candado tomado: toda la cola espera
                return True

        def una_tarea(pos: int, dominio: str) -> None:
            aid = f"{lote}-{pos:04d}"
            inicio, t0 = _ahora(), time.monotonic()
            costo, pasos, errores, cierres = 0.0, 0, [], []
            tokens = {"entrada": 0, "cache": 0, "salida": 0, "razonamiento": 0}
            estado = None
            for intento in range(1, MAX_INTENTOS + 1):
                contador = ContadorLLM(nuevo_cliente(lote, aid, modelo, intento, dominio))
                try:
                    estado = auditar_fn(dominio, lote_id=lote, auditoria_id=aid, intento=intento, modelo=modelo,
                                        cliente_llm=contador if contador.cliente is not None else None)
                except Exception as e:  # una tarea nunca tumba la cola
                    estado = None
                    errores.append(f"error_interno:{type(e).__name__}")
                    cierres.append("error_interno")
                else:
                    costo += estado.costo_usd
                    pasos += estado.pasos
                    errores += contador.errores + [f"{r.herramienta}:{r.error}" for _, r in estado.llamadas
                                                   if not r.ok]
                    cierres.append(estado.motivo_cierre.value)
                for k in tokens:
                    tokens[k] += contador.tokens[k]
                if estado is not None and estado.motivo_cierre != MotivoCierre.ERROR_GATEWAY:
                    break
                if intento < MAX_INTENTOS:
                    dormir(ESPERAS_ENTRE_INTENTOS[intento - 1])
            completada = estado is not None and estado.motivo_cierre != MotivoCierre.ERROR_GATEWAY
            if estado is not None:
                try:
                    guardar(estado)
                except Exception as e:
                    errores.append(f"guardar_informe:{type(e).__name__}")
            linea = {
                "pos": pos, "dominio": dominio, "inicio": inicio, "fin": _ahora(),
                "duracion_s": round(time.monotonic() - t0, 1),
                "resultado": "completada" if completada else "fallida", "exito": completada,
                "motivo_cierre": cierres[-1], "respaldo": bool(estado and estado.informe_de_respaldo),
                "dominio_existe": _existe(estado) if completada else None,
                "intentos": len(cierres), "pasos": pasos, **{f"tokens_{k}": v for k, v in tokens.items()},
                "costo_usd": round(costo, 6), "errores": sorted(set(errores)),
                "recuperacion": _recuperacion(cierres, estado, completada), "lote_id": lote, "auditoria_id": aid,
            }
            with c.candado:
                c._agregar(c.tareas, linea)
                if estado is not None:
                    c._agregar(c.privado, {"pos": pos, "dominio": dominio, "motivo_cierre": cierres[-1],
                                           "existe": linea["dominio_existe"],
                                           "nivel": estado.nivel_riesgo.value if estado.nivel_riesgo else None,
                                           "hallazgos": sorted(estado.hallazgos)})
                c.gasto += costo
                if completada:
                    c.completadas += 1
                    c.seguidas_gateway, c.pausa_n = 0, 0
                else:
                    c.fallidas += 1
                    c.seguidas_gateway += 1 if "error_gateway" in cierres else 0
                avisar(f"{pos:>4} {dominio} · {linea['resultado']} · {cierres[-1]} · {len(cierres)} int · "
                       f"USD {costo:.4f} · total USD {c.gasto:.2f} · {c.completadas} completadas")

        def trabajador() -> None:
            while not parar.is_set():
                try:
                    pos, dominio, _ = trabajo.get_nowait()
                except queue.Empty:
                    return
                if ritmo:
                    esperar_turno()
                if not puede_seguir():
                    parar.set()
                    return
                una_tarea(pos, dominio)

        def vigia() -> None:
            antes = time.time()
            while not parar.wait(30):
                ahora = time.time()
                if ahora - antes > SALTO_RELOJ_SEGUNDOS:
                    with c.candado:
                        c.evento("salto_reloj", segundos=round(ahora - antes))
                antes = ahora

        hilos_lista = [threading.Thread(target=trabajador, name=f"tarea-{i}") for i in range(hilos)]
        if vigilar_reloj:
            threading.Thread(target=vigia, name="vigia", daemon=True).start()
        for h in hilos_lista:
            h.start()
        for h in hilos_lista:
            h.join()
        parar.set()
        resumen = {"completadas": c.completadas, "fallidas": c.fallidas, "gasto_usd": round(c.gasto, 4),
                   "frenada": c.frenada, "pendientes": trabajo.qsize()}
        c.evento("fin_corrida", **resumen)
        return resumen


def escribir_csv(carpeta_lote: Path) -> Path:
    """`tareas.csv` con las mismas filas que `tareas.jsonl` (las listas, separadas por `;`)."""
    filas = sorted(_leer_lineas(carpeta_lote / "tareas.jsonl"), key=lambda t: t.get("pos", 0))
    ruta = carpeta_lote / "tareas.csv"
    with ruta.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNAS, extrasaction="ignore")
        w.writeheader()
        for t in filas:
            w.writerow({k: ";".join(v) if isinstance(v, list) else v for k, v in t.items()})
    return ruta


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(prog="python -m carga.correr", description=__doc__.splitlines()[0])
    p.add_argument("--lote", required=True, help="s4-prueba (posiciones de prueba) o s4-carga (la corrida larga)")
    p.add_argument("--hilos", type=int, default=2)
    p.add_argument("--limite", type=int, help="máximo de tareas en esta pasada")
    p.add_argument("--ritmo", type=float, help=f"segundos mínimos entre tareas (por defecto {RITMO_SEGUNDOS:.0f} en "
                                               "s4-carga y 0 en s4-prueba)")
    a = p.parse_args(argv)
    usos = {"s4-prueba": "prueba", "s4-carga": "corrida"}
    if a.lote not in usos:
        p.error("el lote debe ser s4-prueba o s4-carga")
    filas = [f for f in leer_csv() if f[2] == usos[a.lote]]
    ritmo = a.ritmo if a.ritmo is not None else (RITMO_SEGUNDOS if a.lote == "s4-carga" else 0.0)
    r = correr_cola(a.lote, filas, hilos=a.hilos, limite=a.limite, vigilar_reloj=True, ritmo=ritmo, avisar=print)
    escribir_csv(CARPETA / a.lote)
    print(f"completadas {r['completadas']} · fallidas {r['fallidas']} · USD {r['gasto_usd']:.2f} · "
          f"pendientes {r['pendientes']}{' · FRENADA POR GASTO' if r['frenada'] else ''}")
    return 3 if r["frenada"] else 0


if __name__ == "__main__":
    sys.exit(main())
