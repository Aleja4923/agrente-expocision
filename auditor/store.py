"""Registro de auditorías en SQLite (mínimo del S1).

Una fila por intento de auditoría y sus llamadas a herramientas. En el S3 alimenta las
evaluaciones; en el S4 se le agrega la cola reanudable. La bitácora JSONL sigue siendo
el registro completo de eventos y costos.

Desde el S2 guarda también la caché del registro de dominios (WHOIS/RDAP): el servicio de
.co limita las consultas, así que una respuesta se reutiliza durante VIGENCIA_CACHE_HORAS.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from auditor.config import RUTA_DB, VIGENCIA_CACHE_HORAS
from auditor.modelos import EstadoAuditoria

_ESQUEMA = """
create table if not exists auditorias (
    auditoria_id text not null, intento integer not null, lote_id text not null, dominio text not null,
    objetivo text, modelo text, inicio text, fin text, motivo_cierre text, nivel_riesgo text,
    costo_usd real, pasos integer, informe_de_respaldo integer, hallazgos text, informe_json text,
    ruta_informe text, primary key (auditoria_id, intento)
);
create table if not exists llamadas (
    auditoria_id text not null, intento integer not null, orden integer not null, herramienta text,
    host text, ok integer, error text, primary key (auditoria_id, intento, orden)
);
create table if not exists registro_cache (
    dominio text primary key, existe integer not null, datos text not null, consultado text not null
);
"""


@contextmanager
def _conectar(ruta_db: Path) -> Iterator[sqlite3.Connection]:
    """Conexión con el esquema creado; confirma la transacción al salir y siempre cierra."""
    ruta_db.parent.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(ruta_db)
    try:
        conexion.executescript(_ESQUEMA)
        with conexion:  # transacción: commit si todo va bien, rollback si falla
            yield conexion
    finally:
        conexion.close()


def guardar_auditoria(estado: EstadoAuditoria, ruta_informe: Path | None, ruta_db: Path = RUTA_DB) -> None:
    """Guarda (o reemplaza) la fila del intento y sus llamadas, en una sola transacción."""
    clave = (estado.auditoria_id, estado.intento)
    with _conectar(ruta_db) as conexion:
        conexion.execute("delete from llamadas where auditoria_id = ? and intento = ?", clave)
        conexion.execute("insert or replace into auditorias values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (
            *clave, estado.lote_id, estado.dominio, estado.objetivo, estado.modelo, estado.inicio.isoformat(),
            datetime.now(timezone.utc).isoformat(),
            str(estado.motivo_cierre) if estado.motivo_cierre else None,
            str(estado.nivel_riesgo) if estado.nivel_riesgo else None,
            round(estado.costo_usd, 6), estado.pasos, int(estado.informe_de_respaldo),
            json.dumps(list(estado.hallazgos)),
            estado.informe.model_dump_json() if estado.informe else None,
            str(ruta_informe) if ruta_informe else None,
        ))
        conexion.executemany("insert into llamadas values (?,?,?,?,?,?,?)", [
            (*clave, orden, r.herramienta, argumentos.get("parecido") or argumentos.get("dominio") or argumentos.get("host"), int(r.ok), r.error)
            for orden, (argumentos, r) in enumerate(estado.llamadas, 1)
        ])


def leer_auditoria(auditoria_id: str, intento: int = 1, ruta_db: Path = RUTA_DB) -> dict[str, Any] | None:
    """La auditoría como diccionario (con hallazgos, informe y llamadas ya decodificados), o None."""
    with _conectar(ruta_db) as conexion:
        conexion.row_factory = sqlite3.Row
        fila = conexion.execute("select * from auditorias where auditoria_id = ? and intento = ?",
                                (auditoria_id, intento)).fetchone()
        llamadas = conexion.execute("select orden, herramienta, host, ok, error from llamadas "
                                    "where auditoria_id = ? and intento = ? order by orden",
                                    (auditoria_id, intento)).fetchall()
    if fila is None:
        return None
    datos = dict(fila)
    datos["hallazgos"] = json.loads(datos["hallazgos"])
    datos["informe"] = json.loads(datos.pop("informe_json")) if datos["informe_json"] else None
    datos["informe_de_respaldo"] = bool(datos["informe_de_respaldo"])
    datos["llamadas"] = [{**dict(l), "ok": bool(l["ok"])} for l in llamadas]
    return datos


def leer_cache_registro(dominio: str, ahora: datetime, ruta_db: Path = RUTA_DB) -> dict[str, Any] | None:
    """{"existe", "datos"} si hay una respuesta del registro de menos de VIGENCIA_CACHE_HORAS; si no, None."""
    with _conectar(ruta_db) as conexion:
        fila = conexion.execute("select existe, datos, consultado from registro_cache where dominio = ?",
                                (dominio,)).fetchone()
    if fila is None or ahora - datetime.fromisoformat(fila[2]) > timedelta(hours=VIGENCIA_CACHE_HORAS):
        return None
    return {"existe": bool(fila[0]), "datos": json.loads(fila[1])}


def guardar_cache_registro(dominio: str, existe: bool, datos: dict[str, Any], ahora: datetime,
                           ruta_db: Path = RUTA_DB) -> None:
    """Guarda (o reemplaza) la respuesta del registro para `dominio`, incluido "no registrado"."""
    with _conectar(ruta_db) as conexion:
        conexion.execute("insert or replace into registro_cache values (?,?,?,?)",
                         (dominio, int(existe), json.dumps(datos, ensure_ascii=False), ahora.isoformat()))
