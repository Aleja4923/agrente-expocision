
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from auditor.config import RUTA_LOGS

TipoEvento = Literal["inicio", "llm", "herramienta", "rechazo", "error", "fin"]

# Cualquier cosa con forma de llave del reto, aunque no sea la nuestra.
_PATRON_LLAVE = re.compile(r"pk_[A-Za-z0-9_\-]{8,}")


class Evento(BaseModel):
    """Los 19 campos fijos de la bitácora. Un campo extra o mal escrito es un error.

    Identidad de cada evento: lote > auditoría > intento (ver docs/GLOSSARY.md).
    """

    model_config = ConfigDict(extra="forbid")

    ts: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lote_id: str
    auditoria_id: str | None = None
    intento: int = 1
    dominio: str | None = None
    paso: int = 0
    tipo: TipoEvento
    modelo: str | None = None
    tokens_entrada: int = 0
    tokens_cache: int = 0
    tokens_salida: int = 0
    tokens_razonamiento: int = 0
    costo_usd: float = 0.0
    latencia_ms: int = 0
    herramienta: str | None = None
    args_hash: str | None = None
    ok: bool | None = None
    justificacion: str | None = None
    motivo_cierre: str | None = None


def enmascarar(texto: str) -> str:
    """Reemplaza la llave del entorno y cualquier texto con forma de llave por pk_***."""
    llave = os.getenv("RETO_KEY")
    if llave:
        texto = texto.replace(llave, "pk_***")
    return _PATRON_LLAVE.sub("pk_***", texto)


def hash_args(args: dict[str, Any]) -> str:
    """Huella corta de los argumentos de una herramienta (para detectar repeticiones)."""
    canonico = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonico.encode("utf-8")).hexdigest()[:16]


def escribir(evento: Evento, ruta_logs: Path = RUTA_LOGS) -> Path:
    """Agrega el evento como una línea JSON al archivo del día y devuelve su ruta."""
    ruta_logs.mkdir(parents=True, exist_ok=True)
    archivo = ruta_logs / f"bitacora-{datetime.now():%Y%m%d}.jsonl"
    linea = enmascarar(json.dumps(evento.model_dump(), ensure_ascii=False))
    with archivo.open("a", encoding="utf-8") as f:
        f.write(linea + "\n")
    return archivo
