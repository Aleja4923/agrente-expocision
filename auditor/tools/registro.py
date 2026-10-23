"""Registro público de dominios (WHOIS y RDAP) y herramienta `whois_dominio`.

- `.co` y sus segundos niveles: WHOIS en whois.registry.co, puerto 43. `.co` no está en el
  bootstrap RDAP de IANA (verificado el 2026-10-20).
- `.com`, `.net` y `.org`: RDAP, con una tabla fija de servidores (sin hosts elegidos por terceros).
- El servicio de .co limita las consultas: van en serie, con pausa mínima por servidor, y las
  respuestas se guardan en caché (store.py) durante VIGENCIA_CACHE_HORAS.
Los lectores (parsear_whois_co, parsear_rdap) son funciones puras; el nombre del registrador es
texto externo y solo sale como contenido no confiable.
"""

import json
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from auditor.config import PAUSA_REGISTRO_SEGUNDOS, REGISTRO_TIMEOUT_SEGUNDOS, RUTA_DB, USER_AGENT
from auditor.modelos import ResultadoHerramienta
from auditor.store import guardar_cache_registro, leer_cache_registro
from auditor.tools.base import SUFIJOS_CO, dominio_registrable, registrar
from auditor.tools.correo import EntradaDominio

SERVIDOR_WHOIS_CO = "whois.registry.co"
RDAP = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
}
MAX_BYTES_WHOIS = 65536
BLOQUEOS = ("clientTransferProhibited", "serverTransferProhibited")

# Puntos de inyección para las pruebas (sin red, sin espera real).
RUTA_CACHE_DB: Path = RUTA_DB
_reloj = time.monotonic
_dormir = time.sleep
_ahora = lambda: datetime.now(timezone.utc)  # noqa: E731
_candado = threading.Lock()
_ultima_consulta: dict[str, float] = {}


class ErrorRegistro(Exception):
    """Fallo con código corto: tld_no_soportado, registro_no_responde o respuesta_ilegible."""

    def __init__(self, codigo: str):
        self.codigo = codigo
        super().__init__(codigo)


def _fecha(texto: str) -> str:
    """Fecha ISO 8601 en UTC; si no se puede leer, respuesta_ilegible."""
    try:
        f = datetime.fromisoformat(texto.strip())
    except ValueError:
        raise ErrorRegistro("respuesta_ilegible") from None
    return (f if f.tzinfo else f.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


def parsear_whois_co(texto: str) -> dict[str, Any] | None:
    """Datos del WHOIS de .co; None si el dominio no está registrado."""
    if re.search(r"DOMAIN NOT FOUND|does not exist", texto, re.IGNORECASE):
        return None
    campos: dict[str, list[str]] = {}
    for linea in texto.splitlines():
        clave, sep, valor = linea.partition(":")
        if sep and valor.strip():
            campos.setdefault(clave.strip().lower(), []).append(valor.strip())
    if "creation date" not in campos or "registry expiry date" not in campos:
        raise ErrorRegistro("respuesta_ilegible")
    return {
        "creado": _fecha(campos["creation date"][0]),
        "vence": _fecha(campos["registry expiry date"][0]),
        "estados": [e.split()[0] for e in campos.get("domain status", [])],
        "servidores_nombre": [n.lower().rstrip(".") for n in campos.get("name server", [])],
        "registrador": campos.get("registrar", [""])[0],
    }


def _camel(estado: str) -> str:
    """'client transfer prohibited' -> 'clientTransferProhibited' (estados EPP como en WHOIS)."""
    palabras = estado.split()
    return palabras[0].lower() + "".join(p.capitalize() for p in palabras[1:]) if palabras else ""


def parsear_rdap(dato: dict[str, Any]) -> dict[str, Any]:
    """Mismos datos que parsear_whois_co, desde una respuesta RDAP (RFC 9083)."""
    eventos = {e.get("eventAction"): e.get("eventDate") for e in dato.get("events", [])}
    if not eventos.get("registration") or not eventos.get("expiration"):
        raise ErrorRegistro("respuesta_ilegible")
    registrador = ""
    for entidad in dato.get("entities", []):
        if "registrar" in entidad.get("roles", []):
            for campo in (entidad.get("vcardArray") or [None, []])[1]:
                if campo and campo[0] == "fn":
                    registrador = str(campo[3])
    return {
        "creado": _fecha(eventos["registration"]),
        "vence": _fecha(eventos["expiration"]),
        "estados": [_camel(s) for s in dato.get("status", [])],
        "servidores_nombre": [n.get("ldhName", "").lower().rstrip(".") for n in dato.get("nameservers", [])],
        "registrador": registrador,
    }


def fuente_para(dominio: str) -> tuple[str, str]:
    """("whois", servidor) o ("rdap", url base) según el TLD; si no hay fuente, tld_no_soportado."""
    tld = dominio.rsplit(".", 1)[-1]
    if tld == "co" or ".".join(dominio.split(".")[-2:]) in SUFIJOS_CO:
        return "whois", SERVIDOR_WHOIS_CO
    if tld in RDAP:
        return "rdap", RDAP[tld]
    raise ErrorRegistro("tld_no_soportado")


def _pedir_whois(servidor: str, dominio: str) -> str:
    with socket.create_connection((servidor, 43), timeout=REGISTRO_TIMEOUT_SEGUNDOS) as s:
        s.sendall(f"{dominio}\r\n".encode("ascii"))
        partes, total = [], 0
        while total < MAX_BYTES_WHOIS and (bloque := s.recv(4096)):
            partes.append(bloque)
            total += len(bloque)
    return b"".join(partes).decode("utf-8", errors="replace")


class _SinRedireccionAOtroHost(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).hostname != urlparse(req.full_url).hostname:
            raise ErrorRegistro("registro_no_responde")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _pedir_rdap(url: str) -> dict[str, Any] | None:
    """JSON del RDAP; None si responde 404 (no registrado)."""
    pedido = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
    try:
        with urllib.request.build_opener(_SinRedireccionAOtroHost).open(
                pedido, timeout=REGISTRO_TIMEOUT_SEGUNDOS) as r:
            return json.loads(r.read(1_000_000).decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise ErrorRegistro("registro_no_responde") from None
    except ValueError:
        raise ErrorRegistro("respuesta_ilegible") from None


def _esperar_turno(servidor: str) -> None:
    """En serie y con pausa mínima por servidor; se llama con el candado tomado."""
    ultima = _ultima_consulta.get(servidor)
    if ultima is not None and (falta := PAUSA_REGISTRO_SEGUNDOS - (_reloj() - ultima)) > 0:
        _dormir(falta)
    _ultima_consulta[servidor] = _reloj()


def consultar_registro(dominio: str) -> tuple[str, dict[str, Any] | None]:
    """(fuente, datos) del registro; datos=None si no está registrado. Lanza ErrorRegistro."""
    tipo, destino = fuente_para(dominio)
    en_cache = leer_cache_registro(dominio, _ahora(), RUTA_CACHE_DB)
    if en_cache is not None:
        return tipo, en_cache["datos"] if en_cache["existe"] else None
    servidor = destino if tipo == "whois" else urlparse(destino).hostname
    with _candado:
        _esperar_turno(servidor)
        try:
            if tipo == "whois":
                datos = parsear_whois_co(_pedir_whois(destino, dominio))
            else:
                crudo = _pedir_rdap(f"{destino}domain/{dominio}")
                datos = None if crudo is None else parsear_rdap(crudo)
        except OSError:  # socket.timeout, conexión rechazada o cortada, URLError
            raise ErrorRegistro("registro_no_responde") from None
    guardar_cache_registro(dominio, datos is not None, datos or {}, _ahora(), RUTA_CACHE_DB)
    return tipo, datos


SUGERENCIAS = {
    "no_registrado": "El registro dice que el dominio no está registrado; verifique el nombre o entréguelo como "
                     "limitación.",
    "tld_no_soportado": "No hay fuente de registro para este TLD; declárelo como limitación.",
    "registro_no_responde": "El servicio de registro no respondió; declárelo como limitación (no reintente).",
    "respuesta_ilegible": "La respuesta del registro no trae fechas legibles (puede ser un límite de consultas); "
                          "declárelo como limitación.",
}


@registrar(
    "whois_dominio",
    "Consulta el registro público del dominio: fecha de creación y de vencimiento, servidores de nombre y si "
    "tiene bloqueo de transferencia. Sirve para saber si el dominio puede vencerse o ser transferido sin permiso.",
    EntradaDominio,
)
def whois_dominio(entrada: EntradaDominio) -> ResultadoHerramienta:
    d = dominio_registrable(entrada.dominio)

    def fallo(codigo: str) -> ResultadoHerramienta:
        return ResultadoHerramienta(ok=False, herramienta="whois_dominio", error=codigo,
                                    sugerencia=SUGERENCIAS[codigo])

    try:
        fuente, datos = consultar_registro(d)
    except ErrorRegistro as e:
        return fallo(e.codigo)
    if datos is None:
        return fallo("no_registrado")
    vence = datetime.fromisoformat(datos["vence"])
    return ResultadoHerramienta(
        ok=True,
        herramienta="whois_dominio",
        datos={
            "dominio": d,
            "fuente": fuente,
            "creado": datos["creado"],
            "vence": datos["vence"],
            "dias_para_vencer": (vence.date() - _ahora().date()).days,
            "estados": datos["estados"],
            "bloqueo_transferencia": any(b in datos["estados"] for b in BLOQUEOS),
            "servidores_nombre": datos["servidores_nombre"],
        },
        contenido_no_confiable={"registrador": datos["registrador"]},
    )
