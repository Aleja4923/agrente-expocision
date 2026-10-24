"""Herramienta `subdominios_ct`: subdominios que aparecen en Certificate Transparency.

CT es el registro público de todos los certificados HTTPS emitidos. Se consulta crt.sh
("best effort": es lento y falla a menudo, CONTEXT §6b) con un reintento, y Cert Spotter
como respaldo (plan gratuito: 10 consultas por hora, verificado el 2026-10-24).
No produce hallazgos: entrega candidatos para que Grok elija cuáles revisar, dentro del cupo.
"""

import json
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import quote

from auditor.config import (CT_ESPERA_REINTENTO, CT_TIMEOUT_CERTSPOTTER, CT_TIMEOUT_CRTSH,
                            MAX_SUBDOMINIOS_MOSTRADOS, USER_AGENT)
from auditor.modelos import ResultadoHerramienta
from auditor.tools.base import DominioInvalido, dominio_registrable, en_alcance, normalizar_dominio, registrar
from auditor.tools.correo import EntradaDominio

MAX_BYTES_CT = 50_000_000  # un banco grande devuelve miles de certificados en crt.sh

# Puntos de inyección para las pruebas.
_dormir = time.sleep
_hoy = lambda: datetime.now(timezone.utc).date()  # noqa: E731

Entrada = tuple[list[str], str]  # (nombres del certificado, fecha de vencimiento)


class ErrorCT(Exception):
    """Fallo con código corto: ct_no_responde, limite_de_consultas o respuesta_ilegible."""

    def __init__(self, codigo: str):
        self.codigo = codigo
        super().__init__(codigo)


def _pedir_json(url: str, timeout: float) -> Any:
    pedido = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(pedido, timeout=timeout) as r:
            return json.loads(r.read(MAX_BYTES_CT).decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        raise ErrorCT("limite_de_consultas" if e.code == 429 else "ct_no_responde") from None
    except ValueError:
        raise ErrorCT("respuesta_ilegible") from None
    except OSError:  # tiempo agotado, conexión rechazada, URLError
        raise ErrorCT("ct_no_responde") from None


def _como_lista(dato: Any) -> list[dict[str, Any]]:
    if not isinstance(dato, list) or not all(isinstance(e, dict) for e in dato):
        raise ErrorCT("respuesta_ilegible")
    return dato


def _consultar_crtsh(dominio: str) -> list[Entrada]:
    url = f"https://crt.sh/?q={quote('%.' + dominio)}&output=json"
    try:
        dato = _pedir_json(url, CT_TIMEOUT_CRTSH)
    except ErrorCT as e:
        if e.codigo != "ct_no_responde":
            raise
        _dormir(CT_ESPERA_REINTENTO)  # un solo reintento: crt.sh falla a menudo pero se recupera
        dato = _pedir_json(url, CT_TIMEOUT_CRTSH)
    return [(str(e.get("name_value", "")).split("\n"), str(e.get("not_after", ""))) for e in _como_lista(dato)]


def _consultar_certspotter(dominio: str) -> list[Entrada]:
    url = (f"https://api.certspotter.com/v1/issuances?domain={quote(dominio)}"
           "&include_subdomains=true&expand=dns_names")
    dato = _como_lista(_pedir_json(url, CT_TIMEOUT_CERTSPOTTER))  # solo la primera página (100)
    return [(list(e.get("dns_names") or []), str(e.get("not_after", ""))) for e in dato]


def _fecha(texto: str) -> date | None:
    try:
        return datetime.fromisoformat(texto.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def procesar(entradas: list[Entrada], registrable: str, hoy: date) -> list[dict[str, Any]]:
    """Subdominios únicos y en alcance, con el vencimiento más reciente.

    Orden para mostrarle a Grok (no es una conclusión): vigentes primero, luego los menos profundos
    (pagos.x antes que a.b.c.x) y luego alfabético, para que el tope no deje fuera los importantes.
    """
    vence: dict[str, date | None] = {}
    for nombres, not_after in entradas:
        fecha = _fecha(not_after)
        for crudo in nombres:
            try:
                nombre = normalizar_dominio(crudo.strip().removeprefix("*."))
            except DominioInvalido:
                continue  # correos, comodines raros u otra basura del certificado
            if nombre == registrable or not en_alcance(nombre, registrable):
                continue
            anterior = vence.get(nombre)
            if nombre not in vence or (fecha and (anterior is None or fecha > anterior)):
                vence[nombre] = fecha
    subdominios = [{"nombre": n, "ultimo_certificado_vence": f.isoformat() if f else None,
                    "vigente": bool(f and f >= hoy)} for n, f in vence.items()]
    return sorted(subdominios, key=lambda s: (not s["vigente"], s["nombre"].count("."), s["nombre"]))


SUGERENCIAS = {
    "ct_no_responde": "Los registros de certificados no respondieron; declárelo como limitación (no reintente).",
    "limite_de_consultas": "Se alcanzó el límite de consultas de los registros de certificados; declárelo como "
                           "limitación.",
    "respuesta_ilegible": "La respuesta de los registros de certificados no se pudo leer; declárelo como limitación.",
}


@registrar(
    "subdominios_ct",
    "Lista los subdominios que aparecen en los registros públicos de certificados HTTPS (Certificate "
    "Transparency). No visita ningún sitio. Úsala para elegir qué subdominios revisar (por ejemplo pagos, "
    "webmail o admin); tienes un cupo limitado de subdominios por auditoría.",
    EntradaDominio,
)
def subdominios_ct(entrada: EntradaDominio) -> ResultadoHerramienta:
    registrable = dominio_registrable(entrada.dominio)
    try:
        fuente, entradas = "crtsh", _consultar_crtsh(registrable)
    except ErrorCT:
        try:
            fuente, entradas = "certspotter", _consultar_certspotter(registrable)
        except ErrorCT as e:
            return ResultadoHerramienta(ok=False, herramienta="subdominios_ct", error=e.codigo,
                                        sugerencia=SUGERENCIAS[e.codigo])
    subdominios = procesar(entradas, registrable, _hoy())
    mostrados = subdominios[:MAX_SUBDOMINIOS_MOSTRADOS]
    return ResultadoHerramienta(ok=True, herramienta="subdominios_ct", datos={
        "dominio": registrable, "fuente": fuente, "total": len(subdominios), "mostrados": len(mostrados),
        "truncados": len(subdominios) > len(mostrados), "subdominios": mostrados})
