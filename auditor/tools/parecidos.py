"""Dominios parecidos: variantes generadas por código y las herramientas que las revisan.

Excepción de alcance (CONTEXT §7): las variantes las genera SIEMPRE este módulo, nunca Grok
ni datos externos; `base.ejecutar` rechaza cualquier parecido que no salga de aquí. A los
parecidos solo se les consulta DNS y el registro público: nunca se visita su sitio web.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from typing import TypedDict

from pydantic import BaseModel, Field

from auditor.config import MAX_VARIANTES
from auditor.modelos import ResultadoHerramienta
from auditor.tools import base, correo, registro
from auditor.tools.base import _ETIQUETA, dominio_registrable, registrar
from auditor.tools.correo import SUGERENCIAS, EntradaDominio, ErrorDNS, spf_autoriza_envio
from auditor.tools.registro import ErrorRegistro

HILOS_DNS = 8  # más hilos saturan el router o el resolvedor y dan falsos tiempos agotados
_ahora = lambda: datetime.now(timezone.utc)  # noqa: E731  (inyectable en pruebas)

FAMILIA_TLD = ("com.co", "co", "com")
# Letras que se confunden a simple vista; una sustitución por variante.
HOMOGLIFOS = (("rn", "m"), ("m", "rn"), ("l", "i"), ("i", "l"), ("l", "1"), ("i", "1"), ("o", "0"),
              ("vv", "w"), ("w", "vv"), ("cl", "d"), ("d", "cl"))


class Variante(TypedDict):
    dominio: str
    tipo: str  # otro_tld, homoglifo, sin_punto, omision, transposicion, duplicacion


def _separar(registrable: str) -> tuple[str, str]:
    """'ejemplo.com.co' -> ('ejemplo', 'com.co')."""
    etiqueta, _, sufijo = registrable.partition(".")
    return etiqueta, sufijo


def _candidatas(etiqueta: str, sufijo: str):
    """(etiqueta, sufijo, tipo) en orden de prioridad; aún sin filtrar."""
    for otro in FAMILIA_TLD:
        if otro != sufijo:
            yield etiqueta, otro, "otro_tld"
    if etiqueta.startswith("xn--"):  # nombres con tildes (punycode): un error de tipeo no tiene sentido
        return
    for original, cambio in HOMOGLIFOS:
        inicio = etiqueta.find(original)
        while inicio != -1:
            yield etiqueta[:inicio] + cambio + etiqueta[inicio + len(original):], sufijo, "homoglifo"
            inicio = etiqueta.find(original, inicio + 1)
    if sufijo == "com.co":
        yield etiqueta + "com", "co", "sin_punto"
    for i in range(len(etiqueta)):
        yield etiqueta[:i] + etiqueta[i + 1:], sufijo, "omision"
    for i in range(len(etiqueta) - 1):
        if etiqueta[i] != etiqueta[i + 1]:
            yield etiqueta[:i] + etiqueta[i + 1] + etiqueta[i] + etiqueta[i + 2:], sufijo, "transposicion"
    for i in range(len(etiqueta)):
        yield etiqueta[:i + 1] + etiqueta[i:], sufijo, "duplicacion"


def generar_variantes(dominio: str) -> tuple[list[Variante], bool]:
    """Variantes del dominio registrable, deterministas y sin repetir; (lista, si se cortó en MAX_VARIANTES)."""
    registrable = dominio_registrable(dominio)
    etiqueta, sufijo = _separar(registrable)
    vistas = {registrable}
    variantes: list[Variante] = []
    for e, s, tipo in _candidatas(etiqueta, sufijo):
        nombre = f"{e}.{s}"
        if nombre in vistas or len(e) < 2 or not _ETIQUETA.match(e):
            continue
        vistas.add(nombre)
        variantes.append({"dominio": nombre, "tipo": tipo})
    return variantes[:MAX_VARIANTES], len(variantes) > MAX_VARIANTES


@lru_cache(maxsize=64)
def _validas(registrable: str) -> frozenset[str]:
    return frozenset(v["dominio"] for v in generar_variantes(registrable)[0])


def variantes_validas(registrable: str) -> set[str]:
    """Los únicos dominios ajenos que una herramienta puede consultar para este objetivo."""
    return set(_validas(registrable))


def tipo_de(registrable: str, parecido: str) -> str | None:
    return next((v["tipo"] for v in generar_variantes(registrable)[0] if v["dominio"] == parecido), None)


base.VALIDADOR_PARECIDOS = variantes_validas


# --- herramientas -----------------------------------------------------------------------

def _hosts_mx(mx: list[tuple[int, str]]) -> list[str]:
    """Servidores MX sin el "MX nulo" (RFC 7505: "0 ." significa que no recibe correo)."""
    return [h.lower() for _, h in sorted(mx) if h.strip(".")]


def comparte_servidores(ns_a: list[str], mx_a: list[str], ns_b: list[str], mx_b: list[str]) -> bool:
    """True si comparten algún servidor de nombre o de correo: indicio de mismo dueño (registro defensivo)."""
    return bool(set(ns_a) & set(ns_b)) or bool(set(mx_a) & set(mx_b))


def _servidores_del_dueno(registrable: str) -> tuple[list[str], list[str]]:
    dns = correo._resolver()
    return dns.ns(registrable), _hosts_mx(dns.mx(registrable))


def _fallo(herramienta: str, e: ErrorDNS) -> ResultadoHerramienta:
    return ResultadoHerramienta(ok=False, herramienta=herramienta, error=e.codigo, sugerencia=SUGERENCIAS[e.codigo])


def _revisar_variante(nombre: str) -> tuple[str, list[str], list[str]]:
    """("existe" | "no_existe" | "sin_verificar", ns, mx). Primero NS; el MX solo si existe."""
    dns = correo._resolver()
    try:
        ns = dns.ns(nombre)
    except ErrorDNS as e:
        return ("no_existe" if e.codigo == "dominio_no_existe" else "sin_verificar"), [], []
    if not ns:
        return "no_existe", [], []
    try:
        return "existe", ns, _hosts_mx(dns.mx(nombre))
    except ErrorDNS as e:
        return ("existe" if e.codigo == "dominio_no_existe" else "sin_verificar"), ns, []


@registrar(
    "buscar_parecidos",
    "Genera variantes del dominio (errores de tipeo, letras parecidas, otro TLD) y revisa por DNS cuáles existen "
    "y tienen correo configurado (MX). No visita ningún sitio. Devuelve la lista de candidatos para que elijas "
    "cuáles investigar con investigar_parecido.",
    EntradaDominio,
)
def buscar_parecidos(entrada: EntradaDominio) -> ResultadoHerramienta:
    registrable = dominio_registrable(entrada.dominio)
    try:
        ns_propios, mx_propios = _servidores_del_dueno(registrable)
    except ErrorDNS as e:
        return _fallo("buscar_parecidos", e)
    variantes, truncadas = generar_variantes(registrable)
    with ThreadPoolExecutor(max_workers=HILOS_DNS) as pool:
        revisadas = list(pool.map(lambda v: _revisar_variante(v["dominio"]), variantes))
    con_correo, sin_verificar, existentes = [], [], 0
    for v, (estado, ns, mx) in zip(variantes, revisadas):
        if estado == "sin_verificar":
            sin_verificar.append(v["dominio"])
            continue
        if estado == "existe":
            existentes += 1
            if mx:
                con_correo.append({"dominio": v["dominio"], "tipo": v["tipo"], "mx": mx,
                                   "comparte_servidores": comparte_servidores(ns, mx, ns_propios, mx_propios)})
    return ResultadoHerramienta(ok=True, herramienta="buscar_parecidos", datos={
        "dominio": registrable, "generadas": len(variantes), "truncadas": truncadas, "existentes": existentes,
        "con_correo": con_correo, "sin_verificar": sin_verificar,
        "ns_propios": ns_propios, "mx_propios": mx_propios})


class EntradaParecido(BaseModel):
    dominio: str = Field(description="El dominio objetivo, ej. ejemplo.com.co")
    parecido: str = Field(description="Una de las variantes que entregó buscar_parecidos")


@registrar(
    "investigar_parecido",
    "Investiga UN dominio parecido de los que entregó buscar_parecidos: fecha de registro, si su SPF autoriza "
    "enviar correo y si comparte servidores con el dominio objetivo (registro defensivo). Solo DNS y registro "
    "público, nunca su sitio web. Tienes un cupo limitado por auditoría: elige los más sospechosos.",
    EntradaParecido,
    campo_parecido="parecido",
)
def investigar_parecido(entrada: EntradaParecido) -> ResultadoHerramienta:
    registrable = dominio_registrable(entrada.dominio)
    parecido = entrada.parecido
    dns = correo._resolver()
    try:
        ns_propios, mx_propios = _servidores_del_dueno(registrable)
        estado, ns, mx = _revisar_variante(parecido)
        if estado == "sin_verificar":
            raise ErrorDNS("tiempo_agotado")
        txt = dns.txt(parecido) if estado == "existe" else []
    except ErrorDNS as e:
        if e.codigo != "dominio_no_existe":
            return _fallo("investigar_parecido", e)
        txt = []
    datos = {"parecido": parecido, "tipo": tipo_de(registrable, parecido), "existe": estado == "existe",
             "tiene_mx": bool(mx), "creado": None, "dias_desde_registro": None,
             "spf_autoriza_envio": spf_autoriza_envio(txt), "comparte_servidores":
             comparte_servidores(ns, mx, ns_propios, mx_propios), "fuente_registro": "ninguna", "aviso": None}
    no_confiable = {}
    if datos["existe"]:
        try:
            fuente, reg = registro.consultar_registro(parecido)
            if reg is None:
                datos["aviso"] = "El registro no lo reporta como registrado, aunque responde en DNS."
            else:
                datos["fuente_registro"], datos["creado"] = fuente, reg["creado"]
                datos["dias_desde_registro"] = (_ahora() - datetime.fromisoformat(reg["creado"])).days
                no_confiable["registrador"] = reg.get("registrador", "")
        except ErrorRegistro as e:
            datos["aviso"] = f"Fecha de registro no disponible ({e.codigo})."
    return ResultadoHerramienta(ok=True, herramienta="investigar_parecido", datos=datos,
                                contenido_no_confiable=no_confiable)
