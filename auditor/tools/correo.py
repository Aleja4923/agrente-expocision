"""Herramienta `dns_correo`: MX y proveedor, SPF y DMARC de un dominio.

Los lectores (analizar_spf, analizar_dmarc, inferir_proveedor) son funciones puras:
reciben texto y devuelven datos, así se prueban sin red. Solo reportan lo que hay;
qué es un hallazgo y con qué severidad lo decide scoring.py (CONTEXT.md §6b).
"""

from typing import Any, Callable

import dns.exception
import dns.resolver
from pydantic import BaseModel, Field

from auditor.config import DNS_TIMEOUT_SEGUNDOS
from auditor.modelos import ResultadoHerramienta
from auditor.tools.base import registrar

MAX_CONSULTAS_SPF = 10   # RFC 7208 §4.6.4
MAX_CONSULTAS_VACIAS = 2  # RFC 7208 §4.6.4 (void lookups)
TOPE_CONTEO_SPF = 30      # se sigue contando pasado el límite para dar la cifra exacta como evidencia
POLITICAS_DMARC = {"none", "quarantine", "reject"}


def inferir_proveedor(mx_hosts: list[str]) -> str:
    """google, microsoft, otro o ninguno, según los servidores MX."""
    hosts = [h.lower().rstrip(".") for h in mx_hosts]
    if not hosts:
        return "ninguno"
    for h in hosts:
        if h in ("smtp.google.com", "aspmx.l.google.com") or h.endswith((".aspmx.l.google.com", "googlemail.com")):
            return "google"
        if h.endswith(".mail.protection.outlook.com"):
            return "microsoft"
    return "otro"


def _es_spf(txt: str) -> bool:
    t = txt.strip().lower()
    return t == "v=spf1" or t.startswith("v=spf1 ")


def spf_autoriza_envio(txts: list[str]) -> bool:
    """True si el primer SPF autoriza algún servidor (algo más que el cierre 'all', con cualquier calificador)."""
    registro = next((t for t in txts if _es_spf(t)), None)
    return registro is not None and any(
        t.lstrip("+-~?").lower() != "all" for t in registro.split()[1:])


def analizar_spf(txts: list[str], consultar_txt: Callable[[str], list[str]]) -> dict[str, Any]:
    """Registros SPF, cierre y consultas DNS contadas de forma recursiva (include y redirect)."""
    registros = [t.strip() for t in txts if _es_spf(t)]
    r: dict[str, Any] = {"registros": registros, "cantidad": len(registros), "cierre": "ninguno",
                         "consultas_dns": 0, "consultas_vacias": 0, "consultas_con_error": 0,
                         "permerror": False, "detalle": None}
    if len(registros) != 1:
        if registros:
            r["permerror"], r["detalle"] = True, "hay más de un registro SPF"
        return r

    for termino in registros[0].split()[1:]:
        t = termino.lower()
        if t.startswith("redirect="):
            r["cierre"] = "redirect"
        elif t.lstrip("+-~?") == "all":
            r["cierre"] = (t[0] if t[0] in "+-~?" else "+") + "all"

    visitados: set[str] = set()

    def contar(registro: str) -> None:
        for termino in registro.split()[1:]:
            if r["consultas_dns"] >= TOPE_CONTEO_SPF:
                return
            t = termino.lower()
            destino = None
            if t.startswith("redirect="):
                destino = t.split("=", 1)[1]
            else:
                mecanismo = t.lstrip("+-~?")
                nombre = mecanismo.split(":", 1)[0].split("/", 1)[0]
                if nombre in ("a", "mx", "ptr", "exists"):
                    r["consultas_dns"] += 1
                if nombre == "include" and ":" in mecanismo:
                    destino = mecanismo.split(":", 1)[1]
            if destino is None:
                continue
            r["consultas_dns"] += 1
            if destino in visitados:
                continue
            visitados.add(destino)
            try:
                spf_destino = [x for x in consultar_txt(destino) if _es_spf(x)]
            except ErrorDNS:
                # Tiempo agotado o servidor que no responde: no es una consulta "vacía" del RFC,
                # es algo que no se pudo verificar. No debe producir un permerror falso.
                r["consultas_con_error"] += 1
                continue
            if spf_destino:
                contar(spf_destino[0])
            else:
                r["consultas_vacias"] += 1

    contar(registros[0])
    if r["consultas_dns"] > MAX_CONSULTAS_SPF:
        r["permerror"], r["detalle"] = True, f"más de {MAX_CONSULTAS_SPF} consultas DNS"
    elif r["consultas_vacias"] > MAX_CONSULTAS_VACIAS:
        r["permerror"], r["detalle"] = True, f"más de {MAX_CONSULTAS_VACIAS} consultas sin respuesta"
    elif r["consultas_con_error"]:
        r["detalle"] = (f"no se pudo verificar todo el SPF: {r['consultas_con_error']} consultas sin respuesta "
                        "del DNS a tiempo")
    return r


def _etiquetas_dmarc(registro: str) -> dict[str, str]:
    etiquetas = {}
    for parte in registro.split(";"):
        if "=" in parte:
            clave, valor = parte.split("=", 1)
            etiquetas[clave.strip().lower()] = valor.strip()
    return etiquetas


def analizar_dmarc(txts: list[str]) -> dict[str, Any]:
    """Etiquetas DMARC según RFC 9989 (p, sp, np, t, psd, rua) y las obsoletas como nota."""
    registros = [t.strip() for t in txts if t.strip().lower().startswith("v=dmarc1")]
    r: dict[str, Any] = {"existe": bool(registros), "valido": False, "multiple": len(registros) > 1,
                         "p": None, "p_ausente": False, "sp": None, "np": None, "t": None, "psd": None,
                         "rua": [], "pct": None, "etiquetas_obsoletas": [], "politica_mas_estricta": None}
    if len(registros) > 1:
        # Con varios registros nada se aplica, pero hay que saber qué política ya tenía la
        # empresa: la recomendación nunca debe proponer una más débil.
        politicas = {_etiquetas_dmarc(x).get("p", "").lower() for x in registros} & POLITICAS_DMARC
        orden = ["none", "quarantine", "reject"]
        r["politica_mas_estricta"] = max(politicas, key=orden.index) if politicas else None
    if len(registros) != 1:
        return r
    etiquetas = _etiquetas_dmarc(registros[0])
    p = etiquetas.get("p", "").lower()
    if not p:
        p, r["p_ausente"] = "none", True
    r["p"] = p
    for clave in ("sp", "np", "t", "psd"):
        if clave in etiquetas:
            r[clave] = etiquetas[clave].lower()
    r["rua"] = [d.strip() for d in etiquetas.get("rua", "").split(",") if d.strip()]
    try:
        r["pct"] = int(etiquetas["pct"]) if "pct" in etiquetas else None
    except ValueError:
        r["pct"] = None
    r["etiquetas_obsoletas"] = [k for k in ("pct", "rf", "ri") if k in etiquetas]
    r["valido"] = p in POLITICAS_DMARC
    return r


# --- consulta DNS (lo único de este archivo que toca la red) --------------------

class ErrorDNS(Exception):
    """Fallo de DNS con código corto: dominio_no_existe, sin_respuesta o tiempo_agotado."""

    def __init__(self, codigo: str):
        self.codigo = codigo
        super().__init__(codigo)


def _unir_fragmentos(fragmentos: tuple[bytes, ...]) -> str:
    """Un TXT largo llega partido en trozos de hasta 255 bytes: se une antes de leerlo."""
    return b"".join(fragmentos).decode("utf-8", errors="replace")


class ResolverDNS:
    """Consultas TXT y MX con tiempo límite; los errores salen como ErrorDNS con nombre."""

    def __init__(self):
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = DNS_TIMEOUT_SEGUNDOS

    def _consultar(self, nombre: str, tipo: str):
        try:
            return self._resolver.resolve(nombre, tipo)
        except dns.resolver.NXDOMAIN:
            raise ErrorDNS("dominio_no_existe") from None
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NoNameservers:
            raise ErrorDNS("sin_respuesta") from None
        except dns.exception.Timeout:
            raise ErrorDNS("tiempo_agotado") from None

    def txt(self, nombre: str) -> list[str]:
        return [_unir_fragmentos(r.strings) for r in self._consultar(nombre, "TXT")]

    def mx(self, nombre: str) -> list[tuple[int, str]]:
        return [(r.preference, str(r.exchange).rstrip(".")) for r in self._consultar(nombre, "MX")]

    def ns(self, nombre: str) -> list[str]:
        return [str(r.target).rstrip(".").lower() for r in self._consultar(nombre, "NS")]

    def cname(self, nombre: str) -> str | None:
        """Destino del CNAME, o None si el nombre no es un alias."""
        respuesta = self._consultar(nombre, "CNAME")
        return str(respuesta[0].target).rstrip(".").lower() if respuesta else None


resolver: ResolverDNS | None = None  # se crea al primer uso: si falla, no tumba la importación de las herramientas


def _resolver() -> ResolverDNS:
    global resolver
    if resolver is None:
        resolver = ResolverDNS()
    return resolver

SUGERENCIAS = {
    "dominio_no_existe": "Verifique que el dominio esté bien escrito; si no existe, no hay más que revisar: "
                         "entregue el informe indicándolo.",
    "tiempo_agotado": "El DNS no respondió a tiempo; puede reintentar una vez o declararlo como limitación.",
    "sin_respuesta": "Los servidores DNS del dominio no responden; declárelo como limitación.",
}


class EntradaDominio(BaseModel):
    dominio: str = Field(description="Dominio a revisar: el objetivo o uno de sus subdominios, ej. ejemplo.com.co")


@registrar(
    "dns_correo",
    "Revisa la configuración de correo del dominio: servidores MX y proveedor, SPF y DMARC. "
    "Úsala primero: es la base para evaluar la suplantación de correo.",
    EntradaDominio,
)
def dns_correo(entrada: EntradaDominio) -> ResultadoHerramienta:
    d = entrada.dominio

    dns = _resolver()

    def txt_para_spf(nombre: str) -> list[str]:
        """Para la recursión del SPF: un nombre inexistente es una consulta vacía (RFC 7208);
        un tiempo agotado se propaga para contarlo como 'no verificable', no como vacía."""
        try:
            return dns.txt(nombre)
        except ErrorDNS as e:
            if e.codigo == "dominio_no_existe":
                return []
            raise

    try:
        mx = dns.mx(d)
        txt = dns.txt(d)
        try:
            txt_dmarc = dns.txt(f"_dmarc.{d}")
        except ErrorDNS as e:
            if e.codigo != "dominio_no_existe":  # sin _dmarc = no hay DMARC, no es un error
                raise
            txt_dmarc = []
    except ErrorDNS as e:
        return ResultadoHerramienta(ok=False, herramienta="dns_correo", error=e.codigo,
                                    sugerencia=SUGERENCIAS[e.codigo])

    servidores = [{"prioridad": p, "host": h} for p, h in sorted(mx)]
    return ResultadoHerramienta(
        ok=True,
        herramienta="dns_correo",
        datos={
            "dominio": d,
            "mx": {"servidores": servidores, "proveedor": inferir_proveedor([s["host"] for s in servidores])},
            "spf": analizar_spf(txt, txt_para_spf),
            "dmarc": analizar_dmarc(txt_dmarc),
        },
        contenido_no_confiable={"txt_dominio": txt, "txt_dmarc": txt_dmarc},
    )
