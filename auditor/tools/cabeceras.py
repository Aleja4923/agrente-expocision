"""Herramientas `cabeceras_web` y `security_txt`: lo que la portada del sitio declara sobre su seguridad.

Solo se pide la portada (y /.well-known/security.txt) con GET, a través de peticiones.pedir, que
aplica anti-SSRF, User-Agent honesto, tope de bytes y redirecciones solo dentro del dominio.
Los lectores (analizar_cabeceras, analizar_security_txt) son funciones puras; los valores crudos
de las cabeceras los escribe el servidor, así que solo salen como contenido no confiable.
"""

import re
from datetime import datetime, timezone
from urllib.parse import urljoin

from auditor.modelos import ResultadoHerramienta
from auditor.tools import peticiones
from auditor.tools.base import dominio_registrable, registrar
from auditor.tools.correo import EntradaDominio
from auditor.tools.peticiones import CODIGOS_REDIRECCION, ErrorHTTP
from auditor.tools.web import EntradaHost

CRUDAS = ("server", "x-powered-by", "strict-transport-security", "content-security-policy", "x-frame-options")
_VERSION = re.compile(r"\d+\.\d+")

_ahora = lambda: datetime.now(timezone.utc)  # noqa: E731  (inyectable en pruebas)


def _primer_valor(valor: str) -> str:
    """Una cabecera repetida (por ejemplo, la app y el proxy la mandan) llega unida: 'nosniff, nosniff'."""
    return valor.split(",")[0].strip()


def analizar_cabeceras(c: dict[str, str]) -> dict:
    """Qué protecciones declara una respuesta HTTP (cabeceras con nombre en minúsculas)."""
    hsts = c.get("strict-transport-security", "")
    max_age = None
    if m := re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.IGNORECASE):
        max_age = int(m.group(1))
    csp = c.get("content-security-policy", "")
    return {
        "hsts": {"presente": bool(hsts), "max_age": max_age,
                 "include_subdomains": "includesubdomains" in hsts.lower()},
        "x_frame_options": _primer_valor(c.get("x-frame-options", "")).upper() in ("DENY", "SAMEORIGIN"),
        "frame_ancestors": "frame-ancestors" in csp.lower(),
        "nosniff": _primer_valor(c.get("x-content-type-options", "")).lower() == "nosniff",
        "csp_presente": bool(csp),
        "referrer_policy": bool(c.get("referrer-policy")),
        "servidor_con_version": bool(_VERSION.search(c.get("server", "") + " " + c.get("x-powered-by", ""))),
    }


def analizar_security_txt(cuerpo: bytes, tipo: str, ahora: datetime) -> dict:
    """RFC 9116: existe si es texto (no una página HTML) con campos; Contact es obligatorio."""
    texto = cuerpo.decode("utf-8", errors="replace")
    campos: dict[str, str] = {}
    for linea in texto.splitlines():
        clave, sep, valor = linea.partition(":")
        if sep and not linea.lstrip().startswith("#"):
            campos.setdefault(clave.strip().lower(), valor.strip())
    if "html" in tipo.lower() or not campos.keys() & {"contact", "expires"}:
        return {"existe": False, "tiene_contact": False, "expires": None, "vencido": False}
    expira = None
    try:
        expira = datetime.fromisoformat(campos["expires"])
        expira = expira if expira.tzinfo else expira.replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        pass
    return {"existe": True, "tiene_contact": "contact" in campos,
            "expires": expira.isoformat() if expira else None, "vencido": bool(expira and expira < ahora)}


SUGERENCIAS = {
    "certificado_invalido": "El certificado HTTPS no es válido; tls_certificado lo reporta. No reintentes.",
    "tls_fallido": "El servidor no completó la conexión segura; tls_certificado da el detalle.",
    "sin_conexion": "El sitio no acepta conexiones; si no hay sitio web, declárelo como limitación.",
    "tiempo_agotado": "El sitio no respondió a tiempo; puedes reintentar una vez.",
    "ip_bloqueada": "El sitio apunta a una red privada o especial; no se revisa por seguridad.",
    "dominio_no_existe": "Ese host no existe en DNS.",
    "sin_direccion_web": "El nombre existe pero no tiene dirección web: no hay sitio en ese host.",
    "demasiadas_redirecciones": "El sitio redirige más de 3 veces; declárelo como limitación.",
    "respuesta_invalida": "El sitio respondió algo que no es HTTP válido; declárelo como limitación.",
    "fuera_de_alcance": "Solo se revisan el dominio objetivo y sus subdominios.",
}


def _fallo(herramienta: str, codigo: str) -> ResultadoHerramienta:
    return ResultadoHerramienta(ok=False, herramienta=herramienta, error=codigo,
                                sugerencia=SUGERENCIAS.get(codigo, "Declárelo como limitación."))


@registrar(
    "cabeceras_web",
    "Pide la portada de un host (solo GET, sin formularios) y revisa sus cabeceras de seguridad: si http:// "
    "redirige a https://, HSTS, protección contra marcos, nosniff y si expone la versión del servidor. Úsala con "
    "el dominio objetivo y, si quieres, con subdominios elegidos (gastan el mismo cupo que tls_certificado).",
    EntradaHost,
    campo_dominio="host",
)
def cabeceras_web(entrada: EntradaHost) -> ResultadoHerramienta:
    host = entrada.host
    registrable = dominio_registrable(host)
    try:
        # Se sigue la cadena (en alcance): muchos sitios van de http://d a http://www.d y luego a https.
        r_http = peticiones.pedir(f"http://{host}/", registrable)
        saltos = [*r_http.redirecciones, r_http.url]
        if r_http.fuera_de_alcance and r_http.codigo in CODIGOS_REDIRECCION:
            saltos.append(urljoin(r_http.url, r_http.cabeceras.get("location", "")))
        http_responde = True
        redirige = any(u.startswith("https://") for u in saltos)
    except ErrorHTTP:  # sin puerto 80: no hay contenido sin cifrar que proteger
        http_responde, redirige = False, None
    try:
        r = peticiones.pedir(f"https://{host}/", registrable)
    except ErrorHTTP as e:
        return _fallo("cabeceras_web", e.codigo)
    evaluable = r.fuera_de_alcance is None and 200 <= r.codigo < 400
    return ResultadoHerramienta(
        ok=True, herramienta="cabeceras_web",
        datos={"host": host, "http_responde": http_responde, "redirige_a_https": redirige,
               "codigo_final": r.codigo, "url_final": r.url, "redirecciones": len(r.redirecciones),
               "redirige_fuera": r.fuera_de_alcance, "evaluable": evaluable, **analizar_cabeceras(r.cabeceras)},
        contenido_no_confiable={k: r.cabeceras[k] for k in CRUDAS if k in r.cabeceras})


@registrar(
    "security_txt",
    "Busca el archivo /.well-known/security.txt (RFC 9116), donde un sitio publica a quién avisar si alguien "
    "encuentra un problema de seguridad. Un solo GET al dominio objetivo.",
    EntradaDominio,
)
def security_txt(entrada: EntradaDominio) -> ResultadoHerramienta:
    dominio = entrada.dominio
    try:
        r = peticiones.pedir(f"https://{dominio}/.well-known/security.txt", dominio_registrable(dominio))
    except ErrorHTTP as e:
        return _fallo("security_txt", e.codigo)
    no_confiable = {}
    if r.codigo == 200:
        datos = analizar_security_txt(r.cuerpo, r.cabeceras.get("content-type", ""), _ahora())
        no_confiable = {"security_txt": r.cuerpo.decode("utf-8", errors="replace")}
    elif r.codigo in (404, 410):
        datos = {"existe": False, "tiene_contact": False, "expires": None, "vencido": False}
    else:
        # Una redirección a otro dominio (RFC 9116 la permite), un 403 o un error del servidor no prueban
        # que no exista: queda como no verificable (existe=None), nunca como hallazgo.
        datos = {"existe": None, "tiene_contact": False, "expires": None, "vencido": False}
    return ResultadoHerramienta(ok=True, herramienta="security_txt",
                                datos={"dominio": dominio, "codigo": r.codigo, "redirige_fuera": r.fuera_de_alcance,
                                       **datos},
                                contenido_no_confiable=no_confiable)
