"""Peticiones HTTP seguras para las herramientas web (CONTEXT §7).

- Solo GET y HEAD, con el User-Agent honesto del proyecto, y nunca más de MAX_BYTES_HTTP.
- Anti-SSRF: antes de cada petición (también en cada redirección) se resuelve la IP, se exige
  que sea pública (ip_permitida) y se conecta a ESA IP. Así un DNS que cambie entre la
  validación y la conexión no puede llevarnos a la red interna.
- Pero la petición lleva `Host:` y el saludo TLS lleva SNI con el NOMBRE del sitio: si fuera la
  IP, los sitios en hosting compartido o detrás de Cloudflare responderían con error.
- Máximo 3 redirecciones, y solo dentro del dominio auditado; una redirección hacia fuera se
  reporta, nunca se sigue.
"""

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from auditor.config import HTTP_TIMEOUT_SEGUNDOS, USER_AGENT
from auditor.tools.base import DominioInvalido, en_alcance, ip_permitida, normalizar_dominio
from auditor.tools.web import ErrorConexion, resolver_ip

MAX_BYTES_HTTP = 65536
MAX_REDIRECCIONES = 3
CODIGOS_REDIRECCION = (301, 302, 303, 307, 308)


class ErrorHTTP(Exception):
    """Fallo con código corto: fuera_de_alcance, ip_bloqueada, demasiadas_redirecciones, tiempo_agotado,
    sin_conexion, certificado_invalido, tls_fallido, respuesta_invalida o los de resolver_ip."""

    def __init__(self, codigo: str):
        self.codigo = codigo
        super().__init__(codigo)


@dataclass
class Respuesta:
    url: str                      # la última URL pedida
    codigo: int
    cabeceras: dict[str, str]     # nombres en minúsculas
    cuerpo: bytes
    redirecciones: list[str] = field(default_factory=list)
    fuera_de_alcance: str | None = None  # host externo al que redirigió (no se siguió)


class _ConexionHTTP(http.client.HTTPConnection):
    """Conecta a la IP validada; `self.host` (y por tanto la cabecera Host) sigue siendo el nombre."""

    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _ConexionHTTPS(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        crudo = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(crudo, server_hostname=self.host)  # SNI con el nombre


def _enviar(ip: str, host: str, puerto: int, https: bool, metodo: str, ruta: str) -> tuple[int, dict[str, str], bytes]:
    """Una petición, sin seguir redirecciones: (código, cabeceras en minúsculas, cuerpo recortado)."""
    clase = _ConexionHTTPS if https else _ConexionHTTP
    conexion = clase(host, ip, puerto, HTTP_TIMEOUT_SEGUNDOS)
    try:
        conexion.request(metodo, ruta, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        r = conexion.getresponse()
        cabeceras: dict[str, str] = {}
        for nombre, valor in r.getheaders():
            clave = nombre.lower()
            cabeceras[clave] = f"{cabeceras[clave]}, {valor}" if clave in cabeceras else valor
        return r.status, cabeceras, r.read(MAX_BYTES_HTTP) if metodo == "GET" else b""
    finally:
        conexion.close()


def _host_en_alcance(url: str, registrable: str) -> tuple[str, bool]:
    partes = urlsplit(url)
    if partes.scheme not in ("http", "https") or not partes.hostname:
        raise ErrorHTTP("fuera_de_alcance")
    try:
        host = normalizar_dominio(partes.hostname)
    except DominioInvalido:
        raise ErrorHTTP("fuera_de_alcance") from None
    return host, en_alcance(host, registrable)


def pedir(url: str, registrable: str, metodo: str = "GET", seguir: bool = True) -> Respuesta:
    """GET o HEAD a `url` (dentro de `registrable`), siguiendo hasta 3 redirecciones en alcance."""
    if metodo not in ("GET", "HEAD"):
        raise ValueError("solo se permiten GET y HEAD")
    host, dentro = _host_en_alcance(url, registrable)
    if not dentro:
        raise ErrorHTTP("fuera_de_alcance")
    redirecciones: list[str] = []
    while True:
        partes = urlsplit(url)
        try:
            ip = resolver_ip(host)
        except ErrorConexion as e:
            raise ErrorHTTP(e.codigo) from None
        if not ip_permitida(ip):
            raise ErrorHTTP("ip_bloqueada")
        https = partes.scheme == "https"
        ruta = (partes.path or "/") + (f"?{partes.query}" if partes.query else "")
        try:
            codigo, cabeceras, cuerpo = _enviar(ip, host, partes.port or (443 if https else 80), https, metodo, ruta)
        except ssl.SSLCertVerificationError:
            raise ErrorHTTP("certificado_invalido") from None
        except ssl.SSLError:
            raise ErrorHTTP("tls_fallido") from None
        except (TimeoutError, socket.timeout):
            raise ErrorHTTP("tiempo_agotado") from None
        except http.client.HTTPException:
            raise ErrorHTTP("respuesta_invalida") from None
        except OSError:
            raise ErrorHTTP("sin_conexion") from None
        respuesta = Respuesta(url, codigo, cabeceras, cuerpo, list(redirecciones))
        destino = cabeceras.get("location")
        if not (seguir and codigo in CODIGOS_REDIRECCION and destino):
            return respuesta
        siguiente = urljoin(url, destino)
        host_siguiente, dentro = _host_en_alcance(siguiente, registrable)
        if not dentro:
            respuesta.fuera_de_alcance = host_siguiente
            return respuesta
        if len(redirecciones) >= MAX_REDIRECCIONES:
            raise ErrorHTTP("demasiadas_redirecciones")
        redirecciones.append(siguiente)
        url, host = siguiente, host_siguiente
