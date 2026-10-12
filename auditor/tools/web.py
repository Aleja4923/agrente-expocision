"""Herramienta `tls_certificado`: validez del certificado HTTPS de un host.

Solo se hace el saludo TLS al puerto 443, sin pedir ninguna página. Un certificado
inválido es un resultado (lo que hay que reportar), no un fallo de la herramienta.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, Field

from auditor.config import TLS_TIMEOUT_SEGUNDOS
from auditor.modelos import ResultadoHerramienta
from auditor.tools.base import ip_permitida, registrar

# Códigos de verificación de OpenSSL → motivo en palabras del informe.
_MOTIVOS = {
    10: "vencido",             # X509_V_ERR_CERT_HAS_EXPIRED
    18: "autofirmado",         # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
    19: "autofirmado",         # X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
    20: "cadena_incompleta",   # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    21: "cadena_incompleta",   # X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
    62: "nombre_no_coincide",  # X509_V_ERR_HOSTNAME_MISMATCH
}


def motivo_de_error(codigo_openssl: int) -> str:
    return _MOTIVOS.get(codigo_openssl, "otro")


def _atributo(nombre: x509.Name, oid) -> str | None:
    valores = nombre.get_attributes_for_oid(oid)
    return str(valores[0].value) if valores else None


def datos_de_certificado(der: bytes, ahora: datetime) -> tuple[dict[str, Any], dict[str, Any]]:
    """(datos, no_confiable): vencimiento y días restantes son fechas confiables; emisor, sujeto y
    nombres los escribe quien fabrica el certificado, así que van como contenido no confiable."""
    c = x509.load_der_x509_certificate(der)
    emisor = (_atributo(c.issuer, NameOID.ORGANIZATION_NAME)
              or _atributo(c.issuer, NameOID.COMMON_NAME) or "desconocido")
    vence = c.not_valid_after_utc
    try:
        nombres = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value \
            .get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        nombres = []
    datos = {"vence": vence.date().isoformat(), "dias_restantes": (vence - ahora).days}
    no_confiable = {"emisor": emisor, "sujeto": _atributo(c.subject, NameOID.COMMON_NAME) or "",
                    "nombres": nombres}
    return datos, no_confiable


# --- conexión (lo único de este archivo que toca la red) -----------------------

class ErrorConexion(Exception):
    """Fallo de conexión con código corto: sin_https, tiempo_agotado, tls_fallido o dominio_no_existe."""

    def __init__(self, codigo: str):
        self.codigo = codigo
        super().__init__(codigo)


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


def resolver_ip(host: str) -> str:
    """Primera IP del host. Se revisa con ip_permitida y luego se conecta a ESA misma IP."""
    try:
        return socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror:
        raise ErrorConexion("dominio_no_existe") from None


def _conectar(ip: str, host: str, verificar: bool) -> tuple[bytes, str]:
    """Saludo TLS con la IP ya validada; devuelve (certificado en DER, versión de TLS)."""
    if verificar:
        contexto = ssl.create_default_context()
    else:  # solo para leer un certificado que no pasó la verificación
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        try:
            contexto.minimum_version = ssl.TLSVersion.TLSv1
            contexto.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            pass
    try:
        with socket.create_connection((ip, 443), timeout=TLS_TIMEOUT_SEGUNDOS) as conexion:
            with contexto.wrap_socket(conexion, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), tls.version()
    except ssl.SSLCertVerificationError:
        raise
    except ssl.SSLError:
        raise ErrorConexion("tls_fallido") from None
    except TimeoutError:
        raise ErrorConexion("tiempo_agotado") from None
    except OSError:
        raise ErrorConexion("sin_https") from None


SUGERENCIAS = {
    "sin_https": "El host no acepta conexiones HTTPS en el puerto 443; repórtalo, no reintentes.",
    "tiempo_agotado": "No respondió a tiempo; puedes reintentar una vez.",
    "ip_bloqueada": "El host apunta a una red privada o especial; no se revisa por seguridad.",
    "dominio_no_existe": "Ese host no existe en DNS.",
    "tls_fallido": "El servidor no completó la conexión segura; puede usar una versión de TLS muy antigua.",
}


class EntradaHost(BaseModel):
    host: str = Field(description="El dominio objetivo o un subdominio, ej. ejemplo.com.co o pagos.ejemplo.com.co")


@registrar(
    "tls_certificado",
    "Revisa el certificado HTTPS de un host: si es válido, cuándo vence y qué versión de TLS usa. "
    "Úsala con el dominio y con subdominios sensibles (pagos, webmail, admin).",
    EntradaHost,
    campo_dominio="host",
)
def tls_certificado(entrada: EntradaHost) -> ResultadoHerramienta:
    host = entrada.host

    def fallo(codigo: str) -> ResultadoHerramienta:
        return ResultadoHerramienta(ok=False, herramienta="tls_certificado", error=codigo,
                                    sugerencia=SUGERENCIAS[codigo])

    try:
        ip = resolver_ip(host)
        if not ip_permitida(ip):
            return fallo("ip_bloqueada")
        try:
            der, version = _conectar(ip, host, verificar=True)
            valido, motivo = True, None
        except ssl.SSLCertVerificationError as e:
            valido, motivo = False, motivo_de_error(e.verify_code)
            der, version = _conectar(ip, host, verificar=False)
    except ErrorConexion as e:
        return fallo(e.codigo)

    datos, no_confiable = datos_de_certificado(der, _ahora())
    return ResultadoHerramienta(
        ok=True,
        herramienta="tls_certificado",
        datos={"valido": valido, "motivo": motivo, **datos, "version_tls": version, "ip": ip},
        contenido_no_confiable=no_confiable,
    )
