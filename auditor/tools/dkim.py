"""Herramienta `dkim_selector`: busca la clave DKIM (la firma digital del correo) por selector.

El DNS no permite listar los selectores: hay que probar nombres. Grok elige cuáles según el
proveedor de correo que encontró dns_correo (Google usa `google`; Microsoft 365, `selector1` y
`selector2` como CNAME hacia *.onmicrosoft.com o *.dkim.mail.microsoft, verificado en la
documentación de Microsoft el 2026-10-24). El lector `analizar_dkim` es una función pura.
"""

import base64
import binascii

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pydantic import BaseModel, Field, field_validator

from auditor.modelos import ResultadoHerramienta
from auditor.tools import correo
from auditor.tools.base import registrar
from auditor.tools.correo import SUGERENCIAS, ErrorDNS

DESTINOS_MICROSOFT = (".onmicrosoft.com", ".dkim.mail.microsoft")


def analizar_dkim(txt: str) -> dict:
    """{valido, revocada, tipo_clave, bits} de un registro DKIM (RFC 6376 §3.6.1)."""
    etiquetas = {}
    for parte in txt.split(";"):
        clave, sep, valor = parte.partition("=")
        if sep:
            etiquetas[clave.strip().lower()] = valor.strip()
    vacio = {"valido": False, "revocada": False, "tipo_clave": None, "bits": None}
    if "p" not in etiquetas or etiquetas.get("v", "DKIM1") != "DKIM1":
        return vacio
    tipo = etiquetas.get("k", "rsa").lower()
    p = "".join(etiquetas["p"].split())
    if not p:
        return {**vacio, "revocada": True, "tipo_clave": tipo}
    try:
        crudo = base64.b64decode(p, validate=True)
        if tipo == "ed25519":
            bits = 256 if len(crudo) == 32 else None
        else:
            clave = load_der_public_key(crudo)
            bits = clave.key_size if isinstance(clave, rsa.RSAPublicKey) else None
    except (binascii.Error, ValueError, TypeError):
        bits = None
    return {"valido": bits is not None, "revocada": False, "tipo_clave": tipo, "bits": bits}


def destino_microsoft(destino: str) -> bool:
    return destino.lower().rstrip(".").endswith(DESTINOS_MICROSOFT)


class EntradaDKIM(BaseModel):
    dominio: str = Field(description="Dominio objetivo, ej. ejemplo.com.co")
    selectores: list[str] = Field(
        min_length=1, max_length=6,
        description="Selectores a probar, según el proveedor: 'google' para Google Workspace; 'selector1' y "
                    "'selector2' para Microsoft 365; para otros, comunes como default, k1, s1, s2, mail, dkim.")

    @field_validator("selectores")
    @classmethod
    def _validos(cls, v: list[str]) -> list[str]:
        limpios = [s.strip().lower() for s in v]
        malos = [s for s in limpios if not s or len(s) > 63 or not all(c.isalnum() or c == "-" for c in s)
                 or not s.isascii()]
        if malos:
            raise ValueError(f"selectores no válidos (solo letras, números y guiones): {malos}")
        return limpios


def _revisar(dominio: str, selector: str) -> tuple[dict, list[str]]:
    """Datos de un selector y sus TXT crudos (contenido no confiable)."""
    nombre = f"{selector}._domainkey.{dominio}"
    dns = correo._resolver()
    datos = {"selector": selector, "existe": False, "via_cname": False, "destino_cname": None,
             "destino_microsoft": False, "revocada": False, "tipo_clave": None, "bits": None, "error": None}
    try:
        try:
            destino = dns.cname(nombre)
        except ErrorDNS as e:
            if e.codigo != "dominio_no_existe":
                raise
            destino = None
        try:
            txts = dns.txt(nombre)  # el resolvedor sigue el CNAME por su cuenta
        except ErrorDNS as e:
            if e.codigo != "dominio_no_existe":
                raise
            txts = []
    except ErrorDNS as e:
        return {**datos, "error": e.codigo}, []
    if destino:
        datos.update(via_cname=True, destino_cname=destino, destino_microsoft=destino_microsoft(destino))
    registro = next((t for t in txts if "p=" in t), None)
    if registro is not None:
        d = analizar_dkim(registro)
        datos.update(existe=d["valido"], revocada=d["revocada"], tipo_clave=d["tipo_clave"], bits=d["bits"])
    return datos, txts


@registrar(
    "dkim_selector",
    "Busca la firma DKIM del correo en los selectores que indiques. El DNS no permite listar los selectores: "
    "elígelos según el proveedor que encontró dns_correo (google para Google Workspace; selector1 y selector2 "
    "para Microsoft 365). Devuelve, por selector, si hay clave, su tipo y su tamaño.",
    EntradaDKIM,
)
def dkim_selector(entrada: EntradaDKIM) -> ResultadoHerramienta:
    selectores = list(dict.fromkeys(entrada.selectores))
    revisados = [_revisar(entrada.dominio, s) for s in selectores]
    errores = [d["error"] for d, _ in revisados if d["error"]]
    if len(errores) == len(revisados):
        return ResultadoHerramienta(ok=False, herramienta="dkim_selector", error=errores[0],
                                    sugerencia=SUGERENCIAS[errores[0]])
    return ResultadoHerramienta(
        ok=True, herramienta="dkim_selector",
        datos={"dominio": entrada.dominio, "selectores": [d for d, _ in revisados]},
        contenido_no_confiable={d["selector"]: txts for d, txts in revisados if txts})
