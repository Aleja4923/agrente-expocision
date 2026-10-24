"""tools/dkim.py: firma DKIM por selector (TXT directo o CNAME de Microsoft 365), sin red."""

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from auditor.tools import base, correo
from auditor.tools.correo import ErrorDNS
from auditor.tools.dkim import analizar_dkim, destino_microsoft

D = "ejemplo.com.co"


def clave_rsa(bits: int) -> str:
    publica = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    der = publica.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


@pytest.fixture(scope="module")
def rsa2048():
    return clave_rsa(2048)


@pytest.fixture(scope="module")
def rsa1024():
    return clave_rsa(1024)


# --- lector (función pura) -------------------------------------------------------------

def test_analizar_rsa_2048(rsa2048):
    assert analizar_dkim(f"v=DKIM1; k=rsa; p={rsa2048}") == {"valido": True, "revocada": False,
                                                            "tipo_clave": "rsa", "bits": 2048}


def test_analizar_rsa_1024_sin_k(rsa1024):
    assert analizar_dkim(f"v=DKIM1; p={rsa1024}")["bits"] == 1024  # k por defecto es rsa (RFC 6376)


def test_analizar_revocada():
    assert analizar_dkim("v=DKIM1; k=rsa; p=") == {"valido": False, "revocada": True, "tipo_clave": "rsa",
                                                   "bits": None}


def test_analizar_ed25519():
    publica = ed25519.Ed25519PrivateKey.generate().public_key()
    crudo = publica.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    d = analizar_dkim(f"v=DKIM1; k=ed25519; p={base64.b64encode(crudo).decode()}")
    assert (d["valido"], d["tipo_clave"], d["bits"]) == (True, "ed25519", 256)


@pytest.mark.parametrize("txt", ["v=spf1 -all", "v=DKIM1; k=rsa; p=@@no-es-base64@@", "texto suelto"])
def test_analizar_no_dkim_o_ilegible(txt):
    d = analizar_dkim(txt)
    assert d["valido"] is False and d["revocada"] is False


def test_analizar_espacios_en_p(rsa2048):
    partido = " ".join(rsa2048[i:i + 60] for i in range(0, len(rsa2048), 60))
    assert analizar_dkim(f"v=DKIM1; k=rsa; p={partido}")["bits"] == 2048


@pytest.mark.parametrize("destino,esperado", [
    ("selector1-ejemplo-com-co._domainkey.ejemplo.onmicrosoft.com", True),
    ("selector1-ejemplo-com-co._domainkey.ejemplo.n-v1.dkim.mail.microsoft", True),
    ("selector1._domainkey.otro-proveedor.com", False)])
def test_destino_microsoft(destino, esperado):
    assert destino_microsoft(destino) is esperado


# --- herramienta (DNS falso) -----------------------------------------------------------

class DNSFalso:
    def __init__(self, txt=None, cname=None, errores=None):
        self._txt, self._cname, self._errores = txt or {}, cname or {}, errores or {}

    def txt(self, nombre):
        if ("txt", nombre) in self._errores:
            raise ErrorDNS(self._errores[("txt", nombre)])
        if nombre in self._txt:
            return self._txt[nombre]
        if nombre in self._cname:
            return []  # el CNAME existe pero su destino no publica la clave
        raise ErrorDNS("dominio_no_existe")

    def cname(self, nombre):
        if ("cname", nombre) in self._errores:
            raise ErrorDNS(self._errores[("cname", nombre)])
        return self._cname.get(nombre)


def correr(monkeypatch, dns, selectores, dominio=D):
    monkeypatch.setattr(correo, "resolver", dns)
    return base.ejecutar("dkim_selector", {"dominio": dominio, "selectores": selectores}, D)


def test_google_encontrado(monkeypatch, rsa2048):
    r = correr(monkeypatch, DNSFalso(txt={f"google._domainkey.{D}": [f"v=DKIM1; k=rsa; p={rsa2048}"]}), ["google"])
    assert r.ok
    [s] = r.datos["selectores"]
    assert s == {"selector": "google", "existe": True, "via_cname": False, "destino_cname": None,
                 "destino_microsoft": False, "revocada": False, "tipo_clave": "rsa", "bits": 2048, "error": None}
    assert r.contenido_no_confiable["google"][0].startswith("v=DKIM1")


def test_microsoft_cname_con_clave(monkeypatch, rsa2048):
    nombre = f"selector1._domainkey.{D}"
    destino = "selector1-ejemplo-com-co._domainkey.ejemplo.onmicrosoft.com"
    r = correr(monkeypatch, DNSFalso(cname={nombre: destino}, txt={nombre: [f"v=DKIM1; k=rsa; p={rsa2048}"]}),
               ["selector1", "selector2"])
    s1, s2 = r.datos["selectores"]
    assert (s1["existe"], s1["via_cname"], s1["destino_microsoft"]) == (True, True, True)
    assert (s2["existe"], s2["via_cname"]) == (False, False)


def test_microsoft_cname_sin_clave_no_existe(monkeypatch):
    nombre = f"selector1._domainkey.{D}"
    r = correr(monkeypatch, DNSFalso(cname={nombre: "selector1-x._domainkey.x.onmicrosoft.com"}), ["selector1"])
    [s] = r.datos["selectores"]
    assert (s["existe"], s["via_cname"], s["destino_cname"]) == (False, True, "selector1-x._domainkey.x.onmicrosoft.com")


def test_selector_con_tiempo_agotado(monkeypatch, rsa2048):
    dns = DNSFalso(txt={f"google._domainkey.{D}": [f"v=DKIM1; p={rsa2048}"]},
                   errores={("cname", f"s1._domainkey.{D}"): "tiempo_agotado"})
    r = correr(monkeypatch, dns, ["google", "s1"])
    assert r.ok and r.datos["selectores"][1]["error"] == "tiempo_agotado"


def test_todos_con_tiempo_agotado(monkeypatch):
    dns = DNSFalso(errores={("cname", f"google._domainkey.{D}"): "tiempo_agotado"})
    r = correr(monkeypatch, dns, ["google"])
    assert (r.ok, r.error) == (False, "tiempo_agotado")


@pytest.mark.parametrize("selectores", [[], ["a"] * 7, ["con espacio"], ["../x"], ["a.b"]])
def test_selectores_invalidos(monkeypatch, selectores):
    r = correr(monkeypatch, DNSFalso(), selectores)
    assert r.error == "argumentos_invalidos"


def test_selectores_se_normalizan_y_no_repiten(monkeypatch, rsa2048):
    r = correr(monkeypatch, DNSFalso(txt={f"google._domainkey.{D}": [f"v=DKIM1; p={rsa2048}"]}), ["Google", "google"])
    assert [s["selector"] for s in r.datos["selectores"]] == ["google"]


def test_subdominio_fuera_de_alcance(monkeypatch):
    r = correr(monkeypatch, DNSFalso(), ["google"], dominio="otro.com")
    assert r.error == "fuera_de_alcance"
