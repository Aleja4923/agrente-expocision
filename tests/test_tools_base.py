"""tools/base.py: normalización, guarda de alcance, anti-SSRF y ejecución que nunca lanza."""

import pytest
from pydantic import BaseModel

from auditor.modelos import ResultadoHerramienta
from auditor.tools import base
from auditor.tools.base import DominioInvalido, en_alcance, ip_permitida, normalizar_dominio


def test_normalizar_limpia_url():
    assert normalizar_dominio("HTTPS://WWW.Ejemplo.com.co:443/contacto?x=1") == "www.ejemplo.com.co"


def test_normalizar_quita_punto_final_y_espacios():
    assert normalizar_dominio(" ejemplo.com.co. ") == "ejemplo.com.co"


def test_normalizar_idn_a_punycode():
    assert normalizar_dominio("ferretería.com.co") == "xn--ferretera-n5a.com.co"


@pytest.mark.parametrize("malo", ["", "localhost", "a@b.com", "ex ample.com", "x" * 64 + ".com"])
def test_normalizar_rechaza_invalidos(malo):
    with pytest.raises(DominioInvalido):
        normalizar_dominio(malo)


def test_en_alcance_acepta_objetivo_y_subdominios():
    assert en_alcance("ejemplo.com.co", "ejemplo.com.co")
    assert en_alcance("webmail.ejemplo.com.co", "ejemplo.com.co")


@pytest.mark.parametrize("truco", ["ejemplo.com.co.evil.com", "evilejemplo.com.co", "otro.com.co"])
def test_en_alcance_rechaza_trucos(truco):
    assert not en_alcance(truco, "ejemplo.com.co")


def test_ip_permitida_acepta_publica():
    assert ip_permitida("8.8.8.8")
    assert ip_permitida("2001:4860:4860::8888")


@pytest.mark.parametrize("ip", ["10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1",
                                "::1", "::ffff:10.0.0.1", "fe80::1", "no-es-ip"])
def test_ip_permitida_bloquea_disfrazadas(ip):
    assert not ip_permitida(ip)


class EntradaEco(BaseModel):
    dominio: str


@pytest.fixture
def eco():
    llamadas = []

    @base.registrar("eco", "Devuelve el dominio recibido.", EntradaEco)
    def _eco(e: EntradaEco) -> ResultadoHerramienta:
        llamadas.append(e.dominio)
        return ResultadoHerramienta(ok=True, herramienta="eco", datos={"dominio": e.dominio})

    @base.registrar("explota", "Siempre falla.", EntradaEco)
    def _explota(e: EntradaEco) -> ResultadoHerramienta:
        raise RuntimeError("boom")

    yield llamadas
    base.REGISTRO.pop("eco", None)
    base.REGISTRO.pop("explota", None)


def test_ejecutar_normaliza_y_llama(eco):
    r = base.ejecutar("eco", '{"dominio": "HTTPS://Webmail.Ejemplo.com.co/"}', "ejemplo.com.co")
    assert r.ok and r.datos == {"dominio": "webmail.ejemplo.com.co"}
    assert r.duracion_ms >= 0


def test_ejecutar_acepta_dict(eco):
    r = base.ejecutar("eco", {"dominio": "ejemplo.com.co"}, "Ejemplo.com.co")
    assert r.datos == {"dominio": "ejemplo.com.co"}


def test_ejecutar_fuera_de_alcance(eco):
    r = base.ejecutar("eco", {"dominio": "otro.com"}, "ejemplo.com.co")
    assert (r.ok, r.error) == (False, "fuera_de_alcance")
    assert "ejemplo.com.co" in r.sugerencia
    assert eco == []


@pytest.mark.parametrize("nombre,args,error", [
    ("no_existe", {"dominio": "ejemplo.com.co"}, "herramienta_desconocida"),
    ("eco", "{dominio", "argumentos_invalidos"),
    ("eco", {}, "argumentos_invalidos"),
    ("eco", {"dominio": "a@b.com"}, "dominio_invalido"),
])
def test_ejecutar_errores_con_nombre(eco, nombre, args, error):
    r = base.ejecutar(nombre, args, "ejemplo.com.co")
    assert (r.ok, r.error) == (False, error)
    assert r.sugerencia


def test_ejecutar_nunca_lanza(eco):
    r = base.ejecutar("explota", {"dominio": "ejemplo.com.co"}, "ejemplo.com.co")
    assert (r.ok, r.error) == (False, "error_interno: RuntimeError")


def test_esquemas_para_grok(eco):
    [esquema] = base.esquemas_para_grok(["eco"])
    assert esquema["type"] == "function"
    assert esquema["function"]["name"] == "eco"
    assert esquema["function"]["description"] == "Devuelve el dominio recibido."
    assert "dominio" in esquema["function"]["parameters"]["properties"]
