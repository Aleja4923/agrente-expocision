"""tools/cabeceras.py: cabeceras de seguridad de la portada y security.txt (red simulada)."""

from datetime import datetime, timezone

import pytest

from auditor.tools import base, cabeceras, peticiones
from auditor.tools.cabeceras import analizar_cabeceras, analizar_security_txt
from auditor.tools.peticiones import ErrorHTTP, Respuesta

D = "ejemplo.com.co"
AHORA = datetime(2026, 10, 24, tzinfo=timezone.utc)
BUENAS = {"strict-transport-security": "max-age=31536000; includeSubDomains", "x-frame-options": "SAMEORIGIN",
          "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'",
          "referrer-policy": "strict-origin", "server": "nginx"}


# --- lectores (funciones puras) -----------------------------------------------------------

def test_analizar_cabeceras_completas():
    assert analizar_cabeceras(BUENAS) == {
        "hsts": {"presente": True, "max_age": 31536000, "include_subdomains": True},
        "x_frame_options": True, "frame_ancestors": False, "nosniff": True, "csp_presente": True,
        "referrer_policy": True, "servidor_con_version": False}


def test_analizar_cabeceras_vacias_y_version():
    d = analizar_cabeceras({"server": "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3"})
    assert d["hsts"] == {"presente": False, "max_age": None, "include_subdomains": False}
    assert (d["x_frame_options"], d["nosniff"], d["servidor_con_version"]) == (False, False, True)


def test_frame_ancestors_en_csp_cuenta():
    assert analizar_cabeceras({"content-security-policy": "frame-ancestors 'none'"})["frame_ancestors"] is True


def test_hsts_mal_escrito():
    assert analizar_cabeceras({"strict-transport-security": "max-age=abc"})["hsts"]["max_age"] is None


def test_security_txt_valido():
    d = analizar_security_txt(b"Contact: mailto:seguridad@ejemplo.com.co\nExpires: 2027-01-01T00:00:00Z\n",
                              "text/plain; charset=utf-8", AHORA)
    assert d == {"existe": True, "tiene_contact": True, "expires": "2027-01-01T00:00:00+00:00", "vencido": False}


def test_security_txt_vencido_y_sin_contact():
    d = analizar_security_txt(b"Expires: 2025-01-01T00:00:00Z\n", "text/plain", AHORA)
    assert (d["existe"], d["tiene_contact"], d["vencido"]) == (True, False, True)


def test_security_txt_que_es_html_no_cuenta():
    d = analizar_security_txt(b"<html>Contact: nada</html>", "text/html", AHORA)
    assert d["existe"] is False


# --- herramientas -----------------------------------------------------------------------

@pytest.fixture
def web(monkeypatch):
    estado = {"tabla": {}}

    def pedir(url, registrable, metodo="GET", seguir=True):
        valor = estado["tabla"].get((url, seguir))
        if valor is None:
            raise ErrorHTTP("sin_conexion")
        if isinstance(valor, Exception):
            raise valor
        return valor

    monkeypatch.setattr(peticiones, "pedir", pedir)
    monkeypatch.setattr(cabeceras, "_ahora", lambda: AHORA)
    return estado


def resp(url, codigo=200, cab=None, cuerpo=b"", redirecciones=(), fuera=None):
    return Respuesta(url, codigo, {k.lower(): v for k, v in (cab or {}).items()}, cuerpo, list(redirecciones), fuera)


def cabeceras_de(host=D):
    return base.ejecutar("cabeceras_web", {"host": host}, D)


def test_sitio_bien_configurado(web):
    web["tabla"] = {(f"http://{D}/", True): resp(f"https://{D}/", 200, redirecciones=[f"https://{D}/"]),
                    (f"https://{D}/", True): resp(f"https://{D}/", 200, BUENAS)}
    r = cabeceras_de()
    assert r.ok and r.datos["http_responde"] and r.datos["redirige_a_https"] is True
    assert r.datos["evaluable"] is True and r.datos["hsts"]["presente"]
    assert r.contenido_no_confiable["server"] == "nginx"


def test_http_sin_redireccion(web):
    web["tabla"] = {(f"http://{D}/", True): resp(f"http://{D}/", 200),
                    (f"https://{D}/", True): resp(f"https://{D}/", 200)}
    r = cabeceras_de()
    assert r.datos["redirige_a_https"] is False and r.datos["hsts"]["presente"] is False


def test_http_cerrado_no_es_problema(web):
    web["tabla"] = {(f"https://{D}/", True): resp(f"https://{D}/", 200, BUENAS)}
    r = cabeceras_de()
    assert r.ok and r.datos["http_responde"] is False and r.datos["redirige_a_https"] is None


def test_redireccion_a_otra_plataforma_no_es_evaluable(web):
    web["tabla"] = {(f"https://{D}/", True): resp(f"https://{D}/", 301, {}, fuera="tienda.plataforma.com")}
    r = cabeceras_de()
    assert r.ok and r.datos["evaluable"] is False and r.datos["redirige_fuera"] == "tienda.plataforma.com"


def test_https_falla(web):
    web["tabla"] = {(f"https://{D}/", True): ErrorHTTP("certificado_invalido")}
    r = cabeceras_de()
    assert (r.ok, r.error) == (False, "certificado_invalido") and r.sugerencia


def test_cabeceras_fuera_de_alcance(web):
    assert cabeceras_de("otro.com").error == "fuera_de_alcance"


def test_security_txt_herramienta(web):
    url = f"https://{D}/.well-known/security.txt"
    web["tabla"] = {(url, True): resp(url, 200, {"Content-Type": "text/plain"}, b"Contact: mailto:s@ejemplo.com.co\n")}
    r = base.ejecutar("security_txt", {"dominio": D}, D)
    assert r.ok and r.datos["existe"] and r.datos["tiene_contact"] and r.datos["codigo"] == 200
    assert "Contact" in r.contenido_no_confiable["security_txt"]


def test_security_txt_no_existe(web):
    url = f"https://{D}/.well-known/security.txt"
    web["tabla"] = {(url, True): resp(url, 404)}
    r = base.ejecutar("security_txt", {"dominio": D}, D)
    assert r.ok and r.datos["existe"] is False


def test_security_txt_sin_sitio(web):
    r = base.ejecutar("security_txt", {"dominio": D}, D)
    assert (r.ok, r.error) == (False, "sin_conexion")


def test_http_que_redirige_en_dos_saltos_cuenta(web):
    # http://d -> http://www.d -> https://www.d (caso real de un sitio grande)
    web["tabla"] = {(f"http://{D}/", True): resp(f"https://www.{D}/", 200, redirecciones=[f"http://www.{D}/",
                                                                                         f"https://www.{D}/"]),
                    (f"https://{D}/", True): resp(f"https://{D}/", 200, BUENAS)}
    assert cabeceras_de().datos["redirige_a_https"] is True


def test_http_que_redirige_a_https_externo_cuenta(web):
    web["tabla"] = {(f"http://{D}/", True): resp(f"http://{D}/", 301, {"Location": "https://tienda.plataforma.com/"},
                                                 fuera="tienda.plataforma.com"),
                    (f"https://{D}/", True): resp(f"https://{D}/", 200, BUENAS)}
    assert cabeceras_de().datos["redirige_a_https"] is True


# --- revisión: cabeceras repetidas y security.txt que redirige ---------------------------------

def test_cabeceras_repetidas_por_un_proxy_cuentan():
    d = analizar_cabeceras({"x-frame-options": "SAMEORIGIN, SAMEORIGIN", "x-content-type-options": "nosniff, nosniff"})
    assert d["x_frame_options"] is True and d["nosniff"] is True


def test_security_txt_que_redirige_a_otro_dominio_no_se_da_por_inexistente(web):
    url = f"https://{D}/.well-known/security.txt"
    web["tabla"] = {(url, True): resp(url, 301, {"Location": "https://grupo.com/.well-known/security.txt"},
                                      fuera="grupo.com")}
    r = base.ejecutar("security_txt", {"dominio": D}, D)
    assert r.ok and r.datos["existe"] is None and r.datos["redirige_fuera"] == "grupo.com"


@pytest.mark.parametrize("codigo,existe", [(404, False), (410, False), (403, None), (500, None)])
def test_security_txt_solo_404_y_410_son_inexistente(web, codigo, existe):
    url = f"https://{D}/.well-known/security.txt"
    web["tabla"] = {(url, True): resp(url, codigo)}
    assert base.ejecutar("security_txt", {"dominio": D}, D).datos["existe"] is existe
