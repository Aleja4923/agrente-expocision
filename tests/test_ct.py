"""tools/ct.py: subdominios desde Certificate Transparency (crt.sh con Cert Spotter de respaldo), sin red."""

from datetime import date

import pytest

from auditor.tools import base, ct
from auditor.tools.ct import ErrorCT, procesar

HOY = date(2026, 10, 24)
D = "ejemplo.com.co"

CRTSH = [  # misma forma que la respuesta real de crt.sh (output=json), seudonimizada
    {"name_value": "*.pagos.ejemplo.com.co\npagos.ejemplo.com.co", "not_after": "2027-01-10T00:00:00"},
    {"name_value": "webmail.ejemplo.com.co", "not_after": "2025-03-01T00:00:00"},
    {"name_value": "webmail.ejemplo.com.co", "not_after": "2026-12-01T00:00:00"},
    {"name_value": "ejemplo.com.co\nwww.ejemplo.com.co", "not_after": "2027-02-01T00:00:00"},
    {"name_value": "ejemplo.com.co.evil.com", "not_after": "2027-01-01T00:00:00"},
    {"name_value": "contacto@ejemplo.com.co", "not_after": "2027-01-01T00:00:00"},
    {"name_value": "VIEJO.Ejemplo.com.co", "not_after": "2020-01-01T00:00:00"},
]
CERTSPOTTER = [{"dns_names": ["admin.ejemplo.com.co", "*.ejemplo.com.co"], "not_after": "2027-03-01T00:00:00Z"}]


def entradas_crtsh():
    return [(e["name_value"].split("\n"), e["not_after"]) for e in CRTSH]


def test_procesar_quita_comodin_deduplica_y_filtra_alcance():
    r = procesar(entradas_crtsh(), D, HOY)
    nombres = [s["nombre"] for s in r]
    assert nombres == ["pagos.ejemplo.com.co", "webmail.ejemplo.com.co", "www.ejemplo.com.co", "viejo.ejemplo.com.co"]
    assert "ejemplo.com.co" not in nombres  # el propio dominio no es un subdominio


def test_procesar_guarda_el_vencimiento_mas_reciente():
    [webmail] = [s for s in procesar(entradas_crtsh(), D, HOY) if s["nombre"] == "webmail.ejemplo.com.co"]
    assert webmail == {"nombre": "webmail.ejemplo.com.co", "ultimo_certificado_vence": "2026-12-01", "vigente": True}


def test_procesar_vigentes_primero():
    r = procesar(entradas_crtsh(), D, HOY)
    assert [s["vigente"] for s in r] == [True, True, True, False]


@pytest.fixture
def fuentes(monkeypatch):
    estado = {"crtsh": [], "certspotter": [], "dormido": []}

    def crtsh(dominio):
        estado["crtsh"].append(dominio)
        valor = estado.get("crtsh_resp", entradas_crtsh())
        if isinstance(valor, Exception):
            raise valor
        return valor

    def certspotter(dominio):
        estado["certspotter"].append(dominio)
        valor = estado.get("cs_resp", [(e["dns_names"], e["not_after"]) for e in CERTSPOTTER])
        if isinstance(valor, Exception):
            raise valor
        return valor

    monkeypatch.setattr(ct, "_consultar_crtsh", crtsh)
    monkeypatch.setattr(ct, "_consultar_certspotter", certspotter)
    monkeypatch.setattr(ct, "_hoy", lambda: HOY)
    return estado


def correr(dominio=D):
    return base.ejecutar("subdominios_ct", {"dominio": dominio}, D)


def test_herramienta_usa_crtsh(fuentes):
    r = correr()
    assert r.ok and r.datos["fuente"] == "crtsh" and r.datos["total"] == 4
    assert r.datos["mostrados"] == 4 and r.datos["truncados"] is False
    assert fuentes["certspotter"] == []


def test_respaldo_certspotter_si_crtsh_falla(fuentes):
    fuentes["crtsh_resp"] = ErrorCT("ct_no_responde")
    r = correr()
    assert r.ok and r.datos["fuente"] == "certspotter"
    assert [s["nombre"] for s in r.datos["subdominios"]] == ["admin.ejemplo.com.co"]


def test_ambas_fallan(fuentes):
    fuentes["crtsh_resp"] = ErrorCT("ct_no_responde")
    fuentes["cs_resp"] = ErrorCT("limite_de_consultas")
    r = correr()
    assert (r.ok, r.error) == (False, "limite_de_consultas") and r.sugerencia


def test_usa_el_registrable(fuentes):
    correr("tienda.ejemplo.com.co")
    assert fuentes["crtsh"] == [D]


def test_tope_de_mostrados(fuentes, monkeypatch):
    monkeypatch.setattr(ct, "MAX_SUBDOMINIOS_MOSTRADOS", 2)
    r = correr()
    assert r.datos["total"] == 4 and r.datos["mostrados"] == 2 and r.datos["truncados"] is True
    assert len(r.datos["subdominios"]) == 2


def test_crtsh_reintenta_una_vez(monkeypatch):
    llamadas, dormido = [], []

    def pedir(url, timeout):
        llamadas.append(url)
        if len(llamadas) == 1:
            raise ErrorCT("ct_no_responde")
        return CRTSH
    monkeypatch.setattr(ct, "_pedir_json", pedir)
    monkeypatch.setattr(ct, "_dormir", dormido.append)
    assert len(ct._consultar_crtsh(D)) == len(CRTSH)
    assert len(llamadas) == 2 and dormido == [ct.CT_ESPERA_REINTENTO]
    assert llamadas[0] == "https://crt.sh/?q=%25.ejemplo.com.co&output=json"


def test_respuesta_ilegible(monkeypatch):
    monkeypatch.setattr(ct, "_pedir_json", lambda url, timeout: {"no": "es una lista"})
    with pytest.raises(ErrorCT, match="respuesta_ilegible"):
        ct._consultar_certspotter(D)


def test_procesar_prefiere_los_menos_profundos():
    entradas = [(["admin.lab.interno.ejemplo.com.co"], "2027-01-01T00:00:00"),
                (["zpagos.ejemplo.com.co"], "2027-01-01T00:00:00")]
    assert [s["nombre"] for s in procesar(entradas, D, HOY)] == ["zpagos.ejemplo.com.co",
                                                                 "admin.lab.interno.ejemplo.com.co"]
