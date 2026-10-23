"""tools/registro.py: WHOIS de .co, RDAP, caché, pausa entre consultas y herramienta whois_dominio (sin red)."""

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from auditor.tools import base, registro
from auditor.tools.registro import ErrorRegistro, fuente_para, parsear_rdap, parsear_whois_co

FIXTURES = Path(__file__).parent / "fixtures"
AHORA = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


def leer(nombre: str) -> str:
    return (FIXTURES / nombre).read_text(encoding="utf-8")


# --- lectores (funciones puras) ----------------------------------------------------

def test_parsear_whois_co_existente():
    d = parsear_whois_co(leer("whois_co_existe.txt"))
    assert d["creado"].startswith("2003-04-21") and d["vence"].startswith("2027-04-24")
    assert d["estados"] == ["clientTransferProhibited", "clientUpdateProhibited", "clientDeleteProhibited"]
    assert d["servidores_nombre"][0] == "ns1.ejemplo-dns.com"
    assert d["registrador"] == "Registrador Ejemplo S.A.S."


def test_parsear_whois_co_no_existe():
    assert parsear_whois_co(leer("whois_co_no_existe.txt")) is None


@pytest.mark.parametrize("texto", ["", "WHOIS LIMIT EXCEEDED - try later", "Domain Name: EJEMPLO.COM.CO\n",
                                   "Creation Date: no-es-fecha\nRegistry Expiry Date: 2027-01-01T00:00:00Z\n"])
def test_parsear_whois_ilegible(texto):
    with pytest.raises(ErrorRegistro, match="respuesta_ilegible"):
        parsear_whois_co(texto)


def test_parsear_rdap_camelcase():
    d = parsear_rdap(json.loads(leer("rdap_com.json")))
    assert d["creado"].startswith("1997-09-15") and d["vence"].startswith("2028-09-14")
    assert "clientTransferProhibited" in d["estados"] and "serverTransferProhibited" in d["estados"]
    assert d["servidores_nombre"] == ["ns1.ejemplo-dns.com", "ns2.ejemplo-dns.com"]
    assert d["registrador"] == "Registrador Ejemplo S.A.S."


def test_parsear_rdap_sin_fechas_es_ilegible():
    with pytest.raises(ErrorRegistro, match="respuesta_ilegible"):
        parsear_rdap({"events": []})


@pytest.mark.parametrize("dominio,tipo", [("ejemplo.com.co", "whois"), ("ejemplo.co", "whois"),
                                          ("ejemplo.nom.co", "whois"), ("ejemplo.com", "rdap"),
                                          ("ejemplo.net", "rdap"), ("ejemplo.org", "rdap")])
def test_fuente_para(dominio, tipo):
    assert fuente_para(dominio)[0] == tipo


def test_fuente_tld_no_soportado():
    with pytest.raises(ErrorRegistro, match="tld_no_soportado"):
        fuente_para("ejemplo.com.mx")


# --- consulta con caché y pausa ------------------------------------------------------

@pytest.fixture
def red_falsa(monkeypatch, tmp_path):
    """Sin red: WHOIS y RDAP falsos, caché en tmp_path, reloj y espera falsos."""
    estado = {"whois": [], "rdap": [], "dormido": [], "reloj": 1000.0,
              "texto": leer("whois_co_existe.txt"), "json": json.loads(leer("rdap_com.json"))}

    def pedir_whois(servidor, dominio):
        estado["whois"].append(dominio)
        if isinstance(estado["texto"], Exception):
            raise estado["texto"]
        return estado["texto"]

    def pedir_rdap(url):
        estado["rdap"].append(url)
        return estado["json"]

    monkeypatch.setattr(registro, "_pedir_whois", pedir_whois)
    monkeypatch.setattr(registro, "_pedir_rdap", pedir_rdap)
    monkeypatch.setattr(registro, "RUTA_CACHE_DB", tmp_path / "cache.db")
    monkeypatch.setattr(registro, "_reloj", lambda: estado["reloj"])
    monkeypatch.setattr(registro, "_dormir", lambda s: estado["dormido"].append(round(s, 2)))
    monkeypatch.setattr(registro, "_ahora", lambda: AHORA)
    monkeypatch.setattr(registro, "_ultima_consulta", {})
    return estado


def test_consulta_usa_cache(red_falsa):
    assert registro.consultar_registro("ejemplo.com.co")[0] == "whois"
    fuente, datos = registro.consultar_registro("ejemplo.com.co")
    assert red_falsa["whois"] == ["ejemplo.com.co"]
    assert fuente == "whois" and datos["vence"].startswith("2027-04-24")


def test_cache_recuerda_no_registrado(red_falsa):
    red_falsa["texto"] = leer("whois_co_no_existe.txt")
    assert registro.consultar_registro("libre.com.co") == ("whois", None)
    assert registro.consultar_registro("libre.com.co") == ("whois", None)
    assert red_falsa["whois"] == ["libre.com.co"]


def test_respuesta_ilegible_no_se_guarda_en_cache(red_falsa):
    red_falsa["texto"] = "WHOIS LIMIT EXCEEDED"
    for _ in range(2):
        with pytest.raises(ErrorRegistro, match="respuesta_ilegible"):
            registro.consultar_registro("ejemplo.com.co")
    assert len(red_falsa["whois"]) == 2


def test_pausa_entre_consultas_al_mismo_servidor(red_falsa):
    registro.consultar_registro("uno.com.co")
    red_falsa["reloj"] += 0.5
    registro.consultar_registro("dos.com.co")
    assert red_falsa["dormido"] == [1.0]


def test_rdap_para_com(red_falsa):
    assert registro.consultar_registro("ejemplo.com")[0] == "rdap"
    assert red_falsa["rdap"] == ["https://rdap.verisign.com/com/v1/domain/ejemplo.com"]


def test_whois_que_no_responde(red_falsa):
    red_falsa["texto"] = socket.timeout("lento")
    with pytest.raises(ErrorRegistro, match="registro_no_responde"):
        registro.consultar_registro("ejemplo.com.co")


# --- herramienta whois_dominio -----------------------------------------------------

def test_whois_dominio_usa_registrable(red_falsa):
    r = base.ejecutar("whois_dominio", {"dominio": "tienda.ejemplo.com.co"}, "ejemplo.com.co")
    assert r.ok and red_falsa["whois"] == ["ejemplo.com.co"] and r.datos["dominio"] == "ejemplo.com.co"


def test_whois_dominio_dias_y_bloqueo(red_falsa):
    r = base.ejecutar("whois_dominio", {"dominio": "ejemplo.com.co"}, "ejemplo.com.co")
    assert r.datos["dias_para_vencer"] == 183  # 2026-10-23 -> 2027-04-24
    assert r.datos["bloqueo_transferencia"] is True and r.datos["fuente"] == "whois"
    assert r.contenido_no_confiable == {"registrador": "Registrador Ejemplo S.A.S."}
    assert "registrador" not in r.datos


def test_whois_dominio_no_registrado(red_falsa):
    red_falsa["texto"] = leer("whois_co_no_existe.txt")
    r = base.ejecutar("whois_dominio", {"dominio": "ejemplo.com.co"}, "ejemplo.com.co")
    assert (r.ok, r.error) == (False, "no_registrado") and r.sugerencia


@pytest.mark.parametrize("error,codigo", [(socket.timeout("x"), "registro_no_responde"),
                                          (ConnectionResetError("x"), "registro_no_responde")])
def test_whois_dominio_errores_de_red(red_falsa, error, codigo):
    red_falsa["texto"] = error
    r = base.ejecutar("whois_dominio", {"dominio": "ejemplo.com.co"}, "ejemplo.com.co")
    assert (r.ok, r.error) == (False, codigo) and r.sugerencia


def test_whois_dominio_tld_no_soportado(red_falsa):
    r = base.ejecutar("whois_dominio", {"dominio": "ejemplo.com.mx"}, "ejemplo.com.mx")
    assert (r.ok, r.error) == (False, "tld_no_soportado") and red_falsa["whois"] == []
