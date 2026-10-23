"""tools/parecidos.py: variantes generadas por código y herramientas de dominios parecidos (sin red)."""

import pytest

from auditor.config import MAX_VARIANTES
from auditor.tools import base
from auditor.tools.base import _ETIQUETA
from auditor.tools.parecidos import generar_variantes


def _dominios(dominio):
    return {v["dominio"]: v["tipo"] for v in generar_variantes(dominio)[0]}


# --- generador ----------------------------------------------------------------------

def test_otro_tld_primero():
    v, _ = generar_variantes("ejemplo.com.co")
    assert [x["dominio"] for x in v[:2]] == ["ejemplo.co", "ejemplo.com"]
    assert v[0]["tipo"] == "otro_tld"


def test_tipos_esperados():
    d = _dominios("ejemplo.com.co")
    assert d["ejernplo.com.co"] == "homoglifo"
    assert d["ejemplocom.co"] == "sin_punto"
    assert d["ejmplo.com.co"] == "omision"
    assert d["jeemplo.com.co"] == "transposicion"
    assert d["ejjemplo.com.co"] == "duplicacion"


def test_nunca_incluye_el_propio_ni_duplicados():
    v, _ = generar_variantes("ejemplo.com.co")
    nombres = [x["dominio"] for x in v]
    assert "ejemplo.com.co" not in nombres and len(nombres) == len(set(nombres))


def test_determinista():
    assert generar_variantes("ejemplo.com.co") == generar_variantes("ejemplo.com.co")


def test_tope_y_truncadas():
    v, truncadas = generar_variantes("abcdefghijklmnopqrstuvwxyzabcdefghijklmn.com.co")
    assert len(v) == MAX_VARIANTES and truncadas
    assert generar_variantes("ejemplo.com.co")[1] is False


def test_subdominio_usa_registrable():
    assert generar_variantes("tienda.ejemplo.com.co") == generar_variantes("ejemplo.com.co")


def test_sin_punto_solo_con_com_co():
    assert not any(t == "sin_punto" for t in _dominios("ejemplo.co").values())
    assert "ejemplo.com.co" in _dominios("ejemplo.co")


def test_etiqueta_corta_sin_excepcion():
    for nombre in _dominios("ab.co"):
        etiqueta = nombre.split(".")[0]
        assert len(etiqueta) >= 2 and _ETIQUETA.match(etiqueta)


def test_etiquetas_siempre_validas():
    for nombre in _dominios("a-b1.com.co"):
        assert all(_ETIQUETA.match(e) for e in nombre.split("."))


def test_idn_solo_otro_tld():
    assert set(_dominios("xn--ferretera-n5a.com.co").values()) == {"otro_tld"}


def test_validador_registrado():
    assert "ejernplo.com.co" in base.VALIDADOR_PARECIDOS("ejemplo.com.co")


# --- herramientas (DNS y registro falsos) --------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

from auditor.tools import correo, parecidos, registro  # noqa: E402
from auditor.tools.correo import ErrorDNS  # noqa: E402
from auditor.tools.registro import ErrorRegistro  # noqa: E402

DUENO = "ejemplo.com.co"
AHORA = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


class DNSFalso:
    """Tablas por nombre; un valor str en `errores` se lanza como ErrorDNS. Lo que no está, no existe."""

    def __init__(self, ns=None, mx=None, txt=None, errores=None):
        self._ns, self._mx, self._txt, self._errores = ns or {}, mx or {}, txt or {}, errores or {}
        self.consultas = []

    def _get(self, tipo, tabla, nombre, faltante):
        self.consultas.append((tipo, nombre))
        if (tipo, nombre) in self._errores:
            raise ErrorDNS(self._errores[(tipo, nombre)])
        if nombre not in tabla and faltante:
            raise ErrorDNS("dominio_no_existe")
        return tabla.get(nombre, [])

    def ns(self, nombre):
        return self._get("ns", self._ns, nombre, faltante=True)

    def mx(self, nombre):
        return self._get("mx", self._mx, nombre, faltante=nombre not in self._ns)

    def txt(self, nombre):
        return self._get("txt", self._txt, nombre, faltante=nombre not in self._ns)


@pytest.fixture
def entorno(monkeypatch):
    estado = {"registro": {}}

    def consultar(dominio):
        valor = estado["registro"].get(dominio, ("whois", None))
        if isinstance(valor, Exception):
            raise valor
        return valor

    monkeypatch.setattr(registro, "consultar_registro", consultar)
    monkeypatch.setattr(parecidos, "_ahora", lambda: AHORA)

    def usar(dns):
        monkeypatch.setattr(correo, "resolver", dns)
        return dns
    estado["usar"] = usar
    return estado


def _dns_base(**extra):
    ns = {DUENO: ["ns1.dueno-dns.com"], "ejemplo.co": ["ns1.otro.com"], "ejmplo.com.co": ["ns1.otro.com"],
          "ejernplo.com.co": ["ns1.dueno-dns.com"]} | extra.get("ns", {})
    mx = {DUENO: [(10, "mx.dueno.com")], "ejemplo.co": [(10, "mx.otro.com")],
          "ejernplo.com.co": [(10, "mx.otro2.com")]} | extra.get("mx", {})
    return DNSFalso(ns=ns, mx=mx, txt=extra.get("txt", {}), errores=extra.get("errores", {}))


def buscar(dominio=DUENO):
    return base.ejecutar("buscar_parecidos", {"dominio": dominio}, DUENO)


def test_buscar_solo_lista_existentes_con_mx(entorno):
    entorno["usar"](_dns_base())
    r = buscar()
    assert r.ok and r.datos["existentes"] == 3 and r.datos["generadas"] == 27
    assert [c["dominio"] for c in r.datos["con_correo"]] == ["ejemplo.co", "ejernplo.com.co"]
    assert r.datos["con_correo"][0] == {"dominio": "ejemplo.co", "tipo": "otro_tld", "mx": ["mx.otro.com"],
                                        "comparte_servidores": False}


def test_buscar_marca_compartidos(entorno):
    entorno["usar"](_dns_base())
    con = {c["dominio"]: c for c in buscar().datos["con_correo"]}
    assert con["ejernplo.com.co"]["comparte_servidores"] is True  # mismo NS que el dueño


def test_buscar_mx_nulo_no_cuenta_como_correo(entorno):
    entorno["usar"](_dns_base(mx={"ejemplo.co": [(0, "")]}))
    assert "ejemplo.co" not in [c["dominio"] for c in buscar().datos["con_correo"]]


def test_buscar_no_pide_mx_a_variantes_inexistentes(entorno):
    dns = entorno["usar"](_dns_base())
    buscar()
    assert {n for t, n in dns.consultas if t == "mx"} == {DUENO, "ejemplo.co", "ejmplo.com.co", "ejernplo.com.co"}


def test_buscar_variante_con_timeout_va_a_sin_verificar(entorno):
    entorno["usar"](_dns_base(errores={("ns", "ejemplo.com"): "tiempo_agotado"}))
    r = buscar()
    assert r.ok and r.datos["sin_verificar"] == ["ejemplo.com"]


def test_buscar_dns_del_dueno_falla(entorno):
    entorno["usar"](_dns_base(errores={("ns", DUENO): "tiempo_agotado"}))
    r = buscar()
    assert (r.ok, r.error) == (False, "tiempo_agotado") and r.sugerencia


def test_buscar_desde_subdominio_usa_registrable(entorno):
    entorno["usar"](_dns_base())
    assert buscar("tienda.ejemplo.com.co").datos["dominio"] == DUENO


def investigar(parecido):
    return base.ejecutar("investigar_parecido", {"dominio": DUENO, "parecido": parecido}, DUENO)


def test_investigar_reciente_con_spf(entorno):
    entorno["usar"](_dns_base(txt={"ejmplo.com.co": ["v=spf1 include:_spf.otro.com ~all"]},
                              mx={"ejmplo.com.co": [(10, "mx.otro.com")]}))
    entorno["registro"]["ejmplo.com.co"] = ("whois", {"creado": (AHORA - timedelta(days=12)).isoformat(),
                                                       "registrador": "Registrador X"})
    r = investigar("ejmplo.com.co")
    assert r.ok
    assert r.datos == {"parecido": "ejmplo.com.co", "tipo": "omision", "existe": True, "tiene_mx": True,
                       "creado": (AHORA - timedelta(days=12)).isoformat(), "dias_desde_registro": 12,
                       "spf_autoriza_envio": True, "comparte_servidores": False, "fuente_registro": "whois",
                       "aviso": None}
    assert r.contenido_no_confiable == {"registrador": "Registrador X"}


def test_investigar_tld_no_soportado_sigue_ok(entorno):
    entorno["usar"](_dns_base())
    entorno["registro"]["ejemplo.co"] = ErrorRegistro("tld_no_soportado")
    r = investigar("ejemplo.co")
    assert r.ok and r.datos["creado"] is None and r.datos["fuente_registro"] == "ninguna"
    assert r.datos["aviso"] and r.datos["tiene_mx"] is True


def test_investigar_parecido_que_no_existe(entorno):
    entorno["usar"](_dns_base())
    r = investigar("ejemplo.com")
    assert r.ok and r.datos["existe"] is False and r.datos["tiene_mx"] is False


def test_investigar_dns_falla(entorno):
    entorno["usar"](_dns_base(errores={("ns", "ejemplo.co"): "tiempo_agotado"}))
    r = investigar("ejemplo.co")
    assert (r.ok, r.error) == (False, "tiempo_agotado")


def test_investigar_no_hace_http_ni_tls(entorno, monkeypatch):
    import socket
    import urllib.request

    def prohibido(*a, **k):
        raise AssertionError("un parecido nunca se visita por HTTP ni TLS")
    monkeypatch.setattr(urllib.request, "urlopen", prohibido)
    monkeypatch.setattr(socket, "create_connection", prohibido)
    entorno["usar"](_dns_base())
    assert investigar("ejemplo.co").ok


def test_investigar_por_ejecutar_rechaza_no_variante(entorno):
    entorno["usar"](_dns_base())
    r = investigar("otro.com")
    assert (r.ok, r.error) == (False, "fuera_de_alcance")
