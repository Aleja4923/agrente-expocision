"""evals/reproducir.py: lo grabado se entrega detrás de las guardas reales, con fechas que no caducan."""

from datetime import date, timedelta

import pytest

from auditor import agent, scoring
from auditor.modelos import ResultadoHerramienta
from auditor.tools.parecidos import generar_variantes
from evals.casos import Caso, clave
from evals.reproducir import SIN_DATOS, Reproductor, desplazar_fechas
from tests.test_agent import (BASE, DOMINIO, GrokGuion, busqueda_ok, cabeceras_ok, dkim_ok, dns_ok, informe,
                              resp, security_ok, tls_de, tls_ok, whois_ok)

GRABADO = date(2026, 11, 2)
PARECIDO = generar_variantes(DOMINIO)[0][5]["dominio"]


def ct_con(*subs):
    """subs: (nombre, tiene_sitio)."""
    return ResultadoHerramienta(ok=True, herramienta="subdominios_ct", datos={
        "dominio": DOMINIO, "fuente": "crtsh", "total": len(subs), "mostrados": len(subs), "truncados": False,
        "con_sitio": sum(s for _, s in subs),
        "subdominios": [{"nombre": n, "ultimo_certificado_vence": "2027-01-01", "vigente": True, "tiene_sitio": s}
                        for n, s in subs]})


def caso(**grabacion_extra) -> Caso:
    grabacion = {
        clave("dns_correo", DOMINIO): dns_ok(),
        clave("tls_certificado", DOMINIO): tls_ok(),
        clave("whois_dominio", DOMINIO): whois_ok(vence="2026-11-22T23:59:59+00:00"),
        clave("buscar_parecidos", DOMINIO): busqueda_ok(PARECIDO),
        clave("subdominios_ct", DOMINIO): ct_con((f"pagos.{DOMINIO}", True), (f"viejo.{DOMINIO}", False)),
        clave("cabeceras_web", DOMINIO): cabeceras_ok(),
        clave("security_txt", DOMINIO): security_ok(),
        clave("dkim_selector", DOMINIO): dkim_ok("google"),
    } | {clave(*k.split("|")): v for k, v in grabacion_extra.items()}
    return Caso(id="fab-00", origen="fabricado", perfil="pyme_estandar", grabado_el=GRABADO, dominio=DOMINIO,
                objetivo=None, grabacion=grabacion,
                esperado={"nivel_esperado": "alto", "hallazgos_obligatorios": [], "hallazgos_por_decision": [],
                          "hallazgos_prohibidos": [], "cierre_esperado": "informe_entregado"})


def reproducir(nombre, argumentos, c=None, hoy=GRABADO):
    return Reproductor(c or caso(), hoy=hoy)(nombre, argumentos, DOMINIO)


def test_devuelve_lo_grabado():
    r = reproducir("dns_correo", {"dominio": DOMINIO})
    assert r.ok and r.datos == dns_ok().datos


def test_no_altera_lo_grabado():
    c = caso()
    reproducir("tls_certificado", {"host": DOMINIO}, c, hoy=GRABADO + timedelta(days=30))
    assert c.grabacion[clave("tls_certificado", DOMINIO)].datos["vence"] == "2027-01-01"
    assert c.grabacion[clave("tls_certificado", DOMINIO)].duracion_ms == tls_ok().duracion_ms


def test_host_sin_sitio_da_sin_direccion_web():
    for herramienta in ("tls_certificado", "cabeceras_web"):
        r = reproducir(herramienta, {"host": f"viejo.{DOMINIO}"})
        assert (r.ok, r.error) == (False, "sin_direccion_web") and r.sugerencia


def test_host_con_sitio_no_grabado_da_sin_datos():
    r = reproducir("cabeceras_web", {"host": f"pagos.{DOMINIO}"})
    assert (r.ok, r.error) == (False, SIN_DATOS) and "limitación" in r.sugerencia


def test_host_grabado_de_subdominio():
    c = caso(**{f"cabeceras_web|pagos.{DOMINIO}": cabeceras_ok(f"pagos.{DOMINIO}", nosniff=False)})
    assert reproducir("cabeceras_web", {"host": f"pagos.{DOMINIO}"}, c).datos["nosniff"] is False


def test_parecido_valido_no_grabado_da_sin_datos():
    r = reproducir("investigar_parecido", {"dominio": DOMINIO, "parecido": PARECIDO})
    assert r.error == SIN_DATOS


def test_parecido_invalido_lo_rechaza_la_guarda():
    r = reproducir("investigar_parecido", {"dominio": DOMINIO, "parecido": "cualquiera.com"})
    assert r.error == "fuera_de_alcance"


def test_dominio_ajeno_lo_rechaza_la_guarda():
    assert reproducir("dns_correo", {"dominio": "ajeno.com"}).error == "fuera_de_alcance"


def test_www_en_whois_busca_el_registrable():
    r = reproducir("whois_dominio", {"dominio": f"www.{DOMINIO}"})
    assert r.ok and r.herramienta == "whois_dominio"


def test_host_con_mayusculas_y_punto_final():
    assert reproducir("tls_certificado", {"host": DOMINIO.upper() + "."}).ok


def test_selectores_grabados_y_no_grabados():
    r = reproducir("dkim_selector", {"dominio": DOMINIO, "selectores": ["google", "s1"]})
    assert r.ok
    por_selector = {s["selector"]: s for s in r.datos["selectores"]}
    assert por_selector["google"]["existe"] is True
    assert por_selector["s1"]["error"] == SIN_DATOS and por_selector["s1"]["existe"] is False


def test_ningun_selector_grabado():
    r = reproducir("dkim_selector", {"dominio": DOMINIO, "selectores": ["s1", "s2"]})
    assert (r.ok, r.error) == (False, SIN_DATOS)


def test_selector_no_grabado_no_cuenta_como_probado():
    c = caso(**{f"dkim_selector|{DOMINIO}": dkim_ok()})  # sin selectores grabados
    r = Reproductor(c, hoy=GRABADO)("dkim_selector", {"dominio": DOMINIO, "selectores": ["google"]}, DOMINIO)
    llamadas = [({"dominio": DOMINIO}, dns_ok(scoring_correo_google())),
                ({"dominio": DOMINIO, "selectores": ["google"]}, r)]
    assert "CORREO-DKIM-NO-ENCONTRADO" not in scoring.evaluar(llamadas, DOMINIO)


def scoring_correo_google():
    from tests.test_scoring import correo
    return correo(mx={"proveedor": "google"})


def test_fechas_estables_a_un_ano():
    c = caso()

    def hallazgos(hoy):
        rep = Reproductor(c, hoy=hoy)
        llamadas = [({"dominio": DOMINIO}, rep("whois_dominio", {"dominio": DOMINIO}, DOMINIO)),
                    ({"host": DOMINIO}, rep("tls_certificado", {"host": DOMINIO}, DOMINIO))]
        return scoring.evaluar(llamadas, DOMINIO, hoy=hoy)

    hoy = hallazgos(GRABADO)
    assert "DOMINIO-POR-VENCER" in hoy
    en_un_ano = hallazgos(GRABADO + timedelta(days=365))
    assert {k: v.evidencia for k, v in en_un_ano.items()}.keys() == hoy.keys()


def test_fecha_con_zona_conserva_formato():
    r = ResultadoHerramienta(ok=True, herramienta="x", datos={
        "vence": "2026-11-22T23:59:59+00:00", "creado": "2020-01-01T00:00:00Z", "expires": None,
        "lista": [{"vence": "2027-01-01"}], "dias_para_vencer": 20})
    d = desplazar_fechas(r, 10).datos
    assert d["vence"] == "2026-12-02T23:59:59+00:00"
    assert d["creado"] == "2020-01-11T00:00:00Z"
    assert d["lista"][0]["vence"] == "2027-01-11"
    assert d["expires"] is None and d["dias_para_vencer"] == 20


def test_sin_datos_gasta_cupo_y_no_hace_bucle(tmp_path):
    subs = [f"s{i}.{DOMINIO}" for i in range(12)]
    grok = GrokGuion(resp(*BASE), resp(*[tls_de(h) for h in subs]),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = agent.auditar(DOMINIO, lote_id="L1", auditoria_id="A1", cliente_llm=grok,
                           ejecutor=Reproductor(caso(), hoy=GRABADO), ruta_logs=tmp_path)
    errores = [r.error for a, r in estado.llamadas if r.herramienta == "tls_certificado" and a["host"] in subs]
    assert errores == [SIN_DATOS] * 10
    assert estado.motivo_cierre == "informe_entregado" and estado.pasos == 3
