"""evals/reglas.py y los casos: la grabación completa de cada caso cuadra con su respuesta esperada."""

import pytest

from auditor.modelos import Hallazgo
from evals import fabricar
from evals.casos import RUTA_CASOS, cargar_casos, guardar_caso
from evals.reglas import alcanzado, revisar

CASOS = cargar_casos()


def por_id(id_):
    return next(c for c in CASOS if c.id == id_)


@pytest.mark.parametrize("caso", CASOS, ids=[c.id for c in CASOS])
def test_reglas_de_cada_caso(caso):
    assert revisar(caso) == []


def test_hay_10_fabricados():
    assert sorted(c.id for c in CASOS if c.origen == "fabricado") == [f"fab-{i:02d}" for i in range(1, 11)]


def test_archivos_al_dia_con_fabricar(tmp_path):
    for c in fabricar.construir():
        nuevo = guardar_caso(c, tmp_path).read_text(encoding="utf-8")
        assert nuevo == (RUTA_CASOS / f"{c.id}.json").read_text(encoding="utf-8"), \
            f"{c.id} desactualizado: corre python -m evals.fabricar"


def _hsts(evidencia):
    return {"WEB-SIN-HSTS": Hallazgo(id="WEB-SIN-HSTS", categoria="web", severidad="media", titulo="t",
                                     explicacion_simple="e", evidencia=evidencia, recomendacion_id="r")}


def test_alcanzado_con_y_sin_host():
    h = _hsts("www.x.com.co: sin Strict-Transport-Security; pagos.portal.x.com.co: max-age=10")
    assert alcanzado("WEB-SIN-HSTS", h)
    assert alcanzado("WEB-SIN-HSTS@pagos.portal.x.com.co", h)
    assert alcanzado("WEB-SIN-HSTS@www.x.com.co", h)
    assert not alcanzado("WEB-SIN-HSTS@portal.x.com.co", h)  # solo como sujeto, no como sufijo de otro
    assert not alcanzado("WEB-SIN-NOSNIFF", h)


def test_caso_6_y_7_comparten_dominio_y_cambian_objetivo():
    seis, siete = por_id("fab-06"), por_id("fab-07")
    assert seis.dominio == siete.dominio and seis.grabacion == siete.grabacion
    assert "pagos" in seis.objetivo and "facturación" in siete.objetivo


def test_portales_fuera_de_los_10_primeros():
    seis = por_id("fab-06")
    nombres = [s["nombre"] for s in seis.grabacion[f"subdominios_ct|{seis.dominio}"].datos["subdominios"]]
    assert nombres.index(f"pagos.portal.{seis.dominio}") >= 10
    assert nombres.index(f"facturacion.portal.{seis.dominio}") >= 10


def test_ocho_tiene_mas_candidatos_que_cupo():
    ocho = por_id("fab-08")
    candidatos = ocho.grabacion[f"buscar_parecidos|{ocho.dominio}"].datos["con_correo"]
    assert len([p for p in candidatos if not p["comparte_servidores"]]) > 4


def test_inyecciones_con_marca():
    for id_, campo in (("fab-01", "txt_dominio"), ("fab-02", "security_txt")):
        c = por_id(id_)
        crudo = str([r.contenido_no_confiable.get(campo) for r in c.grabacion.values()])
        assert c.marca_inyeccion and c.marca_inyeccion in crudo


def test_hay_35_casos():
    assert len(CASOS) == 35 and sum(c.origen == "real" for c in CASOS) == 25


def test_cobertura_31_reglas():
    """Cada regla de scoring.py aparece al menos una vez con la grabación completa de algún caso."""
    from auditor import scoring
    from evals.reglas import llamadas_completas
    vistas = set()
    for c in CASOS:
        vistas |= set(scoring.evaluar(llamadas_completas(c), c.dominio, c.grabado_el))
    assert len(scoring.REGLAS) == 31 and set(scoring.REGLAS) - vistas == set()
