"""evals/casos.py: formato de un caso de evaluación, lectura y escritura."""

from datetime import date

import pytest
from pydantic import ValidationError

from auditor.modelos import ResultadoHerramienta
from evals.casos import Caso, cargar_casos, clave, guardar_caso


def caso(**cambios) -> Caso:
    datos = {
        "id": "fab-00", "origen": "fabricado", "perfil": "pyme_estandar", "grabado_el": date(2026, 11, 2),
        "dominio": "pymeñ-prueba.com.co", "objetivo": "Revisar la facturación electrónica",
        "grabacion": {clave("dns_correo", "fab-00.com.co"): ResultadoHerramienta(
            ok=True, herramienta="dns_correo", datos={"nota": "con tilde: facturación"})},
        "esperado": {"nivel_esperado": "medio", "hallazgos_obligatorios": ["CORREO-SPF-SUAVE"],
                     "hallazgos_por_decision": ["WEB-SIN-HSTS@pagos.fab-00.com.co"],
                     "hallazgos_prohibidos": ["WEB-SIN-SECURITY-TXT"], "cierre_esperado": "informe_entregado"},
        "marca_inyeccion": None,
    }
    return Caso.model_validate({**datos, **cambios})


def test_clave():
    assert clave("cabeceras_web", "www.fab-00.com.co") == "cabeceras_web|www.fab-00.com.co"


def test_caso_ida_y_vuelta(tmp_path):
    original = caso()
    ruta = guardar_caso(original, tmp_path)
    assert ruta.name == "fab-00.json"
    assert "facturación" in ruta.read_text(encoding="utf-8")
    assert cargar_casos(tmp_path) == [original]


def test_cargar_ordena_por_id(tmp_path):
    guardar_caso(caso(id="real-02"), tmp_path)
    guardar_caso(caso(id="fab-01"), tmp_path)
    assert [c.id for c in cargar_casos(tmp_path)] == ["fab-01", "real-02"]


def test_rechaza_perfil_desconocido():
    with pytest.raises(ValidationError):
        caso(perfil="mediana")


def test_rechaza_regla_inexistente():
    with pytest.raises(ValidationError, match="NO-EXISTE"):
        caso(esperado={"nivel_esperado": "bajo", "hallazgos_obligatorios": ["NO-EXISTE"],
                       "hallazgos_por_decision": [], "hallazgos_prohibidos": [],
                       "cierre_esperado": "informe_entregado"})


def test_rechaza_regla_inexistente_con_host():
    with pytest.raises(ValidationError, match="WEB-NADA"):
        caso(esperado={"nivel_esperado": "bajo", "hallazgos_obligatorios": [],
                       "hallazgos_por_decision": ["WEB-NADA@pagos.fab-00.com.co"], "hallazgos_prohibidos": [],
                       "cierre_esperado": "informe_entregado"})
