"""modelos.py: el contrato de datos rechaza lo que no tiene la forma correcta."""

import pytest
from pydantic import ValidationError

from auditor.modelos import (
    AccionPriorizada,
    Hallazgo,
    InformeFinal,
    NivelRiesgo,
    ResultadoHerramienta,
)


def hallazgo(**cambios):
    datos = dict(
        id="CORREO-DMARC-AUSENTE",
        categoria="correo",
        severidad="critica",
        titulo="No hay DMARC",
        explicacion_simple="Cualquiera puede enviar correos haciéndose pasar por usted.",
        evidencia="_dmarc.ejemplo.com.co: sin registro TXT",
        recomendacion_id="REC-DMARC-CREAR",
    )
    return Hallazgo(**(datos | cambios))


def test_hallazgo_valido():
    assert hallazgo().severidad == "critica"


def test_severidad_inventada_se_rechaza():
    with pytest.raises(ValidationError):
        hallazgo(severidad="gravisima")


def test_id_de_hallazgo_con_formato_incorrecto_se_rechaza():
    with pytest.raises(ValidationError):
        hallazgo(id="dmarc ausente")


def test_contenido_no_confiable_se_recorta_a_300():
    largo = "v=spf1 " + "include:x.com " * 100
    r = ResultadoHerramienta(
        ok=True,
        herramienta="dns_correo",
        contenido_no_confiable={"txt": [largo, "corto"], "anidado": {"t": largo}},
    )
    assert len(r.contenido_no_confiable["txt"][0]) == 301
    assert r.contenido_no_confiable["txt"][0].endswith("…")
    assert r.contenido_no_confiable["txt"][1] == "corto"
    assert len(r.contenido_no_confiable["anidado"]["t"]) == 301


def test_resultado_fallido_exige_codigo_de_error():
    with pytest.raises(ValidationError):
        ResultadoHerramienta(ok=False, herramienta="dns_correo")
    r = ResultadoHerramienta(ok=False, herramienta="dns_correo", error="dominio_no_existe")
    assert r.error == "dominio_no_existe"


def test_resultado_exitoso_no_puede_traer_error():
    with pytest.raises(ValidationError):
        ResultadoHerramienta(ok=True, herramienta="dns_correo", error="tiempo_agotado")


def test_informe_sin_hallazgos_es_valido():
    # Un dominio bien configurado: el agente no debe inventar problemas.
    informe = InformeFinal(
        resumen="Su dominio está bien protegido.",
        nivel_riesgo="bajo",
        hallazgos_citados=[],
        acciones_priorizadas=[],
    )
    assert informe.nivel_riesgo is NivelRiesgo.BAJO


def test_accion_que_cita_hallazgo_no_listado_se_rechaza():
    with pytest.raises(ValidationError):
        InformeFinal(
            resumen="r",
            nivel_riesgo="alto",
            hallazgos_citados=["CORREO-SPF-AUSENTE"],
            acciones_priorizadas=[AccionPriorizada(hallazgo_id="CORREO-DMARC-AUSENTE",
                                                   por_que_primero="p")],
        )


def test_informe_rechaza_campos_extra():
    with pytest.raises(ValidationError):
        InformeFinal(resumen="r", nivel_riesgo="medio", hallazgos_citados=[],
                     acciones_priorizadas=[], recomendacion_libre="algo inventado")


def test_schema_del_informe_sirve_como_herramienta_para_grok():
    schema = InformeFinal.model_json_schema()
    assert set(schema["required"]) == {"resumen", "nivel_riesgo", "hallazgos_citados",
                                       "acciones_priorizadas"}
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["NivelRiesgo"]["enum"] == ["alto", "medio", "bajo"]
