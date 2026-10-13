"""report.py: informe Markdown para el dueño, con el dato técnico exacto por recomendación."""

from datetime import datetime, timezone

import pytest

from auditor.modelos import (AccionPriorizada, EstadoAuditoria, InformeFinal, MotivoCierre, NivelRiesgo,
                             ResultadoHerramienta)
from auditor.report import PLANTILLAS, generar_informe, guardar_informe
from auditor.scoring import REGLAS, _hallazgo
from tests.test_scoring import correo

D = "ejemplo.com.co"


def estado(ids=(), acciones=None, proveedor="google", nivel="alto", respaldo=False, limitaciones=None,
           evidencias=None):
    evidencias = evidencias or {}
    hallazgos = {i: _hallazgo(i, evidencias.get(i, "evidencia de prueba")) for i in ids}
    acciones = acciones if acciones is not None else [
        AccionPriorizada(hallazgo_id=i, por_que_primero=f"Porque {i} es importante.",
                         recomendacion=f"Recomendación de Grok para {i}.") for i in ids]
    datos = correo(mx={"proveedor": proveedor, "servidores": [] if proveedor == "ninguno" else
                       [{"prioridad": 1, "host": "smtp.google.com"}]})
    e = EstadoAuditoria(dominio=D, lote_id="L1", auditoria_id="A1", modelo="grok-4.7", pasos=3, costo_usd=0.0213,
                        inicio=datetime(2026, 10, 12, 21, 40, tzinfo=timezone.utc))
    e.llamadas = [({"dominio": D}, ResultadoHerramienta(ok=True, herramienta="dns_correo", datos=datos))]
    e.hallazgos = hallazgos
    e.informe = InformeFinal(resumen="Resumen escrito por Grok para el dueño.", hallazgos_citados=list(ids),
                             acciones_priorizadas=acciones, limitaciones=limitaciones or ["Límite de Grok."])
    e.nivel_riesgo = NivelRiesgo(nivel)
    e.informe_de_respaldo = respaldo
    e.motivo_cierre = MotivoCierre.INFORME_ENTREGADO
    return e


SECCIONES = ["## Qué hacer primero", "## Hallazgos", "## Verificaciones sugeridas",
             "## Lo que no se pudo verificar"]


def test_toda_regla_tiene_plantilla():
    assert {r[4] for r in REGLAS.values()} <= set(PLANTILLAS)


def test_secciones_en_orden():
    md = generar_informe(estado(["CORREO-DMARC-AUSENTE", "WEB-TLS-INVALIDO"]))
    posiciones = [md.index(s) for s in SECCIONES]
    assert posiciones == sorted(posiciones)
    assert md.startswith(f"# Informe de exposición digital · {D}")
    assert md.index("Resumen escrito por Grok") < md.index(SECCIONES[0])


@pytest.mark.parametrize("nivel,icono", [("alto", "🔴"), ("medio", "🟡"), ("bajo", "🟢")])
def test_semaforo(nivel, icono):
    assert f"{icono} {nivel.upper()}" in generar_informe(estado(nivel=nivel))


def test_accion_lleva_recomendacion_de_grok_y_bloque_tecnico():
    md = generar_informe(estado(["CORREO-DMARC-AUSENTE"]))
    assert "Recomendación de Grok para CORREO-DMARC-AUSENTE." in md
    assert "Reenvíe esto a su proveedor" in md
    assert f"v=DMARC1; p=none; rua=mailto:dmarc@{D}" in md
    assert "p=reject" not in md.split("## Hallazgos")[0]  # nunca se recomienda endurecer de entrada


@pytest.mark.parametrize("proveedor,esperado", [
    ("google", "v=spf1 include:_spf.google.com ~all"),
    ("microsoft", "v=spf1 include:spf.protection.outlook.com -all"),
    ("otro", "el include que le indique su proveedor de correo"),
])
def test_spf_segun_proveedor(proveedor, esperado):
    assert esperado in generar_informe(estado(["CORREO-SPF-AUSENTE"], proveedor=proveedor))


def test_spf_sin_mx_recomienda_menos_all():
    md = generar_informe(estado(["CORREO-SPF-AUSENTE"], proveedor="ninguno"))
    assert "v=spf1 -all" in md and "include:" not in md


def test_tls_usa_hosts_de_la_evidencia():
    md = generar_informe(estado(["WEB-TLS-INVALIDO"], evidencias={
        "WEB-TLS-INVALIDO": f"{D}: vencido (venció el 2026-10-01); pagos.{D}: autofirmado"}))
    assert f"{D}, pagos.{D}" in md


def test_verificacion_dian_si_hay_hallazgo_dmarc():
    md = generar_informe(estado(["CORREO-DMARC-NONE"]))
    assert "facturas electrónicas" in md.split("## Verificaciones sugeridas")[1]
    assert "facturas electrónicas" not in generar_informe(estado(["WEB-TLS-INVALIDO"]))


def test_limitacion_dkim_siempre():
    md = generar_informe(estado())
    seccion = md.split("## Lo que no se pudo verificar")[1]
    assert "DKIM" in seccion and "Límite de Grok." in seccion


def test_informe_de_respaldo_lo_dice():
    md = generar_informe(estado(["CORREO-DMARC-AUSENTE"], respaldo=True))
    assert "se armó automáticamente" in md.split("## Qué hacer primero")[0]


def test_dominio_sano():
    md = generar_informe(estado(nivel="bajo"))
    assert "No encontramos aspectos que requieran acción" in md
    assert "Reenvíe esto" not in md


def test_hallazgos_con_evidencia_y_sin_ids_sueltos():
    md = generar_informe(estado(["CORREO-DMARC-NONE"], evidencias={"CORREO-DMARC-NONE": "política p=none"}))
    hallazgos = md.split("## Hallazgos")[1].split("## Verificaciones")[0]
    assert REGLAS["CORREO-DMARC-NONE"][2] in hallazgos and "política p=none" in hallazgos
    assert REGLAS["CORREO-DMARC-NONE"][3] in hallazgos


def test_pie_con_costo_modelo_y_id():
    pie = generar_informe(estado()).split("\n---\n")[-1]
    for texto in ("grok-4.7", "USD 0.0213", "A1", "2026-10-12", "pasiva"):
        assert texto in pie


def test_guardar_informe_utf8(tmp_path):
    ruta = guardar_informe(estado(["CORREO-DMARC-AUSENTE"]), tmp_path)
    assert ruta.parent == tmp_path and ruta.name.startswith(f"{D}-") and ruta.suffix == ".md"
    assert "exposición" in ruta.read_text(encoding="utf-8")


def test_sin_mx_pero_envia_correo_no_sugiere_reject():
    # Sin MX pero con SPF que autoriza servidores: el dominio SÍ envía correo (p. ej. boletines).
    e = estado(["CORREO-SIN-MX", "CORREO-DMARC-NONE"], proveedor="ninguno")
    e.llamadas[0][1].datos["spf"]["registros"] = ["v=spf1 include:envios.ejemplo-masivo.com -all"]
    accion_mx = generar_informe(e).split("### 1.")[1].split("### 2.")[0]  # la acción de CORREO-SIN-MX
    assert "autoriza servidores para enviar correo" in accion_mx
    assert "p=reject" not in accion_mx


def test_sin_mx_y_sin_envio_sugiere_configuracion_nula():
    e = estado(["CORREO-SIN-MX"], proveedor="ninguno")
    e.llamadas[0][1].datos["spf"]["registros"] = ["v=spf1 -all"]
    assert "MX nulo" in generar_informe(e)


def test_dmarc_duplicado_conserva_la_politica_mas_estricta():
    e = estado(["CORREO-DMARC-INVALIDO"])
    e.llamadas[0][1].datos["dmarc"].update({"multiple": True, "valido": False, "p": None,
                                            "politica_mas_estricta": "reject"})
    bloque = generar_informe(e).split("## Hallazgos")[0]
    assert "p=reject" in bloque and "p=none" not in bloque


def test_sin_mx_ni_envio_es_coherente_con_dmarc_y_spf():
    # Caso real (fase 8, perfil B): sin MX, sin SPF, sin DMARC. Antes salían p=none y p=reject sin aclarar.
    e = estado(["CORREO-DMARC-AUSENTE", "CORREO-SPF-AUSENTE", "CORREO-SIN-MX"], proveedor="ninguno")
    e.llamadas[0][1].datos["spf"]["registros"] = []
    md = generar_informe(e)
    accion_spf = md.split("### 2.")[1].split("### 3.")[0]
    assert "v=spf1 -all" in accion_spf and "si sí envía" in accion_spf.lower()
    accion_mx = md.split("### 3.")[1].split("## Hallazgos")[0]
    assert "en lugar de los pasos anteriores" in accion_mx


def test_dominio_inexistente_sin_semaforo_ni_acciones():
    # Caso real (fase 8, perfil E): antes decía "🟢 BAJO" y "no requiere acción", que es engañoso.
    e = estado(nivel="bajo")
    e.llamadas = [({"dominio": D}, ResultadoHerramienta(ok=False, herramienta="dns_correo",
                                                         error="dominio_no_existe", sugerencia="x"))]
    md = generar_informe(e)
    assert f"**El dominio {D} no existe**" in md
    for ausente in ("Nivel de riesgo", "🟢", "## Qué hacer primero", "## Verificaciones sugeridas", "## Hallazgos"):
        assert ausente not in md
    assert "Resumen escrito por Grok" in md and "## Lo que no se pudo verificar" in md
    assert "\n---\n" in md
