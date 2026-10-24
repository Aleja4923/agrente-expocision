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


def test_inexistente_sin_redundancia_ni_dkim():
    e = estado(nivel="bajo")
    e.llamadas = [({"dominio": D}, ResultadoHerramienta(ok=False, herramienta="dns_correo",
                                                         error="dominio_no_existe", sugerencia="x"))]
    md = generar_informe(e)
    assert "Resumen escrito por Grok" in md
    assert "No está registrado en internet" not in md  # Grok ya lo explica: sin párrafo repetido
    assert "DKIM" not in md


def test_inexistente_de_respaldo_conserva_explicacion_fija():
    e = estado(nivel="bajo", respaldo=True)
    e.llamadas = [({"dominio": D}, ResultadoHerramienta(ok=False, herramienta="dns_correo",
                                                         error="dominio_no_existe", sugerencia="x"))]
    assert "No está registrado en internet" in generar_informe(e)


def test_limitacion_primera_ip():
    seccion = generar_informe(estado()).split("## Lo que no se pudo verificar")[1]
    assert "primera dirección IP" in seccion


# --- S2: parecidos y registro del dominio ------------------------------------------------

from auditor.report import LIMITACION_PARECIDOS, limitaciones_de_parecidos  # noqa: E402


def _busqueda(*con_correo, sin_verificar=()):
    return ResultadoHerramienta(ok=True, herramienta="buscar_parecidos", datos={
        "dominio": D, "generadas": 27, "truncadas": False, "existentes": len(con_correo),
        "con_correo": [{"dominio": d, "tipo": "omision", "mx": ["mx.x.com"], "comparte_servidores": False}
                       for d in con_correo], "sin_verificar": list(sin_verificar), "ns_propios": [], "mx_propios": []})


def test_plantilla_parecido_lista_dominios_y_no_acusa():
    e = estado(["PARECIDO-ENVIA"], evidencias={"PARECIDO-ENVIA":
               "ejmplo.com.co: registrado hace 12 días, con MX, SPF autoriza envío; ejemplo.co: con MX"})
    md = generar_informe(e)
    bloque = md.split("**Reenvíe esto a su proveedor:**")[1].split("```")[1]
    assert "ejmplo.com.co" in bloque and "ejemplo.co" in bloque
    assert "Verifique si es suyo o de alguien conocido" in bloque
    assert "fraude" not in md.lower() and "falso" not in md.lower()


def test_plantillas_de_dominio():
    md = generar_informe(estado(["DOMINIO-POR-VENCER", "DOMINIO-SIN-BLOQUEO"]))
    assert "renovación automática" in md and "bloqueo de transferencia" in md


def test_limitacion_no_investigados():
    e = estado()
    e.llamadas += [({"dominio": D}, _busqueda("a.co", "b.co", "c.co")),
                   ({"dominio": D, "parecido": "a.co"}, ResultadoHerramienta(
                       ok=True, herramienta="investigar_parecido", datos={"parecido": "a.co"}))]
    assert limitaciones_de_parecidos(e) == [
        "Se encontraron 3 dominios parecidos con correo; se investigaron 1. Sin investigar: b.co, c.co."]


def test_limitacion_sin_verificar_y_registro():
    e = estado()
    e.llamadas += [({"dominio": D}, _busqueda(sin_verificar=["x.co"])),
                   ({"dominio": D}, ResultadoHerramienta(ok=False, herramienta="whois_dominio",
                                                         error="tld_no_soportado", sugerencia="s"))]
    textos = " ".join(limitaciones_de_parecidos(e))
    assert "x.co" in textos and "registro" in textos


def test_limitacion_fija_parecidos_y_pie_nuevo():
    md = generar_informe(estado())
    assert LIMITACION_PARECIDOS in md and "registro público de dominios" in md


# --- S2: subdominios por CT --------------------------------------------------------------

from auditor.report import limitaciones_de_subdominios  # noqa: E402


def _ct(*nombres, total=None):
    return ResultadoHerramienta(ok=True, herramienta="subdominios_ct", datos={
        "dominio": D, "fuente": "crtsh", "total": total or len(nombres), "mostrados": len(nombres),
        "truncados": False, "subdominios": [{"nombre": n, "ultimo_certificado_vence": None, "vigente": True}
                                            for n in nombres]})


def _tls(host):
    return ({"host": host}, ResultadoHerramienta(ok=True, herramienta="tls_certificado", datos={"host": host}))


def test_limitacion_subdominios_revisados():
    e = estado()
    e.llamadas += [({"dominio": D}, _ct("pagos." + D, "webmail." + D, "admin." + D, total=40)),
                   _tls(D), _tls("www." + D), _tls("pagos." + D)]
    assert limitaciones_de_subdominios(e) == [
        "En los registros de certificados aparecen 40 subdominios; se revisaron 1: pagos.ejemplo.com.co. "
        "Estos registros solo muestran sitios que tuvieron certificado HTTPS; puede haber otros."]


def test_limitacion_ct_fallo():
    e = estado()
    e.llamadas += [({"dominio": D}, ResultadoHerramienta(ok=False, herramienta="subdominios_ct",
                                                         error="ct_no_responde", sugerencia="s"))]
    assert "no se pudieron consultar" in limitaciones_de_subdominios(e)[0]


def test_limitaciones_de_subdominios_en_el_informe():
    e = estado()
    e.llamadas += [({"dominio": D}, _ct("pagos." + D))]
    assert "aparece 1 subdominio; no se revisó ninguno." in generar_informe(e)


def test_limitacion_subdominios_cuenta_cabeceras():
    e = estado()
    e.llamadas += [({"dominio": D}, _ct("b2b." + D, total=3)),
                   ({"host": "b2b." + D}, ResultadoHerramienta(ok=True, herramienta="cabeceras_web", datos={}))]
    assert "se revisaron 1: b2b.ejemplo.com.co." in limitaciones_de_subdominios(e)[0]


# --- S2: DKIM ----------------------------------------------------------------------------

from auditor.report import limitaciones_de_dkim  # noqa: E402


def _dkim(*selectores):
    return ({"dominio": D}, ResultadoHerramienta(ok=True, herramienta="dkim_selector", datos={
        "dominio": D, "selectores": [{"selector": s, "existe": e, "via_cname": False, "destino_cname": None,
                                      "destino_microsoft": False, "revocada": False, "tipo_clave": "rsa" if e else None,
                                      "bits": 2048 if e else None, "error": None} for s, e in selectores]}))


def test_dkim_sin_revisar_lo_dice():
    assert limitaciones_de_dkim(estado()) == [
        "DKIM (la firma digital de sus correos) no se revisó en esta auditoría, así que este informe no afirma "
        "nada sobre ella."]


def test_dkim_no_encontrado_lo_dice_con_los_selectores():
    e = estado()
    e.llamadas.append(_dkim(("default", False), ("k1", False)))
    assert limitaciones_de_dkim(e) == [
        "DKIM se buscó en los selectores default y k1 y no se encontró; si su proveedor usa otro nombre de "
        "selector, este informe no pudo verlo."]


def test_dkim_encontrado_no_es_limitacion():
    e = estado()
    e.llamadas.append(_dkim(("google", True)))
    assert limitaciones_de_dkim(e) == []


def test_ya_no_hay_limitacion_fija_de_dkim():
    e = estado()
    e.llamadas.append(_dkim(("google", True)))
    assert "no se revisa en esta versión" not in generar_informe(e)


@pytest.mark.parametrize("proveedor,texto", [("google", "Autenticar correo electrónico"),
                                             ("microsoft", "security.microsoft.com/authentication?viewid=DKIM"),
                                             ("otro", "pida a su proveedor de correo")])
def test_plantilla_dkim_activar_segun_proveedor(proveedor, texto):
    md = generar_informe(estado(["CORREO-DKIM-NO-ENCONTRADO"], proveedor=proveedor))
    assert texto in md


@pytest.mark.parametrize("proveedor,texto", [("google", "2048"), ("microsoft", "Rotate-DkimSigningConfig"),
                                             ("otro", "2048")])
def test_plantilla_dkim_rotar_segun_proveedor(proveedor, texto):
    md = generar_informe(estado(["CORREO-DKIM-CLAVE-1024"], proveedor=proveedor,
                                evidencias={"CORREO-DKIM-CLAVE-1024": "google: RSA de 1024 bits"}))
    assert texto in md.split("**Reenvíe esto a su proveedor:**")[1]


def test_endurecer_dmarc_avisa_si_no_hay_dkim():
    md = generar_informe(estado(["CORREO-DMARC-NONE", "CORREO-DKIM-NO-ENCONTRADO"]))
    assert "Sin DKIM, el paso a quarantine depende solo de SPF" in md


# --- S2: cabeceras y security.txt -------------------------------------------------------

@pytest.mark.parametrize("id_,texto", [
    ("WEB-SIN-REDIRECCION-HTTPS", "de http:// a https://"),
    ("WEB-SIN-HSTS", "Strict-Transport-Security: max-age=31536000"),
    ("WEB-SIN-PROTECCION-MARCOS", "frame-ancestors 'self'"),
    ("WEB-SIN-NOSNIFF", "X-Content-Type-Options: nosniff"),
    ("WEB-VERSION-EXPUESTA", "server_tokens off"),
])
def test_plantillas_de_cabeceras_usan_los_hosts(id_, texto):
    md = generar_informe(estado([id_], evidencias={id_: "www.ejemplo.com.co: detalle; tienda.ejemplo.com.co: detalle"}))
    bloque = md.split("**Reenvíe esto a su proveedor:**")[1].split("```")[1]
    assert texto in bloque and "www.ejemplo.com.co, tienda.ejemplo.com.co" in bloque


def test_plantilla_security_txt():
    md = generar_informe(estado(["WEB-SIN-SECURITY-TXT"]))
    assert f"https://{D}/.well-known/security.txt" in md and f"Contact: mailto:seguridad@{D}" in md


def test_limitacion_portada_si_se_revisaron_cabeceras():
    e = estado()
    e.llamadas.append(({"host": D}, ResultadoHerramienta(ok=True, herramienta="cabeceras_web", datos={"host": D})))
    assert "solo en la portada" in generar_informe(e)
    assert "solo en la portada" not in generar_informe(estado())


@pytest.mark.parametrize("total,inicio", [
    (0, "En los registros de certificados no aparece ningún subdominio."),
    (1, "En los registros de certificados aparece 1 subdominio; no se revisó ninguno."),
    (7, "En los registros de certificados aparecen 7 subdominios; no se revisó ninguno."),
])
def test_limitacion_subdominios_redaccion(total, inicio):
    e = estado()
    e.llamadas.append(({"dominio": D}, _ct(*[f"s{i}.{D}" for i in range(total)], total=total)))
    assert limitaciones_de_subdominios(e)[0].startswith(inicio)


# --- revisión: subdominios, DKIM sin respuesta y CT repetido ---------------------------------

def _tls_error(host, error):
    return ({"host": host}, ResultadoHerramienta(ok=False, herramienta="tls_certificado", error=error, sugerencia="s"))


def test_subdominios_solo_cuenta_revisiones_exitosas_y_normalizadas():
    e = estado()
    e.llamadas += [({"dominio": D}, _ct("pagos." + D, "b2b." + D, total=2)), _tls("Pagos." + D + "."),
                   _tls_error("otro-sitio.com", "fuera_de_alcance"), _tls_error("b2b." + D, "tiempo_agotado"),
                   _tls(D.upper())]
    assert "se revisaron 1: pagos.ejemplo.com.co." in limitaciones_de_subdominios(e)[0]


def test_subdominios_usa_la_ultima_consulta_exitosa():
    e = estado()
    e.llamadas += [({"dominio": D}, _ct("pagos." + D, total=9)),
                   ({"dominio": "pagos." + D}, ResultadoHerramienta(ok=False, herramienta="subdominios_ct",
                                                                   error="limite_de_consultas", sugerencia="s"))]
    assert limitaciones_de_subdominios(e)[0].startswith("En los registros de certificados aparecen 9 subdominios")


def test_dkim_selector_sin_respuesta_no_se_da_por_no_encontrado():
    e = estado()
    _, r = _dkim(("default", False))
    r.datos["selectores"].insert(0, {"selector": "google", "existe": False, "via_cname": False, "destino_cname": None,
                                     "destino_microsoft": False, "revocada": False, "tipo_clave": None, "bits": None,
                                     "error": "tiempo_agotado"})
    e.llamadas.append(({"dominio": D}, r))
    assert limitaciones_de_dkim(e) == [
        "DKIM se buscó en el selector default y no se encontró; si su proveedor usa otro nombre de selector, este "
        "informe no pudo verlo.",
        "El selector DKIM google no respondió en DNS, así que no se pudo verificar."]
