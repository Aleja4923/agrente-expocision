"""report_html.py: el mismo informe en HTML imprimible (A4), sin recursos externos y con todo escapado."""

import re
from html import escape

from auditor.modelos import InformeFinal, ResultadoHerramienta
from auditor.report import contenido, guardar_informe
from auditor.report_html import generar_informe_html
from tests.test_report import D, estado

SECCIONES = ["Qué hacer primero", "Hallazgos", "Verificaciones sugeridas", "Lo que no se pudo verificar"]


def test_secciones_en_el_mismo_orden_que_el_markdown():
    html = generar_informe_html(estado(["CORREO-DMARC-AUSENTE", "WEB-TLS-INVALIDO"]))
    posiciones = [html.index(f">{s}</h2>") for s in SECCIONES]
    assert posiciones == sorted(posiciones)


def test_dice_lo_mismo_que_el_markdown():
    e = estado(["CORREO-DMARC-NONE", "PARECIDO-ENVIA"],
               evidencias={"PARECIDO-ENVIA": "ejmplo.com.co: registrado hace 3 días, con MX"})
    html, c = generar_informe_html(e), contenido(e)
    for a in c.acciones:
        assert escape(a.titulo) in html and escape(a.recomendacion) in html and escape(a.bloque) in html
    for limitacion in c.limitaciones:
        assert escape(limitacion) in html
    assert escape(c.pie) in html


def test_texto_de_grok_sale_escapado():
    e = estado(["CORREO-DMARC-NONE"])
    e.informe = InformeFinal(resumen="<script>alert('x')</script> & <b>negrita</b>",
                             hallazgos_citados=["CORREO-DMARC-NONE"], acciones_priorizadas=[], limitaciones=[])
    html = generar_informe_html(e)
    assert "<script" not in html and "<b>negrita" not in html
    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt; &amp; &lt;b&gt;negrita&lt;/b&gt;" in html


def test_sin_recursos_externos_ni_javascript():
    html = generar_informe_html(estado(["CORREO-DKIM-NO-ENCONTRADO"], proveedor="microsoft"))
    for prohibido in ("<script", "<link", "src=", "url(", "@import", "<iframe", "<img"):
        assert prohibido not in html


def test_imprimible_en_a4():
    html = generar_informe_html(estado())
    assert "@page" in html and "size: A4" in html and "@media print" in html
    assert html.startswith("<!doctype html>") and '<html lang="es">' in html and 'charset="utf-8"' in html


def test_semaforo_con_texto_y_no_solo_color():
    html = generar_informe_html(estado(["CORREO-DMARC-AUSENTE"], nivel="alto"))
    assert re.search(r'class="semaforo nivel-alto"', html) and "Nivel de riesgo: ALTO" in html


def test_dominio_inexistente_sin_semaforo():
    e = estado()
    e.llamadas = [({"dominio": D}, ResultadoHerramienta(ok=False, herramienta="dns_correo", error="dominio_no_existe",
                                                        sugerencia="s"))]
    html = generar_informe_html(e)
    assert f"El dominio {D} no existe" in html and "Nivel de riesgo" not in html


def test_guardar_informe_escribe_md_y_html(tmp_path):
    ruta = guardar_informe(estado(["CORREO-DMARC-AUSENTE"]), tmp_path)
    html = ruta.with_suffix(".html")
    assert ruta.suffix == ".md" and html.exists()
    assert html.read_text(encoding="utf-8").startswith("<!doctype html>")
