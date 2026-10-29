"""Informe HTML imprimible (A4) para el dueño de la pyme.

Dibuja el mismo `report.contenido(estado)` que el Markdown, así las dos salidas nunca dicen
cosas distintas. Es un solo archivo: CSS embebido, sin JavaScript ni recursos externos, para
que se abra sin internet, se imprima o se reenvíe tal cual. Todo el texto pasa por
html.escape, también el que escribió Grok: un "<script>" en un registro TXT o en el resumen
se muestra como texto y nunca se ejecuta.
"""

from html import escape

from auditor.modelos import EstadoAuditoria
from auditor.report import AVISO_RESPALDO, SEVERIDAD_LEGIBLE, contenido, titulo_del_nivel

ESTILOS = """
:root { --texto: #1c2430; --suave: #5b6675; --borde: #d9dee5; --fondo: #ffffff; --panel: #f5f7fa;
        --alto: #b42318; --medio: #b54708; --bajo: #067647; --acento: #1d4ed8; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--fondo); color: var(--texto);
       font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; }
main { max-width: 820px; margin: 0 auto; padding: 32px 20px 48px; }
header { border-bottom: 2px solid var(--texto); padding-bottom: 12px; margin-bottom: 20px; }
.marca { margin: 0; color: var(--suave); font-size: 13px; letter-spacing: .04em; text-transform: uppercase; }
h1 { margin: 4px 0 2px; font-size: 26px; line-height: 1.2; }
.dominio { margin: 0; font-size: 18px; color: var(--suave); overflow-wrap: anywhere; }
h2 { font-size: 19px; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--borde); }
h3 { font-size: 16px; margin: 0 0 4px; }
.semaforo { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-radius: 8px;
            border: 2px solid currentColor; font-size: 18px; margin: 0 0 16px; }
.semaforo .punto { width: 16px; height: 16px; border-radius: 50%; background: currentColor; flex: none; }
.nivel-alto { color: var(--alto); } .nivel-medio { color: var(--medio); } .nivel-bajo { color: var(--bajo); }
.no-existe { color: var(--texto); }
.resumen { font-size: 16px; white-space: pre-line; }
.aviso { background: var(--panel); border-left: 4px solid var(--medio); padding: 10px 14px; }
ol.acciones { list-style: none; padding: 0; margin: 0; counter-reset: accion; }
.accion, .hallazgo { border: 1px solid var(--borde); border-radius: 8px; padding: 14px 16px; margin: 0 0 14px; }
.accion h3::before { counter-increment: accion; content: counter(accion) ". "; }
.meta { margin: 0 0 8px; color: var(--suave); font-size: 13px; }
.sev { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600;
       border: 1px solid currentColor; vertical-align: middle; }
.sev-critica, .sev-alta { color: var(--alto); } .sev-media { color: var(--medio); }
.sev-baja, .sev-informativa { color: var(--suave); }
.reenvio { background: var(--panel); border-radius: 6px; padding: 10px 12px; margin-top: 10px; }
.reenvio .etiqueta { margin: 0 0 6px; font-weight: 600; font-size: 13px; }
pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere;
      font: 13px/1.5 ui-monospace, "Cascadia Mono", Consolas, monospace; }
code { font: 13px ui-monospace, "Cascadia Mono", Consolas, monospace; overflow-wrap: anywhere; }
.evidencia { margin: 6px 0 0; font-size: 14px; }
ul.limitaciones li { margin-bottom: 4px; }
footer { margin-top: 36px; padding-top: 12px; border-top: 1px solid var(--borde); color: var(--suave);
         font-size: 12.5px; }
@page { size: A4; margin: 16mm 14mm; }
@media print {
  body { font-size: 11pt; }
  main { max-width: none; padding: 0; }
  .semaforo, .accion, .hallazgo, .reenvio, .aviso { break-inside: avoid; }
  .pagina-nueva { break-before: page; }
  .reenvio, .aviso { background: none; border: 1px solid var(--borde); }
}
"""

NIVEL_TEXTO = {"alto": "ALTO", "medio": "MEDIO", "bajo": "BAJO"}


def _parrafo(texto: str, clase: str = "") -> str:
    atributo = f' class="{clase}"' if clase else ""
    return f"<p{atributo}>{escape(texto)}</p>"


def generar_informe_html(estado: EstadoAuditoria) -> str:
    c = contenido(estado)
    partes = ["<header>", '<p class="marca">Auditor de exposición digital · revisión pasiva</p>',
              "<h1>Informe de exposición digital</h1>", f'<p class="dominio">{escape(c.dominio)}</p>', "</header>"]
    if c.no_existe:
        partes += ['<div class="semaforo no-existe">', f"<strong>El dominio {escape(c.dominio)} no existe</strong>",
                   "</div>", _parrafo(c.resumen, "resumen")]
        if c.explicacion_no_existe:
            partes.append(_parrafo(c.explicacion_no_existe))
    else:
        nivel = c.nivel.value
        partes += [f'<div class="semaforo nivel-{nivel}"><span class="punto" aria-hidden="true"></span>',
                   f"<strong>{titulo_del_nivel(c)}: {NIVEL_TEXTO[nivel]}</strong></div>"]
        if c.aviso_subdominios:
            partes.append(_parrafo(c.aviso_subdominios, "aviso-subdominios"))
        partes.append(_parrafo(c.resumen, "resumen"))
        if c.respaldo:
            partes.append(_parrafo(AVISO_RESPALDO.removeprefix("> "), "aviso"))

        partes += ["<section>", "<h2>Qué hacer primero</h2>"]
        if not c.acciones:
            partes.append(_parrafo("No encontramos aspectos que requieran acción en lo que revisamos."))
        else:
            partes.append('<ol class="acciones">')
            for a in c.acciones:
                partes += [f'<li class="accion">', f"<h3>{escape(a.titulo)}</h3>",
                           f'<p class="meta"><span class="sev sev-{_clase(a.severidad)}">{escape(a.severidad)}</span>'
                           f" · {escape(a.id)}</p>",
                           _parrafo(a.recomendacion),
                           f"<p><strong>Por qué va en este lugar:</strong> {escape(a.por_que)}</p>",
                           '<div class="reenvio"><p class="etiqueta">Reenvíe esto a su proveedor:</p>',
                           f"<pre>{escape(a.bloque)}</pre></div>", "</li>"]
            partes.append("</ol>")
        partes.append("</section>")

        partes += ['<section class="pagina-nueva">', "<h2>Hallazgos</h2>"]
        if not c.hallazgos:
            partes.append(_parrafo("No se encontraron hallazgos."))
        for h in c.hallazgos:
            severidad = SEVERIDAD_LEGIBLE[h.severidad.value]
            partes += ['<article class="hallazgo">',
                       f'<h3>{escape(h.titulo)} <span class="sev sev-{_clase(severidad)}">{escape(severidad)}</span>'
                       "</h3>", _parrafo(h.explicacion_simple),
                       f'<p class="evidencia">Evidencia: <code>{escape(h.evidencia)}</code></p>', "</article>"]
        partes.append("</section>")

        partes += ["<section>", "<h2>Verificaciones sugeridas</h2>"]
        if c.verificaciones:
            partes += ["<ul>", *[f"<li>{escape(v)}</li>" for v in c.verificaciones], "</ul>"]
        else:
            partes.append(_parrafo("Ninguna por ahora."))
        partes.append("</section>")

    partes += ["<section>", "<h2>Lo que no se pudo verificar</h2>", '<ul class="limitaciones">',
               *[f"<li>{escape(limitacion)}</li>" for limitacion in c.limitaciones], "</ul>", "</section>",
               f"<footer>{escape(c.pie)}</footer>"]
    cuerpo = "\n".join(partes)
    return (f'<!doctype html>\n<html lang="es">\n<head>\n<meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>Informe de exposición digital · {escape(c.dominio)}</title>\n"
            f"<style>{ESTILOS}</style>\n</head>\n<body>\n<main>\n{cuerpo}\n</main>\n</body>\n</html>\n")


def _clase(severidad_legible: str) -> str:
    return {"crítica": "critica"}.get(severidad_legible, severidad_legible)
