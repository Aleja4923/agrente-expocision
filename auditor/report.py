"""Informe Markdown para el dueño de la pyme.

Grok aporta el resumen, el orden y el texto de cada recomendación. El código aporta los
hallazgos con su evidencia y el DATO TÉCNICO EXACTO de cada recomendación (plantillas
fijas por recomendacion_id): así nadie copia en su DNS un registro inventado por el LLM.
Nunca se copia contenido no confiable al informe.
"""

from datetime import datetime
from pathlib import Path
from typing import Callable

from auditor.config import RUTA_SALIDAS
from auditor.modelos import EstadoAuditoria, Hallazgo, NivelRiesgo
from auditor.tools.correo import spf_autoriza_envio

SEMAFORO = {NivelRiesgo.ALTO: "🔴", NivelRiesgo.MEDIO: "🟡", NivelRiesgo.BAJO: "🟢"}
SEVERIDAD_LEGIBLE = {"critica": "crítica", "alta": "alta", "media": "media", "baja": "baja",
                     "informativa": "informativa"}

LIMITACION_PRIMERA_IP = ("El certificado se revisó en la primera dirección IP de cada sitio; si un sitio tiene "
                         "varias, no se revisaron todas.")
LIMITACION_DKIM = ("DKIM (la firma digital de sus correos) no se revisa en esta versión, así que este "
                   "informe no afirma nada sobre ella.")
LIMITACION_PARECIDOS = ("La búsqueda de dominios parecidos cubre errores de tipeo frecuentes y los dominios .co, "
                        ".com.co y .com; no cubre todos los nombres posibles ni letras de otros alfabetos. A estos "
                        "dominios solo se les consultó DNS y el registro público; nunca se visitó su sitio web.")
AVISO_RESPALDO = ("> Este informe se armó automáticamente con los hallazgos verificados porque la revisión "
                  "se detuvo antes de tiempo. Los hallazgos son correctos; el texto es más breve de lo habitual.")


def _hosts(evidencia: str) -> str:
    """'a.co: vencido; b.co: autofirmado' -> 'a.co, b.co'."""
    return ", ".join(parte.split(":", 1)[0].strip() for parte in evidencia.split("; "))


def _spf_crear(d: str, ctx: dict) -> str:
    proveedor = ctx.get("proveedor", "otro")
    if proveedor == "ninguno":
        return (f"Si {d} no envía correo, publicar un registro TXT en {d}:\nv=spf1 -all\n"
                f"Si sí envía (por ejemplo, desde una tienda en línea o un servicio de boletines), publicar en "
                f"su lugar el registro que indique ese servicio, terminando en ~all.")
    registro = {
        "google": "v=spf1 include:_spf.google.com ~all",
        "microsoft": "v=spf1 include:spf.protection.outlook.com -all",
    }.get(proveedor)
    if registro:
        texto = f"Publicar un registro TXT en {d}:\n{registro}"
    else:
        texto = (f"Publicar un registro TXT en {d} con el include que le indique su proveedor de correo, "
                 "terminando en ~all:\nv=spf1 include:<servidor de su proveedor> ~all")
    return texto + (f"\nAntes, confirme qué otros servicios envían correo con @{d} (tienda en línea, "
                    "boletines, facturación) y agréguelos al mismo registro.")


PLANTILLAS: dict[str, Callable[[str, dict], str]] = {
    "REC-DMARC-CREAR": lambda d, ctx: (
        f"Publicar un registro TXT en _dmarc.{d}:\nv=DMARC1; p=none; rua=mailto:dmarc@{d}\n"
        f"(Cree el buzón dmarc@{d} o cambie la dirección por una que alguien revise.)"),
    "REC-DMARC-CORREGIR": lambda d, ctx: (
        f"Dejar un único registro TXT en _dmarc.{d}, conservando la política más estricta que ya tiene "
        f"(p={ctx['politica_dmarc']}) y uniendo en él las direcciones rua de los registros actuales:\n"
        f"v=DMARC1; p={ctx['politica_dmarc']}; rua=mailto:dmarc@{d}"
        if ctx.get("politica_dmarc") else
        f"Dejar un único registro TXT en _dmarc.{d}, con este formato:\nv=DMARC1; p=none; rua=mailto:dmarc@{d}"),
    "REC-DMARC-ENDURECER": lambda d, ctx: (
        f"Después de revisar los reportes de DMARC durante 2 a 4 semanas y confirmar qué servicios envían "
        f"correo legítimo con @{d}:\n"
        f"1. En _dmarc.{d}, cambiar p=none por p=quarantine (puede agregar t=y para probar primero).\n"
        f"2. Cuando todo funcione, cambiar a p=reject."),
    "REC-DMARC-RUA": lambda d, ctx: f"Agregar al registro TXT de _dmarc.{d} la etiqueta:\nrua=mailto:dmarc@{d}",
    "REC-DMARC-OBSOLETO": lambda d, ctx: (
        f"En la próxima actualización del registro _dmarc.{d}, quitar las etiquetas "
        f"{ctx['evidencia'].removeprefix('etiquetas: ')} (el estándar actual, RFC 9989, ya no las usa)."),
    "REC-SPF-CREAR": _spf_crear,
    "REC-SPF-UNIR": lambda d, ctx: (
        f"Dejar un solo registro TXT que empiece por v=spf1 en {d}, uniendo en él todos los include e ip "
        f"de los registros actuales, y borrar los demás."),
    "REC-SPF-CERRAR": lambda d, ctx: (
        f"Cambiar el final del registro SPF de {d} por ~all (o por -all cuando haya confirmado todos los "
        f"servicios que envían correo con @{d})."),
    "REC-SPF-SIMPLIFICAR": lambda d, ctx: (
        f"Reducir el registro SPF de {d} a 10 consultas DNS como máximo (hoy: {ctx['evidencia']}): quitar los "
        f"include de servicios que ya no use o reemplazarlos por sus rangos ip4/ip6."),
    "REC-SIN-MX": lambda d, ctx: (
        f"{d} no tiene servidores MX, pero su SPF autoriza servidores para enviar correo (por ejemplo, "
        f"boletines). Confirmar que no necesita recibir respuestas en {d}; si las necesita, configurar sus MX. "
        f"No endurecer DMARC fuera del paso gradual."
        if ctx.get("envia_correo") else
        (f"Si confirma que {d} no envía ni recibe correo, puede publicar esta configuración en lugar de los "
         f"pasos anteriores de DMARC y SPF (sin correo legítimo, no hace falta la fase de observación):\n"
         if ctx.get("otros_de_correo") else f"Si {d} no envía ni recibe correo, publicar:\n")
        + f"- TXT en {d}: v=spf1 -all\n"
        f"- TXT en _dmarc.{d}: v=DMARC1; p=reject\n- (opcional) MX nulo en {d}: 0 .  (RFC 7505)"),
    "REC-TLS-RENOVAR": lambda d, ctx: (
        f"Renovar o reinstalar el certificado HTTPS de: {_hosts(ctx['evidencia'])}.\n"
        f"Conviene activar la renovación automática (por ejemplo, con Let's Encrypt)."),
    "REC-TLS-VERSION": lambda d, ctx: (
        f"Desactivar TLS 1.0 y TLS 1.1 en el servidor de: {_hosts(ctx['evidencia'])}; dejar habilitados solo "
        f"TLS 1.2 y TLS 1.3."),
    "REC-PARECIDO-VERIFICAR": lambda d, ctx: (
        f"Dominios parecidos a {d}: {_hosts(ctx['evidencia'])}\n"
        f"1. Verifique si es suyo o de alguien conocido (su agencia, su proveedor) antes de alertar a sus clientes.\n"
        f"2. Si no lo es y ve correos sospechosos, guarde la evidencia y repórtelo al registrador del dominio y al "
        f"CAI Virtual de la Policía Nacional.\n"
        f"3. Puede registrar a su nombre las variantes más cercanas (registro defensivo)."),
    "REC-DOMINIO-RENOVAR": lambda d, ctx: (
        f"Renovar el dominio {d} con su registrador ({ctx['evidencia']}) y activar la renovación automática, con "
        f"un medio de pago vigente y un correo de contacto que alguien revise."),
    "REC-DOMINIO-BLOQUEO": lambda d, ctx: (
        f"Pedir al registrador de {d} que active el bloqueo de transferencia (Registrar Lock / "
        f"clientTransferProhibited). Se quita solo cuando usted decida cambiar de registrador."),
    "REC-HTTPS": lambda d, ctx: (
        f"Instalar un certificado HTTPS en: {_hosts(ctx['evidencia'])} (puede ser gratuito, por ejemplo con "
        f"Let's Encrypt) y redirigir todo el tráfico de http a https."),
}


def _datos_correo(estado: EstadoAuditoria) -> dict:
    """Datos del último dns_correo exitoso sobre el dominio objetivo (vacío si no hay)."""
    for _, r in reversed(estado.llamadas):
        if r.herramienta == "dns_correo" and r.ok and r.datos.get("dominio") == estado.dominio:
            return r.datos
    return {}


def _envia_correo(datos: dict) -> bool:
    """True si el SPF autoriza algún servidor (algo más que el cierre 'all')."""
    return spf_autoriza_envio(datos.get("spf", {}).get("registros", [])[:1])


def _bloque_tecnico(estado: EstadoAuditoria, h: Hallazgo) -> str:
    datos = _datos_correo(estado)
    contexto = {"proveedor": datos.get("mx", {}).get("proveedor", "otro"), "evidencia": h.evidencia,
                "envia_correo": _envia_correo(datos),
                "politica_dmarc": datos.get("dmarc", {}).get("politica_mas_estricta"),
                "otros_de_correo": any(i.startswith(("CORREO-DMARC", "CORREO-SPF")) for i in estado.hallazgos)}
    return PLANTILLAS[h.recomendacion_id](estado.dominio, contexto)


def generar_informe(estado: EstadoAuditoria) -> str:
    """Markdown en español: resumen, qué hacer primero, hallazgos, verificaciones, limitaciones, pie."""
    d, informe = estado.dominio, estado.informe
    if dominio_no_existe(estado):
        # Sin dominio no hay riesgo que medir: un semáforo "bajo" sería engañoso.
        partes = [f"# Informe de exposición digital · {d}", "", f"**El dominio {d} no existe**", "",
                  informe.resumen.strip(), ""]
        if estado.informe_de_respaldo:  # el resumen automático es genérico: se agrega la explicación
            partes += ["No está registrado en internet (no responde en DNS), así que no hay correo ni sitio que "
                       "revisar. Si es su dominio y debería existir, confirme con su proveedor que el nombre esté "
                       "bien escrito y que el registro esté vigente.", ""]
        return _limitaciones_y_pie(estado, partes, limitaciones_fijas=[])

    nivel = estado.nivel_riesgo or NivelRiesgo.BAJO
    partes = [f"# Informe de exposición digital · {d}", "",
              f"**Nivel de riesgo: {SEMAFORO[nivel]} {nivel.value.upper()}**", "", informe.resumen.strip(), ""]
    if estado.informe_de_respaldo:
        partes += [AVISO_RESPALDO, ""]

    partes += ["## Qué hacer primero", ""]
    acciones = [a for a in informe.acciones_priorizadas if a.hallazgo_id in estado.hallazgos]
    if not acciones:
        partes += ["No encontramos aspectos que requieran acción en lo que revisamos.", ""]
    for n, a in enumerate(acciones, 1):
        h = estado.hallazgos[a.hallazgo_id]
        partes += [f"### {n}. {h.titulo}", f"*Severidad {SEVERIDAD_LEGIBLE[h.severidad.value]} · {h.id}*", "",
                   a.recomendacion.strip(), "", f"**Por qué va en este lugar:** {a.por_que_primero.strip()}", "",
                   "**Reenvíe esto a su proveedor:**", "", "```", _bloque_tecnico(estado, h), "```", ""]

    partes += ["## Hallazgos", ""]
    if not estado.hallazgos:
        partes += ["No se encontraron hallazgos.", ""]
    for h in estado.hallazgos.values():
        partes += [f"### {h.titulo} ({SEVERIDAD_LEGIBLE[h.severidad.value]})", "", h.explicacion_simple, "",
                   f"- Evidencia: `{h.evidencia}`", ""]

    partes += ["## Verificaciones sugeridas", ""]
    if any(i.startswith("CORREO-DMARC") for i in estado.hallazgos):
        partes += [f"- Antes de endurecer DMARC, confirme desde qué dirección salen sus facturas electrónicas; si "
                   f"salen como @{d}, ese servidor debe estar autorizado en su SPF.", ""]
    else:
        partes += ["Ninguna por ahora.", ""]

    return _limitaciones_y_pie(estado, partes)


def dominio_no_existe(estado: EstadoAuditoria) -> bool:
    """True si el último dns_correo sobre el objetivo dijo que el dominio no existe."""
    for argumentos, r in reversed(estado.llamadas):
        if r.herramienta == "dns_correo" and (argumentos.get("dominio") or "").lower().strip(".") == estado.dominio:
            return r.error == "dominio_no_existe"
    return False


def limitaciones_de_parecidos(estado: EstadoAuditoria) -> list[str]:
    """Lo que quedó sin revisar en registro y parecidos, dicho por el código (no por Grok)."""
    textos: list[str] = []
    busqueda = next((r.datos for _, r in reversed(estado.llamadas)
                     if r.herramienta == "buscar_parecidos" and r.ok), None)
    investigados = {r.datos.get("parecido") for _, r in estado.llamadas
                    if r.herramienta == "investigar_parecido" and r.ok}
    if busqueda:
        candidatos = [c["dominio"] for c in busqueda["con_correo"] if not c["comparte_servidores"]]
        pendientes = [c for c in candidatos if c not in investigados]
        if pendientes:
            textos.append(f"Se encontraron {len(candidatos)} dominios parecidos con correo; se investigaron "
                          f"{len(candidatos) - len(pendientes)}. Sin investigar: {', '.join(pendientes)}.")
        if busqueda["sin_verificar"]:
            textos.append("Algunos dominios parecidos no respondieron en DNS y no se pudieron verificar: "
                          f"{', '.join(busqueda['sin_verificar'])}.")
    for _, r in estado.llamadas:
        if r.herramienta == "whois_dominio" and not r.ok:
            textos.append(f"No se pudo consultar el registro público del dominio ({r.error}), así que no se "
                          "revisó su vencimiento ni su bloqueo de transferencia.")
            break
    return textos


def _limitaciones_y_pie(estado: EstadoAuditoria, partes: list[str],
                        limitaciones_fijas: list[str] | None = None) -> str:
    """Limitaciones de Grok + las fijas del sistema, y el pie con fecha, modelo y costo."""
    if limitaciones_fijas is None:
        fijas = [*limitaciones_de_parecidos(estado), LIMITACION_PRIMERA_IP, LIMITACION_DKIM, LIMITACION_PARECIDOS]
    else:
        fijas = limitaciones_fijas
    partes += ["## Lo que no se pudo verificar", ""]
    partes += [f"- {limitacion.strip()}" for limitacion in estado.informe.limitaciones]
    partes += [f"- {limitacion}" for limitacion in fijas] + [""]
    partes += ["---",
               f"Revisión pasiva con información pública (DNS, certificado del sitio y registro público de dominios), "
               f"sin escaneos ni accesos. "
               f"Fecha: {estado.inicio:%Y-%m-%d %H:%M} UTC · Modelo: {estado.modelo} · "
               f"Costo: USD {estado.costo_usd:.4f} · Pasos: {estado.pasos} · "
               f"Auditoría: {estado.auditoria_id} (intento {estado.intento})."]
    return "\n".join(partes) + "\n"


def guardar_informe(estado: EstadoAuditoria, ruta: Path = RUTA_SALIDAS) -> Path:
    """Escribe salidas/<dominio>-<AAAAMMDD-HHMM>.md en UTF-8 y devuelve la ruta."""
    ruta.mkdir(parents=True, exist_ok=True)
    archivo = ruta / f"{estado.dominio}-{datetime.now():%Y%m%d-%H%M}.md"
    archivo.write_text(generar_informe(estado), encoding="utf-8")
    return archivo
