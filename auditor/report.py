"""Informe Markdown para el dueño de la pyme.

Grok aporta el resumen, el orden y el texto de cada recomendación. El código aporta los
hallazgos con su evidencia y el DATO TÉCNICO EXACTO de cada recomendación (plantillas
fijas por recomendacion_id): así nadie copia en su DNS un registro inventado por el LLM.
Nunca se copia contenido no confiable al informe.
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from auditor.config import RUTA_SALIDAS
from auditor.modelos import EstadoAuditoria, Hallazgo, NivelRiesgo
from auditor.scoring import evaluar, hallazgos_de_lo_principal, selectores_dkim
from auditor.tools.base import DominioInvalido, normalizar_dominio
from auditor.tools.correo import spf_autoriza_envio

SEMAFORO = {NivelRiesgo.ALTO: "🔴", NivelRiesgo.MEDIO: "🟡", NivelRiesgo.BAJO: "🟢"}
SEVERIDAD_LEGIBLE = {"critica": "crítica", "alta": "alta", "media": "media", "baja": "baja",
                     "informativa": "informativa"}

LIMITACION_PRIMERA_IP = ("El certificado se revisó en la primera dirección IP de cada sitio; si un sitio tiene "
                         "varias, no se revisaron todas.")
LIMITACION_SIN_DKIM = ("DKIM (la firma digital de sus correos) no se revisó en esta auditoría, así que este "
                       "informe no afirma nada sobre ella.")
LIMITACION_PARECIDOS = ("La búsqueda de dominios parecidos cubre errores de tipeo frecuentes y los dominios .co, "
                        ".com.co y .com; no cubre todos los nombres posibles ni letras de otros alfabetos. A estos "
                        "dominios solo se les consultó DNS y el registro público; nunca se visitó su sitio web.")
LIMITACION_PORTADA = ("Las cabeceras de seguridad se revisaron solo en la portada de cada sitio; otras páginas "
                      "pueden estar configuradas de otra forma.")
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


def _dkim_activar(d: str, ctx: dict) -> str:
    proveedor = ctx.get("proveedor", "otro")
    if proveedor == "google":
        return (f"En la Consola de administración de Google: Menú → Apps → Google Workspace → Gmail → Autenticar "
                f"correo electrónico. Elija {d}, genere un registro nuevo de 2048 bits (selector google), publique "
                f"en su DNS el TXT que le muestra la consola en google._domainkey.{d} y, cuando esté publicado, "
                f"pulse «Iniciar la autenticación».")
    if proveedor == "microsoft":
        return (f"En el portal de Microsoft Defender (https://security.microsoft.com/authentication?viewid=DKIM), "
                f"pestaña DKIM, elija {d}. Publique en su DNS los dos CNAME que indica el portal "
                f"(selector1._domainkey.{d} y selector2._domainkey.{d}) y active «Sign messages for this domain "
                f"with DKIM signatures».")
    return (f"Si su proveedor de correo ofrece DKIM, pida a su proveedor de correo que lo active para {d} con una "
            f"clave de 2048 bits y publique en su DNS el registro que le entregue.")


def _dkim_rotar(d: str, ctx: dict) -> str:
    proveedor = ctx.get("proveedor", "otro")
    if proveedor == "google":
        texto = (f"En la Consola de administración de Google (Gmail → Autenticar correo electrónico), genere para {d} "
                 f"una clave nueva de 2048 bits, publíquela en su DNS e inicie la autenticación.")
    elif proveedor == "microsoft":
        texto = (f"En Exchange Online PowerShell: Rotate-DkimSigningConfig -Identity {d} -KeySize 2048\n"
                 f"(La rotación tarda unos 4 días en aplicarse; los CNAME selector1 y selector2 no cambian.)")
    else:
        texto = (f"Pedir a su proveedor de correo una clave DKIM nueva de 2048 bits para {d}, publicarla en un "
                 f"selector nuevo y retirar la anterior cuando la nueva funcione.")
    return f"Clave actual: {ctx['evidencia']}.\n{texto}"


def _dmarc_endurecer(d: str, ctx: dict) -> str:
    texto = (f"Después de revisar los reportes de DMARC durante 2 a 4 semanas y confirmar qué servicios envían "
             f"correo legítimo con @{d}:\n"
             f"1. En _dmarc.{d}, cambiar p=none por p=quarantine (puede agregar t=y para probar primero).\n"
             f"2. Cuando todo funcione, cambiar a p=reject.")
    if ctx.get("sin_dkim"):
        texto += "\nSin DKIM, el paso a quarantine depende solo de SPF: conviene activar DKIM antes."
    return texto


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
    "REC-DMARC-ENDURECER": _dmarc_endurecer,
    "REC-DKIM-ACTIVAR": _dkim_activar,
    "REC-DKIM-ROTAR": _dkim_rotar,
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
        f"Dominio {d}: {ctx['evidencia']}.\n"
        f"Renovarlo con su registrador y activar la renovación automática, con un medio de pago vigente y un "
        f"correo de contacto que alguien revise."),
    "REC-DOMINIO-BLOQUEO": lambda d, ctx: (
        f"Pedir al registrador de {d} que active el bloqueo de transferencia (Registrar Lock / "
        f"clientTransferProhibited). Se quita solo cuando usted decida cambiar de registrador."),
    "REC-HTTPS-REDIRECCION": lambda d, ctx: (
        f"En el servidor o panel de hosting de: {_hosts(ctx['evidencia'])}\n"
        f"Activar la redirección permanente (301) de http:// a https:// para todas las páginas. En muchos paneles "
        f"(cPanel, Cloudflare, Wix, Shopify) es una opción llamada «Forzar HTTPS»."),
    "REC-HSTS": lambda d, ctx: (
        f"Agregar en las respuestas HTTPS de: {_hosts(ctx['evidencia'])}\n"
        f"Strict-Transport-Security: max-age=31536000\n"
        f"Antes, confirme que todo el sitio funciona con https:// (y sus subdominios, si luego agrega "
        f"includeSubDomains)."),
    "REC-MARCOS": lambda d, ctx: (
        f"Agregar en las respuestas de: {_hosts(ctx['evidencia'])}\n"
        f"Content-Security-Policy: frame-ancestors 'self'\n"
        f"(o X-Frame-Options: SAMEORIGIN). Si alguna página suya debe verse dentro de otro sitio, inclúyalo en "
        f"esa lista."),
    "REC-NOSNIFF": lambda d, ctx: (
        f"Agregar en las respuestas de: {_hosts(ctx['evidencia'])}\nX-Content-Type-Options: nosniff"),
    "REC-OCULTAR-VERSION": lambda d, ctx: (
        f"En el servidor de: {_hosts(ctx['evidencia'])}\n"
        f"Ocultar la versión del software (Apache: ServerTokens Prod; Nginx: server_tokens off; PHP: "
        f"expose_php = Off)."),
    "REC-SECURITY-TXT": lambda d, ctx: (
        f"Publicar en https://{d}/.well-known/security.txt un archivo de texto con, por lo menos:\n"
        f"Contact: mailto:seguridad@{d}\n"
        f"Expires: <una fecha de hasta un año en el futuro, en formato 2027-12-31T00:00:00Z>\n"
        f"(RFC 9116. Cree el buzón seguridad@{d} o use una dirección que alguien revise.)"),
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
                "otros_de_correo": any(i.startswith(("CORREO-DMARC", "CORREO-SPF")) for i in estado.hallazgos),
                "sin_dkim": "CORREO-DKIM-NO-ENCONTRADO" in estado.hallazgos}
    return PLANTILLAS[h.recomendacion_id](estado.dominio, contexto)


@dataclass
class Accion:
    n: int
    titulo: str
    severidad: str   # legible: "crítica", "alta"...
    id: str
    recomendacion: str
    por_que: str
    bloque: str      # dato técnico exacto (plantilla del código)


@dataclass
class Contenido:
    """El informe ya decidido, sin formato: lo dibujan el Markdown y el HTML, así nunca dicen cosas distintas."""
    dominio: str
    no_existe: bool
    nivel: NivelRiesgo | None
    resumen: str
    explicacion_no_existe: str | None
    respaldo: bool
    aviso_subdominios: str | None
    acciones: list[Accion]
    hallazgos: list[Hallazgo]
    verificaciones: list[str]
    limitaciones: list[str]
    pie: str


EXPLICACION_NO_EXISTE = ("No está registrado en internet (no responde en DNS), así que no hay correo ni sitio que "
                         "revisar. Si es su dominio y debería existir, confirme con su proveedor que el nombre esté "
                         "bien escrito y que el registro esté vigente.")


def contenido(estado: EstadoAuditoria) -> Contenido:
    """Todo lo que dice el informe, en orden: Grok aporta resumen y textos; el código, todo lo demás."""
    d, informe = estado.dominio, estado.informe
    no_existe = dominio_no_existe(estado)
    if no_existe:
        # Sin dominio no hay riesgo que medir: un semáforo "bajo" sería engañoso.
        return Contenido(d, True, None, informe.resumen.strip(),
                         EXPLICACION_NO_EXISTE if estado.informe_de_respaldo else None, False, None, [], [], [],
                         _limitaciones(estado, fijas=[]), _pie(estado))
    acciones = []
    for n, a in enumerate((a for a in informe.acciones_priorizadas if a.hallazgo_id in estado.hallazgos), 1):
        h = estado.hallazgos[a.hallazgo_id]
        acciones.append(Accion(n, h.titulo, SEVERIDAD_LEGIBLE[h.severidad.value], h.id, a.recomendacion.strip(),
                               a.por_que_primero.strip(), _bloque_tecnico(estado, h)))
    verificaciones = []
    if any(i.startswith("CORREO-DMARC") for i in estado.hallazgos):
        verificaciones.append(f"Antes de endurecer DMARC, confirme desde qué dirección salen sus facturas "
                              f"electrónicas; si salen como @{d}, ese servidor debe estar autorizado en su SPF.")
    return Contenido(d, False, estado.nivel_riesgo or NivelRiesgo.BAJO, informe.resumen.strip(), None,
                     estado.informe_de_respaldo, aviso_de_subdominios(estado), acciones,
                     list(estado.hallazgos.values()), verificaciones,
                     _limitaciones(estado), _pie(estado))


SEVERIDAD_EN_PLURAL = {"critica": ("crítico", "críticos"), "alta": ("alto", "altos"), "media": ("medio", "medios"),
                       "baja": ("bajo", "bajos"), "informativa": ("informativo", "informativos")}


def aviso_de_subdominios(estado: EstadoAuditoria) -> str | None:
    """El semáforo mide solo lo principal; si hay hallazgos que solo están en subdominios, se dice al lado."""
    principales = hallazgos_de_lo_principal(estado.llamadas, estado.dominio)
    solo_en_subdominios = evaluar(estado.llamadas, estado.dominio).keys() - principales.keys()
    cuenta = Counter(h.severidad.value for i, h in estado.hallazgos.items() if i in solo_en_subdominios)
    if not cuenta:
        return None
    partes = []
    for severidad, (singular, plural) in SEVERIDAD_EN_PLURAL.items():
        if n := cuenta.get(severidad):
            palabra = singular if n == 1 else plural
            partes.append(f"{n} {'hallazgo' if n == 1 else 'hallazgos'} {palabra}" if not partes else f"{n} {palabra}")
    return ("Este nivel mide su correo, su dominio y su sitio principal. En otros sitios de su dominio "
            f"(subdominios) hay además {_lista(partes)}; están en la lista de abajo.")


def titulo_del_nivel(c: Contenido) -> str:
    """Si la revisión se cortó, el nivel no puede tranquilizar: se dice que es provisional."""
    return "Nivel de riesgo provisional" if c.respaldo else "Nivel de riesgo"


def generar_informe(estado: EstadoAuditoria) -> str:
    """Markdown en español: resumen, qué hacer primero, hallazgos, verificaciones, limitaciones, pie."""
    c = contenido(estado)
    partes = [f"# Informe de exposición digital · {c.dominio}", ""]
    if c.no_existe:
        partes += [f"**El dominio {c.dominio} no existe**", "", c.resumen, ""]
        if c.explicacion_no_existe:  # el resumen automático es genérico: se agrega la explicación
            partes += [c.explicacion_no_existe, ""]
    else:
        partes += [f"**{titulo_del_nivel(c)}: {SEMAFORO[c.nivel]} {c.nivel.value.upper()}**", ""]
        if c.aviso_subdominios:
            partes += [c.aviso_subdominios, ""]
        partes += [c.resumen, ""]
        if c.respaldo:
            partes += [AVISO_RESPALDO, ""]
        partes += ["## Qué hacer primero", ""]
        if not c.acciones:
            partes += ["No encontramos aspectos que requieran acción en lo que revisamos.", ""]
        for a in c.acciones:
            partes += [f"### {a.n}. {a.titulo}", f"*Severidad {a.severidad} · {a.id}*", "", a.recomendacion, "",
                       f"**Por qué va en este lugar:** {a.por_que}", "", "**Reenvíe esto a su proveedor:**", "",
                       "```", a.bloque, "```", ""]
        partes += ["## Hallazgos", ""]
        if not c.hallazgos:
            partes += ["No se encontraron hallazgos.", ""]
        for h in c.hallazgos:
            partes += [f"### {h.titulo} ({SEVERIDAD_LEGIBLE[h.severidad.value]})", "", h.explicacion_simple, "",
                       f"- Evidencia: `{h.evidencia}`", ""]
        partes += ["## Verificaciones sugeridas", ""]
        partes += [f"- {v}" for v in c.verificaciones] + [""] if c.verificaciones else ["Ninguna por ahora.", ""]
    partes += ["## Lo que no se pudo verificar", ""]
    partes += [f"- {limitacion}" for limitacion in c.limitaciones] + [""]
    partes += ["---", c.pie]
    return "\n".join(partes) + "\n"


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


def limitaciones_de_dkim(estado: EstadoAuditoria) -> list[str]:
    """Qué selectores DKIM se probaron cuando no se encontró ninguno (o si DKIM no se revisó).

    Un selector cuya consulta falló (tiempo agotado) no se da por "no encontrado": se dice aparte.
    """
    selectores = selectores_dkim(estado.llamadas, estado.dominio)
    if not selectores:
        return [LIMITACION_SIN_DKIM]
    if any(d["existe"] for d in selectores.values()):
        return []
    textos = []
    sin_clave = [s for s, d in selectores.items() if not d["error"]]
    sin_respuesta = [s for s, d in selectores.items() if d["error"]]
    if sin_clave:
        textos.append(f"DKIM se buscó en {'el selector' if len(sin_clave) == 1 else 'los selectores'} "
                      f"{_lista(sin_clave)} y no se encontró; si su proveedor usa otro nombre de selector, este "
                      "informe no pudo verlo.")
    if sin_respuesta:
        textos.append(f"El selector DKIM {sin_respuesta[0]} no respondió en DNS, así que no se pudo verificar."
                      if len(sin_respuesta) == 1 else
                      f"Los selectores DKIM {_lista(sin_respuesta)} no respondieron en DNS, así que no se pudieron "
                      "verificar.")
    return textos


def _lista(nombres: list[str]) -> str:
    return nombres[0] if len(nombres) == 1 else ", ".join(nombres[:-1]) + " y " + nombres[-1]


def limitaciones_de_subdominios(estado: EstadoAuditoria) -> list[str]:
    """Cuántos subdominios mostró CT y cuáles se revisaron, dicho por el código (no por Grok)."""
    consultas = [r for _, r in estado.llamadas if r.herramienta == "subdominios_ct"]
    if not consultas:
        return []
    ct = next((r for r in reversed(consultas) if r.ok), None)  # una falla posterior no tapa un éxito
    if ct is None:
        return [f"Los registros públicos de certificados no se pudieron consultar ({consultas[-1].error}), así "
                "que no se buscaron subdominios."]
    gratis = {estado.dominio, f"www.{estado.dominio}"}
    revisados = sorted({h for a, r in estado.llamadas if r.herramienta in ("tls_certificado", "cabeceras_web")
                        and r.ok and (h := _host_normalizado(a.get("host"))) and h not in gratis})
    total = ct.datos["total"]
    nota = "Estos registros solo muestran sitios que tuvieron certificado HTTPS; puede haber otros."
    if total == 0:
        return [f"En los registros de certificados no aparece ningún subdominio. {nota}"]
    con = ct.datos["con_sitio"]
    if total == 1:
        cuantos = f"aparece 1 subdominio, {'con' if con else 'sin'} sitio web"
    else:
        cuantos = f"aparecen {total} subdominios, {f'{con} con' if con else 'ninguno con'} sitio web"
    revision = f"se revisaron {len(revisados)}: {', '.join(revisados)}" if revisados else "no se revisó ninguno"
    return [f"En los registros de certificados {cuantos}; {revision}. {nota}"]


def limitaciones_de_security_txt(estado: EstadoAuditoria) -> list[str]:
    """Si no se pudo saber si existe security.txt, lo dice el código: sin esto el informe callaba."""
    consultas = [r for _, r in estado.llamadas if r.herramienta == "security_txt"]
    if not consultas or any(r.ok and r.datos["existe"] is not None for r in consultas):
        return []  # un resultado verificado (aunque sea posterior a una falla) no deja limitación
    inicio = f"No se pudo verificar si {estado.dominio} publica un contacto de seguridad (security.txt): "
    r = consultas[-1]
    if not r.ok:
        return [inicio + f"el sitio no respondió ({r.error})."]
    if r.datos["redirige_fuera"]:
        return [inicio + "la dirección redirige a otro dominio, que no se revisa."]
    return [inicio + f"el servidor respondió con un error (código {r.datos['codigo']})."]


def _host_normalizado(texto) -> str | None:
    try:
        return normalizar_dominio(str(texto or ""))
    except DominioInvalido:
        return None


def _limitaciones(estado: EstadoAuditoria, fijas: list[str] | None = None) -> list[str]:
    """Las limitaciones que escribió Grok y, después, las que agrega el código."""
    if fijas is None:
        fijas = [*limitaciones_de_dkim(estado), *limitaciones_de_parecidos(estado),
                 *limitaciones_de_subdominios(estado), *limitaciones_de_security_txt(estado),
                 LIMITACION_PRIMERA_IP, LIMITACION_PARECIDOS]
        if any(r.herramienta == "cabeceras_web" and r.ok for _, r in estado.llamadas):
            fijas.append(LIMITACION_PORTADA)
    return [limitacion.strip() for limitacion in estado.informe.limitaciones] + fijas


def _pie(estado: EstadoAuditoria) -> str:
    return (f"Revisión pasiva con información pública (DNS, certificado y portada del sitio, y registro público de "
            f"dominios), sin escaneos ni accesos. "
            f"Fecha: {estado.inicio:%Y-%m-%d %H:%M} UTC · Modelo: {estado.modelo} · "
            f"Costo: USD {estado.costo_usd:.4f} · Pasos: {estado.pasos} · "
            f"Auditoría: {estado.auditoria_id} (intento {estado.intento}).")


def guardar_informe(estado: EstadoAuditoria, ruta: Path = RUTA_SALIDAS) -> Path:
    """Escribe salidas/<dominio>-<AAAAMMDD-HHMM>.md y, al lado, el mismo informe en .html imprimible.

    Devuelve la ruta del .md; la del HTML es la misma con extensión .html.
    """
    from auditor.report_html import generar_informe_html  # report_html importa este módulo

    ruta.mkdir(parents=True, exist_ok=True)
    archivo = ruta / f"{estado.dominio}-{datetime.now():%Y%m%d-%H%M}.md"
    archivo.write_text(generar_informe(estado), encoding="utf-8")
    archivo.with_suffix(".html").write_text(generar_informe_html(estado), encoding="utf-8")
    return archivo
