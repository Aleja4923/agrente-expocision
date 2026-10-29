"""Reglas deterministas: convierten los datos de las herramientas en hallazgos.

Aquí se decide QUÉ es un problema y CON QUÉ severidad (CONTEXT.md §6b). Grok nunca
crea hallazgos: solo puede citar los que salen de este archivo. Los textos siguen
las reglas de redacción de CONTEXT.md §7b (nada absoluto, trato de usted).
La evidencia se arma solo con `datos` parseados, nunca con contenido no confiable.
"""

from datetime import date, datetime
from typing import Any

from auditor.config import DIAS_DOMINIO_POR_VENCER, DIAS_REGISTRO_RECIENTE
from auditor.modelos import Categoria, Hallazgo, NivelRiesgo, ResultadoHerramienta, Severidad
from auditor.tools.base import DominioInvalido, dominio_registrable, normalizar_dominio

Llamada = tuple[dict[str, Any], ResultadoHerramienta]  # (argumentos que pidió Grok, resultado)

C, W, F, D = Categoria.CORREO, Categoria.WEB, Categoria.FRAUDE, Categoria.DOMINIO
S = Severidad

# id -> (categoría, severidad, título, explicación simple, recomendacion_id)
REGLAS: dict[str, tuple[Categoria, Severidad, str, str, str]] = {
    "CORREO-DMARC-AUSENTE": (
        C, S.CRITICA, "Su dominio no tiene DMARC",
        "Su dominio no les indica a quienes reciben sus correos qué hacer con mensajes que se hagan pasar "
        "por usted, y usted no recibe reportes de quién los envía. Filtrarlos queda a criterio de cada "
        "proveedor de correo.",
        "REC-DMARC-CREAR"),
    "CORREO-DMARC-INVALIDO": (
        C, S.ALTA, "El registro DMARC está mal formado",
        "Su dominio tiene DMARC, pero escrito de una forma que los receptores no pueden aplicar, así que "
        "en la práctica funciona como si no lo tuviera.",
        "REC-DMARC-CORREGIR"),
    "CORREO-DMARC-NONE": (
        C, S.ALTA, "DMARC está solo en modo de observación",
        "Su DMARC pide a los receptores que no hagan nada con los correos que fallan la verificación. "
        "Sirve para empezar y recibir reportes, pero todavía no protege su nombre.",
        "REC-DMARC-ENDURECER"),
    "CORREO-DMARC-SIN-REPORTES": (
        C, S.BAJA, "DMARC no envía reportes",
        "Usted no recibe los reportes que dicen quién envía correo usando su dominio. Sin ellos es difícil "
        "saber si es seguro endurecer la protección.",
        "REC-DMARC-RUA"),
    "CORREO-DMARC-OBSOLETO": (
        C, S.INFORMATIVA, "DMARC usa etiquetas antiguas",
        "Su DMARC incluye etiquetas que el estándar actual ya no usa. No es un riesgo, pero conviene "
        "limpiarlas en la próxima actualización.",
        "REC-DMARC-OBSOLETO"),
    "CORREO-SPF-AUSENTE": (
        C, S.ALTA, "Su dominio no tiene SPF",
        "Su dominio no publica la lista de servidores autorizados a enviar correo en su nombre, lo que "
        "hace más difícil que los receptores detecten correos falsos.",
        "REC-SPF-CREAR"),
    "CORREO-SPF-MULTIPLE": (
        C, S.ALTA, "Hay más de un registro SPF",
        "Su dominio tiene varios registros SPF. El estándar exige uno solo; con varios, los receptores "
        "lo tratan como un error y no lo aplican.",
        "REC-SPF-UNIR"),
    "CORREO-SPF-PERMISIVO": (
        C, S.CRITICA, "SPF autoriza a cualquier servidor",
        "Su SPF termina en +all, que autoriza a todos los servidores del mundo a enviar correo con su "
        "dominio. Equivale a no tener SPF y puede hacer que los correos falsos parezcan legítimos.",
        "REC-SPF-CERRAR"),
    "CORREO-SPF-NEUTRO": (
        C, S.ALTA, "SPF no dice qué hacer con servidores no autorizados",
        "Su SPF no indica qué hacer con correos enviados desde servidores que no están en su lista, así "
        "que los receptores no pueden usarlo para rechazar correos falsos.",
        "REC-SPF-CERRAR"),
    "CORREO-SPF-SUAVE": (
        C, S.BAJA, "SPF en modo suave sin DMARC que lo respalde",
        "Su SPF termina en ~all, que es lo recomendado, pero solo protege del todo cuando DMARC está en "
        "quarantine o reject. Ganará fuerza cuando endurezca su DMARC.",
        "REC-DMARC-ENDURECER"),
    "CORREO-SPF-LOOKUPS": (
        C, S.ALTA, "SPF demasiado largo para ser evaluado",
        "Su SPF necesita más consultas de las que el estándar permite, así que los receptores lo marcan "
        "como error y no lo aplican.",
        "REC-SPF-SIMPLIFICAR"),
    "CORREO-SIN-MX": (
        C, S.INFORMATIVA, "El dominio no recibe correo",
        "Su dominio no tiene servidores para recibir correo. Puede ser normal si no lo usa para correo; en "
        "ese caso conviene declararlo para que nadie lo use en su nombre.",
        "REC-SIN-MX"),
    # S2 · DKIM: solo se concluye "no encontrado" donde el selector estándar se conoce (Google y Microsoft).
    "CORREO-DKIM-NO-ENCONTRADO": (
        C, S.MEDIA, "No encontramos la firma DKIM de su correo",
        "Su proveedor de correo publica normalmente esta firma digital y no la encontramos. Sin ella, los "
        "receptores tienen menos formas de comprobar que sus correos son suyos y DMARC depende solo de SPF.",
        "REC-DKIM-ACTIVAR"),
    "CORREO-DKIM-CLAVE-DEBIL": (
        C, S.ALTA, "La firma DKIM usa una clave demasiado corta",
        "La clave de su firma DKIM es más corta de lo que hoy se considera seguro, así que podría falsificarse "
        "y los receptores pueden ignorarla.",
        "REC-DKIM-ROTAR"),
    "CORREO-DKIM-CLAVE-1024": (
        C, S.BAJA, "La firma DKIM usa una clave de 1024 bits",
        "Su firma DKIM funciona, pero la recomendación actual es una clave de 2048 bits. Conviene cambiarla en "
        "el próximo mantenimiento.",
        "REC-DKIM-ROTAR"),
    "WEB-TLS-INVALIDO": (
        W, S.CRITICA, "El certificado de seguridad del sitio no es válido",
        "Los navegadores muestran una advertencia al entrar, lo que espanta a sus clientes y facilita que "
        "un sitio falso pase por el suyo.",
        "REC-TLS-RENOVAR"),
    "WEB-TLS-POR-VENCER": (
        W, S.ALTA, "El certificado del sitio vence pronto",
        "Si no se renueva a tiempo, los navegadores empezarán a mostrar advertencias a sus clientes.",
        "REC-TLS-RENOVAR"),
    "WEB-TLS-VERSION-VIEJA": (
        W, S.ALTA, "El sitio usa una versión antigua de cifrado",
        "Su sitio acepta una versión de TLS que los navegadores ya no consideran segura.",
        "REC-TLS-VERSION"),
    "WEB-SIN-HTTPS": (
        W, S.ALTA, "El sitio no ofrece conexión segura",
        "Su sitio no acepta conexiones HTTPS, así que lo que escriban sus clientes viaja sin cifrar y el "
        "navegador lo marca como no seguro.",
        "REC-HTTPS"),
    # S2 · cabeceras de la portada y security.txt
    "WEB-SIN-REDIRECCION-HTTPS": (
        W, S.MEDIA, "El sitio no lleva a sus visitantes a la versión segura",
        "Quien escribe la dirección sin https:// entra a una versión sin cifrar, donde lo que escribe puede "
        "leerse o alterarse en el camino.",
        "REC-HTTPS-REDIRECCION"),
    "WEB-SIN-HSTS": (
        W, S.BAJA, "El sitio no exige conexión segura a los navegadores",
        "Sin la cabecera HSTS, el navegador no recuerda que su sitio siempre debe abrirse con cifrado, así que "
        "una primera visita puede caer en la versión sin cifrar.",
        "REC-HSTS"),
    "WEB-SIN-PROTECCION-MARCOS": (
        W, S.BAJA, "Su sitio puede mostrarse dentro de otras páginas",
        "Otra página podría mostrar la suya dentro de un marco invisible para que sus visitantes hagan clic sin "
        "darse cuenta.",
        "REC-MARCOS"),
    "WEB-SIN-NOSNIFF": (
        W, S.INFORMATIVA, "Falta una cabecera de protección básica",
        "La cabecera X-Content-Type-Options evita que el navegador interprete archivos de una forma distinta a "
        "la declarada. Es un ajuste sencillo del servidor.",
        "REC-NOSNIFF"),
    "WEB-VERSION-EXPUESTA": (
        W, S.INFORMATIVA, "El servidor muestra qué versión de software usa",
        "Anunciar la versión exacta facilita que alguien busque fallas conocidas de esa versión. No es un "
        "problema por sí solo, pero conviene ocultarla.",
        "REC-OCULTAR-VERSION"),
    "WEB-SIN-SECURITY-TXT": (
        W, S.INFORMATIVA, "El sitio no indica a quién avisar de un problema de seguridad",
        "Un archivo security.txt le dice a quien encuentre un problema en su sitio cómo avisarle. Sin él, ese "
        "aviso puede no llegarle nunca.",
        "REC-SECURITY-TXT"),
    # S2 · dominios parecidos: nunca acusan (CONTEXT §7); puede ser de otro negocio o del mismo dueño.
    "PARECIDO-ENVIA": (
        F, S.ALTA, "Un dominio muy parecido al suyo está preparado para enviar correo",
        "Tiene correo configurado y publica autorización para enviar, así que podría usarse para escribirles a "
        "sus clientes haciéndose pasar por usted. No prueba que se use para engañar: puede ser de otro negocio "
        "o suyo.",
        "REC-PARECIDO-VERIFICAR"),
    "PARECIDO-RECIENTE": (
        F, S.MEDIA, "Un dominio muy parecido al suyo se registró hace poco y tiene correo configurado",
        "Puede recibir correos que sus clientes le escriban con un error de tipeo. Un registro reciente merece "
        "atención, pero no prueba que se use para engañar: puede ser de otro negocio o suyo.",
        "REC-PARECIDO-VERIFICAR"),
    "PARECIDO-MX": (
        F, S.INFORMATIVA, "Existe un dominio muy parecido al suyo con correo configurado",
        "Puede recibir correos que sus clientes le escriban con un error de tipeo. No prueba que se use para "
        "engañar: puede ser de otro negocio o suyo.",
        "REC-PARECIDO-VERIFICAR"),
    # S2 · registro del propio dominio
    "DOMINIO-VENCIDO": (
        D, S.CRITICA, "Su dominio está vencido",
        "Si no lo renueva, su correo y su sitio dejan de funcionar y otra persona podría registrarlo y recibir "
        "los correos dirigidos a usted.",
        "REC-DOMINIO-RENOVAR"),
    "DOMINIO-POR-VENCER": (
        D, S.MEDIA, "Su dominio vence pronto",
        "Si no se renueva a tiempo, su correo y su sitio dejan de funcionar. Conviene confirmar que la "
        "renovación automática esté activa.",
        "REC-DOMINIO-RENOVAR"),
    "DOMINIO-SIN-BLOQUEO": (
        D, S.BAJA, "Su dominio no tiene bloqueo de transferencia",
        "El bloqueo impide que el dominio se pase a otra empresa de registro sin su autorización. Sin él, un "
        "engaño a su proveedor podría hacerle perder el dominio.",
        "REC-DOMINIO-BLOQUEO"),
}


def _hallazgo(id_: str, evidencia: str) -> Hallazgo:
    categoria, severidad, titulo, explicacion, recomendacion = REGLAS[id_]
    return Hallazgo(id=id_, categoria=categoria, severidad=severidad, titulo=titulo,
                    explicacion_simple=explicacion, evidencia=evidencia, recomendacion_id=recomendacion)


def reglas_correo(datos: dict[str, Any]) -> list[Hallazgo]:
    """Hallazgos de correo a partir de los datos de un dns_correo exitoso."""
    dominio, mx, spf, dmarc = datos["dominio"], datos["mx"], datos["spf"], datos["dmarc"]
    h: list[Hallazgo] = []

    if not dmarc["existe"]:
        h.append(_hallazgo("CORREO-DMARC-AUSENTE", f"no existe registro DMARC en _dmarc.{dominio}"))
    elif not dmarc["valido"]:
        evidencia = ("hay más de un registro DMARC" if dmarc["multiple"]
                     else f"política p={dmarc['p']} no válida")
        h.append(_hallazgo("CORREO-DMARC-INVALIDO", evidencia))
    else:
        if dmarc["p"] == "none":
            h.append(_hallazgo("CORREO-DMARC-NONE", "política p=none"))
        if not dmarc["rua"]:
            h.append(_hallazgo("CORREO-DMARC-SIN-REPORTES", "el registro DMARC no tiene rua"))
    if dmarc["etiquetas_obsoletas"]:
        h.append(_hallazgo("CORREO-DMARC-OBSOLETO", "etiquetas: " + ", ".join(dmarc["etiquetas_obsoletas"])))

    dmarc_estricto = dmarc["valido"] and dmarc["p"] in ("quarantine", "reject")
    if spf["cantidad"] == 0:
        h.append(_hallazgo("CORREO-SPF-AUSENTE", f"no hay registro SPF en {dominio}"))
    elif spf["cantidad"] > 1:
        h.append(_hallazgo("CORREO-SPF-MULTIPLE", f"{spf['cantidad']} registros SPF (debe haber uno)"))
    else:
        cierre = spf["cierre"]
        if cierre == "+all":
            h.append(_hallazgo("CORREO-SPF-PERMISIVO", "SPF termina en +all"))
        elif cierre == "?all":
            h.append(_hallazgo("CORREO-SPF-NEUTRO", "SPF termina en ?all"))
        elif cierre == "ninguno":
            h.append(_hallazgo("CORREO-SPF-NEUTRO", "SPF no tiene cierre all"))
        elif cierre == "~all" and not dmarc_estricto:
            h.append(_hallazgo("CORREO-SPF-SUAVE", "SPF termina en ~all y DMARC no está en quarantine ni reject"))
        if spf["permerror"]:
            evidencia = (f"{spf['consultas_dns']} consultas DNS (máximo 10)" if spf["consultas_dns"] > 10
                         else f"{spf['consultas_vacias']} consultas sin respuesta (máximo 2)")
            h.append(_hallazgo("CORREO-SPF-LOOKUPS", evidencia))

    if mx["proveedor"] == "ninguno":
        h.append(_hallazgo("CORREO-SIN-MX", f"{dominio} no tiene servidores MX"))
    return h


MOTIVO_LEGIBLE = {
    "vencido": "vencido",
    "autofirmado": "autofirmado",
    "nombre_no_coincide": "nombre del certificado no coincide",
    "cadena_incompleta": "cadena de certificados incompleta",
    "raiz_no_confiable": "raíz no confiable",
    "otro": "otro problema de verificación",
}


def reglas_tls(llamadas: list[Llamada]) -> list[Hallazgo]:
    """Hallazgos web; cada regla se agrupa en un solo hallazgo con todos los hosts en la evidencia."""
    evidencias: dict[str, list[str]] = {}

    def agregar(id_: str, texto: str) -> None:
        evidencias.setdefault(id_, []).append(texto)

    for argumentos, r in llamadas:
        host = r.datos.get("host") or argumentos.get("host")
        if r.ok:
            d = r.datos
            if not d["valido"]:
                detalle = f" (venció el {d['vence']})" if d["motivo"] == "vencido" else ""
                motivo = MOTIVO_LEGIBLE.get(d["motivo"], MOTIVO_LEGIBLE["otro"])
                agregar("WEB-TLS-INVALIDO", f"{host}: {motivo}{detalle}")
            elif d["dias_restantes"] <= 15:
                agregar("WEB-TLS-POR-VENCER", f"{host}: vence en {d['dias_restantes']} días")
            if d["version_tls"] in ("TLSv1", "TLSv1.1"):
                agregar("WEB-TLS-VERSION-VIEJA", f"{host}: {d['version_tls']}")
        elif r.error == "sin_https":
            agregar("WEB-SIN-HTTPS", f"{host}: no acepta HTTPS en el puerto 443")
    return [_hallazgo(id_, "; ".join(textos)) for id_, textos in evidencias.items()]


def _evidencia_parecido(p: dict[str, Any]) -> str:
    if p["dias_desde_registro"] is None:
        texto = f"{p['parecido']}: con MX (fecha de registro desconocida)"
    else:
        texto = f"{p['parecido']}: registrado hace {p['dias_desde_registro']} días, con MX"
    return texto + (", SPF autoriza envío" if p["spf_autoriza_envio"] else "")


def reglas_parecidos(busqueda: dict[str, Any] | None, investigados: list[dict[str, Any]],
                     creado_dueno: str | None = None) -> list[Hallazgo]:
    """Señal por combinación (CONTEXT §6b, spec C+D §5); cada parecido aparece en un solo hallazgo.

    Se excluyen los defensivos (comparten NS o MX con el dueño). Un `otro_tld` (mismo nombre, otro TLD) suele
    ser de un homónimo: solo sube de severidad si además se registró hace poco. Un parecido registrado ANTES
    que el dominio del dueño no se creó para imitarlo: se queda en informativa.
    """
    evidencias: dict[str, list[str]] = {}
    revisados = set()
    for p in investigados:
        revisados.add(p["parecido"])
        if not (p["existe"] and p["tiene_mx"]) or p["comparte_servidores"]:
            continue
        evidencia = _evidencia_parecido(p)
        anterior = bool(p["creado"] and creado_dueno
                        and datetime.fromisoformat(p["creado"]) < datetime.fromisoformat(creado_dueno))
        reciente = p["dias_desde_registro"] is not None and p["dias_desde_registro"] <= DIAS_REGISTRO_RECIENTE
        envia = p["spf_autoriza_envio"] and (reciente or p["tipo"] != "otro_tld")
        if anterior:
            id_, evidencia = "PARECIDO-MX", evidencia + " (registrado antes que su dominio)"
        else:
            id_ = "PARECIDO-ENVIA" if envia else "PARECIDO-RECIENTE" if reciente else "PARECIDO-MX"
        evidencias.setdefault(id_, []).append(evidencia)
    for c in (busqueda or {}).get("con_correo", []):
        if c["dominio"] not in revisados and not c["comparte_servidores"]:
            evidencias.setdefault("PARECIDO-MX", []).append(f"{c['dominio']}: con MX")
    return [_hallazgo(id_, "; ".join(textos)) for id_, textos in evidencias.items()]


def reglas_dominio(datos: dict[str, Any], hoy: date) -> list[Hallazgo]:
    """Hallazgos del registro del propio dominio (whois_dominio)."""
    h: list[Hallazgo] = []
    vence = datetime.fromisoformat(datos["vence"]).date()
    dias = (vence - hoy).days
    estado_baja = next((e for e in datos["estados"] if e in ("redemptionPeriod", "pendingDelete")), None)
    if dias < 0 or estado_baja:
        h.append(_hallazgo("DOMINIO-VENCIDO", f"estado {estado_baja}" if estado_baja else f"venció el {vence}"))
    elif dias <= DIAS_DOMINIO_POR_VENCER:
        h.append(_hallazgo("DOMINIO-POR-VENCER", f"vence el {vence} (en {dias} días)"))
    if not any(e in datos["estados"] for e in ("clientTransferProhibited", "serverTransferProhibited")):
        h.append(_hallazgo("DOMINIO-SIN-BLOQUEO", "sin clientTransferProhibited ni serverTransferProhibited"))
    return h


HSTS_MINIMO = 15552000  # 180 días


def reglas_cabeceras(datos_por_host: list[dict[str, Any]]) -> list[Hallazgo]:
    """Hallazgos de cabeceras agrupados por regla, con todos los hosts en la evidencia (como TLS).

    Si la portada redirige a otra plataforma o no responde 2xx/3xx, solo cuentan la redirección a https y
    HSTS: las demás cabeceras no se pueden atribuir al sitio del dueño.
    """
    evidencias: dict[str, list[str]] = {}

    def agregar(id_: str, texto: str) -> None:
        evidencias.setdefault(id_, []).append(texto)

    for d in datos_por_host:
        h = d["host"]
        if d["http_responde"] and d["redirige_a_https"] is False:
            agregar("WEB-SIN-REDIRECCION-HTTPS", f"{h}: http:// responde sin redirigir a https://")
        if not d["hsts"]["presente"]:
            agregar("WEB-SIN-HSTS", f"{h}: sin Strict-Transport-Security")
        elif d["hsts"]["max_age"] is None or d["hsts"]["max_age"] < HSTS_MINIMO:
            agregar("WEB-SIN-HSTS", f"{h}: max-age={d['hsts']['max_age']} (menos de 180 días)")
        if not d["evaluable"]:
            continue
        if not (d["x_frame_options"] or d["frame_ancestors"]):
            agregar("WEB-SIN-PROTECCION-MARCOS", f"{h}: sin X-Frame-Options ni frame-ancestors")
        if not d["nosniff"]:
            agregar("WEB-SIN-NOSNIFF", f"{h}: sin X-Content-Type-Options: nosniff")
        if d["servidor_con_version"]:
            agregar("WEB-VERSION-EXPUESTA", f"{h}: la cabecera Server o X-Powered-By muestra la versión")
    return [_hallazgo(id_, "; ".join(textos)) for id_, textos in evidencias.items()]


def reglas_security_txt(datos: dict[str, Any]) -> list[Hallazgo]:
    if datos["existe"] is None:  # no verificable (redirige a otro dominio, 403, 5xx): no se concluye nada
        return []
    if not datos["existe"]:
        return [_hallazgo("WEB-SIN-SECURITY-TXT", f"https://{datos['dominio']}/.well-known/security.txt no existe")]
    if datos["vencido"]:
        return [_hallazgo("WEB-SIN-SECURITY-TXT", f"security.txt vencido (Expires: {datos['expires']})")]
    if not datos["tiene_contact"]:
        return [_hallazgo("WEB-SIN-SECURITY-TXT", "security.txt sin el campo Contact")]
    return []


def selectores_dkim(llamadas: list[Llamada], objetivo: str) -> dict[str, dict[str, Any]]:
    """Selectores DKIM probados sobre el objetivo, uniendo varias llamadas (por selector, gana la última).

    Única fuente de esta regla: la usan las reglas de aquí y las limitaciones del informe.
    """
    selectores: dict[str, dict[str, Any]] = {}
    for _, r in llamadas:
        if r.herramienta == "dkim_selector" and r.ok and r.datos["dominio"] == objetivo:
            selectores.update({d["selector"]: d for d in r.datos["selectores"]})
    return selectores


SELECTORES_ESTANDAR = {"google": ("google",), "microsoft": ("selector1", "selector2")}


def _estado_selector(d: dict[str, Any]) -> str:
    if d["error"]:
        return f"sin respuesta: {d['error']}"
    if d["revocada"]:
        return "clave revocada"
    return "CNAME sin clave" if d["via_cname"] else "sin registro"


def reglas_dkim(selectores: list[dict[str, Any]], proveedor: str) -> list[Hallazgo]:
    """Hallazgos DKIM del dominio objetivo a partir de todos los selectores probados."""
    h: list[Hallazgo] = []
    validos = [d for d in selectores if d["existe"]]
    probados = {d["selector"] for d in selectores if not d["error"]}
    estandar = SELECTORES_ESTANDAR.get(proveedor)
    if estandar and not validos and set(estandar) <= probados:
        h.append(_hallazgo("CORREO-DKIM-NO-ENCONTRADO", "selectores probados: " + ", ".join(
            f"{d['selector']} ({_estado_selector(d)})" for d in selectores)))
    for id_, condicion in (("CORREO-DKIM-CLAVE-DEBIL", lambda b: b < 1024), ("CORREO-DKIM-CLAVE-1024", lambda b: b == 1024)):
        debiles = [d for d in validos if d["tipo_clave"] == "rsa" and condicion(d["bits"])]
        if debiles:
            h.append(_hallazgo(id_, "; ".join(f"{d['selector']}: RSA de {d['bits']} bits" for d in debiles)))
    return h


# Argumento que identifica el "host" de cada herramienta (para quedarse con el último resultado).
CAMPO_CLAVE = {"tls_certificado": "host", "cabeceras_web": "host", "investigar_parecido": "parecido"}


def evaluar(llamadas: list[Llamada], objetivo: str, hoy: date | None = None) -> dict[str, Hallazgo]:
    """Todos los hallazgos de una auditoría, del más grave al menos grave.

    Por cada herramienta y host cuenta solo el último resultado. Las reglas de correo
    se aplican solo al dominio objetivo; las de TLS, a cada host revisado; las de registro y
    parecidos, al dominio registrable del objetivo.
    """
    objetivo = normalizar_dominio(objetivo)
    registrable = dominio_registrable(objetivo)
    ultimos: dict[tuple[str, str], Llamada] = {}
    for argumentos, r in llamadas:
        campo = CAMPO_CLAVE.get(r.herramienta, "dominio")
        try:
            host = normalizar_dominio(str(argumentos.get(campo, "")))
        except DominioInvalido:
            continue
        ultimos[(r.herramienta, host)] = ({**argumentos, campo: host}, r)

    hallazgos: list[Hallazgo] = []
    for (herramienta, host), (_, r) in ultimos.items():
        if herramienta == "dns_correo" and r.ok and host == objetivo:
            hallazgos += reglas_correo(r.datos)
    hallazgos += reglas_tls([ll for (herramienta, _), ll in ultimos.items() if herramienta == "tls_certificado"])

    exitosos = [r for (_, r) in ultimos.values() if r.ok]

    hallazgos += reglas_cabeceras([r.datos for (herramienta, _), (_, r) in ultimos.items()
                                   if herramienta == "cabeceras_web" and r.ok])
    for r in exitosos:
        if r.herramienta == "security_txt" and r.datos["dominio"] == objetivo:
            hallazgos += reglas_security_txt(r.datos)

    # DKIM: Grok puede probar selectores en varias llamadas; se unen (por selector, gana la última).
    selectores = selectores_dkim(llamadas, objetivo)
    correo_objetivo = ultimos.get(("dns_correo", objetivo))
    if selectores and correo_objetivo and correo_objetivo[1].ok:
        hallazgos += reglas_dkim(list(selectores.values()), correo_objetivo[1].datos["mx"]["proveedor"])
    for r in exitosos:
        if r.herramienta == "whois_dominio" and r.datos["dominio"] == registrable:
            hallazgos += reglas_dominio(r.datos, hoy or date.today())
    busqueda = next((r.datos for r in reversed(exitosos)
                     if r.herramienta == "buscar_parecidos" and r.datos["dominio"] == registrable), None)
    registro_propio = next((r.datos for r in exitosos
                            if r.herramienta == "whois_dominio" and r.datos["dominio"] == registrable), None)
    hallazgos += reglas_parecidos(busqueda, [r.datos for r in exitosos if r.herramienta == "investigar_parecido"],
                                  registro_propio["creado"] if registro_propio else None)

    orden = list(Severidad)  # de crítica a informativa
    return {h.id: h for h in sorted(hallazgos, key=lambda h: orden.index(h.severidad))}


HERRAMIENTAS_POR_HOST = ("tls_certificado", "cabeceras_web")


def solo_lo_principal(llamadas: list[Llamada], objetivo: str) -> list[Llamada]:
    """Las revisiones que se hacen en toda auditoría: correo, registro, parecidos y el sitio del objetivo y www.

    Qué subdominios se revisan lo elige Grok en cada auditoría; si contaran para el semáforo, el mismo
    dominio daría niveles distintos. Sus hallazgos siguen en el informe, solo no mueven el nivel.
    """
    objetivo = normalizar_dominio(objetivo)
    principales = {objetivo, f"www.{objetivo}"}

    def es_principal(argumentos: dict[str, Any], r: ResultadoHerramienta) -> bool:
        if r.herramienta not in HERRAMIENTAS_POR_HOST:
            return True
        try:
            return normalizar_dominio(str(argumentos.get("host", ""))) in principales
        except DominioInvalido:
            return False

    return [(a, r) for a, r in llamadas if es_principal(a, r)]


def hallazgos_de_lo_principal(llamadas: list[Llamada], objetivo: str, hoy: date | None = None) -> dict[str, Hallazgo]:
    """Los hallazgos con los que se calcula el semáforo."""
    return evaluar(solo_lo_principal(llamadas, objetivo), objetivo, hoy)


def nivel_riesgo(hallazgos: dict[str, Hallazgo]) -> NivelRiesgo:
    """Semáforo calculado por código: alto si hay algo crítico o alto, medio si hay algo medio."""
    severidades = {h.severidad for h in hallazgos.values()}
    if severidades & {Severidad.CRITICA, Severidad.ALTA}:
        return NivelRiesgo.ALTO
    if Severidad.MEDIA in severidades:
        return NivelRiesgo.MEDIO
    return NivelRiesgo.BAJO
