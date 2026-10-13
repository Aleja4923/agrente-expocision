"""Reglas deterministas: convierten los datos de las herramientas en hallazgos.

Aquí se decide QUÉ es un problema y CON QUÉ severidad (CONTEXT.md §6b). Grok nunca
crea hallazgos: solo puede citar los que salen de este archivo. Los textos siguen
las reglas de redacción de CONTEXT.md §7b (nada absoluto, trato de usted).
La evidencia se arma solo con `datos` parseados, nunca con contenido no confiable.
"""

from typing import Any

from auditor.modelos import Categoria, Hallazgo, NivelRiesgo, ResultadoHerramienta, Severidad
from auditor.tools.base import DominioInvalido, normalizar_dominio

Llamada = tuple[dict[str, Any], ResultadoHerramienta]  # (argumentos que pidió Grok, resultado)

C, W = Categoria.CORREO, Categoria.WEB
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


def evaluar(llamadas: list[Llamada], objetivo: str) -> dict[str, Hallazgo]:
    """Todos los hallazgos de una auditoría, del más grave al menos grave.

    Por cada herramienta y host cuenta solo el último resultado. Las reglas de correo
    se aplican solo al dominio objetivo; las de TLS, a cada host revisado.
    """
    objetivo = normalizar_dominio(objetivo)
    ultimos: dict[tuple[str, str], Llamada] = {}
    for argumentos, r in llamadas:
        campo = "host" if r.herramienta == "tls_certificado" else "dominio"
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

    orden = list(Severidad)  # de crítica a informativa
    return {h.id: h for h in sorted(hallazgos, key=lambda h: orden.index(h.severidad))}


def nivel_riesgo(hallazgos: dict[str, Hallazgo]) -> NivelRiesgo:
    """Semáforo calculado por código: alto si hay algo crítico o alto, medio si hay algo medio."""
    severidades = {h.severidad for h in hallazgos.values()}
    if severidades & {Severidad.CRITICA, Severidad.ALTA}:
        return NivelRiesgo.ALTO
    if Severidad.MEDIA in severidades:
        return NivelRiesgo.MEDIO
    return NivelRiesgo.BAJO
