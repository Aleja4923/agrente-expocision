"""agent.py: bucle del agente con un Grok falso que sigue un guion (sin red, sin llave, sin costo)."""

import copy
import json
import re

import pytest

from auditor import agent
from auditor.llm import ErrorGateway, RespuestaLLM
from auditor.modelos import ResultadoHerramienta
from tests.test_scoring import correo

DOMINIO = "ejemplo.com.co"


# --- dobles de prueba ----------------------------------------------------------

def resp(*llamadas, texto=None, costo=0.005):
    """Respuesta de Grok: cada llamada es (herramienta, argumentos)."""
    tcs = [{"id": f"c{i}", "nombre": n, "argumentos": a if isinstance(a, str) else json.dumps(a)}
           for i, (n, a) in enumerate(llamadas)]
    mensaje = {"role": "assistant", "content": texto}
    if tcs:
        mensaje["tool_calls"] = [{"id": t["id"], "type": "function",
                                  "function": {"name": t["nombre"], "arguments": t["argumentos"]}} for t in tcs]
    return RespuestaLLM(mensaje=mensaje, texto=texto, tool_calls=tcs,
                        finish_reason="tool_calls" if tcs else "stop", modelo_respuesta="grok-4.7",
                        tokens_entrada=0, tokens_cache=0, tokens_salida=0, tokens_razonamiento=0,
                        costo_usd=costo, costo_calculado_usd=costo, latencia_ms=1)


class GrokGuion:
    """Imita ClienteLLM.completar devolviendo respuestas en orden (o una función del número de paso)."""

    def __init__(self, *pasos, al_llamar=None):
        self.pasos = list(pasos)
        self.mensajes, self.limites, self.herramientas = [], [], None
        self.al_llamar = al_llamar

    def completar(self, mensajes, herramientas=None, *, paso=0, justificacion=None, limite=None):
        self.mensajes.append(copy.deepcopy(mensajes))
        self.limites.append(limite)
        self.herramientas = herramientas
        if self.al_llamar:
            self.al_llamar()
        p = self.pasos.pop(0) if len(self.pasos) > 1 else self.pasos[0]
        p = p(len(self.mensajes)) if callable(p) else p
        if isinstance(p, Exception):
            raise p
        return p


def dns_ok(datos=None):
    return ResultadoHerramienta(ok=True, herramienta="dns_correo", datos=datos or correo(dmarc={"p": "none"}),
                                contenido_no_confiable={"txt_dominio": ["v=spf1 -all"]})


def tls_ok(host=DOMINIO, **cambios):
    datos = {"valido": True, "motivo": None, "vence": "2027-01-01", "dias_restantes": 80,
             "version_tls": "TLSv1.3", "ip": "93.184.216.34", "host": host} | cambios
    return ResultadoHerramienta(ok=True, herramienta="tls_certificado", datos=datos)


def whois_ok(**cambios):
    datos = {"dominio": DOMINIO, "fuente": "whois", "creado": "2003-04-21T00:00:00+00:00",
             "vence": "2099-04-24T23:59:59+00:00", "dias_para_vencer": 26000,
             "estados": ["clientTransferProhibited"], "bloqueo_transferencia": True,
             "servidores_nombre": ["ns1.ejemplo-dns.com"]} | cambios
    return ResultadoHerramienta(ok=True, herramienta="whois_dominio", datos=datos)


def busqueda_ok(*con_correo):
    return ResultadoHerramienta(ok=True, herramienta="buscar_parecidos", datos={
        "dominio": DOMINIO, "generadas": 27, "truncadas": False, "existentes": len(con_correo),
        "con_correo": [{"dominio": d, "tipo": "omision", "mx": ["mx.otro.com"], "comparte_servidores": False}
                       for d in con_correo], "sin_verificar": [], "ns_propios": [], "mx_propios": []})


def investigacion_ok(parecido, dias=400, spf=False):
    return ResultadoHerramienta(ok=True, herramienta="investigar_parecido", datos={
        "parecido": parecido, "tipo": "omision", "existe": True, "tiene_mx": True,
        "creado": "2025-01-01T00:00:00+00:00", "dias_desde_registro": dias, "spf_autoriza_envio": spf,
        "comparte_servidores": False, "fuente_registro": "whois", "aviso": None})


def ct_ok(*nombres):
    return ResultadoHerramienta(ok=True, herramienta="subdominios_ct", datos={
        "dominio": DOMINIO, "fuente": "crtsh", "total": len(nombres), "mostrados": len(nombres), "truncados": False,
        "subdominios": [{"nombre": n, "ultimo_certificado_vence": "2027-01-01", "vigente": True} for n in nombres]})


def cabeceras_ok(host=DOMINIO, **cambios):
    datos = {"host": host, "http_responde": True, "redirige_a_https": True, "codigo_final": 200,
             "url_final": f"https://{host}/", "redirecciones": 0, "redirige_fuera": None, "evaluable": True,
             "hsts": {"presente": True, "max_age": 31536000, "include_subdomains": True}, "x_frame_options": True,
             "frame_ancestors": False, "nosniff": True, "csp_presente": True, "referrer_policy": True,
             "servidor_con_version": False} | cambios
    return ResultadoHerramienta(ok=True, herramienta="cabeceras_web", datos=datos)


def security_ok():
    return ResultadoHerramienta(ok=True, herramienta="security_txt", datos={
        "dominio": DOMINIO, "codigo": 200, "existe": True, "tiene_contact": True, "expires": None, "vencido": False})


class EjecutorFalso:
    def __init__(self, tabla=None):
        self.tabla = tabla or {}
        self.recibidos = []

    def __call__(self, nombre, argumentos, objetivo):
        self.recibidos.append((nombre, argumentos))
        host = argumentos.get("parecido") or argumentos.get("dominio") or argumentos.get("host")
        clave = (nombre, host)
        if clave in self.tabla:
            return self.tabla[clave]
        por_defecto = {"dns_correo": dns_ok, "whois_dominio": whois_ok, "buscar_parecidos": busqueda_ok,
                       "investigar_parecido": lambda: investigacion_ok(host), "subdominios_ct": ct_ok,
                       "dkim_selector": lambda: dkim_ok("google"), "cabeceras_web": lambda: cabeceras_ok(host),
                       "security_txt": security_ok}
        return por_defecto[nombre]() if nombre in por_defecto else tls_ok(host)


def informe(*citados, acciones=None):
    acciones = acciones if acciones is not None else [
        {"hallazgo_id": c, "por_que_primero": "Es lo más urgente.", "recomendacion": "Pídale a su proveedor ajustarlo."}
        for c in citados]
    return {"resumen": "Resumen para el dueño.", "hallazgos_citados": list(citados),
            "acciones_priorizadas": acciones, "limitaciones": []}


DNS = ("dns_correo", {"dominio": DOMINIO, "justificacion": "Base para evaluar suplantación."})
TLS = ("tls_certificado", {"host": DOMINIO, "justificacion": "Revisar el sitio."})
WHOIS = ("whois_dominio", {"dominio": DOMINIO, "justificacion": "Vencimiento y bloqueo del dominio."})
BUSCAR = ("buscar_parecidos", {"dominio": DOMINIO, "justificacion": "Dominios parecidos con correo."})
CT = ("subdominios_ct", {"dominio": DOMINIO, "justificacion": "Subdominios con certificado."})
CAB = ("cabeceras_web", {"host": DOMINIO, "justificacion": "Cabeceras de la portada."})
SEC = ("security_txt", {"dominio": DOMINIO, "justificacion": "Contacto de seguridad."})
DKIM = ("dkim_selector", {"dominio": DOMINIO, "selectores": ["google"], "justificacion": "Proveedor Google."})
BASE = (DNS, TLS, WHOIS, BUSCAR, CT, CAB, SEC, DKIM)  # obligatorias del S2 (DKIM, porque el proveedor de prueba es Google)


def investigar(parecido):
    return ("investigar_parecido", {"dominio": DOMINIO, "parecido": parecido, "justificacion": "Sospechoso."})


def correr(grok, tmp_path, ejecutor=None, **kw):
    return agent.auditar(DOMINIO, lote_id="L1", auditoria_id="A1", cliente_llm=grok,
                         ejecutor=ejecutor or EjecutorFalso(), ruta_logs=tmp_path, **kw)


def eventos(tmp_path):
    archivo = next(tmp_path.glob("bitacora-*.jsonl"))
    return [json.loads(l) for l in archivo.read_text(encoding="utf-8").splitlines()]


# --- tarea 2: núcleo -------------------------------------------------------------

def test_camino_feliz(tmp_path):
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "informe_entregado"
    assert estado.informe_de_respaldo is False
    assert estado.nivel_riesgo == "alto"
    assert estado.informe.hallazgos_citados == ["CORREO-DMARC-NONE"]
    assert "CORREO-DMARC-NONE" in estado.hallazgos
    assert estado.pasos == 2 and estado.costo_usd == pytest.approx(0.010)
    assert [e["tipo"] for e in eventos(tmp_path)] == ["inicio"] + ["herramienta"] * 8 + ["fin"]
    assert all((e["lote_id"], e["auditoria_id"], e["dominio"]) == ("L1", "A1", DOMINIO) for e in eventos(tmp_path))


def test_prompt_sistema_sin_dominio_ni_fecha(tmp_path):
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    correr(grok, tmp_path)
    assert "ejemplo" not in agent.PROMPT_SISTEMA
    assert not re.search(r"20\d\d", agent.PROMPT_SISTEMA)
    primero, usuario = grok.mensajes[0][0], grok.mensajes[0][1]
    assert primero == {"role": "system", "content": agent.PROMPT_SISTEMA}
    assert DOMINIO in usuario["content"]


def test_herramientas_exigen_justificacion():
    herramientas = {h["function"]["name"]: h["function"]["parameters"] for h in agent.herramientas_para_grok()}
    assert {"dns_correo", "tls_certificado", "entregar_informe"} <= set(herramientas)
    for nombre, parametros in herramientas.items():
        if nombre != "entregar_informe":
            assert "justificacion" in parametros["required"]


def test_justificacion_va_a_bitacora_y_no_a_la_herramienta(tmp_path):
    ejecutor = EjecutorFalso()
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    correr(grok, tmp_path, ejecutor)
    assert all("justificacion" not in args for _, args in ejecutor.recibidos)
    [e] = [e for e in eventos(tmp_path) if e["herramienta"] == "dns_correo"]
    assert e["justificacion"] == "Base para evaluar suplantación." and e["ok"] is True and e["args_hash"]


def test_mensaje_tool_lleva_hallazgos_y_no_confiable(tmp_path):
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    correr(grok, tmp_path)
    [herramienta_dns] = [m for m in grok.mensajes[1] if m.get("role") == "tool" and m["tool_call_id"] == "c0"]
    contenido = json.loads(herramienta_dns["content"])
    assert set(contenido) == {"resultado", "contenido_no_confiable", "hallazgos_actuales"}
    assert contenido["contenido_no_confiable"] == {"txt_dominio": ["v=spf1 -all"]}
    assert "CORREO-DMARC-NONE" in [h["id"] for h in contenido["hallazgos_actuales"]]


def test_texto_sin_herramientas_recibe_recordatorio(tmp_path):
    grok = GrokGuion(resp(texto="Voy a revisar el dominio."), resp(*BASE),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "informe_entregado" and estado.pasos == 3
    assert grok.mensajes[1][-1]["role"] == "user"
    assert "entregar_informe" in grok.mensajes[1][-1]["content"]


def test_fuera_de_alcance_registra_rechazo(tmp_path):
    fuera = ResultadoHerramienta(ok=False, herramienta="tls_certificado", error="fuera_de_alcance",
                                 sugerencia="Solo se permite ejemplo.com.co y sus subdominios.")
    ejecutor = EjecutorFalso({("tls_certificado", "otro.com"): fuera})
    grok = GrokGuion(resp(*BASE, ("tls_certificado", {"host": "otro.com", "justificacion": "x"})),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    correr(grok, tmp_path, ejecutor)
    rechazos = [e for e in eventos(tmp_path) if e["tipo"] == "rechazo"]
    assert len(rechazos) == 1 and rechazos[0]["herramienta"] == "tls_certificado"


# --- tarea 3: completitud, validador e informe de respaldo -------------------------

def test_entrega_incompleta_se_rechaza(tmp_path):
    grok = GrokGuion(resp(DNS), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))), resp(TLS, WHOIS, BUSCAR, CT, CAB, SEC, DKIM),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "informe_entregado" and estado.pasos == 4
    rechazos = [e for e in eventos(tmp_path) if e["tipo"] == "rechazo"]
    assert len(rechazos) == 1 and "tls_certificado" in rechazos[0]["justificacion"]
    rechazo_a_grok = json.loads(grok.mensajes[2][-1]["content"])
    assert rechazo_a_grok["aceptado"] is False
    assert any("tls_certificado" in p for p in rechazo_a_grok["problemas"])


def test_dominio_inexistente_permite_entregar_sin_tls(tmp_path):
    no_existe = ResultadoHerramienta(ok=False, herramienta="dns_correo", error="dominio_no_existe",
                                     sugerencia="Verifique que el dominio esté bien escrito.")
    grok = GrokGuion(resp(DNS), resp(("entregar_informe", informe())))
    estado = correr(grok, tmp_path, EjecutorFalso({("dns_correo", DOMINIO): no_existe}))
    assert estado.motivo_cierre == "informe_entregado"
    assert estado.hallazgos == {} and estado.nivel_riesgo == "bajo"


def test_informe_con_id_inventado_se_rechaza(tmp_path):
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe("CORREO-DMARC-NONE", "CORREO-INVENTADO"))),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "informe_entregado" and estado.informe_de_respaldo is False
    problemas = json.loads(grok.mensajes[2][-1]["content"])["problemas"]
    assert any("CORREO-INVENTADO" in p for p in problemas)


def test_informe_que_omite_critico_se_rechaza(tmp_path):
    vencido = tls_ok(valido=False, motivo="vencido", dias_restantes=-3, vence="2026-10-09")
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))),
                     resp(("entregar_informe", informe("WEB-TLS-INVALIDO", "CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path, EjecutorFalso({("tls_certificado", DOMINIO): vencido}))
    assert estado.motivo_cierre == "informe_entregado"
    problemas = json.loads(grok.mensajes[2][-1]["content"])["problemas"]
    assert any("WEB-TLS-INVALIDO" in p for p in problemas)


def test_rechazos_agotados_cierra_con_respaldo(tmp_path):
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe())), resp(("entregar_informe", informe())))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "rechazos_agotados"
    assert estado.informe_de_respaldo is True
    assert "CORREO-DMARC-NONE" in estado.informe.hallazgos_citados
    assert [a.hallazgo_id for a in estado.informe.acciones_priorizadas] == ["CORREO-DMARC-NONE"]
    assert estado.informe.limitaciones


def test_argumentos_de_informe_invalidos_cuentan_como_rechazo(tmp_path):
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", '{"resumen": 5}')),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "informe_entregado"
    assert len([e for e in eventos(tmp_path) if e["tipo"] == "rechazo"]) == 1


# --- tarea 4: topes, repetición y errores del gateway ----------------------------

def fin(tmp_path):
    [e] = [e for e in eventos(tmp_path) if e["tipo"] == "fin"]
    return e


def test_tope_pasos(tmp_path):
    # Grok nunca entrega: pide un subdominio distinto en cada paso (sin repetir llamadas).
    grok = GrokGuion(lambda n: resp(("dns_correo", {"dominio": f"s{n}.{DOMINIO}", "justificacion": "x"})))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "tope_pasos" and estado.pasos == 20
    assert len(grok.mensajes) == 20
    assert estado.informe_de_respaldo is True and fin(tmp_path)["motivo_cierre"] == "tope_pasos"


def test_tope_costo(tmp_path):
    grok = GrokGuion(lambda n: resp(("dns_correo", {"dominio": f"s{n}.{DOMINIO}", "justificacion": "x"}),
                                    costo=0.06))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "tope_costo" and estado.pasos == 4
    assert estado.costo_usd == pytest.approx(0.24)
    assert estado.informe_de_respaldo is True


def test_tope_tiempo(tmp_path):
    reloj = {"t": 0.0}

    def avanzar():
        reloj["t"] += 70

    grok = GrokGuion(lambda n: resp(("dns_correo", {"dominio": f"s{n}.{DOMINIO}", "justificacion": "x"})),
                     al_llamar=avanzar)
    estado = correr(grok, tmp_path, reloj=lambda: reloj["t"])
    assert estado.motivo_cierre == "tope_tiempo" and estado.pasos == 5
    assert set(grok.limites) == {300.0}


def test_repeticion_avisa_y_luego_cierra(tmp_path):
    ejecutor = EjecutorFalso()
    grok = GrokGuion(resp(DNS))
    estado = correr(grok, tmp_path, ejecutor)
    assert estado.motivo_cierre == "repeticion" and estado.pasos == 4
    assert len(ejecutor.recibidos) == 2  # la 3.ª y la 4.ª no se ejecutan
    aviso = json.loads(grok.mensajes[3][-1]["content"])
    assert aviso["resultado"]["error"] == "repeticion"
    assert any(e["tipo"] == "rechazo" and e["justificacion"] == "repeticion" for e in eventos(tmp_path))


def test_error_gateway_cierra_ordenado(tmp_path):
    grok = GrokGuion(resp(*BASE), ErrorGateway("sin_creditos", "Sin créditos."))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "error_gateway"
    assert estado.informe_de_respaldo is True
    assert any("sin_creditos" in l for l in estado.informe.limitaciones)
    assert "CORREO-DMARC-NONE" in estado.informe.hallazgos_citados


def test_sin_tiempo_del_cliente_es_tope_tiempo(tmp_path):
    grok = GrokGuion(resp(*BASE), ErrorGateway("sin_tiempo", "No quedó tiempo."))
    assert correr(grok, tmp_path).motivo_cierre == "tope_tiempo"


# --- fase 7: observador en vivo --------------------------------------------------

def test_observador_recibe_trayectoria(tmp_path):
    lineas = []
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe())),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    correr(grok, tmp_path, observador=lineas.append)
    texto = "\n".join(lineas)
    assert "paso 1 · Grok" in texto
    assert "dns_correo(ejemplo.com.co) «Base para evaluar suplantación.»" in texto
    assert "✓ MX google, SPF -all, DMARC none" in texto
    assert "✓ válido, vence en 80 días" in texto
    assert "⚑ hallazgos: CORREO-DMARC-NONE" in texto
    assert "✗ informe rechazado" in texto
    assert lineas[-1] == "fin · informe_entregado · riesgo alto"


def test_verbose_muestra_dmarc_duplicado():
    datos = correo(dmarc={"multiple": True, "valido": False, "p": None})
    r = ResultadoHerramienta(ok=True, herramienta="dns_correo", datos=datos)
    assert "DMARC duplicado" in agent._resumen_resultado(r) and "None" not in agent._resumen_resultado(r)


# --- S2: obligatorias, cupo de parecidos y --verbose ----------------------------------

def test_faltantes_exige_las_cuatro(tmp_path):
    grok = GrokGuion(resp(DNS, TLS), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))),
                     resp(WHOIS, BUSCAR, CT, CAB, SEC, DKIM), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path)
    assert estado.motivo_cierre == "informe_entregado" and estado.pasos == 4
    problemas = json.loads(grok.mensajes[2][-1]["content"])["problemas"]
    assert all(any(h in p for p in problemas) for h in ("whois_dominio", "buscar_parecidos", "subdominios_ct", "cabeceras_web", "security_txt",
                                                    "dkim_selector"))


def test_obligatorias_desde_subdominio_cuentan():
    estado = agent.EstadoAuditoria(dominio=DOMINIO, lote_id="L", auditoria_id="A", modelo="grok-4.7")
    estado.llamadas = [({"dominio": DOMINIO}, dns_ok()), ({"host": DOMINIO}, tls_ok()),
                       ({"dominio": "www." + DOMINIO}, whois_ok()), ({"dominio": "www." + DOMINIO}, busqueda_ok()),
                       ({"dominio": "www." + DOMINIO}, ct_ok()), ({"dominio": DOMINIO}, dkim_ok("google")),
                       ({"host": DOMINIO}, cabeceras_ok()), ({"dominio": DOMINIO}, security_ok())]
    assert agent.faltantes(estado) == []


def test_quinto_investigar_parecido_es_cupo_agotado(tmp_path):
    parecidos = ["ejmplo.com.co", "ejemlo.com.co", "jeemplo.com.co", "ejjemplo.com.co", "ejemplo.co"]
    ejecutor = EjecutorFalso({("buscar_parecidos", DOMINIO): busqueda_ok(*parecidos)})
    grok = GrokGuion(resp(*BASE), resp(*[investigar(p) for p in parecidos]),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path, ejecutor)
    assert estado.motivo_cierre == "informe_entregado"
    assert sorted(a["parecido"] for n, a in ejecutor.recibidos if n == "investigar_parecido") == sorted(parecidos[:4])
    quinto = [json.loads(m["content"]) for m in grok.mensajes[2] if m.get("tool_call_id") == "c4"][-1]
    assert quinto["resultado"]["error"] == "cupo_agotado"
    assert any(e["tipo"] == "rechazo" and e["justificacion"] == "cupo_agotado" for e in eventos(tmp_path))
    assert sum(1 for _, r in estado.llamadas if r.herramienta == "investigar_parecido") == 4


def test_prompt_menciona_herramientas_nuevas_y_no_acusar():
    assert all(n in agent.PROMPT_SISTEMA for n in ("whois_dominio", "buscar_parecidos", "investigar_parecido"))
    assert "en paralelo" in agent.PROMPT_SISTEMA


def test_resumen_verbose_nuevas_herramientas():
    assert agent._resumen_resultado(busqueda_ok("a.co", "b.co")) == "✓ 27 variantes, 2 existen, 2 con correo"
    assert agent._resumen_resultado(investigacion_ok("a.co", dias=12, spf=True)) == (
        "✓ registrado hace 12 días, MX sí, SPF envía sí")
    sin_fecha = investigacion_ok("a.co")
    sin_fecha.datos["dias_desde_registro"] = None
    assert agent._resumen_resultado(sin_fecha) == "✓ fecha desconocida, MX sí, SPF envía no"
    assert agent._resumen_resultado(whois_ok(dias_para_vencer=210)) == "✓ vence en 210 días, bloqueo sí"


def test_verbose_anuncia_la_tanda_antes_de_ejecutar(tmp_path):
    lineas = []
    grok = GrokGuion(resp(*BASE), resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    correr(grok, tmp_path, observador=lineas.append)
    anuncio = next(i for i, l in enumerate(lineas) if "ejecutando en paralelo" in l)
    primera = next(i for i, l in enumerate(lineas) if "→" in l)
    assert anuncio < primera
    assert "dns_correo, tls_certificado, whois_dominio, buscar_parecidos, subdominios_ct" in lineas[anuncio]


def test_verbose_muestra_el_parecido_investigado(tmp_path):
    lineas = []
    ejecutor = EjecutorFalso({("buscar_parecidos", DOMINIO): busqueda_ok("ejmplo.com.co")})
    grok = GrokGuion(resp(*BASE), resp(investigar("ejmplo.com.co")),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    correr(grok, tmp_path, ejecutor, observador=lineas.append)
    assert any("investigar_parecido(ejmplo.com.co)" in l for l in lineas)


def tls_de(host):
    return ("tls_certificado", {"host": host, "justificacion": "Subdominio sensible."})


def test_sexto_subdominio_es_cupo_agotado(tmp_path):
    subs = [f"s{i}.{DOMINIO}" for i in range(6)]
    ejecutor = EjecutorFalso({("subdominios_ct", DOMINIO): ct_ok(*subs)})
    grok = GrokGuion(resp(*BASE), resp(tls_de("www." + DOMINIO), *[tls_de(h) for h in subs]),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    estado = correr(grok, tmp_path, ejecutor)
    revisados = [a["host"] for n, a in ejecutor.recibidos if n == "tls_certificado"]
    assert sorted(revisados) == sorted([DOMINIO, "www." + DOMINIO] + subs[:5])  # el objetivo y www no gastan cupo
    assert any(e["tipo"] == "rechazo" and e["justificacion"] == "cupo_agotado" for e in eventos(tmp_path))
    assert estado.motivo_cierre == "informe_entregado"


def test_mismo_subdominio_no_gasta_dos_cupos(tmp_path):
    subs = [f"s{i}.{DOMINIO}" for i in range(5)]
    grok = GrokGuion(resp(*BASE), resp(*[tls_de(h) for h in subs]), resp(tls_de(subs[0])),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    ejecutor = EjecutorFalso()
    correr(grok, tmp_path, ejecutor)
    assert [a["host"] for n, a in ejecutor.recibidos if n == "tls_certificado"].count(subs[0]) == 2


def test_resumen_verbose_ct():
    assert agent._resumen_resultado(ct_ok("a.ejemplo.com.co", "b.ejemplo.com.co")) == (
        "✓ crtsh: 2 subdominios (2 mostrados)")


# --- S2: DKIM condicional ---------------------------------------------------------------

def dkim_ok(*selectores):
    return ResultadoHerramienta(ok=True, herramienta="dkim_selector", datos={"dominio": DOMINIO, "selectores": [
        {"selector": s, "existe": True, "via_cname": False, "destino_cname": None, "destino_microsoft": False,
         "revocada": False, "tipo_clave": "rsa", "bits": 2048, "error": None} for s in selectores]})


def _estado_con(*llamadas):
    estado = agent.EstadoAuditoria(dominio=DOMINIO, lote_id="L", auditoria_id="A", modelo="grok-4.7")
    estado.llamadas = [({"dominio": DOMINIO}, dns_ok(correo(mx={"proveedor": p}))) if isinstance(p := l, str)
                       else l for l in llamadas]
    return estado


BASE_OK = [({"host": DOMINIO}, tls_ok()), ({"dominio": DOMINIO}, whois_ok()), ({"dominio": DOMINIO}, busqueda_ok()),
           ({"dominio": DOMINIO}, ct_ok()), ({"host": DOMINIO}, cabeceras_ok()),
           ({"dominio": DOMINIO}, security_ok())]


@pytest.mark.parametrize("proveedor,exige", [("google", True), ("microsoft", True), ("otro", False),
                                             ("ninguno", False)])
def test_dkim_obligatorio_segun_proveedor(proveedor, exige):
    estado = _estado_con(proveedor, *BASE_OK)
    assert (f"dkim_selector sobre {DOMINIO}" in agent.faltantes(estado)) is exige
    estado.llamadas.append(({"dominio": DOMINIO}, dkim_ok("google")))
    assert agent.faltantes(estado) == []


def test_resumen_verbose_dkim():
    r = dkim_ok("google")
    r.datos["selectores"].append({"selector": "s1", "existe": False, "via_cname": True, "destino_cname": "x",
                                  "destino_microsoft": False, "revocada": False, "tipo_clave": None, "bits": None,
                                  "error": None})
    assert agent._resumen_resultado(r) == "✓ google: RSA 2048 bits; s1: CNAME sin clave"


def test_prompt_guia_selectores():
    assert "dkim_selector" in agent.PROMPT_SISTEMA and "selector1" in agent.PROMPT_SISTEMA


def test_reintentar_un_parecido_no_gasta_otro_cupo(tmp_path):
    parecidos = ["ejmplo.com.co", "ejemlo.com.co", "jeemplo.com.co", "ejjemplo.com.co"]
    ejecutor = EjecutorFalso({("buscar_parecidos", DOMINIO): busqueda_ok(*parecidos)})
    grok = GrokGuion(resp(*BASE), resp(*[investigar(p) for p in parecidos[:3]]),
                     resp(investigar(parecidos[0]), investigar(parecidos[3])),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    correr(grok, tmp_path, ejecutor)
    recibidos = [a["parecido"] for n, a in ejecutor.recibidos if n == "investigar_parecido"]
    assert sorted(recibidos) == sorted(parecidos + [parecidos[0]])


def test_cabeceras_de_subdominio_comparten_cupo_con_tls(tmp_path):
    subs = [f"s{i}.{DOMINIO}" for i in range(5)]
    grok = GrokGuion(resp(*BASE), resp(*[tls_de(h) for h in subs], ("cabeceras_web", {"host": subs[0], "justificacion": "x"}),
                                       ("cabeceras_web", {"host": f"s9.{DOMINIO}", "justificacion": "x"})),
                     resp(("entregar_informe", informe("CORREO-DMARC-NONE"))))
    ejecutor = EjecutorFalso()
    correr(grok, tmp_path, ejecutor)
    cab = [a["host"] for n, a in ejecutor.recibidos if n == "cabeceras_web"]
    assert sorted(cab) == sorted([DOMINIO, subs[0]])  # s9 sería el 6.º host: cupo agotado


def test_resumen_verbose_cabeceras_y_security_txt():
    assert agent._resumen_resultado(cabeceras_ok(nosniff=False)) == (
        "✓ http→https sí, HSTS sí, marcos sí, nosniff no")
    assert agent._resumen_resultado(security_ok()) == "✓ security.txt existe, Contact sí"
