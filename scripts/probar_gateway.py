"""Verificación del gateway del reto (fase 0, sección 4.0 de la especificación).

Responde con llamadas reales, no con suposiciones, qué soporta el gateway:
endpoints, campos de `usage`, herramientas en paralelo, reasoning_effort,
grok-4.20, errores de llave y caché de prompts.

Uso:  venv\\Scripts\\python.exe scripts\\probar_gateway.py

- Cada llamada a Grok deja una línea en logs/bitacora-AAAAMMDD.jsonl (todo gasto
  queda registrado) con los campos del esquema de la bitácora.
- Las respuestas crudas van a logs/gateway_resultados.json para redactar
  docs/NOTAS_GATEWAY.md.
- La llave nunca se imprime: cualquier texto de error pasa por `enmascarar`.
"""

import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auditor.bitacora import Evento, enmascarar, escribir  # noqa: E402
from auditor.config import BASE_URL, RUTA_LOGS, cargar_llave  # noqa: E402
from auditor.llm import calcular_costo  # noqa: E402

LLAVE = cargar_llave()
LOTE_ID = f"gateway-{uuid.uuid4().hex[:8]}"
SALIDA = RUTA_LOGS / "gateway_resultados.json"

cliente = OpenAI(base_url=BASE_URL, api_key=LLAVE, timeout=90, max_retries=0)
resultados: dict[str, object] = {}
paso = 0
BITACORA = None


def leer(obj, *ruta, defecto=None):
    """Lee un campo anidado de un objeto o dict sin fallar si no existe."""
    for clave in ruta:
        if obj is None:
            return defecto
        obj = obj.get(clave) if isinstance(obj, dict) else getattr(obj, clave, None)
    return defecto if obj is None else obj


def tokens_de(usage) -> dict:
    """Normaliza `usage` de chat/completions y de responses a un solo formato."""
    u = usage.model_dump() if hasattr(usage, "model_dump") else (usage or {})
    entrada = leer(u, "prompt_tokens") or leer(u, "input_tokens", defecto=0)
    salida = leer(u, "completion_tokens") or leer(u, "output_tokens", defecto=0)
    cache = leer(u, "prompt_tokens_details", "cached_tokens") or leer(
        u, "input_tokens_details", "cached_tokens", defecto=0
    )
    razonamiento = leer(u, "completion_tokens_details", "reasoning_tokens") or leer(
        u, "output_tokens_details", "reasoning_tokens", defecto=0
    )
    total = leer(u, "total_tokens", defecto=0)
    # ¿Los tokens de razonamiento vienen dentro de los de salida o aparte?
    razonamiento_aparte = bool(razonamiento) and total == entrada + salida + razonamiento
    return {
        "tokens_entrada": entrada,
        "tokens_cache": cache,
        "tokens_salida": salida,
        "tokens_razonamiento": razonamiento,
        "razonamiento_aparte": razonamiento_aparte,
        "usage_crudo": u,
    }


def costo_usd(modelo: str, t: dict) -> float:
    """Mismo cálculo que llm.py. En `responses` el razonamiento ya viene dentro de la salida."""
    razonamiento = t["tokens_razonamiento"] if t["razonamiento_aparte"] else 0
    return calcular_costo(modelo, t["tokens_entrada"], t["tokens_cache"], t["tokens_salida"], razonamiento)


def anotar(modelo, t, latencia_ms, ok, nombre):
    """Escribe un evento `llm` en la bitácora con el esquema de la sección 4.4."""
    global paso, BITACORA
    paso += 1
    evento = Evento(
        lote_id=LOTE_ID,
        paso=paso,
        tipo="llm" if ok else "error",
        modelo=modelo,
        tokens_entrada=t.get("tokens_entrada", 0),
        tokens_cache=t.get("tokens_cache", 0),
        tokens_salida=t.get("tokens_salida", 0),
        tokens_razonamiento=t.get("tokens_razonamiento", 0),
        costo_usd=round(costo_usd(modelo, t), 8) if t else 0.0,
        latencia_ms=latencia_ms,
        ok=ok,
        justificacion=f"verificacion_gateway:{nombre}",
    )
    BITACORA = escribir(evento)
    return evento.model_dump()


def describir_error(e: Exception) -> dict:
    info = {"tipo": type(e).__name__, "mensaje": enmascarar(str(e))[:500]}
    if isinstance(e, APIStatusError):
        info["status"] = e.status_code
        try:
            info["cuerpo"] = json.loads(enmascarar(json.dumps(e.body, ensure_ascii=False)))
        except (TypeError, ValueError):
            info["cuerpo"] = enmascarar(str(e.body))[:500]
    return info


def probar(nombre: str, modelo: str, llamada):
    """Ejecuta una llamada, registra costo y guarda el resultado o el error."""
    inicio = time.perf_counter()
    try:
        resp = llamada()
    except (APIStatusError, APIConnectionError, APITimeoutError) as e:
        latencia = int((time.perf_counter() - inicio) * 1000)
        anotar(modelo, {}, latencia, False, nombre)
        resultados[nombre] = {"ok": False, "latencia_ms": latencia, "error": describir_error(e)}
        print(f"[{nombre}] ERROR {resultados[nombre]['error']}")
        return None
    latencia = int((time.perf_counter() - inicio) * 1000)
    t = tokens_de(getattr(resp, "usage", None))
    evento = anotar(modelo, t, latencia, True, nombre)
    resultados[nombre] = {
        "ok": True,
        "modelo_respuesta": getattr(resp, "model", None),
        "latencia_ms": latencia,
        "costo_usd": evento["costo_usd"],
        **t,
    }
    print(
        f"[{nombre}] ok · entrada={t['tokens_entrada']} cache={t['tokens_cache']} "
        f"salida={t['tokens_salida']} razonamiento={t['tokens_razonamiento']} "
        f"· {latencia} ms · USD {evento['costo_usd']:.6f}"
    )
    return resp


# --- 0. Modelos disponibles -------------------------------------------------
try:
    modelos = [m.model_dump() for m in cliente.models.list()]
    resultados["modelos"] = modelos
    print("[modelos]", [m.get("id") for m in modelos])
except Exception as e:  # noqa: BLE001 - solo diagnóstico
    resultados["modelos"] = {"error": describir_error(e)}
    print("[modelos] ERROR", resultados["modelos"])

MSG_CORTO = [{"role": "user", "content": "Responde solo con la palabra: listo"}]

# --- 1. chat/completions y responses con grok-4.7 -----------------------------
r = probar("chat_grok47", "grok-4.7",
           lambda: cliente.chat.completions.create(model="grok-4.7", messages=MSG_CORTO))
if r:
    resultados["chat_grok47"]["texto"] = r.choices[0].message.content

r = probar("responses_grok47", "grok-4.7",
           lambda: cliente.responses.create(model="grok-4.7", input="Responde solo con la palabra: listo"))
if r:
    resultados["responses_grok47"]["texto"] = getattr(r, "output_text", None)

# --- 3. Herramientas y tool_calls en paralelo ---------------------------------
HERRAMIENTAS = [
    {"type": "function", "function": {
        "name": "consultar_mx", "description": "Devuelve los servidores MX de un dominio.",
        "parameters": {"type": "object", "properties": {"dominio": {"type": "string"}},
                       "required": ["dominio"]}}},
    {"type": "function", "function": {
        "name": "consultar_tls", "description": "Devuelve el estado del certificado TLS de un host.",
        "parameters": {"type": "object", "properties": {"host": {"type": "string"}},
                       "required": ["host"]}}},
]
MSG_TOOLS = [{"role": "user", "content":
              "Necesito el MX y el TLS de ejemplo.com.co. Llama ambas herramientas "
              "en este mismo turno, en paralelo, sin texto adicional."}]
r = probar("tools_paralelo", "grok-4.7", lambda: cliente.chat.completions.create(
    model="grok-4.7", messages=MSG_TOOLS, tools=HERRAMIENTAS))
if r:
    msg = r.choices[0].message
    llamadas = msg.tool_calls or []
    resultados["tools_paralelo"]["num_tool_calls"] = len(llamadas)
    resultados["tools_paralelo"]["tool_calls"] = [
        {"id": c.id, "nombre": c.function.name, "args": c.function.arguments} for c in llamadas]
    resultados["tools_paralelo"]["finish_reason"] = r.choices[0].finish_reason
    # Ida y vuelta: devolver resultados de herramienta y ver si Grok continúa bien.
    if llamadas:
        seguimiento = MSG_TOOLS + [msg.model_dump(exclude_none=True)] + [
            {"role": "tool", "tool_call_id": c.id,
             "content": json.dumps({"ok": True, "datos": "simulado"})} for c in llamadas]
        r2 = probar("tools_vuelta", "grok-4.7", lambda: cliente.chat.completions.create(
            model="grok-4.7", messages=seguimiento, tools=HERRAMIENTAS))
        if r2:
            resultados["tools_vuelta"]["texto"] = r2.choices[0].message.content
            resultados["tools_vuelta"]["finish_reason"] = r2.choices[0].finish_reason

# --- 4. reasoning_effort ------------------------------------------------------
MSG_RAZONAR = [{"role": "user", "content":
                "¿Cuántos números primos hay entre 1 y 60? Responde solo el número."}]
for nivel in ("low", "medium", "high"):
    r = probar(f"effort_{nivel}", "grok-4.7", lambda: cliente.chat.completions.create(
        model="grok-4.7", messages=MSG_RAZONAR, reasoning_effort=nivel))
    if r:
        resultados[f"effort_{nivel}"]["texto"] = r.choices[0].message.content
r = probar("effort_ninguno", "grok-4.7", lambda: cliente.chat.completions.create(
    model="grok-4.7", messages=MSG_RAZONAR))
if r:
    resultados["effort_ninguno"]["texto"] = r.choices[0].message.content

# --- 5. grok-4.20 -------------------------------------------------------------
r = probar("chat_grok420", "grok-4.20",
           lambda: cliente.chat.completions.create(model="grok-4.20", messages=MSG_CORTO))
if r:
    resultados["chat_grok420"]["texto"] = r.choices[0].message.content
r = probar("tools_grok420", "grok-4.20", lambda: cliente.chat.completions.create(
    model="grok-4.20", messages=MSG_TOOLS, tools=HERRAMIENTAS))
if r:
    resultados["tools_grok420"]["num_tool_calls"] = len(r.choices[0].message.tool_calls or [])

# --- 6. Llave inválida --------------------------------------------------------
cliente_malo = OpenAI(base_url=BASE_URL, api_key="pk_invalida_prueba", timeout=30, max_retries=0)
try:
    cliente_malo.chat.completions.create(model="grok-4.7", messages=MSG_CORTO)
    resultados["llave_invalida"] = {"ok": True, "nota": "¡la llamada no falló!"}
except Exception as e:  # noqa: BLE001 - queremos ver cualquier error
    resultados["llave_invalida"] = describir_error(e)
print("[llave_invalida]", resultados["llave_invalida"])

# --- 7. Caché de prompts con x-grok-conv-id ------------------------------------
SISTEMA_LARGO = (
    "Eres un auditor pasivo de seguridad para pymes colombianas. "
    "Revisas SPF, DMARC, MX y certificados TLS usando solo información pública. "
) * 60  # ~1.500 tokens: suficiente para que la caché aplique
conv_id = str(uuid.uuid4())
for intento in (1, 2):
    probar(f"cache_{intento}", "grok-4.7", lambda: cliente.chat.completions.create(
        model="grok-4.7",
        messages=[{"role": "system", "content": SISTEMA_LARGO}, *MSG_CORTO],
        extra_headers={"x-grok-conv-id": conv_id}))

# --- Resumen ------------------------------------------------------------------
total = sum(v.get("costo_usd", 0) for v in resultados.values() if isinstance(v, dict))
resultados["_resumen"] = {"lote_id": LOTE_ID, "costo_total_usd_calculado": round(total, 6),
                          "precios": "provisionales", "ts": datetime.now(timezone.utc).isoformat()}
SALIDA.write_text(json.dumps(resultados, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
print(f"\nCosto total calculado (precios provisionales): USD {total:.6f}")
print(f"Lote: {LOTE_ID} · bitácora: {BITACORA.name if BITACORA else '-'} · detalle: {SALIDA.name}")
