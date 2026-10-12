"""Cliente de Grok: la única puerta de entrada al gateway del reto.

- Cada llamada deja un evento en la bitácora con tokens, costo real y latencia.
- Costo real = `usage.cost_in_usd_ticks` del gateway; el calculado con precios de
  config.py queda de respaldo y de verificación cruzada.
- Cada intento de una auditoría es una conversación propia (`x-grok-conv-id`),
  así Grok reutiliza su caché de prompts.
- Reintenta solo lo que puede arreglarse esperando (429, 5xx, tiempo agotado,
  conexión) y nunca se pasa del tiempo que le queda a la auditoría.
"""

import logging
import time
from pathlib import Path
from typing import Any, Callable

from openai import APIConnectionError, APIStatusError, OpenAI, RateLimitError
from pydantic import BaseModel
from tenacity import RetryCallState, Retrying, retry_if_exception, wait_random_exponential

from auditor.bitacora import Evento, enmascarar, escribir
from auditor.config import (
    BASE_URL,
    ESPERA_MAX_SEGUNDOS,
    MAX_INTENTOS_LLM,
    PRECIOS_USD_POR_MILLON,
    REASONING_EFFORT,
    RUTA_LOGS,
    TIMEOUT_LLM_SEGUNDOS,
    USD_POR_TICK,
    cargar_llave,
)

log = logging.getLogger(__name__)


class ErrorGateway(Exception):
    """Fallo del gateway con un código corto y un mensaje en español, sin la llave."""

    def __init__(self, codigo: str, mensaje: str):
        self.codigo = codigo
        self.mensaje = enmascarar(mensaje)
        super().__init__(self.mensaje)


class RespuestaLLM(BaseModel):
    mensaje: dict[str, Any]  # mensaje del asistente, listo para reenviarse en el historial
    texto: str | None
    tool_calls: list[dict[str, str]]  # cada uno: {id, nombre, argumentos}
    finish_reason: str | None
    modelo_respuesta: str | None
    tokens_entrada: int
    tokens_cache: int
    tokens_salida: int
    tokens_razonamiento: int
    costo_usd: float
    costo_calculado_usd: float
    latencia_ms: int


def calcular_costo(modelo: str, entrada: int, cache: int, salida: int, razonamiento: int) -> float:
    """USD de una llamada. En chat, el razonamiento viene aparte de la salida y se cobra como salida."""
    p_in, p_cache, p_out = PRECIOS_USD_POR_MILLON[modelo]
    return ((entrada - cache) * p_in + cache * p_cache + (salida + razonamiento) * p_out) / 1_000_000


def extraer_uso(usage: dict[str, Any] | None) -> dict[str, Any]:
    """Tokens y costo reportado del `usage` de chat/completions; todo en 0 si no vino."""
    u = usage or {}
    return {
        "tokens_entrada": u.get("prompt_tokens") or 0,
        "tokens_cache": (u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0,
        "tokens_salida": u.get("completion_tokens") or 0,
        "tokens_razonamiento": (u.get("completion_tokens_details") or {}).get("reasoning_tokens") or 0,
        "ticks": u.get("cost_in_usd_ticks"),
    }


def _es_reintentable(e: BaseException) -> bool:
    if isinstance(e, (RateLimitError, APIConnectionError)):  # APITimeoutError hereda de APIConnectionError
        return True
    return isinstance(e, APIStatusError) and e.status_code >= 500


def _retry_after(e: BaseException) -> float | None:
    if not isinstance(e, APIStatusError):
        return None
    try:
        return float(e.response.headers.get("retry-after"))
    except (TypeError, ValueError):
        return None


def _espera(estado: RetryCallState) -> float:
    """Respeta Retry-After si el gateway lo manda (con tope); si no, espera exponencial con jitter."""
    pedido = _retry_after(estado.outcome.exception())
    if pedido is not None:
        return min(pedido, ESPERA_MAX_SEGUNDOS)
    return wait_random_exponential(multiplier=1, max=ESPERA_MAX_SEGUNDOS)(estado)


def _a_error_gateway(e: BaseException, intentos: int) -> ErrorGateway:
    if isinstance(e, APIStatusError) and not _es_reintentable(e):
        if e.status_code == 401:
            return ErrorGateway("llave_invalida",
                                "La llave del reto es inválida o fue revocada. Revisa RETO_KEY en .env.")
        if e.status_code in (402, 403):
            return ErrorGateway("sin_creditos",
                                "El gateway rechazó la llamada por créditos o permisos. Revisa el panel del reto.")
        return ErrorGateway("solicitud_invalida", f"El gateway rechazó la solicitud: {str(e.body or e)[:300]}")
    return ErrorGateway("gateway_caido", f"El gateway no respondió después de {intentos} intento(s).")


class ClienteLLM:
    """Habla con Grok para un intento de una auditoría y anota cada llamada en la bitácora."""

    def __init__(
        self,
        lote_id: str,
        auditoria_id: str,
        modelo: str,
        *,
        intento: int = 1,
        dominio: str | None = None,
        cliente: Any = None,
        llave: str | None = None,
        ruta_logs: Path = RUTA_LOGS,
        dormir: Callable[[float], None] = time.sleep,
        reloj: Callable[[], float] = time.monotonic,
    ):
        self.lote_id, self.auditoria_id, self.intento = lote_id, auditoria_id, intento
        self.modelo, self.dominio, self.ruta_logs = modelo, dominio, ruta_logs
        self.dormir, self.reloj = dormir, reloj
        self.conv_id = f"{auditoria_id}-{intento}"
        self.cliente = cliente or OpenAI(
            base_url=BASE_URL, api_key=llave or cargar_llave(),
            timeout=TIMEOUT_LLM_SEGUNDOS, max_retries=0,
        )

    def _anotar(self, paso: int, justificacion: str | None, **campos) -> None:
        escribir(Evento(lote_id=self.lote_id, auditoria_id=self.auditoria_id, intento=self.intento,
                        dominio=self.dominio, paso=paso, modelo=self.modelo,
                        justificacion=justificacion, **campos), self.ruta_logs)

    def completar(
        self,
        mensajes: list[dict[str, Any]],
        herramientas: list[dict[str, Any]] | None = None,
        *,
        paso: int = 0,
        justificacion: str | None = None,
        limite: float | None = None,
    ) -> RespuestaLLM:
        """Una llamada a chat/completions con reintentos. `limite` es el instante (time.monotonic)
        en que vence la auditoría: ningún intento ni espera lo sobrepasa."""
        kw: dict[str, Any] = {
            "model": self.modelo,
            "messages": mensajes,
            "extra_headers": {"x-grok-conv-id": self.conv_id},
        }
        if herramientas:
            kw["tools"] = herramientas
        if REASONING_EFFORT:
            kw["reasoning_effort"] = REASONING_EFFORT
        inicio = self.reloj()

        def parar(estado: RetryCallState) -> bool:
            if estado.attempt_number >= MAX_INTENTOS_LLM:
                return True
            espera = estado.upcoming_sleep or 0
            return limite is not None and self.reloj() + espera + 1 > limite

        def anotar_fallo(estado: RetryCallState) -> None:
            e = estado.outcome.exception()
            motivo = getattr(e, "status_code", None) or type(e).__name__
            self._anotar(paso, f"reintento:{motivo}", tipo="error", ok=False,
                         latencia_ms=int((self.reloj() - inicio) * 1000))

        def llamar():
            if limite is not None:
                restante = limite - self.reloj()
                if restante <= 0:
                    raise ErrorGateway("sin_tiempo", "No quedó tiempo de la auditoría para llamar a Grok.")
                kw["timeout"] = min(TIMEOUT_LLM_SEGUNDOS, restante)
            return self.cliente.chat.completions.create(**kw)

        reintentos = Retrying(retry=retry_if_exception(_es_reintentable), stop=parar, wait=_espera,
                              sleep=self.dormir, after=anotar_fallo, reraise=True)
        def fallar(error: ErrorGateway) -> ErrorGateway:
            self._anotar(paso, error.codigo, tipo="error", ok=False,
                         latencia_ms=int((self.reloj() - inicio) * 1000))
            return error

        try:
            resp = reintentos(llamar)
        except ErrorGateway as e:
            raise fallar(e) from None
        except (APIStatusError, APIConnectionError) as e:
            error = _a_error_gateway(e, reintentos.statistics.get("attempt_number", 1))
            if _es_reintentable(e):  # cada intento ya quedó anotado uno por uno
                raise error from None
            raise fallar(error) from None
        if not resp.choices:
            raise fallar(ErrorGateway("respuesta_invalida", "El gateway respondió sin ningún mensaje de Grok."))

        latencia = int((self.reloj() - inicio) * 1000)
        uso = extraer_uso(resp.usage.model_dump() if resp.usage else None)
        if resp.usage is None:
            log.warning("El gateway no devolvió usage; la llamada queda con costo 0.")
        calculado = calcular_costo(self.modelo, uso["tokens_entrada"], uso["tokens_cache"],
                                   uso["tokens_salida"], uso["tokens_razonamiento"])
        costo = uso["ticks"] * USD_POR_TICK if uso["ticks"] is not None else calculado
        if abs(costo - calculado) > max(0.01 * costo, 1e-6):
            log.warning("Costo del gateway (%.6f) difiere del calculado (%.6f): revisar precios.",
                        costo, calculado)

        mensaje = resp.choices[0].message
        tool_calls = [{"id": c.id, "nombre": c.function.name, "argumentos": c.function.arguments}
                      for c in mensaje.tool_calls or []]
        tokens = {k: uso[k] for k in ("tokens_entrada", "tokens_cache", "tokens_salida", "tokens_razonamiento")}
        self._anotar(paso, justificacion, tipo="llm", ok=True, costo_usd=round(costo, 10),
                     latencia_ms=latencia, **tokens)
        return RespuestaLLM(
            mensaje=mensaje.model_dump(exclude_none=True),
            texto=mensaje.content,
            tool_calls=tool_calls,
            finish_reason=resp.choices[0].finish_reason,
            modelo_respuesta=resp.model,
            costo_usd=round(costo, 10),
            costo_calculado_usd=round(calculado, 10),
            latencia_ms=latencia,
            **tokens,
        )
