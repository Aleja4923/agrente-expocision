"""llm.py: costo real por llamada, conversación por intento y evento en la bitácora (sin red)."""

import json

import pytest
from openai.types.chat import ChatCompletion

from auditor.llm import ClienteLLM, ErrorGateway, calcular_costo, extraer_uso

# usage real de grok-4.7 medido en la fase 0 (logs/gateway_resultados.json, chat_grok47)
USAGE_REAL = {
    "completion_tokens": 19,
    "prompt_tokens": 1251,
    "total_tokens": 1805,
    "completion_tokens_details": {"reasoning_tokens": 535},
    "prompt_tokens_details": {"cached_tokens": 1152},
    "cost_in_usd_ticks": 40980000,
}


def respuesta(contenido="listo", tool_calls=None, usage=USAGE_REAL):
    mensaje = {"role": "assistant", "content": contenido}
    if tool_calls:
        mensaje["tool_calls"] = tool_calls
    return ChatCompletion.model_validate({
        "id": "x", "object": "chat.completion", "created": 0, "model": "grok-4.7",
        "choices": [{"index": 0, "message": mensaje,
                     "finish_reason": "tool_calls" if tool_calls else "stop"}],
        "usage": usage,
    })


class GrokFalso:
    """Imita cliente.chat.completions.create: guarda lo que recibe y devuelve respuestas fijas."""

    def __init__(self, *respuestas):
        self.respuestas = list(respuestas)
        self.llamadas = []
        self.chat = self
        self.completions = self

    def create(self, **kw):
        self.llamadas.append(kw)
        r = self.respuestas.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def cliente(falso, tmp_path, **extra):
    return ClienteLLM("lote-1", "a-1", "grok-4.7", cliente=falso, ruta_logs=tmp_path, **extra)


def eventos(tmp_path):
    archivo = next(tmp_path.glob("bitacora-*.jsonl"))
    return [json.loads(l) for l in archivo.read_text(encoding="utf-8").splitlines()]


def test_calcular_costo_coincide_con_gateway():
    assert calcular_costo("grok-4.7", 1251, 1152, 19, 535) == pytest.approx(0.004098, abs=1e-9)


def test_extraer_uso_chat():
    assert extraer_uso(USAGE_REAL) == {
        "tokens_entrada": 1251, "tokens_cache": 1152, "tokens_salida": 19,
        "tokens_razonamiento": 535, "ticks": 40980000,
    }


def test_completar_exitoso_escribe_evento(tmp_path):
    r = cliente(GrokFalso(respuesta()), tmp_path).completar(
        [{"role": "user", "content": "hola"}], paso=3, justificacion="prueba")
    assert r.texto == "listo"
    assert r.costo_usd == pytest.approx(0.004098)
    [e] = eventos(tmp_path)
    assert (e["tipo"], e["ok"], e["lote_id"], e["auditoria_id"], e["intento"]) == \
        ("llm", True, "lote-1", "a-1", 1)
    assert (e["paso"], e["tokens_razonamiento"], e["costo_usd"]) == (3, 535, pytest.approx(0.004098))


def test_conv_id_es_auditoria_e_intento(tmp_path):
    falso = GrokFalso(respuesta(), respuesta())
    c = cliente(falso, tmp_path, intento=2)
    c.completar([{"role": "user", "content": "uno"}])
    c.completar([{"role": "user", "content": "dos"}])
    ids = [kw["extra_headers"]["x-grok-conv-id"] for kw in falso.llamadas]
    assert ids == ["a-1-2", "a-1-2"]
    assert "reasoning_effort" not in falso.llamadas[0]


def test_tool_calls_paralelas(tmp_path):
    llamadas = [
        {"id": "c0", "type": "function",
         "function": {"name": "consultar_mx", "arguments": '{"dominio": "ejemplo.com.co"}'}},
        {"id": "c1", "type": "function",
         "function": {"name": "consultar_tls", "arguments": '{"host": "ejemplo.com.co"}'}},
    ]
    r = cliente(GrokFalso(respuesta(None, llamadas)), tmp_path).completar([], herramientas=[])
    assert len(r.tool_calls) == 2
    assert r.tool_calls[0] == {"id": "c0", "nombre": "consultar_mx",
                               "argumentos": '{"dominio": "ejemplo.com.co"}'}
    assert r.mensaje["role"] == "assistant"
    assert len(r.mensaje["tool_calls"]) == 2
    assert r.finish_reason == "tool_calls"


def test_costo_sin_ticks_usa_calculado(tmp_path):
    sin_ticks = {k: v for k, v in USAGE_REAL.items() if k != "cost_in_usd_ticks"}
    r = cliente(GrokFalso(respuesta(usage=sin_ticks)), tmp_path).completar([])
    assert r.costo_usd == r.costo_calculado_usd == pytest.approx(0.004098)


def test_sin_usage_no_rompe(tmp_path):
    r = cliente(GrokFalso(respuesta(usage=None)), tmp_path).completar([])
    assert (r.tokens_entrada, r.tokens_salida, r.costo_usd) == (0, 0, 0.0)
    assert len(eventos(tmp_path)) == 1


def test_sin_tiempo_lanza_error_y_lo_anota(tmp_path):
    falso = GrokFalso(respuesta())
    c = cliente(falso, tmp_path, reloj=lambda: 100.0)
    with pytest.raises(ErrorGateway) as error:
        c.completar([], limite=99.0)
    assert error.value.codigo == "sin_tiempo"
    assert falso.llamadas == []
    [e] = eventos(tmp_path)
    assert (e["tipo"], e["ok"], e["justificacion"]) == ("error", False, "sin_tiempo")


def test_respuesta_sin_choices_es_error_claro(tmp_path):
    vacia = respuesta()
    vacia.choices = []
    with pytest.raises(ErrorGateway) as error:
        cliente(GrokFalso(vacia), tmp_path).completar([])
    assert error.value.codigo == "respuesta_invalida"
    [e] = eventos(tmp_path)
    assert (e["tipo"], e["justificacion"]) == ("error", "respuesta_invalida")


def test_respuesta_vacia_se_devuelve(tmp_path):
    r = cliente(GrokFalso(respuesta(None)), tmp_path).completar([])
    assert r.texto is None
    assert r.tool_calls == []


# --- reintentos y errores con nombre (pulido del S1) ----------------------------

import httpx2  # noqa: E402
import openai  # noqa: E402

URL = "https://api.reto.pltk.mx/v1/chat/completions"


def error_http(clase, status, headers=None, body=None):
    respuesta_http = httpx2.Response(status, request=httpx2.Request("POST", URL), headers=headers or {})
    return clase("error de prueba", response=respuesta_http, body=body)


def cliente_con_esperas(falso, tmp_path, ahora=100.0):
    esperas = []
    c = cliente(falso, tmp_path, dormir=esperas.append, reloj=lambda: ahora)
    return c, esperas


def test_429_reintenta_y_luego_funciona(tmp_path):
    falso = GrokFalso(error_http(openai.RateLimitError, 429), error_http(openai.RateLimitError, 429), respuesta())
    c, esperas = cliente_con_esperas(falso, tmp_path)
    assert c.completar([]).texto == "listo"
    assert len(esperas) == 2 and len(falso.llamadas) == 3
    tipos = [(e["tipo"], e["justificacion"]) for e in eventos(tmp_path)]
    assert tipos == [("error", "reintento:429"), ("error", "reintento:429"), ("llm", None)]


def test_respeta_retry_after(tmp_path):
    falso = GrokFalso(error_http(openai.RateLimitError, 429, {"retry-after": "2"}), respuesta())
    c, esperas = cliente_con_esperas(falso, tmp_path)
    c.completar([])
    assert esperas == [2.0]


def test_retry_after_se_limita(tmp_path):
    falso = GrokFalso(error_http(openai.RateLimitError, 429, {"retry-after": "3600"}), respuesta())
    c, esperas = cliente_con_esperas(falso, tmp_path)
    c.completar([])
    assert esperas == [30.0]


def test_no_reintenta_si_no_alcanza_el_tiempo(tmp_path):
    falso = GrokFalso(error_http(openai.RateLimitError, 429, {"retry-after": "10"}), respuesta())
    c, esperas = cliente_con_esperas(falso, tmp_path, ahora=100.0)
    with pytest.raises(ErrorGateway) as e:
        c.completar([], limite=105.0)
    assert e.value.codigo == "gateway_caido"
    assert len(falso.llamadas) == 1 and esperas == []


def test_timeout_por_intento_respeta_limite(tmp_path):
    falso = GrokFalso(respuesta())
    c, _ = cliente_con_esperas(falso, tmp_path, ahora=100.0)
    c.completar([], limite=120.0)
    assert falso.llamadas[0]["timeout"] <= 20


def test_500_agota_intentos(tmp_path):
    falso = GrokFalso(*[error_http(openai.InternalServerError, 500) for _ in range(4)])
    c, esperas = cliente_con_esperas(falso, tmp_path)
    with pytest.raises(ErrorGateway) as e:
        c.completar([])
    assert e.value.codigo == "gateway_caido"
    assert len(falso.llamadas) == 4 and len(esperas) == 3
    assert [ev["tipo"] for ev in eventos(tmp_path)] == ["error"] * 4


def test_timeout_reintenta(tmp_path):
    falso = GrokFalso(openai.APITimeoutError(request=httpx2.Request("POST", URL)), respuesta())
    c, esperas = cliente_con_esperas(falso, tmp_path)
    assert c.completar([]).texto == "listo" and len(esperas) == 1


@pytest.mark.parametrize("clase,status,codigo", [
    (openai.AuthenticationError, 401, "llave_invalida"),
    (openai.PermissionDeniedError, 403, "sin_creditos"),
    (openai.APIStatusError, 402, "sin_creditos"),
    (openai.BadRequestError, 400, "solicitud_invalida"),
])
def test_errores_4xx_no_reintentan(tmp_path, clase, status, codigo):
    falso = GrokFalso(error_http(clase, status), respuesta())
    c, esperas = cliente_con_esperas(falso, tmp_path)
    with pytest.raises(ErrorGateway) as e:
        c.completar([])
    assert e.value.codigo == codigo
    assert len(falso.llamadas) == 1 and esperas == []
    [evento] = eventos(tmp_path)
    assert (evento["tipo"], evento["justificacion"]) == ("error", codigo)


def test_error_enmascara_llave(tmp_path):
    falso = GrokFalso(error_http(openai.BadRequestError, 400,
                                 body={"error": "llave pk_FALSA0123456789abcdef revocada"}))
    c, _ = cliente_con_esperas(falso, tmp_path)
    with pytest.raises(ErrorGateway) as e:
        c.completar([])
    assert "pk_FALSA" not in str(e.value)
    assert "pk_FALSA" not in next(tmp_path.glob("bitacora-*.jsonl")).read_text(encoding="utf-8")
