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
