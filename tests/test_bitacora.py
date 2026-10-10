"""bitacora.py: esquema fijo, UTF-8 y la llave nunca llega al archivo."""

import json

import pytest
from pydantic import ValidationError

from auditor.bitacora import Evento, enmascarar, escribir, hash_args

CAMPOS = [
    "ts", "run_id", "auditoria_id", "dominio", "paso", "tipo", "modelo",
    "tokens_entrada", "tokens_cache", "tokens_salida", "tokens_razonamiento",
    "costo_usd", "latencia_ms", "herramienta", "args_hash", "ok",
    "justificacion", "motivo_cierre",
]


def leer_lineas(archivo):
    return [json.loads(l) for l in archivo.read_text(encoding="utf-8").splitlines()]


def test_evento_tiene_exactamente_los_18_campos():
    assert list(Evento.model_fields) == CAMPOS


def test_campo_extra_o_tipo_invalido_se_rechaza():
    with pytest.raises(ValidationError):
        Evento(run_id="r", tipo="llm", costo=0.1)
    with pytest.raises(ValidationError):
        Evento(run_id="r", tipo="charla")


def test_escribir_agrega_una_linea_json_por_evento(tmp_path):
    escribir(Evento(run_id="r1", tipo="inicio", dominio="ferreteria.com.co"), tmp_path)
    archivo = escribir(Evento(run_id="r1", tipo="fin", motivo_cierre="informe_entregado"), tmp_path)
    assert archivo.name.startswith("bitacora-") and archivo.suffix == ".jsonl"
    lineas = leer_lineas(archivo)
    assert [l["tipo"] for l in lineas] == ["inicio", "fin"]
    assert all(list(l) == CAMPOS for l in lineas)


def test_tildes_se_guardan_en_utf8(tmp_path):
    archivo = escribir(Evento(run_id="r", tipo="llm", justificacion="Revisar el correo de Bogotá"),
                       tmp_path)
    assert "Bogotá" in archivo.read_text(encoding="utf-8")


def test_llave_se_enmascara_antes_de_escribir(tmp_path):
    archivo = escribir(
        Evento(run_id="r", tipo="error", justificacion="falló con pk_FALSA0123456789abcdef"),
        tmp_path,
    )
    texto = archivo.read_text(encoding="utf-8")
    assert "pk_FALSA" not in texto
    assert "pk_***" in texto


def test_llave_del_entorno_se_enmascara_aunque_no_tenga_forma_pk(monkeypatch):
    monkeypatch.setenv("RETO_KEY", "secreto-raro-42")
    assert enmascarar("error con secreto-raro-42") == "error con pk_***"


def test_hash_args_no_depende_del_orden():
    assert hash_args({"a": 1, "b": "x"}) == hash_args({"b": "x", "a": 1})
    assert hash_args({"a": 1}) != hash_args({"a": 2})
