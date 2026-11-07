"""carga/consumo.py: bitácora de consumo pública y cruce con el panel (sin red ni llave)."""

import csv
import json

from carga import consumo


def _evento(**kw):
    base = {"ts": "2026-11-06T10:00:00+00:00", "lote_id": "s4-carga", "auditoria_id": "s4-carga-0021", "intento": 1,
            "dominio": "empresa-real.com.co", "paso": 1, "tipo": "llm", "modelo": "grok-4.20", "tokens_entrada": 100,
            "tokens_cache": 50, "tokens_salida": 10, "tokens_razonamiento": 5, "costo_usd": 0.01, "latencia_ms": 900,
            "ok": True, "justificacion": "texto de Grok"}
    return base | kw


def test_hito_por_lote_y_por_fecha():
    assert consumo.hito(_evento()) == "S4"
    assert consumo.hito(_evento(lote_id="evals-inyeccion")) == "S4"
    assert consumo.hito(_evento(lote_id="evals-final")) == "S3"
    assert consumo.hito(_evento(lote_id="cli-x", ts="2026-10-12T10:00:00")) == "S1"
    assert consumo.hito(_evento(lote_id="cli-x", ts="2026-10-24T10:00:00")) == "S2"
    assert consumo.hito(_evento(lote_id=None, run_id="gateway-1", ts="2026-10-09T10:00:00")) == "S1"
    assert consumo.hito(_evento(lote_id="cli-x", ts="2026-11-07T10:00:00")) == "Después del S4"


def test_solo_respuestas_y_cortes_por_tiempo_son_peticiones():
    assert consumo.es_peticion(_evento())
    assert consumo.es_peticion(_evento(tipo="error", justificacion="reintento:APITimeoutError"))
    assert not consumo.es_peticion(_evento(tipo="error", justificacion="reintento:APIConnectionError"))
    assert not consumo.es_peticion(_evento(tipo="error", justificacion="llave_invalida"))
    assert not consumo.es_peticion(_evento(tipo="herramienta"))


def test_la_fila_publica_no_lleva_dominio_ni_justificacion():
    f = consumo.fila(_evento(lote_id="cli-20261028", auditoria_id="falabella.com.co-6ca2979e"))
    assert set(f) == set(consumo.COLUMNAS)
    assert "falabella" not in json.dumps(f) and f["auditoria_id"].startswith("a-")
    assert consumo.fila(_evento())["auditoria_id"] == "s4-carga-0021"  # los lotes públicos conservan su id


def test_exporta_csv_y_cruza_con_el_panel(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    eventos = [_evento(), _evento(tipo="error", costo_usd=0, tokens_entrada=0, justificacion="reintento:APITimeoutError"),
               _evento(tipo="herramienta"), _evento(modelo="grok-4.7", lote_id="evals-final", costo_usd=0.05)]
    (logs / "bitacora-20261106.jsonl").write_text("".join(json.dumps(e) + "\n" for e in eventos) + "{rota",
                                                  encoding="utf-8")
    filas = consumo.leer_peticiones(logs)
    assert len(filas) == 3
    panel = {"consultado": "hoy", "modelos": {"grok-4.20": {"peticiones": 2, "entrada": 100, "salida": 20,
                                                            "costo": 0.01}}}
    consumo.escribir(filas, panel, tmp_path / "consumo")
    with (tmp_path / "consumo" / "consumo.csv").open(encoding="utf-8") as f:
        assert len(list(csv.DictReader(f))) == 3
    texto = (tmp_path / "consumo" / "RESUMEN.md").read_text(encoding="utf-8")
    assert "| grok-4.20 | 2 · 2 |" in texto and "| S4 | 2 | 0.01 |" in texto and "| S3 | 1 | 0.05 |" in texto
    assert "empresa-real" not in (tmp_path / "consumo" / "consumo.csv").read_text(encoding="utf-8")
