"""metricas.py: resumen de auditorías desde la bitácora."""

import pytest

from auditor.metricas import agregado, resumir


def ev(tipo, aud="A1", ts="2026-10-24T10:00:00+00:00", **campos):
    return {"ts": ts, "lote_id": "L", "auditoria_id": aud, "intento": 1, "dominio": "ejemplo.com.co", "paso": 0,
            "tipo": tipo, "costo_usd": 0.0, "herramienta": None, "ok": None, "motivo_cierre": None} | campos


EVENTOS = [
    ev("inicio"), ev("llm", paso=1, costo_usd=0.01), ev("herramienta", herramienta="dns_correo"),
    ev("herramienta", herramienta="tls_certificado"), ev("llm", paso=2, costo_usd=0.02),
    ev("rechazo", herramienta="investigar_parecido"), ev("herramienta", herramienta="dns_correo"),
    ev("fin", ts="2026-10-24T10:00:42+00:00", costo_usd=0.03, ok=True, motivo_cierre="informe_entregado"),
    ev("inicio", aud="A0", ts="2026-10-01T10:00:00+00:00"),  # anterior a "desde"
    ev("inicio", aud="A2"), ev("llm", aud="A2", paso=1, costo_usd=0.005),  # sin fin
]


def test_resumir_una_auditoria():
    [a1, a2] = resumir(EVENTOS, desde="2026-10-24T00:00:00+00:00")
    assert a1 == {"auditoria_id": "A1", "intento": 1, "dominio": "ejemplo.com.co", "pasos": 2, "costo_usd": 0.03,
                  "segundos": 42, "motivo_cierre": "informe_entregado", "respaldo": False,
                  "llamadas_herramientas": 3, "herramientas_distintas": 2, "rechazos": 1}
    assert (a2["motivo_cierre"], a2["segundos"], a2["respaldo"]) == (None, None, None)


def test_agregado():
    filas = resumir(EVENTOS, desde="2026-10-24T00:00:00+00:00")
    a = agregado(filas)
    assert (a["auditorias"], a["informe_entregado"], a["respaldo"], a["costo_total_usd"]) == (2, 1, 0, 0.035)
    assert a["costo_usd"] == pytest.approx({"min": 0.005, "mediana": 0.0175, "max": 0.03})
    assert a["segundos"] == {"min": 42, "mediana": 42, "max": 42}
