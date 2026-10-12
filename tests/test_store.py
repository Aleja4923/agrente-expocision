"""store.py: registro de auditorías en SQLite (base de las evals del S3 y de la cola del S4)."""

import sqlite3

from auditor.modelos import ResultadoHerramienta
from auditor.store import guardar_auditoria, leer_auditoria
from tests.test_report import estado


def test_guarda_y_lee(tmp_path):
    db = tmp_path / "a.db"
    guardar_auditoria(estado(["CORREO-DMARC-NONE"]), tmp_path / "informe.md", db)
    fila = leer_auditoria("A1", 1, db)
    assert fila["dominio"] == "ejemplo.com.co" and fila["lote_id"] == "L1"
    assert fila["motivo_cierre"] == "informe_entregado" and fila["nivel_riesgo"] == "alto"
    assert fila["hallazgos"] == ["CORREO-DMARC-NONE"]
    assert fila["informe"]["hallazgos_citados"] == ["CORREO-DMARC-NONE"]
    assert fila["costo_usd"] == 0.0213 and fila["informe_de_respaldo"] is False
    assert fila["ruta_informe"].endswith("informe.md")


def test_reescribir_mismo_intento_no_duplica(tmp_path):
    db = tmp_path / "a.db"
    guardar_auditoria(estado(), None, db)
    guardar_auditoria(estado(["CORREO-DMARC-NONE"]), None, db)
    with sqlite3.connect(db) as conexion:
        assert conexion.execute("select count(*) from auditorias").fetchone()[0] == 1
        assert conexion.execute("select count(*) from llamadas").fetchone()[0] == 1
    assert leer_auditoria("A1", 1, db)["hallazgos"] == ["CORREO-DMARC-NONE"]


def test_llamadas_en_orden(tmp_path):
    db = tmp_path / "a.db"
    e = estado()
    e.llamadas.append(({"host": "pagos.ejemplo.com.co"}, ResultadoHerramienta(
        ok=False, herramienta="tls_certificado", error="sin_https", sugerencia="x")))
    guardar_auditoria(e, None, db)
    assert leer_auditoria("A1", 1, db)["llamadas"] == [
        {"orden": 1, "herramienta": "dns_correo", "host": "ejemplo.com.co", "ok": True, "error": None},
        {"orden": 2, "herramienta": "tls_certificado", "host": "pagos.ejemplo.com.co", "ok": False,
         "error": "sin_https"},
    ]


def test_leer_inexistente(tmp_path):
    assert leer_auditoria("no-existe", 1, tmp_path / "a.db") is None
