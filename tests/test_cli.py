"""CLI: python -m auditor auditar <dominio> [--objetivo] [--modelo] [--verbose]."""

import sqlite3

import pytest

import auditor.__main__ as cli
from tests.test_report import estado


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    llamadas = []

    def auditar_falso(dominio, objetivo=None, *, lote_id, auditoria_id, modelo, observador=None):
        llamadas.append({"dominio": dominio, "objetivo": objetivo, "lote_id": lote_id, "modelo": modelo})
        if observador:
            observador("paso 1 · Grok · USD 0.0040 (acumulado 0.0040)")
            observador("fin · informe_entregado · riesgo alto")
        return estado(["CORREO-DMARC-NONE"])

    monkeypatch.setattr(cli, "auditar", auditar_falso)
    monkeypatch.setattr(cli, "RUTA_SALIDAS", tmp_path / "salidas")
    monkeypatch.setattr(cli, "RUTA_DB", tmp_path / "a.db")
    return tmp_path, llamadas


def test_cli_ejecuta_y_guarda(entorno, capsys):
    tmp_path, llamadas = entorno
    assert cli.main(["auditar", "HTTPS://Ejemplo.com.co/", "--objetivo", "¿Pueden suplantar mi correo?"]) == 0
    assert llamadas[0]["dominio"] == "ejemplo.com.co"
    assert llamadas[0]["objetivo"] == "¿Pueden suplantar mi correo?"
    assert llamadas[0]["lote_id"].startswith("cli-")
    [informe] = list((tmp_path / "salidas").glob("*.md"))
    with sqlite3.connect(tmp_path / "a.db") as conexion:
        assert conexion.execute("select count(*) from auditorias").fetchone()[0] == 1
    salida = capsys.readouterr().out
    assert str(informe) in salida and "ALTO" in salida and "USD 0.0213" in salida


def test_cli_dominio_invalido(entorno, capsys):
    assert cli.main(["auditar", "a@b"]) == 1
    error = capsys.readouterr().err
    assert "Dominio inválido" in error and "Traceback" not in error


def test_cli_modelo_no_permitido(entorno, capsys):
    assert cli.main(["auditar", "ejemplo.com.co", "--modelo", "gpt-5"]) == 2
    assert "no está permitido" in capsys.readouterr().err


def test_cli_verbose_imprime_trayectoria(entorno, capsys):
    cli.main(["auditar", "ejemplo.com.co", "--verbose"])
    assert "paso 1 · Grok" in capsys.readouterr().out


def test_cli_sin_verbose_no_imprime_trayectoria(entorno, capsys):
    cli.main(["auditar", "ejemplo.com.co"])
    assert "paso 1 · Grok" not in capsys.readouterr().out


def test_cli_dominio_inexistente_no_dice_riesgo_bajo(entorno, capsys, monkeypatch):
    from auditor.modelos import ResultadoHerramienta
    e = estado(nivel="bajo")
    e.llamadas = [({"dominio": "ejemplo.com.co"}, ResultadoHerramienta(
        ok=False, herramienta="dns_correo", error="dominio_no_existe", sugerencia="x"))]
    monkeypatch.setattr(cli, "auditar", lambda *a, **k: e)
    assert cli.main(["auditar", "ejemplo.com.co"]) == 0
    salida = capsys.readouterr().out
    assert "El dominio no existe" in salida and "BAJO" not in salida


def test_cli_guarda_e_imprime_el_html(entorno, capsys):
    tmp_path, _ = entorno
    assert cli.main(["auditar", "ejemplo.com.co"]) == 0
    [html] = list((tmp_path / "salidas").glob("*.html"))
    assert f"Informe imprimible: {html}" in capsys.readouterr().out
