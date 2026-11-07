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


# --- Entrega final: salida JSON y lote para que el harness corra sus propios casos ------------------------

import json  # noqa: E402


def test_cli_json_es_una_linea_con_el_resultado(entorno, capsys):
    assert cli.main(["auditar", "ejemplo.com.co", "--json", "--verbose"]) == 0
    salida = capsys.readouterr()
    r = json.loads(salida.out.strip())
    assert r["dominio"] == "ejemplo.com.co" and r["existe"] is True and r["nivel"] == "alto"
    assert r["hallazgos"][0]["id"] == "CORREO-DMARC-NONE" and r["acciones"][0]["hallazgo_id"] == "CORREO-DMARC-NONE"
    assert {"provisional", "limitaciones", "costo_usd", "pasos", "motivo_cierre", "informe_md"} <= set(r)
    assert "paso 1 · Grok" in salida.err  # con --json, la trayectoria va a stderr y stdout queda limpio


def test_cli_lote_audita_cada_linea_y_sigue_con_un_invalido(entorno, capsys, tmp_path):
    _, llamadas = entorno
    lote = tmp_path / "casos.txt"
    lote.write_text("# casos del harness\nejemplo.com.co\n\nno es un dominio\notro.com.co;¿Es seguro mi portal de pagos?\n",
                    encoding="utf-8")
    assert cli.main(["auditar", "--lote", str(lote), "--json"]) == 1  # hubo un dominio inválido
    lineas = [json.loads(x) for x in capsys.readouterr().out.strip().splitlines()]
    assert [x.get("error") for x in lineas] == [None, "dominio_invalido", None]
    assert [c["dominio"] for c in llamadas] == ["ejemplo.com.co", "otro.com.co"]
    assert llamadas[1]["objetivo"] == "¿Es seguro mi portal de pagos?"
    assert llamadas[0]["lote_id"] == llamadas[1]["lote_id"]


def test_cli_exige_dominio_o_lote(entorno):
    with pytest.raises(SystemExit):
        cli.main(["auditar"])
    with pytest.raises(SystemExit):
        cli.main(["auditar", "ejemplo.com.co", "--lote", "x.txt"])
