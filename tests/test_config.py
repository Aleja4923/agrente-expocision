import pytest

from auditor import config


@pytest.fixture
def sin_llave(monkeypatch):
    # setenv + delenv: al terminar la prueba, el entorno vuelve a como estaba.
    monkeypatch.setenv("RETO_KEY", "temporal")
    monkeypatch.delenv("RETO_KEY")


def test_sin_llave_sale_con_mensaje_claro(sin_llave, tmp_path):
    with pytest.raises(SystemExit) as error:
        config.cargar_llave(tmp_path / "no_existe.env")
    assert "RETO_KEY" in str(error.value)


def test_llave_de_plantilla_se_rechaza(sin_llave, tmp_path):
    env = tmp_path / ".env"
    env.write_text("RETO_KEY=pk_REEMPLAZAR\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        config.cargar_llave(env)


def test_llave_desde_archivo_env(sin_llave, tmp_path):
    env = tmp_path / ".env"
    env.write_text("RETO_KEY=pk_prueba_falsa_123\n", encoding="utf-8")
    assert config.cargar_llave(env) == "pk_prueba_falsa_123"


def test_modelo_no_permitido_se_rechaza():
    with pytest.raises(SystemExit) as error:
        config.modelo_elegido("gpt-5")
    assert "grok-4.7" in str(error.value)


def test_modelo_desde_variable_de_entorno(monkeypatch):
    monkeypatch.setenv("MODELO", "grok-4.20")
    assert config.modelo_elegido() == "grok-4.20"


def test_hay_precio_para_cada_modelo_permitido():
    assert set(config.PRECIOS_USD_POR_MILLON) == set(config.MODELOS_PERMITIDOS)
