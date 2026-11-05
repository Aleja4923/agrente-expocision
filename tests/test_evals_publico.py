"""Todo lo público de evals/ pasa la lista blanca; donde exista el mapa privado, tampoco hay nombres reales."""

import json
from pathlib import Path

import pytest

from auditor.config import RAIZ
from evals import lista_blanca
from evals.casos import RUTA_CASOS, cargar_casos
from evals.seudonimos import Mapa, restos_reales

RUTA_MAPA = RAIZ / "docs" / "evals" / "mapa_seudonimos.json"
RESULTADOS = sorted((Path(lista_blanca.__file__).parent / "resultados").glob("*.jsonl"))


def _permitidos_de_todos() -> set[str]:
    return set().union(*(lista_blanca.permitidos_para(c.dominio) for c in cargar_casos()))


@pytest.mark.parametrize("caso", cargar_casos(), ids=lambda c: c.id)
def test_lista_blanca_en_cada_caso(caso):
    texto = (RUTA_CASOS / f"{caso.id}.json").read_text(encoding="utf-8")
    assert lista_blanca.revisar_texto(texto, lista_blanca.permitidos_para(caso.dominio)) == []


@pytest.mark.parametrize("ruta", RESULTADOS, ids=lambda r: r.name)
def test_lista_blanca_en_resultados(ruta):
    assert lista_blanca.revisar_texto(ruta.read_text(encoding="utf-8"), _permitidos_de_todos()) == []


@pytest.mark.skipif(not RUTA_MAPA.exists(), reason="el mapa de nombres reales es privado")
def test_nombres_reales_si_hay_mapa():
    mapas = [Mapa.model_validate(m) for m in json.loads(RUTA_MAPA.read_text(encoding="utf-8")).values()]
    textos = [a.read_text(encoding="utf-8") for a in [*RUTA_CASOS.glob("*.json"), *RESULTADOS]]
    for m in mapas:
        assert all(restos_reales(t, m) == [] for t in textos), m.seudonimo
