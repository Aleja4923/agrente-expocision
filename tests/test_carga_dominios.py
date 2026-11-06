"""carga/dominios.py: lista de la corrida del S4 desde Tranco (sin red)."""

import csv

from carga import dominios

LINEAS = ["1,google.com\r\n", "2,google.com.co\n", "3,Mercado.COM.CO\n", "4,www.tienda.com.co\n", "5,uni.edu.co\n",
          "6,empresa.co\n", "7,google.com.co\n", "8,a_b.com.co\n", "9,-malo.com.co\n", "rango,dominio\n", "\n",
          "10,café.com.co\n", "11,pyme-2.com.co\n"]


def test_filtra_solo_registrables_com_co():
    assert dominios.filtrar(LINEAS) == [(2, "google.com.co"), (3, "mercado.com.co"), (11, "pyme-2.com.co")]


def test_muestra_reproducible_y_sin_repetidos():
    candidatos = [(i, f"d{i}.com.co") for i in range(1, 501)]
    a = dominios.muestra(candidatos, 120, semilla=2026)
    b = dominios.muestra(candidatos, 120, semilla=2026)
    assert a == b and len(a) == 120 and len({d for _, d in a}) == 120
    assert a != dominios.muestra(candidatos, 120, semilla=7)
    assert a != sorted(a)  # el orden de la cola también es al azar


def test_muestra_falla_si_no_alcanzan():
    import pytest
    with pytest.raises(ValueError):
        dominios.muestra([(1, "a.com.co")], 2, semilla=1)


def test_csv_separa_prueba_y_corrida(tmp_path):
    elegidos = [(i * 10, f"d{i}.com.co") for i in range(1, 26)]
    ruta = tmp_path / "dominios.csv"
    dominios.escribir_csv(elegidos, ruta, n_prueba=20)
    filas = list(csv.DictReader(ruta.open(encoding="utf-8")))
    assert [f["pos"] for f in filas[:2]] == ["1", "2"] and filas[0]["dominio"] == "d1.com.co"
    assert filas[0]["rango_tranco"] == "10"
    assert [f["uso"] for f in filas].count("prueba") == 20 and filas[20]["uso"] == "corrida"
    assert dominios.leer_csv(ruta) == [(int(f["pos"]), f["dominio"], f["uso"]) for f in filas]
