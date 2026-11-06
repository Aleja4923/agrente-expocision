"""Lista de dominios de la corrida del S4: muestra al azar de los `.com.co` de la lista Tranco completa.

Método (reproducible):
1. Se descarga la lista Tranco completa con id `TRANCO_ID` (una lista pública de investigación que ordena sitios
   por popularidad; el id fija el día, así que cualquiera obtiene la misma).
2. Se dejan solo los dominios registrables `<nombre>.com.co`.
3. Se saca una muestra de `N_PRUEBA + N_CORRIDA` con `random.Random(SEMILLA)`; el orden de la muestra es el de la
   cola. Las primeras `N_PRUEBA` posiciones son el lote de prueba y el resto, la corrida larga.

Solo se descarga la lista: ningún dominio se consulta aquí.
"""

import argparse
import csv
import random
import re
import urllib.request
from pathlib import Path
from typing import Iterable, Iterator

TRANCO_ID = "JZPGY"
URL_TRANCO = "https://tranco-list.eu/download/{id}/full"
SEMILLA = 2026
N_PRUEBA = 20
N_CORRIDA = 1150
RUTA_CSV = Path(__file__).resolve().parent / "dominios.csv"

_COM_CO = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.com\.co$")


def filtrar(lineas: Iterable[str]) -> list[tuple[int, str]]:
    """(rango, dominio) de cada `<nombre>.com.co` válido, sin repetidos, en el orden de la lista."""
    vistos, salida = set(), []
    for linea in lineas:
        partes = linea.strip().split(",")
        if len(partes) != 2 or not partes[0].isdigit():
            continue
        dominio = partes[1].strip().lower()
        if _COM_CO.match(dominio) and dominio not in vistos:
            vistos.add(dominio)
            salida.append((int(partes[0]), dominio))
    return salida


def muestra(candidatos: list[tuple[int, str]], n: int, semilla: int) -> list[tuple[int, str]]:
    """`n` candidatos al azar, en orden al azar, siempre los mismos para la misma semilla."""
    if n > len(candidatos):
        raise ValueError(f"se piden {n} dominios y solo hay {len(candidatos)}")
    return random.Random(semilla).sample(candidatos, n)


def escribir_csv(elegidos: list[tuple[int, str]], ruta: Path, n_prueba: int = N_PRUEBA) -> None:
    with ruta.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pos", "dominio", "rango_tranco", "uso"])
        for pos, (rango, dominio) in enumerate(elegidos, start=1):
            w.writerow([pos, dominio, rango, "prueba" if pos <= n_prueba else "corrida"])


def leer_csv(ruta: Path = RUTA_CSV) -> list[tuple[int, str, str]]:
    """(posición, dominio, uso) en el orden de la cola."""
    with ruta.open(encoding="utf-8", newline="") as f:
        return [(int(r["pos"]), r["dominio"], r["uso"]) for r in csv.DictReader(f)]


def descargar(tranco_id: str = TRANCO_ID) -> Iterator[str]:
    """Líneas de la lista Tranco completa (unos 110 MB), leídas por partes."""
    pedido = urllib.request.Request(URL_TRANCO.format(id=tranco_id), headers={"User-Agent": "auditor-expo"})
    with urllib.request.urlopen(pedido, timeout=60) as r:
        for linea in r:
            yield linea.decode("utf-8", errors="replace")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m carga.dominios", description=__doc__.splitlines()[0])
    p.add_argument("--desde-archivo", type=Path, help="lista Tranco ya descargada (CSV rango,dominio)")
    a = p.parse_args(argv)
    if a.desde_archivo:
        with a.desde_archivo.open(encoding="utf-8", errors="replace") as f:
            candidatos = filtrar(f)
    else:
        candidatos = filtrar(descargar())
    elegidos = muestra(candidatos, N_PRUEBA + N_CORRIDA, SEMILLA)
    escribir_csv(elegidos, RUTA_CSV)
    print(f"Tranco {TRANCO_ID}: {len(candidatos)} dominios .com.co; muestra de {len(elegidos)} con semilla {SEMILLA}"
          f" ({N_PRUEBA} de prueba y {N_CORRIDA} para la corrida) -> {RUTA_CSV}")


if __name__ == "__main__":
    main()
