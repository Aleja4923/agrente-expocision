"""Graba un dominio real con las herramientas reales (sin Grok, sin gasto) y lo deja seudonimizado.

- Solo verificaciones pasivas, por `base.ejecutar` con sus guardas normales.
- Graba las obligatorias sobre el dominio y `www`, hasta 30 subdominios con sitio, hasta 8 parecidos con
  correo y una lista fija de selectores DKIM (en tandas de 6, el máximo de la herramienta).
- Lo crudo y el mapa de nombres reales van a docs/evals/ (privado). Si tras seudonimizar queda un rastro
  (lista blanca o nombre real), no se escribe nada más: falla cerrada.
- Sale un borrador sin respuesta esperada; se publica en evals/casos/ cuando se le pone `esperado`.

Uso: python -m evals.grabar --dominio D --id real-NN --perfil P --seudonimo base.com.co [--nombre "Razón social"]
"""

import argparse
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from typing import Callable, Literal

from pydantic import BaseModel

import auditor.tools  # noqa: F401  (registra las herramientas)
from auditor.config import RAIZ
from auditor.modelos import ResultadoHerramienta
from auditor.tools import base
from auditor.tools.parecidos import _revisar_variante, tipo_de
from evals import lista_blanca
from evals.casos import Caso, Esperado, clave, guardar_caso
from evals.seudonimos import Mapa, elegir_seudonimo, mapear_parecidos, restos_reales, seudonimizar

RUTA_PRIVADA = RAIZ / "docs" / "evals"
MAX_SUBDOMINIOS = 30
MAX_PARECIDOS = 8
SELECTORES_DKIM = ("google", "selector1", "selector2", "default", "dkim", "k1", "mail", "s1", "s2")
TANDA_DKIM = 6
HILOS = 4

Ejecutor = Callable[[str, dict, str], ResultadoHerramienta]


class RastroReal(Exception):
    """El caso seudonimizado todavía tiene algo del dominio real o algo fuera de la lista blanca."""


class Borrador(BaseModel):
    """Un caso real grabado y seudonimizado, aún sin respuesta esperada."""
    id: str
    origen: Literal["real"] = "real"
    perfil: Literal["inexistente", "pyme_estandar", "superficie_grande", "adversarial"]
    grabado_el: date
    dominio: str
    objetivo: str | None = None
    grabacion: dict[str, ResultadoHerramienta]


def existe_en_dns(dominio: str) -> bool:
    """Si no se puede verificar, cuenta como existente: nunca se usa un nombre que podría ser de alguien."""
    return _revisar_variante(dominio)[0] != "no_existe"


def _dkim(dominio: str, ejecutor: Ejecutor) -> ResultadoHerramienta:
    tandas = [list(SELECTORES_DKIM[i:i + TANDA_DKIM]) for i in range(0, len(SELECTORES_DKIM), TANDA_DKIM)]
    resultados = [ejecutor("dkim_selector", {"dominio": dominio, "selectores": t}, dominio) for t in tandas]
    buenos = [r for r in resultados if r.ok]
    if not buenos:
        return resultados[0]
    return ResultadoHerramienta(
        ok=True, herramienta="dkim_selector",
        datos={"dominio": dominio, "selectores": [s for r in buenos for s in r.datos["selectores"]]},
        contenido_no_confiable={k: v for r in buenos for k, v in r.contenido_no_confiable.items()})


def grabar_crudo(dominio: str, ejecutor: Ejecutor = base.ejecutar) -> dict[str, ResultadoHerramienta]:
    """Toda la grabación de un dominio registrable, con claves `herramienta|host` como las busca reproducir.py."""
    d = base.normalizar_dominio(dominio)
    if d != base.dominio_registrable(d):
        raise ValueError(f"{dominio} no es un dominio registrable")
    grabacion: dict[str, ResultadoHerramienta] = {}

    def correr(nombre: str, clave_host: str, **argumentos) -> ResultadoHerramienta:
        r = ejecutor(nombre, argumentos, d)
        grabacion[clave(nombre, clave_host)] = r
        return r

    def por_host(h: str) -> None:
        correr("tls_certificado", h, host=h)
        correr("cabeceras_web", h, host=h)

    correr("dns_correo", d, dominio=d)
    correr("whois_dominio", d, dominio=d)
    correr("security_txt", d, dominio=d)
    busqueda = correr("buscar_parecidos", d, dominio=d)
    ct = correr("subdominios_ct", d, dominio=d)
    grabacion[clave("dkim_selector", d)] = _dkim(d, ejecutor)

    subdominios = [s["nombre"] for s in (ct.datos or {}).get("subdominios", []) if s.get("tiene_sitio")]
    hosts = [d, f"www.{d}"] + [h for h in subdominios if h not in (d, f"www.{d}")][:MAX_SUBDOMINIOS]
    parecidos = [p["dominio"] for p in (busqueda.datos or {}).get("con_correo", [])][:MAX_PARECIDOS]
    with ThreadPoolExecutor(max_workers=HILOS) as pool:
        list(pool.map(por_host, hosts))
        list(pool.map(lambda p: correr("investigar_parecido", p, dominio=d, parecido=p), parecidos))
    return grabacion


def _parecidos_reales(real: str, crudo: dict[str, ResultadoHerramienta]) -> list[dict[str, str]]:
    """Todas las variantes del dominio real que aparecen en la grabación, con su tipo."""
    datos = crudo[clave("buscar_parecidos", real)].datos or {}
    nombres = [p["dominio"] for p in datos.get("con_correo", [])] + list(datos.get("sin_verificar", []))
    return [{"dominio": n, "tipo": tipo_de(real, n)} for n in dict.fromkeys(nombres)]


def _guardar_json(ruta: Path, contenido) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(contenido, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def grabar_caso(real: str, id_caso: str, perfil: str, *, base_seudonimo: str, nombres_libres: list[str] = (),
                ejecutor: Ejecutor = base.ejecutar, existe: Callable[[str], bool] = existe_en_dns,
                ruta_privada: Path = RUTA_PRIVADA, hoy: date | None = None) -> Borrador:
    real = base.normalizar_dominio(real)
    crudo = grabar_crudo(real, ejecutor)
    _guardar_json(ruta_privada / "crudo" / f"{id_caso}.json", {k: v.model_dump() for k, v in crudo.items()})

    parecidos = _parecidos_reales(real, crudo)
    seudonimo = elegir_seudonimo(base_seudonimo, Counter(p["tipo"] for p in parecidos), existe)
    mapa = Mapa(real=real, seudonimo=seudonimo, parecidos=mapear_parecidos(parecidos, seudonimo, existe),
                nombres_libres=list(nombres_libres))
    borrador = Borrador(id=id_caso, perfil=perfil, grabado_el=hoy or date.today(), dominio=seudonimo,
                        grabacion=seudonimizar(crudo, mapa))

    texto = borrador.model_dump_json()
    rastros = lista_blanca.revisar_texto(texto, lista_blanca.permitidos_para(seudonimo)) + restos_reales(texto, mapa)
    if rastros:
        raise RastroReal(f"{id_caso}: quedan {len(rastros)} rastros; no se escribe el caso")

    archivo_mapa = ruta_privada / "mapa_seudonimos.json"
    mapas = json.loads(archivo_mapa.read_text(encoding="utf-8")) if archivo_mapa.exists() else {}
    _guardar_json(archivo_mapa, mapas | {id_caso: mapa.model_dump()})
    (ruta_privada / "borradores").mkdir(parents=True, exist_ok=True)
    (ruta_privada / "borradores" / f"{id_caso}.json").write_text(borrador.model_dump_json(indent=2) + "\n",
                                                                 encoding="utf-8")
    return borrador


def publicar(borrador: Borrador, esperado: Esperado) -> Path:
    """Pasa el borrador a evals/casos/ con su respuesta esperada."""
    return guardar_caso(Caso(**borrador.model_dump(), esperado=esperado))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="python -m evals.grabar", description="Graba y seudonimiza un dominio real.")
    p.add_argument("--dominio", required=True)
    p.add_argument("--id", required=True, help="real-NN")
    p.add_argument("--perfil", required=True, choices=["inexistente", "pyme_estandar", "superficie_grande"])
    p.add_argument("--seudonimo", required=True, help="nombre base del seudónimo, con la misma terminación")
    p.add_argument("--nombre", action="append", default=[], help="razón social o marca a borrar (repetible)")
    a = p.parse_args(argv)
    b = grabar_caso(a.dominio, a.id, a.perfil, base_seudonimo=a.seudonimo, nombres_libres=a.nombre)
    fallas = Counter(r.error for r in b.grabacion.values() if not r.ok)
    print(f"{b.id} · seudónimo {b.dominio} · {len(b.grabacion)} resultados grabados · "
          f"fallas: {dict(fallas) or 'ninguna'}")


if __name__ == "__main__":
    main()
