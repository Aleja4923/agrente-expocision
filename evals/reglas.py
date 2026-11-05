"""Medida de reglas: la grabación completa de un caso contra su respuesta esperada, sin Grok.

Comprueba que, con toda la información grabada, `scoring.py` da los hallazgos obligatorios, alcanza los que
dependen de una decisión de Grok, no produce los prohibidos y llega al nivel esperado.
"""

import re
from datetime import date
from typing import Any

from auditor import scoring
from auditor.modelos import Hallazgo
from auditor.scoring import Llamada
from auditor.tools import base
from evals.casos import Caso


def _argumentos(caso: Caso, herramienta: str, host: str, datos: dict[str, Any]) -> dict[str, Any]:
    if herramienta == "investigar_parecido":
        return {"dominio": caso.dominio, "parecido": host}
    argumentos = {base.REGISTRO[herramienta].campo_dominio: host}
    if herramienta == "dkim_selector":
        argumentos["selectores"] = [s["selector"] for s in datos.get("selectores", [])]
    return argumentos


def llamadas_completas(caso: Caso) -> list[Llamada]:
    """Toda la grabación como si Grok la hubiera pedido entera."""
    import auditor.tools  # noqa: F401  (registra las herramientas)
    llamadas = []
    for k, r in caso.grabacion.items():
        herramienta, host = k.split("|", 1)
        llamadas.append((_argumentos(caso, herramienta, host, r.datos), r))
    return llamadas


def alcanzado(item: str, hallazgos: dict[str, Hallazgo]) -> bool:
    """`REGLA` o `REGLA@nombre`: la regla existe y, si hay nombre, aparece como sujeto en su evidencia."""
    regla, _, nombre = item.partition("@")
    if regla not in hallazgos:
        return False
    return not nombre or re.search(rf"(?:^|; ){re.escape(nombre)}:", hallazgos[regla].evidencia) is not None


def revisar(caso: Caso, hoy: date | None = None) -> list[str]:
    """Problemas del caso frente a scoring.py; lista vacía si cuadra."""
    hoy = hoy or caso.grabado_el
    llamadas = llamadas_completas(caso)
    todos = scoring.evaluar(llamadas, caso.dominio, hoy)
    principal = scoring.hallazgos_de_lo_principal(llamadas, caso.dominio, hoy)
    minimo = scoring.hallazgos_de_lo_principal(
        [(a, r) for a, r in llamadas if r.herramienta != "investigar_parecido"], caso.dominio, hoy)
    e = caso.esperado
    problemas = [f"obligatorio {h} no sale sin decisiones de Grok" for h in e.hallazgos_obligatorios
                 if not alcanzado(h, minimo)]
    problemas += [f"por decisión {h} no se alcanza ni con todo grabado" for h in e.hallazgos_por_decision
                  if not alcanzado(h, todos)]
    problemas += [f"prohibido {h} aparece" for h in e.hallazgos_prohibidos if alcanzado(h, todos)]
    nivel = scoring.nivel_riesgo(principal)
    if nivel != e.nivel_esperado:
        problemas.append(f"nivel {nivel.value}, se esperaba {e.nivel_esperado.value}")
    return problemas
