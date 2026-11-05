"""Entrega lo grabado de un caso como si las herramientas respondieran en vivo.

Grok corre de verdad; solo la función final de cada herramienta se reemplaza por lo grabado, detrás de las
guardas reales de `base.ejecutar` (alcance y validador de parecidos). Las fechas se desplazan los días que
pasaron desde la grabación, para que un caso no caduque (`reglas_dominio` usa la fecha de hoy).
"""

from datetime import date, datetime, timedelta
from typing import Any

from pydantic import BaseModel

from auditor.modelos import ResultadoHerramienta
from auditor.tools import base, cabeceras, dkim, web
from auditor.tools.base import dominio_registrable
from evals.casos import Caso, clave

SIN_DATOS = "sin_datos_grabados"
SUGERENCIA_SIN_DATOS = ("No hay datos grabados para esta consulta: no reintentes; si importa, "
                        "decláralo como limitación.")
CAMPOS_FECHA = ("vence", "creado", "expires", "ultimo_certificado_vence")
SOBRE_EL_REGISTRABLE = ("whois_dominio", "buscar_parecidos", "subdominios_ct")
SUGERENCIA_SIN_SITIO = {"tls_certificado": web.SUGERENCIAS["sin_direccion_web"],
                        "cabeceras_web": cabeceras.SUGERENCIAS["sin_direccion_web"]}
SELECTOR_VACIO = {"existe": False, "via_cname": False, "destino_cname": None, "destino_microsoft": False,
                  "revocada": False, "tipo_clave": None, "bits": None}


def _desplazar(valor: str, dias: int) -> str:
    """Corre una fecha ISO (solo fecha, o fecha y hora con zona o "Z") conservando su formato."""
    if len(valor) == 10:
        return (date.fromisoformat(valor) + timedelta(days=dias)).isoformat()
    zulu = valor.endswith("Z")
    corrida = (datetime.fromisoformat(valor) + timedelta(days=dias)).isoformat()
    return corrida.replace("+00:00", "Z") if zulu else corrida


def _recorrer(datos: Any, dias: int) -> Any:
    if isinstance(datos, dict):
        return {k: _desplazar(v, dias) if k in CAMPOS_FECHA and isinstance(v, str) else _recorrer(v, dias)
                for k, v in datos.items()}
    if isinstance(datos, list):
        return [_recorrer(v, dias) for v in datos]
    return datos


def desplazar_fechas(resultado: ResultadoHerramienta, dias: int) -> ResultadoHerramienta:
    """Copia del resultado con las fechas absolutas corridas `dias`; los campos en días no cambian."""
    return resultado.model_copy(update={"datos": _recorrer(resultado.datos, dias)}, deep=True)


def sin_datos(herramienta: str) -> ResultadoHerramienta:
    return ResultadoHerramienta(ok=False, herramienta=herramienta, error=SIN_DATOS, sugerencia=SUGERENCIA_SIN_DATOS)


class Reproductor:
    """Ejecutor para `agent.auditar` que responde con lo grabado de un caso."""

    def __init__(self, caso: Caso, hoy: date | None = None):
        self.caso = caso
        self.dias = ((hoy or date.today()) - caso.grabado_el).days
        ct = next((r for r in caso.grabacion.values() if r.herramienta == "subdominios_ct" and r.ok), None)
        self.sin_sitio = {s["nombre"] for s in ct.datos["subdominios"] if not s.get("tiene_sitio", True)} if ct else set()

    def __call__(self, nombre: str, argumentos: Any, objetivo: str) -> ResultadoHerramienta:
        return base.ejecutar(nombre, argumentos, objetivo, sustituta=lambda entrada: self.responder(nombre, entrada))

    def responder(self, nombre: str, entrada: BaseModel) -> ResultadoHerramienta:
        """Recibe la entrada ya validada y normalizada por las guardas."""
        if nombre == "dkim_selector":
            return self._dkim(entrada)
        host = self._host(nombre, entrada)
        grabado = self.caso.grabacion.get(clave(nombre, host))
        if grabado is not None:
            return desplazar_fechas(grabado, self.dias)
        if nombre in SUGERENCIA_SIN_SITIO and host in self.sin_sitio:
            return ResultadoHerramienta(ok=False, herramienta=nombre, error="sin_direccion_web",
                                        sugerencia=SUGERENCIA_SIN_SITIO[nombre])
        return sin_datos(nombre)

    @staticmethod
    def _host(nombre: str, entrada: BaseModel) -> str:
        if nombre == "investigar_parecido":
            return entrada.parecido
        valor = getattr(entrada, base.REGISTRO[nombre].campo_dominio)
        return dominio_registrable(valor) if nombre in SOBRE_EL_REGISTRABLE else valor

    def _dkim(self, entrada: BaseModel) -> ResultadoHerramienta:
        """Como la herramienta real: un resultado por selector pedido; si todos fallan, la llamada falla."""
        grabado = self.caso.grabacion.get(clave("dkim_selector", entrada.dominio))
        if grabado is not None and not grabado.ok:
            return desplazar_fechas(grabado, self.dias)
        disponibles = {s["selector"]: s for s in (grabado.datos["selectores"] if grabado else [])}
        pedidos = list(dict.fromkeys(entrada.selectores))
        selectores = [dict(disponibles[s]) if s in disponibles
                      else {"selector": s, **SELECTOR_VACIO, "error": SIN_DATOS} for s in pedidos]
        errores = [s["error"] for s in selectores if s["error"]]
        if len(errores) == len(selectores):
            return sin_datos("dkim_selector") if errores[0] == SIN_DATOS else ResultadoHerramienta(
                ok=False, herramienta="dkim_selector", error=errores[0], sugerencia=dkim.SUGERENCIAS.get(errores[0]))
        crudos = grabado.contenido_no_confiable if grabado else {}
        return ResultadoHerramienta(ok=True, herramienta="dkim_selector",
                                    datos={"dominio": entrada.dominio, "selectores": selectores},
                                    contenido_no_confiable={s: crudos[s] for s in pedidos if s in crudos})
