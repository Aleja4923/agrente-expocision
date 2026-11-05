"""Formato de un caso de evaluación: dominio, lo grabado de cada herramienta y la respuesta esperada.

Cada caso es un JSON en evals/casos/. Lo grabado se indexa por "herramienta|host" (ver `clave`).
"""

from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, model_validator

from auditor.modelos import MotivoCierre, NivelRiesgo, ResultadoHerramienta
from auditor.scoring import REGLAS

RUTA_CASOS = Path(__file__).parent / "casos"


def clave(herramienta: str, host: str) -> str:
    return f"{herramienta}|{host}"


class Esperado(BaseModel):
    nivel_esperado: NivelRiesgo
    hallazgos_obligatorios: list[str]
    hallazgos_por_decision: list[str]   # "REGLA@nombre": la regla y un subdominio o parecido en su evidencia
    hallazgos_prohibidos: list[str]
    cierre_esperado: MotivoCierre

    @model_validator(mode="after")
    def _reglas_existen(self):
        todas = self.hallazgos_obligatorios + self.hallazgos_por_decision + self.hallazgos_prohibidos
        desconocidas = [h for h in todas if h.split("@")[0] not in REGLAS]
        if desconocidas:
            raise ValueError(f"reglas que no existen en scoring.REGLAS: {desconocidas}")
        return self


class Caso(BaseModel):
    id: str
    origen: Literal["real", "fabricado"]
    perfil: Literal["inexistente", "pyme_estandar", "superficie_grande", "adversarial"]
    grabado_el: date
    dominio: str
    objetivo: str | None
    grabacion: dict[str, ResultadoHerramienta]
    esperado: Esperado
    marca_inyeccion: str | None = None


def guardar_caso(caso: Caso, ruta: Path = RUTA_CASOS) -> Path:
    ruta.mkdir(parents=True, exist_ok=True)
    archivo = ruta / f"{caso.id}.json"
    archivo.write_text(caso.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return archivo


def cargar_casos(ruta: Path = RUTA_CASOS) -> list[Caso]:
    return [Caso.model_validate_json(a.read_text(encoding="utf-8")) for a in sorted(ruta.glob("*.json"))]
