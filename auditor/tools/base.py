"""Base común de las herramientas: guardas de seguridad y registro.

- `normalizar_dominio`: convierte lo que escriba Grok (URL, mayúsculas, tildes) en un dominio limpio.
- `en_alcance`: solo se permite el dominio objetivo o sus subdominios.
- `ip_permitida`: anti-SSRF; solo IPs públicas, nunca la red interna.
- `registrar` / `ejecutar`: cada herramienta se declara una vez; `ejecutar` valida lo que pide
  Grok, aplica las guardas y NUNCA lanza: todo error vuelve como ResultadoHerramienta.
"""

import ipaddress
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from auditor.modelos import ResultadoHerramienta


class DominioInvalido(ValueError):
    """El texto no es un nombre de dominio usable."""


_ETIQUETA = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalizar_dominio(texto: str) -> str:
    """Minúsculas, sin esquema, ruta, puerto ni punto final, e IDN en punycode."""
    t = texto.strip()
    if "@" in t:
        raise DominioInvalido(f"no es un dominio: {texto!r}")
    if "://" in t:
        t = t.split("://", 1)[1]
    t = re.split(r"[/?#]", t, maxsplit=1)[0]
    t = t.rsplit(":", 1)[0] if t.count(":") == 1 else t
    t = t.strip(" .").lower()
    try:
        t = t.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise DominioInvalido(f"no es un dominio: {texto!r}") from e
    etiquetas = t.split(".")
    if len(etiquetas) < 2 or not all(_ETIQUETA.match(e) for e in etiquetas):
        raise DominioInvalido(f"no es un dominio: {texto!r}")
    return t


def en_alcance(dominio: str, objetivo: str) -> bool:
    """True si `dominio` es el objetivo o un subdominio suyo (ambos ya normalizados)."""
    return dominio == objetivo or dominio.endswith("." + objetivo)


def ip_permitida(ip: str) -> bool:
    """Solo IPs públicas: bloquea privadas, loopback, link-local, CGNAT y reservadas, también disfrazadas."""
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(direccion, ipaddress.IPv6Address) and direccion.ipv4_mapped:
        direccion = direccion.ipv4_mapped
    return direccion.is_global


@dataclass
class Herramienta:
    nombre: str
    descripcion: str
    entrada: type[BaseModel]
    funcion: Callable[[BaseModel], ResultadoHerramienta]
    campo_dominio: str


REGISTRO: dict[str, Herramienta] = {}


def registrar(nombre: str, descripcion: str, entrada: type[BaseModel], campo_dominio: str = "dominio"):
    """Decorador: declara una herramienta con su modelo de entrada; de ahí sale su esquema para Grok."""
    def decorar(funcion: Callable[[BaseModel], ResultadoHerramienta]):
        REGISTRO[nombre] = Herramienta(nombre, descripcion, entrada, funcion, campo_dominio)
        return funcion
    return decorar


def esquemas_para_grok(nombres: list[str] | None = None) -> list[dict[str, Any]]:
    """Definiciones `tools` de chat/completions para las herramientas pedidas (todas si es None)."""
    return [
        {"type": "function", "function": {
            "name": h.nombre, "description": h.descripcion, "parameters": h.entrada.model_json_schema()}}
        for h in REGISTRO.values() if nombres is None or h.nombre in nombres
    ]


def ejecutar(nombre: str, argumentos: str | dict[str, Any], objetivo: str) -> ResultadoHerramienta:
    """Valida, aplica guardas y ejecuta una herramienta. Nunca lanza excepciones."""
    inicio = time.perf_counter()

    def fallo(error: str, sugerencia: str) -> ResultadoHerramienta:
        return ResultadoHerramienta(ok=False, herramienta=nombre, error=error, sugerencia=sugerencia,
                                    duracion_ms=int((time.perf_counter() - inicio) * 1000))

    herramienta = REGISTRO.get(nombre)
    if herramienta is None:
        return fallo("herramienta_desconocida", f"Usa una de: {', '.join(sorted(REGISTRO))}.")
    try:
        args = json.loads(argumentos) if isinstance(argumentos, str) else dict(argumentos)
        entrada = herramienta.entrada.model_validate(args)
    except (ValueError, TypeError, ValidationError) as e:
        return fallo("argumentos_invalidos", f"Revisa los argumentos según el esquema: {str(e)[:200]}")
    try:
        objetivo_n = normalizar_dominio(objetivo)
        dominio = normalizar_dominio(getattr(entrada, herramienta.campo_dominio))
    except DominioInvalido as e:
        return fallo("dominio_invalido", f"{e}. Usa el dominio objetivo o uno de sus subdominios.")
    if not en_alcance(dominio, objetivo_n):
        return fallo("fuera_de_alcance", f"Solo se permite {objetivo_n} y sus subdominios.")
    entrada = entrada.model_copy(update={herramienta.campo_dominio: dominio})
    try:
        resultado = herramienta.funcion(entrada)
    except Exception as e:  # noqa: BLE001 - ninguna herramienta puede tumbar el bucle
        return fallo(f"error_interno: {type(e).__name__}", "Error inesperado; prueba otra herramienta o entrega.")
    resultado.duracion_ms = int((time.perf_counter() - inicio) * 1000)
    return resultado
