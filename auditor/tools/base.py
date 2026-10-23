"""Base común de las herramientas: guardas de seguridad y registro.

- `normalizar_dominio`: convierte lo que escriba Grok (URL, mayúsculas, tildes) en un dominio limpio.
- `en_alcance`: solo se permite el dominio objetivo o sus subdominios.
- `ip_permitida`: anti-SSRF; solo IPs públicas, nunca la red interna.
- `dominio_registrable`: el dominio que se compra (ejemplo.com.co), sin subdominios.
- Excepción de alcance (CONTEXT §7): una herramienta con `campo_parecido` solo acepta las variantes
  que genera el propio código (`VALIDADOR_PARECIDOS`), nunca un dominio que elija Grok.
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


# Sufijos colombianos de segundo nivel: en ellos el dominio registrable tiene 3 etiquetas.
SUFIJOS_CO = frozenset({"com.co", "net.co", "org.co", "edu.co", "gov.co", "mil.co", "nom.co"})


def dominio_registrable(dominio: str) -> str:
    """tienda.ejemplo.com.co -> ejemplo.com.co; a.ejemplo.com -> ejemplo.com (dominio ya normalizado)."""
    etiquetas = dominio.split(".")
    n = 3 if ".".join(etiquetas[-2:]) in SUFIJOS_CO else 2
    return ".".join(etiquetas[-n:])


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
    campo_parecido: str | None = None


REGISTRO: dict[str, Herramienta] = {}

# Variantes válidas de un dominio registrable; lo asigna tools/parecidos.py al importarse.
# Si no hay validador, la excepción de alcance falla cerrada (se rechaza todo).
VALIDADOR_PARECIDOS: Callable[[str], set[str]] | None = None


def registrar(nombre: str, descripcion: str, entrada: type[BaseModel], campo_dominio: str = "dominio",
              campo_parecido: str | None = None):
    """Decorador: declara una herramienta con su modelo de entrada; de ahí sale su esquema para Grok."""
    def decorar(funcion: Callable[[BaseModel], ResultadoHerramienta]):
        REGISTRO[nombre] = Herramienta(nombre, descripcion, entrada, funcion, campo_dominio, campo_parecido)
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
    cambios = {herramienta.campo_dominio: dominio}
    if herramienta.campo_parecido:
        try:
            parecido = normalizar_dominio(getattr(entrada, herramienta.campo_parecido))
        except DominioInvalido as e:
            return fallo("dominio_invalido", f"{e}. Usa una variante que entregó buscar_parecidos.")
        validas = VALIDADOR_PARECIDOS(dominio_registrable(objetivo_n)) if VALIDADOR_PARECIDOS else set()
        if parecido not in validas:
            return fallo("fuera_de_alcance", "Solo se permiten las variantes que entregó buscar_parecidos.")
        cambios[herramienta.campo_parecido] = parecido
    entrada = entrada.model_copy(update=cambios)
    try:
        resultado = herramienta.funcion(entrada)
    except Exception as e:  # noqa: BLE001 - ninguna herramienta puede tumbar el bucle
        return fallo(f"error_interno: {type(e).__name__}", "Error inesperado; prueba otra herramienta o entrega.")
    resultado.duracion_ms = int((time.perf_counter() - inicio) * 1000)
    return resultado
