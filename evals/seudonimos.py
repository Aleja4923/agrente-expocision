"""Cambia el dominio real de una grabación por un seudónimo, sin romper las guardas del agente.

- El seudónimo no existe en DNS y tiene las variantes que hacen falta. A cada parecido real le toca una variante
  del seudónimo **del mismo tipo** (el tipo cambia la severidad), que tampoco exista: así no se señala a un tercero.
- Se reescribe todo texto de la grabación, incluidas las claves: el dominio y sus subdominios, los parecidos,
  IP (a rangos de documentación), correos y nombres libres (razón social, marca).
- Del contenido no confiable solo quedan los TXT de SPF y DMARC, ya reescritos; lo demás pasa a "[omitido]".
- Los proveedores comunes se conservan; cualquier otro dominio pasa a `externo-N.example`.
"""

import re
from collections import Counter
from typing import Any, Callable

from pydantic import BaseModel

from auditor.modelos import ResultadoHerramienta
from auditor.tools.parecidos import Variante, generar_variantes
from evals.lista_blanca import PROVEEDORES, TOKEN, dominio_permitido, es_ip, ip_de_documentacion

OMITIDO = "[omitido]"
BUZONES_GENERICOS = frozenset({"dmarc", "seguridad", "security", "abuse", "postmaster", "soporte", "info",
                               "contacto", "admin", "reportes", "rua", "ruf", "hostmaster", "webmaster"})


class SinVariante(Exception):
    """El seudónimo no tiene una variante libre del tipo que hace falta."""


class Mapa(BaseModel):
    real: str
    seudonimo: str
    parecidos: dict[str, str] = {}
    nombres_libres: list[str] = []
    etiquetas: dict[str, str] = {}  # trozos de subdominio que delatan a la empresa (marca, campaña) -> genérico


def _etiqueta(registrable: str) -> str:
    return registrable.split(".", 1)[0]


def _libres_por_tipo(seudonimo: str, existe: Callable[[str], bool], tipos: set[str]) -> dict[str, list[str]]:
    libres: dict[str, list[str]] = {t: [] for t in tipos}
    for v in generar_variantes(seudonimo)[0]:
        if v["tipo"] in tipos and not existe(v["dominio"]):
            libres[v["tipo"]].append(v["dominio"])
    return libres


def elegir_seudonimo(base: str, tipos_necesarios: Counter[str], existe: Callable[[str], bool]) -> str:
    """`base` o `base2`, `base3`…: el primero que no existe y tiene variantes libres de cada tipo necesario."""
    etiqueta, sufijo = base.split(".", 1)
    for n in range(1, 30):
        candidato = base if n == 1 else f"{etiqueta}{n}.{sufijo}"
        if existe(candidato):
            continue
        libres = _libres_por_tipo(candidato, existe, set(tipos_necesarios))
        if all(len(libres[t]) >= k for t, k in tipos_necesarios.items()):
            return candidato
    raise SinVariante(f"ningún seudónimo a partir de {base} tiene las variantes necesarias")


def mapear_parecidos(reales: list[Variante], seudonimo: str, existe: Callable[[str], bool]) -> dict[str, str]:
    """Parecido real -> variante libre del seudónimo del mismo tipo, en orden."""
    libres = _libres_por_tipo(seudonimo, existe, {v["tipo"] for v in reales})
    mapa = {}
    for v in reales:
        if v["dominio"] in mapa:
            continue
        if not libres[v["tipo"]]:
            raise SinVariante(f"{seudonimo} no tiene otra variante libre de tipo {v['tipo']}")
        mapa[v["dominio"]] = libres[v["tipo"]].pop(0)
    return mapa


def _patron_nombres(mapa: Mapa) -> re.Pattern:
    """Nombres libres y etiqueta real en texto libre, solo como palabra completa ("habi" no toca "habilitado")."""
    nombres = sorted({*mapa.nombres_libres, _etiqueta(mapa.real)}, key=len, reverse=True)
    cuerpo = "|".join(re.escape(n) for n in nombres)
    return re.compile(rf"(?<![^\W_])(?:{cuerpo})(?![^\W_])", re.IGNORECASE)


class _Reescritor:
    def __init__(self, mapa: Mapa):
        self.mapa = mapa
        self.etiqueta = _etiqueta(mapa.seudonimo)
        self.dominios = [(mapa.real, mapa.seudonimo), *mapa.parecidos.items()]
        self.libres_texto = _patron_nombres(mapa)
        # Dentro de un nombre de dominio: nombres libres y etiqueta real -> etiqueta del seudónimo, y la etiqueta
        # de cada parecido -> la de su variante (Microsoft pone el nombre del dominio en su MX: x-co.mail...).
        self.cambio_etiqueta = {_etiqueta(r).lower(): _etiqueta(f) for r, f in mapa.parecidos.items()}
        self.cambio_etiqueta |= {n.lower(): self.etiqueta for n in (*mapa.nombres_libres, _etiqueta(mapa.real))}
        self.cambio_etiqueta |= {k.lower(): v for k, v in mapa.etiquetas.items()}
        cuerpo = "|".join(re.escape(n) for n in sorted(self.cambio_etiqueta, key=len, reverse=True))
        self.libres_dominio = re.compile(cuerpo, re.IGNORECASE)
        self.externos: dict[str, str] = {}
        self.ips: dict[str, str] = {}

    def _nombres(self, texto: str) -> str:
        return self.libres_texto.sub(self.etiqueta, texto)

    def _etiquetas(self, prefijo: str) -> str:
        """Dentro de un nombre de dominio el nombre real se borra aunque esté pegado a otra palabra."""
        return self.libres_dominio.sub(lambda m: self.cambio_etiqueta[m.group().lower()], prefijo)

    def dominio(self, d: str) -> str:
        d = d.lower().rstrip(".")
        for real, falso in self.dominios:
            if d == real or d.endswith("." + real):
                return self._etiquetas(d[: -len(real)]) + falso
        proveedor = next((p for p in PROVEEDORES if d == p or d.endswith("." + p)), None)
        if proveedor:
            return self._etiquetas(d[: -len(proveedor)]) + proveedor
        if dominio_permitido(d, set()):  # .example y nombres que no son dominios
            return d
        return self.externos.setdefault(d, f"externo-{len(self.externos) + 1}.example")

    def ip(self, ip: str) -> str:
        if ip_de_documentacion(ip):
            return ip
        if ":" in ip:
            return self.ips.setdefault(ip, f"2001:db8::{len(self.ips) + 1:x}")
        return self.ips.setdefault(ip, f"203.0.113.{len(self.ips) % 254 + 1}")

    def texto(self, texto: str) -> str:
        partes, inicio = [], 0
        for m in TOKEN.finditer(texto):
            partes.append(self._nombres(texto[inicio:m.start()]))
            valor = m.group()
            if m.lastgroup == "correo":
                buzon, dominio = valor.rsplit("@", 1)
                buzon = buzon if buzon.lower() in BUZONES_GENERICOS else "contacto"
                partes.append(f"{buzon}@{self.dominio(dominio)}")
            elif m.lastgroup in ("ip4", "ip6"):
                partes.append(self.ip(valor) if es_ip(valor) else self._nombres(valor))
            else:
                partes.append(self.dominio(valor))
            inicio = m.end()
        partes.append(self._nombres(texto[inicio:]))
        return "".join(partes)

    def valor(self, v: Any) -> Any:
        if isinstance(v, str):
            return self.texto(v)
        if isinstance(v, list):
            return [self.valor(x) for x in v]
        if isinstance(v, dict):
            return {self.texto(k): self.valor(x) for k, x in v.items()}
        return v


def _no_confiable(r: ResultadoHerramienta) -> dict[str, Any]:
    if r.herramienta == "dns_correo":
        return {"txt_dominio": [t for t in r.contenido_no_confiable.get("txt_dominio", [])
                                if t.lower().startswith("v=spf1")],
                "txt_dmarc": list(r.contenido_no_confiable.get("txt_dmarc", []))}
    return {k: OMITIDO for k in r.contenido_no_confiable}


def seudonimizar(resultados: dict[str, ResultadoHerramienta], mapa: Mapa) -> dict[str, ResultadoHerramienta]:
    """La grabación completa con el seudónimo; las claves `herramienta|host` también se reescriben."""
    rw = _Reescritor(mapa)
    salida = {}
    for clave, r in resultados.items():
        herramienta, host = clave.split("|", 1)
        datos = rw.valor(r.datos)
        if r.herramienta == "buscar_parecidos" and r.ok:
            variantes, truncadas = generar_variantes(mapa.seudonimo)
            datos |= {"generadas": len(variantes), "truncadas": truncadas}
        salida[f"{herramienta}|{rw.dominio(host)}"] = r.model_copy(update={
            "datos": datos, "contenido_no_confiable": rw.valor(_no_confiable(r)),
            "error": rw.valor(r.error), "sugerencia": rw.valor(r.sugerencia)})
    return salida


def restos_reales(texto: str, mapa: Mapa) -> list[str]:
    """Nombres reales que quedaron en el texto (dominio, etiqueta, parecidos reales, nombres libres)."""
    bajo = texto.lower()
    dominios = [mapa.real, *mapa.parecidos]
    restos = {d for d in dominios if d in bajo}
    restos |= {m.group().lower() for m in _patron_nombres(mapa).finditer(texto)}
    etiquetas = [_etiqueta(p) for p in dominios]
    restos |= {k.lower() for k in mapa.etiquetas if k.lower() in bajo}
    return sorted(restos | {e for e in etiquetas if re.search(rf"(?<![^\W_]){re.escape(e)}(?![^\W_])", bajo)})
