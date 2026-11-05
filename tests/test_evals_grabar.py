"""evals/grabar.py con un ejecutor falso: límites de grabación y falla cerrada (sin red)."""

import json

import pytest

from auditor.modelos import ResultadoHerramienta
from auditor.tools.base import en_alcance
from auditor.tools.parecidos import generar_variantes
from evals import grabar, lista_blanca
from evals.grabar import RastroReal, grabar_caso, grabar_crudo

REAL = "floresdelvalle.com.co"
VARIANTES = [v for v in generar_variantes(REAL)[0] if v["tipo"] in ("omision", "duplicacion")][:10]


class EjecutorFalso:
    def __init__(self):
        self.llamadas = []

    def __call__(self, nombre, argumentos, objetivo):
        self.llamadas.append((nombre, argumentos))
        d = REAL
        datos = {
            "dns_correo": {"dominio": d, "mx": {"servidores": [{"prioridad": 1, "host": "aspmx.l.google.com"}],
                                               "proveedor": "google"}},
            "tls_certificado": {"host": argumentos.get("host"), "ip": "181.49.12.7", "valido": True},
            "cabeceras_web": {"host": argumentos.get("host"), "url_final": f"https://{argumentos.get('host')}/"},
            "whois_dominio": {"dominio": d, "servidores_nombre": ["ns1.cloudflare.com"]},
            "buscar_parecidos": {"dominio": d, "generadas": 50, "truncadas": False, "existentes": 10,
                                 "con_correo": [{"dominio": v["dominio"], "tipo": v["tipo"], "mx": ["mx.otro.com"],
                                                 "comparte_servidores": False} for v in VARIANTES],
                                 "sin_verificar": [], "ns_propios": [], "mx_propios": []},
            "subdominios_ct": {"dominio": d, "subdominios": [
                {"nombre": f"s{i}.{d}", "tiene_sitio": i % 4 != 3} for i in range(45)]},
            "security_txt": {"dominio": d, "codigo": 404, "existe": False},
            "investigar_parecido": {"parecido": argumentos.get("parecido"), "tipo": "omision"},
        }.get(nombre)
        if nombre == "dkim_selector":
            datos = {"dominio": d, "selectores": [{"selector": s, "existe": s == "google", "error": None}
                                                  for s in argumentos["selectores"]]}
        return ResultadoHerramienta(ok=True, herramienta=nombre, datos=datos)


def nadie_existe(_):
    return False


def test_respeta_cupo_de_30_y_8():
    ej = EjecutorFalso()
    g = grabar_crudo(REAL, ejecutor=ej)
    subs = {k for k in g if k.startswith("tls_certificado|s")}
    assert len(subs) == 30 and len({k for k in g if k.startswith("cabeceras_web|s")}) == 30
    assert "tls_certificado|s3.floresdelvalle.com.co" not in g  # sin sitio: no se graba
    assert f"tls_certificado|www.{REAL}" in g and f"cabeceras_web|{REAL}" in g
    assert len([k for k in g if k.startswith("investigar_parecido|")]) == 8


def test_selectores_en_tandas_de_6():
    ej = EjecutorFalso()
    g = grabar_crudo(REAL, ejecutor=ej)
    tandas = [a["selectores"] for n, a in ej.llamadas if n == "dkim_selector"]
    assert all(len(t) <= 6 for t in tandas) and sum(len(t) for t in tandas) == len(grabar.SELECTORES_DKIM)
    assert [s["selector"] for s in g[f"dkim_selector|{REAL}"].datos["selectores"]] == list(grabar.SELECTORES_DKIM)


def test_graba_borrador_limpio(tmp_path):
    borrador = grabar_caso(REAL, "real-99", "pyme_estandar", base_seudonimo="comercialolimpo.com.co",
                           nombres_libres=["Flores del Valle"], ejecutor=EjecutorFalso(), existe=nadie_existe,
                           ruta_privada=tmp_path)
    assert borrador.dominio == "comercialolimpo.com.co" and borrador.origen == "real"
    texto = (tmp_path / "borradores" / "real-99.json").read_text(encoding="utf-8")
    assert lista_blanca.revisar_texto(texto, lista_blanca.permitidos_para(borrador.dominio)) == []
    assert "flores" not in texto.lower()
    assert all(en_alcance(k.split("|")[1], borrador.dominio) for k in borrador.grabacion
               if not k.startswith("investigar_parecido|"))
    mapa = json.loads((tmp_path / "mapa_seudonimos.json").read_text(encoding="utf-8"))
    assert mapa["real-99"]["real"] == REAL and len(mapa["real-99"]["parecidos"]) == 10
    assert (tmp_path / "crudo" / "real-99.json").exists()


def test_no_escribe_si_queda_rastro(tmp_path, monkeypatch):
    monkeypatch.setattr(grabar, "seudonimizar", lambda resultados, mapa: resultados)
    with pytest.raises(RastroReal):
        grabar_caso(REAL, "real-99", "pyme_estandar", base_seudonimo="comercialolimpo.com.co",
                    ejecutor=EjecutorFalso(), existe=nadie_existe, ruta_privada=tmp_path)
    assert not (tmp_path / "borradores").exists() and not (tmp_path / "mapa_seudonimos.json").exists()


def test_desde_crudo_no_consulta(tmp_path):
    grabar_caso(REAL, "real-99", "pyme_estandar", base_seudonimo="comercialolimpo.com.co",
                ejecutor=EjecutorFalso(), existe=nadie_existe, ruta_privada=tmp_path)
    ej = EjecutorFalso()
    b = grabar_caso(REAL, "real-99", "pyme_estandar", base_seudonimo="comercialolimpo.com.co",
                    ejecutor=ej, existe=nadie_existe, ruta_privada=tmp_path, desde_crudo=True)
    assert ej.llamadas == [] and b.dominio == "comercialolimpo.com.co" and len(b.grabacion) > 60
