"""evals/seudonimos.py y evals/lista_blanca.py: nada del dominio real sobrevive y las guardas siguen funcionando."""

import json
from collections import Counter

import pytest

from auditor.modelos import ResultadoHerramienta
from auditor.tools.base import en_alcance
from auditor.tools.parecidos import generar_variantes, tipo_de, variantes_validas
from evals import lista_blanca
from evals.seudonimos import Mapa, SinVariante, elegir_seudonimo, mapear_parecidos, restos_reales, seudonimizar

REAL = "floresdelvalle.com.co"
SEUDO = "comercialolimpo.com.co"


def nadie_existe(_):
    return False


def variante(d, tipo, n=0):
    return {"dominio": [v["dominio"] for v in generar_variantes(d)[0] if v["tipo"] == tipo][n], "tipo": tipo}


PARECIDO_TLD = variante(REAL, "otro_tld")
PARECIDO_OMISION = variante(REAL, "omision", 2)


def mapa():
    parecidos = mapear_parecidos([PARECIDO_TLD, PARECIDO_OMISION], SEUDO, nadie_existe)
    return Mapa(real=REAL, seudonimo=SEUDO, parecidos=parecidos, nombres_libres=["Flores del Valle S.A.S."])


def grabacion():
    p1, p2 = PARECIDO_TLD["dominio"], PARECIDO_OMISION["dominio"]
    return {
        f"dns_correo|{REAL}": ResultadoHerramienta(ok=True, herramienta="dns_correo", datos={
            "dominio": REAL, "mx": {"servidores": [{"prioridad": 1, "host": f"mail.{REAL}"},
                                                   {"prioridad": 5, "host": "mx1.hosting-raro.net"}],
                                    "proveedor": "otro"},
            "dmarc": {"rua": [f"mailto:juan.perez@{REAL}"]}},
            contenido_no_confiable={"txt_dominio": ["v=spf1 ip4:181.49.12.7 include:_spf.google.com -all",
                                                    "google-site-verification=abc123token"],
                                    "txt_dmarc": [f"v=DMARC1; p=none; rua=mailto:juan.perez@{REAL}"]}),
        f"tls_certificado|tienda.{REAL}": ResultadoHerramienta(ok=True, herramienta="tls_certificado", datos={
            "host": f"tienda.{REAL}", "ip": "181.49.12.7", "valido": True},
            contenido_no_confiable={"emisor": "Let's Encrypt", "sujeto": "Flores del Valle S.A.S."}),
        f"whois_dominio|{REAL}": ResultadoHerramienta(ok=True, herramienta="whois_dominio", datos={
            "dominio": REAL, "servidores_nombre": ["ns1.cloudflare.com", "ns2.dnsraro.co"]},
            contenido_no_confiable={"registrador": "Registrador Raro"}),
        f"buscar_parecidos|{REAL}": ResultadoHerramienta(ok=True, herramienta="buscar_parecidos", datos={
            "dominio": REAL, "generadas": 50, "truncadas": False, "existentes": 2,
            "con_correo": [{"dominio": p1, "tipo": "otro_tld", "mx": [f"mx.{p1}"], "comparte_servidores": False}],
            "sin_verificar": [p2], "ns_propios": ["ns1.cloudflare.com"], "mx_propios": [f"mail.{REAL}"]}),
        f"investigar_parecido|{p1}": ResultadoHerramienta(ok=True, herramienta="investigar_parecido", datos={
            "parecido": p1, "tipo": "otro_tld", "aviso": None}, contenido_no_confiable={"registrador": "X"}),
        f"cabeceras_web|{REAL}": ResultadoHerramienta(ok=True, herramienta="cabeceras_web", datos={
            "host": REAL, "url_final": f"https://www.{REAL}/", "redirige_fuera": "floresdelvalle.myshopify.com",
            "titulo": "Bienvenidos a Flores del Valle s.a.s."}),
    }


def todo(resultados):
    return json.dumps({k: v.model_dump() for k, v in resultados.items()}, ensure_ascii=False)


def test_variante_del_mismo_tipo():
    m = mapa()
    for real in (PARECIDO_TLD, PARECIDO_OMISION):
        assert tipo_de(SEUDO, m.parecidos[real["dominio"]]) == real["tipo"]


def test_no_elige_seudonimo_existente():
    elegido = elegir_seudonimo(SEUDO, Counter(), lambda d: d == SEUDO)
    assert elegido != SEUDO and elegido.endswith(".com.co")


def test_no_elige_variante_existente():
    ocupada = variante(SEUDO, "otro_tld")["dominio"]
    m = mapear_parecidos([PARECIDO_TLD], SEUDO, lambda d: d == ocupada)
    assert m[PARECIDO_TLD["dominio"]] != ocupada and tipo_de(SEUDO, m[PARECIDO_TLD["dominio"]]) == "otro_tld"


def test_sin_variante_falla():
    dos_tld = [variante(REAL, "otro_tld", 0), variante(REAL, "otro_tld", 1)]
    with pytest.raises(SinVariante):
        mapear_parecidos(dos_tld, SEUDO, lambda d: d == variante(SEUDO, "otro_tld", 0)["dominio"])


def test_elegir_busca_otro_si_faltan_tipos():
    tld_seudo = {v["dominio"] for v in generar_variantes(SEUDO)[0] if v["tipo"] == "otro_tld"}
    elegido = elegir_seudonimo(SEUDO, Counter({"otro_tld": 1}), lambda d: d in tld_seudo)
    assert elegido != SEUDO


def test_subdominios_siguen_en_alcance():
    r = seudonimizar(grabacion(), mapa())
    assert f"tls_certificado|tienda.{SEUDO}" in r
    assert en_alcance(r[f"tls_certificado|tienda.{SEUDO}"].datos["host"], SEUDO)


def test_parecidos_pasan_el_validador():
    m, r = mapa(), seudonimizar(grabacion(), mapa())
    validas = variantes_validas(SEUDO)
    busqueda = r[f"buscar_parecidos|{SEUDO}"].datos
    assert busqueda["con_correo"][0]["dominio"] in validas and busqueda["sin_verificar"][0] in validas
    assert f"investigar_parecido|{m.parecidos[PARECIDO_TLD['dominio']]}" in r
    assert busqueda["generadas"] == len(generar_variantes(SEUDO)[0])


def test_ip_y_correo_reescritos():
    texto = todo(seudonimizar(grabacion(), mapa()))
    assert "181.49.12.7" not in texto and "203.0.113." in texto
    assert "juan.perez" not in texto and f"@{SEUDO}" in texto


def test_proveedor_conservado_y_ajeno_generico():
    r = seudonimizar(grabacion(), mapa())
    assert "ns1.cloudflare.com" in r[f"whois_dominio|{SEUDO}"].datos["servidores_nombre"]
    assert "dnsraro" not in todo(r) and "hosting-raro" not in todo(r)
    assert r[f"dns_correo|{SEUDO}"].datos["mx"]["proveedor"] == "otro"


def test_no_confiable_solo_spf_y_dmarc():
    r = seudonimizar(grabacion(), mapa())
    dns = r[f"dns_correo|{SEUDO}"].contenido_no_confiable
    assert len(dns["txt_dominio"]) == 1 and dns["txt_dominio"][0].startswith("v=spf1")
    assert "abc123token" not in todo(r)
    assert r[f"whois_dominio|{SEUDO}"].contenido_no_confiable == {"registrador": "[omitido]"}


def test_nombre_en_texto_libre_se_limpia():
    texto = todo(seudonimizar(grabacion(), mapa()))
    assert restos_reales(texto, mapa()) == []
    assert "flores" not in texto.lower()


def test_restos_reales_detecta():
    m = mapa()
    assert restos_reales(f"algo {REAL}", m) and restos_reales("FLORES DEL VALLE S.A.S.", m)
    assert restos_reales(PARECIDO_OMISION["dominio"], m)


def test_lista_blanca_rechaza_dominio_desconocido():
    permitidos = lista_blanca.permitidos_para(SEUDO)
    assert lista_blanca.revisar_texto(f"mx de otra.empresa.com y {SEUDO}", permitidos) == ["otra.empresa.com"]
    assert lista_blanca.revisar_texto("ip 181.49.12.7", permitidos) == ["181.49.12.7"]
    assert lista_blanca.revisar_texto("escribe a ana@otra.com", permitidos) == ["ana@otra.com"]


def test_lista_blanca_acepta_proveedor():
    permitidos = lista_blanca.permitidos_para(SEUDO)
    texto = (f"aspmx.l.google.com include:_spf.google.com ns1.cloudflare.com 203.0.113.4 externo-1.example "
             f"www.{SEUDO} {variante(SEUDO, 'omision')['dominio']} TLSv1.3 2026-11-02T00:00:00+00:00")
    assert lista_blanca.revisar_texto(texto, permitidos) == []
    assert "google.com" in lista_blanca.PROVEEDORES


def test_seudonimizado_pasa_la_lista_blanca():
    texto = todo(seudonimizar(grabacion(), mapa()))
    assert lista_blanca.revisar_texto(texto, lista_blanca.permitidos_para(SEUDO)) == []


def test_etiqueta_corta_no_rompe_palabras():
    m = Mapa(real="habi.co", seudonimo="empresa-k.co", parecidos={}, nombres_libres=[])
    r = seudonimizar({"cabeceras_web|apihabi.habi.co": ResultadoHerramienta(
        ok=False, herramienta="cabeceras_web", error="sin_direccion_web",
        sugerencia="El host no está habilitado; Habi lo declara en apihabi.habi.co.")}, m)
    (clave, resultado), = r.items()
    assert clave == "cabeceras_web|apiempresa-k.empresa-k.co"
    assert resultado.sugerencia == "El host no está habilitado; empresa-k lo declara en apiempresa-k.empresa-k.co."
    assert restos_reales(resultado.sugerencia, m) == []
    assert restos_reales("lo dice Habi.", m) == ["habi"]


def test_etiqueta_de_parecido_dentro_de_proveedor():
    real_p, seudo_p = PARECIDO_OMISION["dominio"], mapa().parecidos[PARECIDO_OMISION["dominio"]]
    r = seudonimizar({f"buscar_parecidos|{REAL}": ResultadoHerramienta(ok=True, herramienta="buscar_parecidos", datos={
        "dominio": REAL, "con_correo": [{"dominio": real_p, "tipo": "omision",
                                         "mx": [f"{real_p.split('.')[0]}-com-co.mail.protection.outlook.com"],
                                         "comparte_servidores": False}], "sin_verificar": []})}, mapa())
    mx = r[f"buscar_parecidos|{SEUDO}"].datos["con_correo"][0]["mx"][0]
    assert mx == f"{seudo_p.split('.')[0]}-com-co.mail.protection.outlook.com"
    assert restos_reales(todo(r), mapa()) == []


def test_etiquetas_distintivas_de_subdominios():
    m = mapa().model_copy(update={"etiquetas": {"coleccionarte": "coleccion", "davi": "banco"}})
    r = seudonimizar({f"tls_certificado|coleccionarte.{REAL}": ResultadoHerramienta(
        ok=True, herramienta="tls_certificado", datos={"host": f"daviturno.{REAL}"})}, m)
    (clave, resultado), = r.items()
    assert clave == f"tls_certificado|coleccion.{SEUDO}" and resultado.datos["host"] == f"bancoturno.{SEUDO}"
    assert restos_reales(todo(r), m) == [] and restos_reales("api.daviturno.x", m) == ["davi"]
