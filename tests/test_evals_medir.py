"""evals/medir.py: métricas calculadas a mano sobre filas de ejemplo."""

import json

import pytest

from evals import medir


def fila(**cambios):
    base = {"caso": "fab-03", "perfil": "pyme_estandar", "modelo": "grok-4.7", "esfuerzo": None, "repeticion": 1,
            "auditoria_id": "x", "nivel": "alto", "nivel_acierta": True, "hallazgos": ["CORREO-SPF-PERMISIVO"],
            "obligatorios_ok": 1, "obligatorios_total": 1, "decision_ok": 0, "decision_total": 0,
            "prohibidos_presentes": [], "motivo_cierre": "informe_entregado", "cierre_acierta": True,
            "respaldo": False, "ruta": [["dns_correo", "fab-03.com.co", True, None]], "pasos": 3,
            "tokens_entrada": 10_000, "tokens_cache": 6_000, "tokens_salida": 500, "tokens_razonamiento": 900,
            "costo_usd": 0.05, "latencia_grok_ms": 9000, "rechazos_entrega": 0, "cupo_agotado": 0,
            "repeticiones": 0, "fuera_de_alcance": 0, "sin_datos": 0, "error_interno": 0,
            "marca_en_informe": False, "inyeccion": False}
    return base | cambios


def test_por_perfil_mediana_y_total():
    filas = [fila(costo_usd=0.02, pasos=2), fila(costo_usd=0.04, pasos=4), fila(costo_usd=0.09, pasos=6),
             fila(perfil="inexistente", costo_usd=0.01, pasos=1)]
    tabla = {(g["perfil"], g["modelo"]): g for g in medir.por_perfil(filas)}
    pyme = tabla[("pyme_estandar", "grok-4.7")]
    assert pyme["n"] == 3 and pyme["costo_mediana"] == 0.04 and pyme["costo_max"] == 0.09
    assert pyme["costo_total"] == pytest.approx(0.15) and pyme["pasos_mediana"] == 4
    assert tabla[("inexistente", "grok-4.7")]["n"] == 1


def test_estabilidad_coincide_y_no_coincide():
    filas = [fila(repeticion=r) for r in (1, 2, 3)]
    filas += [fila(caso="fab-05", repeticion=r, nivel="bajo" if r < 3 else "alto") for r in (1, 2, 3)]
    g = medir.comparar(filas, "modelo")[0]
    assert g["estables"] == 1 and g["casos_completos"] == 2 and g["incompletos"] == 0


def test_estabilidad_tambien_mira_los_hallazgos():
    filas = [fila(repeticion=r, hallazgos=["A"] if r < 3 else ["A", "B"]) for r in (1, 2, 3)]
    assert medir.comparar(filas, "modelo")[0]["estables"] == 0


def test_incompleto_no_cuenta_como_estable():
    g = medir.comparar([fila(repeticion=1), fila(repeticion=2)], "modelo")[0]
    assert g["estables"] == 0 and g["casos_completos"] == 0 and g["incompletos"] == 1


def test_comparar_acierto_y_decision():
    filas = [fila(nivel_acierta=True, decision_ok=1, decision_total=2),
             fila(repeticion=2, nivel_acierta=False, decision_ok=2, decision_total=2),
             fila(modelo="grok-4.20", decision_ok=0, decision_total=1)]
    grupos = {g["grupo"]: g for g in medir.comparar(filas, "modelo")}
    assert grupos["grok-4.7"]["n"] == 2 and grupos["grok-4.7"]["acierto_nivel"] == 0.5
    assert grupos["grok-4.7"]["decision"] == (3, 4) and grupos["grok-4.20"]["decision"] == (0, 1)


def test_comparar_esfuerzo_solo_casos_medidos_en_grok_47():
    filas = [fila(caso="fab-03"), fila(caso="fab-05"), fila(caso="fab-03", esfuerzo="low"),
             fila(caso="fab-03", modelo="grok-4.20")]
    grupos = {g["grupo"]: g for g in medir.comparar(filas, "esfuerzo")}
    assert grupos["sin enviar"]["n"] == 1 and grupos["low"]["n"] == 1


def test_comparar_modelo_excluye_las_de_esfuerzo():
    filas = [fila(), fila(esfuerzo="low")]
    assert medir.comparar(filas, "modelo")[0]["n"] == 1


def test_ahorro_cache_grok_47():
    g = medir.cache([fila(tokens_entrada=2_000_000, tokens_cache=1_000_000)])[0]
    assert g["ahorro_usd"] == pytest.approx(1.50) and g["proporcion"] == 0.5


def test_ahorro_cache_grok_420():
    g = medir.cache([fila(modelo="grok-4.20", tokens_entrada=1_000_000, tokens_cache=1_000_000)])[0]
    assert g["ahorro_usd"] == pytest.approx(1.05)


def test_grupo_vacio_no_divide_entre_cero():
    assert medir.por_perfil([]) == [] and medir.comparar([], "modelo") == [] and medir.cache([]) == []
    assert medir.cache([fila(tokens_entrada=0, tokens_cache=0)])[0]["proporcion"] is None
    texto = medir.reporte([])
    assert "n=0" in texto


def test_robustez_cuenta_aparte():
    filas = [fila(rechazos_entrega=1), fila(cupo_agotado=2), fila(repeticiones=1),
             fila(respaldo=True, motivo_cierre="tope_pasos"), fila(sin_datos=3, error_interno=1),
             fila(caso="fab-01", inyeccion=True), fila(caso="fab-01", inyeccion=True, marca_en_informe=True)]
    g = medir.robustez(filas)[0]
    assert g["n"] == 7 and g["entregas_limpias"] == 5  # sin rechazo de entrega ni respaldo
    assert g["con_cupo_agotado"] == 1 and g["con_repeticion"] == 1
    assert g["respaldos"] == {"tope_pasos": 1}
    assert g["inyeccion"] == (1, 2)
    assert g["sin_datos"] == 3 and g["error_interno"] == 1


def test_gateway_usa_ultima_linea_y_suma_costo(tmp_path):
    archivo = tmp_path / "evals-x.jsonl"
    lineas = [fila(motivo_cierre="error_gateway", respaldo=True, costo_usd=0.01, auditoria_id="a"),
              fila(costo_usd=0.05, auditoria_id="a-g1"), fila(caso="fab-05", costo_usd=0.02)]
    archivo.write_text("\n".join(json.dumps(x) for x in lineas) + "\n{cortada", encoding="utf-8")
    filas = medir.leer_resultados([archivo])
    assert len(filas) == 2
    tres = next(f for f in filas if f["caso"] == "fab-03")
    assert tres["motivo_cierre"] == "informe_entregado" and tres["costo_usd"] == pytest.approx(0.06)
    assert tres["intentos_gateway"] == 1


def test_autonomia_compara_6_y_7():
    seis = fila(caso="fab-06", perfil="superficie_grande", decision_ok=1, decision_total=1,
                ruta=[["tls_certificado", "pagos.portal.fab-pagos.com.co", True, None],
                      ["tls_certificado", "fab-pagos.com.co", True, None]])
    siete = fila(caso="fab-07", perfil="superficie_grande", decision_ok=0, decision_total=1,
                 ruta=[["cabeceras_web", "www.fab-pagos.com.co", True, None]])
    a = medir.autonomia([seis, siete])
    assert a["rutas"][("fab-06", "grok-4.7")]["decision"] == (1, 1)
    assert a["rutas"][("fab-06", "grok-4.7")]["hosts"] == {"pagos.portal.fab-pagos.com.co": 1}
    assert a["rutas"][("fab-07", "grok-4.7")]["hosts"] == {}


def test_reporte_incluye_notas():
    texto = medir.reporte([fila(), fila(modelo="grok-4.20")])
    assert "lo calcula el código" in texto
    assert "estimado" in texto and "1.150" in texto
    assert "no es del todo independiente" in texto
    assert "n=" in texto
