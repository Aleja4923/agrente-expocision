"""evals/correr.py: una corrida produce su línea pública, con cifras leídas de la bitácora."""

import json

from auditor.bitacora import Evento, escribir
from auditor.llm import ErrorGateway
from evals.casos import cargar_casos
from tests.test_agent import GrokGuion, informe, resp

CASOS = {c.id: c for c in cargar_casos()}


class GrokConBitacora(GrokGuion):
    """GrokGuion que además anota cada llamada en la bitácora, como ClienteLLM."""

    def __init__(self, *pasos, auditoria_id, ruta_logs, tokens=(1000, 600, 50, 200)):
        super().__init__(*pasos)
        self.auditoria_id, self.ruta_logs, self.tokens = auditoria_id, ruta_logs, tokens

    def completar(self, mensajes, herramientas=None, *, paso=0, justificacion=None, limite=None):
        r = super().completar(mensajes, herramientas, paso=paso, justificacion=justificacion, limite=limite)
        entrada, cache, salida, razonamiento = self.tokens
        escribir(Evento(lote_id="evals-t", auditoria_id=self.auditoria_id, tipo="llm", paso=paso,
                        tokens_entrada=entrada, tokens_cache=cache, tokens_salida=salida,
                        tokens_razonamiento=razonamiento, costo_usd=r.costo_usd, latencia_ms=700), self.ruta_logs)
        return r


def obligatorias(c):
    d = c.dominio
    return [("dns_correo", {"dominio": d}), ("tls_certificado", {"host": d}), ("whois_dominio", {"dominio": d}),
            ("buscar_parecidos", {"dominio": d}), ("subdominios_ct", {"dominio": d}),
            ("cabeceras_web", {"host": d}), ("security_txt", {"dominio": d}),
            ("dkim_selector", {"dominio": d, "selectores": ["google"]})]  # fabricados: correo en Google


def aid(caso_id, modelo="grok-4.7", esfuerzo=None, r=1):
    return f"evals-t-{caso_id}-{modelo}-{esfuerzo or 'base'}-r{r}"


def correr(caso, *pasos, tmp_path, esfuerzo=None):
    from evals.correr import correr_una
    grok = GrokConBitacora(*pasos, auditoria_id=aid(caso.id, esfuerzo=esfuerzo), ruta_logs=tmp_path)
    return correr_una(caso, "grok-4.7", esfuerzo, 1, "evals-t", cliente_llm=grok, ruta_logs=tmp_path)


def test_linea_de_corrida_completa(tmp_path):
    c = CASOS["fab-03"]
    linea = correr(c, resp(*obligatorias(c)),
                   resp(("entregar_informe", informe("CORREO-SPF-PERMISIVO"))), tmp_path=tmp_path)
    assert linea["caso"] == "fab-03" and linea["perfil"] == "pyme_estandar" and linea["esfuerzo"] is None
    assert linea["auditoria_id"] == aid("fab-03")
    assert linea["motivo_cierre"] == "informe_entregado" and linea["cierre_acierta"] and not linea["respaldo"]
    assert linea["nivel"] == "alto" and linea["nivel_acierta"]
    assert linea["obligatorios_ok"] == linea["obligatorios_total"] == 1
    assert linea["prohibidos_presentes"] == []
    assert "CORREO-SPF-PERMISIVO" in linea["hallazgos"]
    assert linea["pasos"] == 2
    assert (linea["tokens_entrada"], linea["tokens_cache"], linea["tokens_salida"],
            linea["tokens_razonamiento"]) == (2000, 1200, 100, 400)
    assert linea["costo_usd"] == 0.01 and linea["latencia_grok_ms"] == 1400
    assert ["dns_correo", c.dominio, True, None] in linea["ruta"]
    assert linea["sin_datos"] == 0 and linea["error_interno"] == 0 and linea["marca_en_informe"] is False and linea["inyeccion"] is False
    json.dumps(linea)  # la línea es serializable tal cual


def test_rechazo_de_entrega_y_cupo_se_cuentan_aparte(tmp_path):
    c = CASOS["fab-08"]
    candidatos = [p["dominio"] for p in
                  c.grabacion[f"buscar_parecidos|{c.dominio}"].datos["con_correo"] if not p["comparte_servidores"]]
    investigar = [("investigar_parecido", {"dominio": c.dominio, "parecido": p}) for p in candidatos[:5]]
    linea = correr(c, resp(("entregar_informe", informe())), resp(*obligatorias(c), *investigar),
                   resp(("entregar_informe", informe(*c.esperado.hallazgos_obligatorios))), tmp_path=tmp_path)
    assert linea["rechazos_entrega"] == 1
    assert linea["cupo_agotado"] == 1 and linea["repeticiones"] == 0 and linea["fuera_de_alcance"] == 0


def test_marca_detectada_en_informe(tmp_path):
    c = CASOS["fab-01"]
    falso = informe(*c.esperado.hallazgos_obligatorios)
    falso["resumen"] = f"{falso['resumen']} {c.marca_inyeccion}"
    linea = correr(c, resp(*obligatorias(c)), resp(("entregar_informe", falso)), tmp_path=tmp_path)
    assert linea["marca_en_informe"] is True
    assert linea["inyeccion"] is True


def test_sin_datos_cuenta_hosts_y_selectores(tmp_path):
    c = CASOS["fab-03"]
    extra = [("tls_certificado", {"host": f"nada.{c.dominio}"}),
             ("dkim_selector", {"dominio": c.dominio, "selectores": ["google", "inventado1"]}),
             ("dkim_selector", {"dominio": c.dominio, "selectores": ["inventado2", "inventado3"]})]
    linea = correr(c, resp(*obligatorias(c), *extra),
                   resp(("entregar_informe", informe("CORREO-SPF-PERMISIVO"))), tmp_path=tmp_path)
    # host no grabado (1) + selector faltante en una llamada que sirvió (1) + llamada DKIM sin nada (1)
    assert linea["sin_datos"] == 3


def test_esfuerzo_en_id_y_linea(tmp_path):
    c = CASOS["fab-03"]
    linea = correr(c, resp(*obligatorias(c)), resp(("entregar_informe", informe("CORREO-SPF-PERMISIVO"))),
                   tmp_path=tmp_path, esfuerzo="low")
    assert linea["esfuerzo"] == "low" and linea["auditoria_id"].endswith("-low-r1")
    assert linea["tokens_entrada"] == 2000  # leyó los eventos de su propio id


def test_linea_sin_nombre_real(tmp_path):
    c = CASOS["fab-03"]
    linea = correr(c, resp(*obligatorias(c)), resp(("entregar_informe", informe("CORREO-SPF-PERMISIVO"))),
                   tmp_path=tmp_path)
    texto = json.dumps(linea, ensure_ascii=False)
    assert "justificacion" not in texto and "resumen" not in texto



# --- lote reanudable ---------------------------------------------------------------------------

def guion_simple(c):
    return [resp(*obligatorias(c)), resp(("entregar_informe", informe(*c.esperado.hallazgos_obligatorios)))]


def fabrica(tmp_path, fallar_gateway=()):
    """Grok falso por corrida; los ids en `fallar_gateway` cierran con error del gateway."""
    creados = []

    def crear(caso, auditoria_id):
        creados.append(auditoria_id)
        pasos = [ErrorGateway("gateway_caido", "caído")] if auditoria_id in fallar_gateway else guion_simple(caso)
        return GrokConBitacora(*pasos, auditoria_id=auditoria_id, ruta_logs=tmp_path / "logs")
    crear.creados = creados
    return crear


def lote(plan, tmp_path, fab, hilos=1):
    from evals.correr import correr_lote
    return correr_lote(plan, "evals-t", hilos=hilos, ruta_resultados=tmp_path / "res",
                       fabrica_cliente=fab, ruta_logs=tmp_path / "logs")


def lineas(tmp_path):
    texto = (tmp_path / "res" / "evals-t.jsonl").read_text(encoding="utf-8")
    return [json.loads(x) for x in texto.splitlines() if x.strip()]


def test_planear_cuenta_210():
    from evals.correr import planear
    treinta_y_cinco = (list(CASOS.values()) * 4)[:35]
    assert len(planear(treinta_y_cinco, ["grok-4.7", "grok-4.20"], 3)) == 210
    con_esfuerzo = planear(treinta_y_cinco[:10], ["grok-4.7"], 3, esfuerzos={"low"})
    assert len(con_esfuerzo) == 30 and {p[2] for p in con_esfuerzo} == {"low"}


def test_reanuda_sin_repetir(tmp_path):
    from evals.correr import planear
    plan = planear([CASOS["fab-03"], CASOS["fab-05"]], ["grok-4.7"], 2)
    primero = lote(plan[:3], tmp_path, fabrica(tmp_path))
    assert primero["hechas"] == 3 and primero["saltadas"] == 0 and primero["costo_usd"] == 0.03
    fab = fabrica(tmp_path)
    segundo = lote(plan, tmp_path, fab)
    assert segundo["hechas"] == 1 and segundo["saltadas"] == 3 and len(fab.creados) == 1
    assert len(lineas(tmp_path)) == 4


def test_ignora_ultima_linea_incompleta(tmp_path):
    from evals.correr import planear
    plan = planear([CASOS["fab-03"]], ["grok-4.7"], 2)
    lote(plan, tmp_path, fabrica(tmp_path))
    archivo = tmp_path / "res" / "evals-t.jsonl"
    texto = archivo.read_text(encoding="utf-8")
    archivo.write_text(texto[:-40], encoding="utf-8")  # corte a mitad de la segunda línea
    fab = fabrica(tmp_path)
    resumen = lote(plan, tmp_path, fab)
    assert resumen["hechas"] == 1 and resumen["saltadas"] == 1 and fab.creados == [aid("fab-03", r=2)]
    assert [x["repeticion"] for x in lineas_validas(archivo)] == [1, 2]


def lineas_validas(archivo):
    validas = []
    for x in archivo.read_text(encoding="utf-8").splitlines():
        try:
            validas.append(json.loads(x))
        except ValueError:
            pass
    return validas


def test_error_gateway_se_repite_y_no_se_borra(tmp_path):
    from evals.correr import planear
    plan = planear([CASOS["fab-03"]], ["grok-4.7"], 1)
    resumen = lote(plan, tmp_path, fabrica(tmp_path, fallar_gateway={aid("fab-03")}))
    assert resumen["hechas"] == 2 and resumen["repetidas_gateway"] == 1
    primera, segunda = lineas(tmp_path)
    assert primera["motivo_cierre"] == "error_gateway" and primera["auditoria_id"] == aid("fab-03")
    assert segunda["motivo_cierre"] == "informe_entregado" and segunda["auditoria_id"] == aid("fab-03") + "-g1"
    fab = fabrica(tmp_path)
    assert lote(plan, tmp_path, fab)["saltadas"] == 1 and fab.creados == []


def test_error_gateway_se_repite_solo_una_vez(tmp_path):
    from evals.correr import planear
    plan = planear([CASOS["fab-03"]], ["grok-4.7"], 1)
    caidos = {aid("fab-03"), aid("fab-03") + "-g1"}
    assert lote(plan, tmp_path, fabrica(tmp_path, fallar_gateway=caidos))["hechas"] == 2
    fab = fabrica(tmp_path, fallar_gateway=caidos)
    assert lote(plan, tmp_path, fab)["saltadas"] == 1 and fab.creados == []


def test_mas_de_un_hilo_se_rechaza(tmp_path):
    """La bitácora pierde líneas con varios hilos en Windows (registro_s3): el lote corre en uno solo."""
    import pytest
    from evals.correr import planear
    with pytest.raises(ValueError, match="un hilo"):
        lote(planear([CASOS["fab-03"]], ["grok-4.7"], 1), tmp_path, fabrica(tmp_path), hilos=3)


def test_corrida_cortada_no_se_suma_a_la_repetida(tmp_path):
    """Una corrida cortada a mitad deja eventos con el mismo id: la repetida solo cuenta los suyos."""
    escribir(Evento(lote_id="evals-t", auditoria_id=aid("fab-03"), tipo="llm", tokens_entrada=99_999,
                    costo_usd=0.5, ts="2020-01-01T00:00:00+00:00"), tmp_path)
    c = CASOS["fab-03"]
    linea = correr(c, resp(*obligatorias(c)), resp(("entregar_informe", informe("CORREO-SPF-PERMISIVO"))),
                   tmp_path=tmp_path)
    assert linea["tokens_entrada"] == 2000 and linea["costo_usd"] == 0.01


def test_linea_rota_de_bitacora_no_tumba_la_corrida(tmp_path):
    (tmp_path / "bitacora-20000101.jsonl").write_text('{"tipo": "llm", "trunc\n', encoding="utf-8")
    c = CASOS["fab-03"]
    linea = correr(c, resp(*obligatorias(c)), resp(("entregar_informe", informe("CORREO-SPF-PERMISIVO"))),
                   tmp_path=tmp_path)
    assert linea["tokens_entrada"] == 2000


def test_candado_impide_dos_procesos_en_el_mismo_lote(tmp_path):
    import os
    import pytest
    from evals.correr import planear
    (tmp_path / "res").mkdir()
    (tmp_path / "res" / "evals-t.lock").write_text(str(os.getpid()), encoding="utf-8")  # proceso vivo
    with pytest.raises(RuntimeError, match="ya corre"):
        lote(planear([CASOS["fab-03"]], ["grok-4.7"], 1), tmp_path, fabrica(tmp_path))


def test_candado_de_proceso_muerto_se_reemplaza_y_se_libera(tmp_path):
    from evals.correr import planear
    (tmp_path / "res").mkdir()
    (tmp_path / "res" / "evals-t.lock").write_text("999999", encoding="utf-8")
    assert lote(planear([CASOS["fab-03"]], ["grok-4.7"], 1), tmp_path, fabrica(tmp_path))["hechas"] == 1
    assert not (tmp_path / "res" / "evals-t.lock").exists()
