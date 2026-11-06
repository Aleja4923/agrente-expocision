"""carga/correr.py: la cola del S4 con un auditor falso (sin red ni llave)."""

import json
import threading

import pytest

from auditor.llm import ErrorGateway
from auditor.modelos import EstadoAuditoria, Hallazgo, MotivoCierre, NivelRiesgo, Severidad
from carga import correr

FILAS = [(i, f"d{i}.com.co", "corrida") for i in range(1, 9)]


class AuditorFalso:
    """Imita auditar(): por dominio, una lista de cierres por intento (lo último se repite)."""

    def __init__(self, guion=None, costo=0.03, excepcion=None):
        self.guion = guion or {}
        self.costo = costo
        self.excepcion = excepcion or {}
        self.llamadas = []
        self.candado = threading.Lock()

    def __call__(self, dominio, *, lote_id, auditoria_id, intento, modelo, cliente_llm):
        with self.candado:
            self.llamadas.append((dominio, intento, auditoria_id))
        if dominio in self.excepcion:
            raise self.excepcion[dominio]
        cierres = self.guion.get(dominio, ["informe_entregado"])
        cierre = cierres[min(intento, len(cierres)) - 1]
        e = EstadoAuditoria(dominio=dominio, lote_id=lote_id, auditoria_id=auditoria_id, intento=intento,
                            modelo=modelo, pasos=3, costo_usd=self.costo, motivo_cierre=MotivoCierre(cierre),
                            nivel_riesgo=NivelRiesgo.ALTO, informe_de_respaldo=cierre != "informe_entregado")
        e.hallazgos = {"CORREO-DMARC-NONE": Hallazgo(id="CORREO-DMARC-NONE", categoria="correo",
                                                     severidad=Severidad.ALTA, titulo="t", explicacion_simple="e",
                                                     evidencia="v=DMARC1", recomendacion_id="r")}
        return e


def cola(tmp_path, auditor, filas=FILAS, **kw):
    kw = {"hilos": 1, "dormir": lambda s: None, "guardar": lambda e: None} | kw
    return correr.correr_cola("s4-test", filas, auditar_fn=auditor, carpeta=tmp_path / "pub",
                              carpeta_privada=tmp_path / "priv", **kw)


def tareas(tmp_path):
    return [json.loads(l) for l in (tmp_path / "pub" / "s4-test" / "tareas.jsonl").read_text("utf-8").splitlines()]


def eventos(tmp_path):
    return [json.loads(l) for l in (tmp_path / "pub" / "s4-test" / "eventos.jsonl").read_text("utf-8").splitlines()]


def test_linea_por_tarea_sin_datos_de_riesgo(tmp_path):
    r = cola(tmp_path, AuditorFalso())
    t = tareas(tmp_path)
    assert r["completadas"] == 8 and len(t) == 8
    assert t[0]["dominio"] == "d1.com.co" and t[0]["resultado"] == "completada" and t[0]["exito"] is True
    assert t[0]["costo_usd"] == pytest.approx(0.03) and t[0]["intentos"] == 1 and t[0]["pasos"] == 3
    assert {"inicio", "fin", "duracion_s", "motivo_cierre", "errores", "recuperacion"} <= set(t[0])
    texto = (tmp_path / "pub" / "s4-test" / "tareas.jsonl").read_text("utf-8")
    assert "alto" not in texto.lower() and "DMARC" not in texto  # el riesgo de cada empresa no se publica
    privado = [json.loads(l) for l in (tmp_path / "priv" / "s4-test-hallazgos.jsonl").read_text("utf-8").splitlines()]
    assert privado[0]["nivel"] == "alto" and privado[0]["hallazgos"] == ["CORREO-DMARC-NONE"]


def test_gateway_se_reintenta_y_la_recuperacion_queda_escrita(tmp_path):
    a = AuditorFalso({"d1.com.co": ["error_gateway", "error_gateway", "informe_entregado"],
                      "d2.com.co": ["error_gateway"]})
    r = cola(tmp_path, a, filas=FILAS[:2])
    t = {x["dominio"]: x for x in tareas(tmp_path)}
    assert t["d1.com.co"]["resultado"] == "completada" and t["d1.com.co"]["intentos"] == 3
    assert t["d1.com.co"]["costo_usd"] == pytest.approx(0.09)  # el costo de la tarea suma sus intentos
    assert "2 intentos con error del gateway" in t["d1.com.co"]["recuperacion"]
    assert t["d2.com.co"]["resultado"] == "fallida" and t["d2.com.co"]["exito"] is False
    assert t["d2.com.co"]["intentos"] == 3 and r["fallidas"] == 1
    assert [i for d, i, _ in a.llamadas if d == "d1.com.co"] == [1, 2, 3]


def test_respaldo_por_tope_cuenta_como_completada(tmp_path):
    cola(tmp_path, AuditorFalso({"d1.com.co": ["tope_pasos"]}), filas=FILAS[:1])
    t = tareas(tmp_path)[0]
    assert t["resultado"] == "completada" and t["respaldo"] is True and t["intentos"] == 1


def test_una_excepcion_no_tumba_la_cola(tmp_path):
    a = AuditorFalso(excepcion={"d2.com.co": RuntimeError("se rompió")})
    r = cola(tmp_path, a, filas=FILAS[:3])
    t = {x["dominio"]: x for x in tareas(tmp_path)}
    assert t["d2.com.co"]["resultado"] == "fallida" and "error_interno:RuntimeError" in t["d2.com.co"]["errores"]
    assert t["d3.com.co"]["resultado"] == "completada" and r["completadas"] == 2


def test_reanuda_sin_repetir(tmp_path):
    cola(tmp_path, AuditorFalso(), filas=FILAS[:3])
    a = AuditorFalso()
    r = cola(tmp_path, a, filas=FILAS[:5])
    assert sorted(d for d, _, _ in a.llamadas) == ["d4.com.co", "d5.com.co"] and r["completadas"] == 5
    assert len(tareas(tmp_path)) == 5


def test_reanuda_con_una_ultima_linea_cortada(tmp_path):
    cola(tmp_path, AuditorFalso(), filas=FILAS[:2])
    ruta = tmp_path / "pub" / "s4-test" / "tareas.jsonl"
    ruta.write_text(ruta.read_text("utf-8") + '{"pos": 3, "domi', encoding="utf-8")
    r = cola(tmp_path, AuditorFalso(), filas=FILAS[:3])
    assert r["completadas"] == 3


def test_freno_de_gasto(tmp_path):
    r = cola(tmp_path, AuditorFalso(costo=0.40), freno=(1.0, 1.5, 100))
    assert r["frenada"] is True and r["completadas"] == 4  # 4 × 0.40 = 1.60 ≥ 1.5
    assert any(e["tipo"] == "freno_gasto" for e in eventos(tmp_path))


def test_freno_suave_si_ya_hay_suficientes(tmp_path):
    r = cola(tmp_path, AuditorFalso(costo=0.40), freno=(1.0, 1.5, 2))
    assert r["frenada"] is True and r["completadas"] == 3  # 1.20 ≥ 1.0 con 3 ≥ 2 completadas


def test_pausa_si_el_gateway_se_cae(tmp_path):
    dormidos = []
    a = AuditorFalso({f"d{i}.com.co": ["error_gateway"] for i in range(1, 7)})
    cola(tmp_path, a, dormir=dormidos.append, caidas_seguidas=3)
    pausas = [e for e in eventos(tmp_path) if e["tipo"] == "pausa_gateway"]
    assert len(pausas) >= 1 and pausas[0]["segundos"] == 300
    assert 300 in dormidos


def test_dos_hilos_hacen_todo_una_vez(tmp_path):
    a = AuditorFalso()
    r = cola(tmp_path, a, filas=[(i, f"d{i}.com.co", "corrida") for i in range(1, 41)], hilos=2)
    assert r["completadas"] == 40 and len(tareas(tmp_path)) == 40
    assert sorted(t["pos"] for t in tareas(tmp_path)) == list(range(1, 41))
    assert len(a.llamadas) == 40


def test_limite_de_tareas(tmp_path):
    a = AuditorFalso()
    r = cola(tmp_path, a, limite=3)
    assert r["completadas"] == 3 and len(a.llamadas) == 3


def test_contador_suma_tokens_y_anota_errores_del_gateway():
    class Cliente:
        def __init__(self):
            self.n = 0

        def completar(self, *a, **k):
            self.n += 1
            if self.n == 2:
                raise ErrorGateway("tiempo_agotado", "lento")
            return type("R", (), {"tokens_entrada": 100, "tokens_cache": 40, "tokens_salida": 10,
                                  "tokens_razonamiento": 5})()

    c = correr.ContadorLLM(Cliente())
    c.completar([])
    with pytest.raises(ErrorGateway):
        c.completar([])
    c.completar([])
    assert c.tokens == {"entrada": 200, "cache": 80, "salida": 20, "razonamiento": 10}
    assert c.errores == ["gateway:tiempo_agotado"]


def test_csv_de_tareas(tmp_path):
    cola(tmp_path, AuditorFalso(), filas=FILAS[:3])
    ruta = correr.escribir_csv(tmp_path / "pub" / "s4-test")
    filas = ruta.read_text("utf-8").splitlines()
    assert filas[0].startswith("pos,dominio,inicio") and len(filas) == 4


def test_resumen_publica_solo_agregados(tmp_path):
    from carga import resumen
    a = AuditorFalso({"d1.com.co": ["error_gateway", "informe_entregado"], "d2.com.co": ["error_gateway"],
                      "d3.com.co": ["tope_costo"]})
    cola(tmp_path, a, filas=FILAS[:5])
    pub = tmp_path / "pub" / "s4-test"
    leer = lambda r: [json.loads(l) for l in r.read_text("utf-8").splitlines()]
    m = resumen.metricas(leer(pub / "tareas.jsonl"), leer(pub / "eventos.jsonl"),
                         leer(tmp_path / "priv" / "s4-test-hallazgos.jsonl"))
    assert (m["n"], m["completadas"], m["fallidas"], m["recuperadas"]) == (5, 4, 1, 1)
    assert m["respaldos"] == {"tope_costo": 1}
    assert m["costo_total"] == pytest.approx(0.03 * 8)  # 2 + 3 + 1 + 1 + 1 intentos
    assert m["costo_por_completada"] == pytest.approx(0.24 / 4)
    texto = resumen.reporte("s4-test", m, gasto_bitacora=0.25)
    assert "**80.0 % (4/5)**" in texto and "d1.com.co" not in texto
    assert "`CORREO-DMARC-NONE`" in texto  # solo como prevalencia agregada


def test_gasto_en_bitacora_cuenta_solo_llamadas_del_lote(tmp_path):
    from carga import resumen
    eventos = [{"lote_id": "s4-x", "tipo": "llm", "costo_usd": 0.01}, {"lote_id": "s4-x", "tipo": "fin",
               "costo_usd": 0.01}, {"lote_id": "otro", "tipo": "llm", "costo_usd": 5}]
    (tmp_path / "bitacora-20261106.jsonl").write_text("\n".join(json.dumps(e) for e in eventos) + "\n{roto",
                                                      encoding="utf-8")
    assert resumen.gasto_en_bitacora("s4-x", tmp_path) == pytest.approx(0.01)


def test_ritmo_minimo_entre_tareas(tmp_path):
    """El reto exige 12 h seguidas: las tareas no arrancan más seguido que `ritmo`."""
    reloj = [1000.0]
    dormidos = []

    def dormir(s):
        dormidos.append(round(s, 3))
        reloj[0] += s

    a = AuditorFalso()
    cola(tmp_path, a, filas=FILAS[:4], ritmo=42.0, reloj=lambda: reloj[0], dormir=dormir)
    assert dormidos == [42.0, 42.0, 42.0]  # la primera arranca ya; el auditor falso no gasta tiempo
