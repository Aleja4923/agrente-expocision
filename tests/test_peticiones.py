"""tools/peticiones.py: peticiones HTTP seguras (IP validada, Host correcto, redirecciones en alcance), sin internet."""

import http.server
import threading

import pytest

from auditor.tools import peticiones as red
from auditor.tools.peticiones import ErrorHTTP, Respuesta, pedir
from auditor.tools.web import ErrorConexion

D = "ejemplo.com.co"


# --- la conexión envía Host con el NOMBRE aunque conecte a la IP (servidor local de prueba) ---------

@pytest.fixture
def servidor_local():
    recibidos = []

    class Manejador(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            recibidos.append({"host": self.headers.get("Host"), "agente": self.headers.get("User-Agent"),
                              "ruta": self.path})
            self.send_response(200)
            self.send_header("X-Prueba", "1")
            self.end_headers()
            self.wfile.write(b"x" * 100_000)

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Manejador)
    hilo = threading.Thread(target=srv.serve_forever, daemon=True)
    hilo.start()
    yield srv.server_address[1], recibidos
    srv.shutdown()


def test_conexion_envia_host_con_el_nombre(servidor_local):
    puerto, recibidos = servidor_local
    codigo, cabeceras, cuerpo = red._enviar("127.0.0.1", D, puerto, False, "GET", "/ruta")
    assert codigo == 200 and cabeceras["x-prueba"] == "1"
    assert recibidos == [{"host": f"{D}:{puerto}", "agente": red.USER_AGENT, "ruta": "/ruta"}]
    assert len(cuerpo) == red.MAX_BYTES_HTTP  # nunca lee más de 64 KB


# --- pedir(): redirecciones, alcance y anti-SSRF (red simulada) ------------------------------

@pytest.fixture
def web_falsa(monkeypatch):
    """Tabla (esquema, host, ruta) -> (codigo, cabeceras); IPs por host."""
    estado = {"tabla": {}, "ips": {}, "enviados": []}

    def resolver(host):
        if host not in estado["ips"]:
            raise ErrorConexion("dominio_no_existe")
        return estado["ips"][host]

    def enviar(ip, host, puerto, https, metodo, ruta):
        estado["enviados"].append((ip, host, "https" if https else "http", ruta, metodo))
        valor = estado["tabla"].get(("https" if https else "http", host, ruta), (404, {}))
        if isinstance(valor, Exception):
            raise valor
        codigo, cabeceras = valor
        return codigo, {k.lower(): v for k, v in cabeceras.items()}, b""

    monkeypatch.setattr(red, "resolver_ip", resolver)
    monkeypatch.setattr(red, "_enviar", enviar)
    estado["ips"] = {D: "93.184.216.34", f"www.{D}": "93.184.216.35"}
    return estado


def test_sigue_redireccion_en_alcance(web_falsa):
    web_falsa["tabla"] = {("https", D, "/"): (301, {"Location": f"https://www.{D}/inicio"}),
                          ("https", f"www.{D}", "/inicio"): (200, {"Strict-Transport-Security": "max-age=1"})}
    r = pedir(f"https://{D}/", D)
    assert isinstance(r, Respuesta) and r.codigo == 200 and r.url == f"https://www.{D}/inicio"
    assert r.redirecciones == [f"https://www.{D}/inicio"] and r.cabeceras["strict-transport-security"] == "max-age=1"
    assert [e[0] for e in web_falsa["enviados"]] == ["93.184.216.34", "93.184.216.35"]  # IP revalidada por salto


def test_redireccion_relativa(web_falsa):
    web_falsa["tabla"] = {("https", D, "/"): (302, {"Location": "/es/"}), ("https", D, "/es/"): (200, {})}
    assert pedir(f"https://{D}/", D).url == f"https://{D}/es/"


def test_redireccion_fuera_de_alcance_se_detiene(web_falsa):
    web_falsa["tabla"] = {("https", D, "/"): (301, {"Location": "https://tienda.otra-plataforma.com/"})}
    r = pedir(f"https://{D}/", D)
    assert r.codigo == 301 and r.fuera_de_alcance == "tienda.otra-plataforma.com"
    assert len(web_falsa["enviados"]) == 1  # nunca se conecta fuera del dominio


def test_redireccion_a_ip_privada_se_bloquea(web_falsa):
    web_falsa["ips"]["interno." + D] = "10.0.0.5"
    web_falsa["tabla"] = {("https", D, "/"): (301, {"Location": f"https://interno.{D}/"})}
    with pytest.raises(ErrorHTTP, match="ip_bloqueada"):
        pedir(f"https://{D}/", D)
    assert len(web_falsa["enviados"]) == 1


def test_mas_de_tres_redirecciones(web_falsa):
    web_falsa["tabla"] = {("https", D, f"/{i}"): (302, {"Location": f"/{i + 1}"}) for i in range(5)}
    with pytest.raises(ErrorHTTP, match="demasiadas_redirecciones"):
        pedir(f"https://{D}/0", D)
    assert len(web_falsa["enviados"]) == 4  # la original + 3 redirecciones


def test_sin_seguir_devuelve_la_redireccion(web_falsa):
    web_falsa["tabla"] = {("http", D, "/"): (301, {"Location": f"https://{D}/"})}
    r = pedir(f"http://{D}/", D, seguir=False)
    assert r.codigo == 301 and r.cabeceras["location"] == f"https://{D}/" and r.redirecciones == []


def test_esquema_no_permitido(web_falsa):
    with pytest.raises(ErrorHTTP, match="fuera_de_alcance"):
        pedir(f"ftp://{D}/", D)


def test_metodo_no_permitido(web_falsa):
    with pytest.raises(ValueError):
        pedir(f"https://{D}/", D, metodo="POST")


@pytest.mark.parametrize("error,codigo", [(TimeoutError(), "tiempo_agotado"), (ConnectionRefusedError(), "sin_conexion")])
def test_errores_de_red(web_falsa, error, codigo):
    web_falsa["tabla"] = {("https", D, "/"): error}
    with pytest.raises(ErrorHTTP, match=codigo):
        pedir(f"https://{D}/", D)


def test_host_que_no_existe(web_falsa):
    with pytest.raises(ErrorHTTP, match="dominio_no_existe"):
        pedir(f"https://noexiste.{D}/", D)


# --- revisión: errores que no deben escaparse y plazo total --------------------------------

def test_redireccion_con_tildes_no_lanza(web_falsa):
    web_falsa["tabla"] = {("https", D, "/"): UnicodeEncodeError("ascii", "/inicio-español", 10, 11, "no ascii")}
    with pytest.raises(ErrorHTTP, match="respuesta_invalida"):
        pedir(f"https://{D}/", D)


def test_puerto_invalido_en_redireccion_no_lanza(web_falsa):
    web_falsa["tabla"] = {("https", D, "/"): (301, {"Location": f"https://www.{D}:99999/"})}
    with pytest.raises(ErrorHTTP, match="respuesta_invalida"):
        pedir(f"https://{D}/", D)


@pytest.fixture
def servidor_lento():
    """Responde la línea de estado y luego manda un byte de cabecera cada 0,1 s, sin terminar nunca."""
    import socket
    import time
    parar = threading.Event()
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def atender():
        conexion, _ = srv.accept()
        conexion.recv(4096)
        conexion.sendall(b"HTTP/1.1 200 OK\r\nX-Lento: ")
        while not parar.is_set():
            try:
                conexion.sendall(b"a")
            except OSError:
                break
            time.sleep(0.1)
        conexion.close()

    threading.Thread(target=atender, daemon=True).start()
    yield srv.getsockname()[1]
    parar.set()
    srv.close()


def test_plazo_total_corta_un_servidor_que_gotea(servidor_lento, monkeypatch):
    import time
    monkeypatch.setattr(red, "HTTP_PLAZO_TOTAL_SEGUNDOS", 0.6)
    inicio = time.monotonic()
    with pytest.raises(TimeoutError):
        red._enviar("127.0.0.1", D, servidor_lento, False, "GET", "/")
    assert time.monotonic() - inicio < 3
