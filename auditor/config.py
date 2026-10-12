
### Constantes del proyecto en un único lugar: gateway, modelos, precios, topes y rutas
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
RUTA_LOGS = RAIZ / "logs"
RUTA_SALIDAS = RAIZ / "salidas"
RUTA_CACHE = RAIZ / "cache"
RUTA_ENV = RAIZ / ".env"

BASE_URL = "https://api.reto.pltk.mx/v1"
URL_REPO = "https://github.com/Aleja4923/agrente-expocision"
USER_AGENT = f"AuditorPymeBot/1.0 (+{URL_REPO})"

MODELOS_PERMITIDOS = ("grok-4.7", "grok-4.6", "grok-4.5", "grok-4.20")
MODELO_POR_DEFECTO = "grok-4.7"
PRECIOS_PROVISIONALES = True
PRECIOS_USD_POR_MILLON = {
    "grok-4.7": (2.00, 0.50, 6.00),
    "grok-4.6": (2.00, 0.50, 6.00),
    "grok-4.5": (2.00, 0.30, 6.00),
    "grok-4.20": (1.25, 0.20, 2.50),
}
# El gateway informa el costo real en `usage.cost_in_usd_ticks`.
USD_POR_TICK = 1e-10

# No se envía: en la verificación del gateway no cambió el gasto de forma consistente.
REASONING_EFFORT = None

# Llamadas a Grok: tiempo máximo por intento, intentos y espera máxima entre reintentos.
TIMEOUT_LLM_SEGUNDOS = 60
MAX_INTENTOS_LLM = 4
ESPERA_MAX_SEGUNDOS = 30

# Consultas DNS: tiempo total máximo por consulta.
DNS_TIMEOUT_SEGUNDOS = 5

# Topes por auditoría: ninguna puede quedarse en bucle ni gastar de más.
MAX_PASOS = 15
MAX_USD = 0.15
MAX_SEGUNDOS = 180
MAX_REPETICIONES = 2  #
MAX_CARACTERES_NO_CONFIABLE = 300


def cargar_llave(ruta_env: Path = RUTA_ENV) -> str:
    """Devuelve RETO_KEY desde el entorno o el .env; si falta, sale con un mensaje claro."""
    load_dotenv(ruta_env)
    llave = os.getenv("RETO_KEY", "").strip()
    if not llave or llave == "pk_REEMPLAZAR":
        sys.exit(
            "No encontré la llave del reto. Copia .env.example como .env "
            "y escribe tu llave en RETO_KEY=pk_..."
        )
    return llave


def modelo_elegido(modelo: str | None = None) -> str:
    """Modelo pedido (argumento, variable MODELO o el de por defecto), solo si está permitido."""
    modelo = modelo or os.getenv("MODELO") or MODELO_POR_DEFECTO
    if modelo not in MODELOS_PERMITIDOS:
        sys.exit(
            f"El modelo '{modelo}' no está permitido por el reto. "
            f"Usa uno de: {', '.join(MODELOS_PERMITIDOS)}"
        )
    return modelo
