# Auditor de exposición digital para pymes

Agente autónomo que revisa, **solo con información pública**, qué tan expuesto está el dominio de una pyme colombiana a la **suplantación de su correo y a fraudes con su nombre**. Entrega al dueño un **plan de acción priorizado**, en lenguaje simple y con un texto listo para reenviar a su proveedor.

Proyecto del Track 1 del [Reto Agente 2026](https://reto.pltk.mx/) (Platica.mx × Campuslands). El razonamiento corre sobre **Grok** a través del gateway del reto.

> **Estado:** hito S1 completo: el agente audita un dominio real de principio a fin. Ver [Estado y hoja de ruta](#estado-y-hoja-de-ruta).

---

## El problema

Las pymes colombianas usan su dominio para el correo y la web, pero la mayoría no configura las protecciones que permiten a los receptores reconocer un correo falso (SPF, DKIM, DMARC). El resultado:

- **Facturas y cambios de cuenta bancaria "desde" su correo.** Sin DMARC, el dominio no indica a los receptores qué hacer con correos falsificados y el dueño no recibe reportes. Filtrarlos queda a criterio de cada proveedor de correo.
- **Dominios casi idénticos al suyo** (una letra cambiada, otro TLD) que pueden recibir los correos que sus clientes escriban mal.
- **El dueño no lo sabe**, y aunque lo supiera, no sabe qué pedirle a su proveedor.

## Qué lo hace distinto

Herramientas como MXToolbox o internet.nl ya hacen los chequeos técnicos gratis. Este agente aporta dos cosas que ellas no dan:

1. **Un plan, no un tablero.** Prioriza qué hacer primero, explica por qué en lenguaje de dueño y adjunta el dato técnico exacto para su proveedor. Los cambios se proponen de forma gradual, para no mandar a spam correos legítimos como la facturación electrónica. La recomendación se adapta a cada dominio: si ya tiene DMARC en `reject`, lo conserva; si no recibe correo, ofrece cerrar SPF con `-all`.
2. **Dominios parecidos con correo configurado** (desde el S2). Detectará imitaciones del dominio del dueño que tienen registro MX, y las presentará como una señal para verificar, nunca como una acusación.

En esta versión el agente revisa menos cosas que esas herramientas (por ejemplo, todavía no revisa DKIM): su valor está en convertir los hallazgos en un plan seguro que el dueño pueda ejecutar.

## Por qué es un agente y no un script

**Grok decide qué investigar; el código decide qué se concluye.**

- **Grok elige el camino** según lo que va encontrando: qué revisar, en qué orden y cuándo tiene suficiente para entregar. Cada auditoría tiene topes (15 pasos, USD 0,15 y 180 s). En esta versión, con dos herramientas, alcanzan con holgura; desde el S2, con subdominios y dominios parecidos por revisar, habrá más candidatos que pasos, y Grok tendrá que priorizar qué investigar y qué dejar declarado como limitación. Cada decisión queda en la bitácora con una justificación de una línea.
- **Las conclusiones las calculan reglas deterministas en el código:** cada hallazgo tiene un id, una severidad y su evidencia exacta. Grok no puede crear hallazgos ni cambiar su severidad.
- **Grok redacta y prioriza el plan para el dueño,** pero los datos técnicos (el registro DNS exacto que hay que publicar) los pone el código, literales.
- **El arnés rechaza un informe** que cite hallazgos inexistentes o que omita uno crítico o alto.
- **Los textos que vienen de afuera** (registros DNS, certificados) se pasan como datos no confiables, de modo que una inyección de prompts no cambia los hallazgos.

Trayectorias reales distintas (dominios seudonimizados): en `pyme-e.com.co` el dominio raíz no tenía sitio web y Grok decidió revisar `www`; en `pyme-b.com.co` exploró `mail.`, `webmail.`, `pagos.` y `admin.` por ser *«sensibles para fraudes»* y reintentó una sola vez el que agotó el tiempo; con un dominio inexistente entregó en 2 pasos, sin gastar más.

## Alcance ético y legal

- Solo **verificaciones pasivas de información pública**. En el S1: consultas DNS y el saludo TLS del certificado, sin pedir ninguna página. Desde el S2 se suman cabeceras de la portada, Certificate Transparency, WHOIS y `security.txt`. Sin escaneos de puertos, sin intentos de acceso, sin formularios.
- HTTP (desde el S2) solo con GET y HEAD, máximo 3 redirecciones dentro del mismo dominio, y un User-Agent identificable: `AuditorPymeBot/1.0 (+URL de este repo)`.
- **Anti-SSRF:** antes de cada conexión se resuelve la IP y se bloquean rangos privados, loopback y link-local; luego se conecta a esa misma IP.
- **Guarda de alcance:** ninguna herramienta acepta un dominio distinto del objetivo o sus subdominios. La única excepción (desde el S2) son las variantes que genera el propio agente para detectar dominios parecidos, y esas solo se consultan por DNS y WHOIS.
- Los ejemplos publicados usan dominios seudonimizados, y las estadísticas se publican solo en agregado.

## Arquitectura

```
auditor/
  config.py      modelos, precios, topes por auditoría y rutas
  modelos.py     contrato de datos (Pydantic): resultado de herramienta, hallazgo, informe
  bitacora.py    bitácora JSONL de esquema fijo; enmascara cualquier llave
  llm.py         cliente de Grok: costo real por llamada, caché por conversación,
                 reintentos con backoff y errores con nombre
  tools/
    base.py      guardas: normalización del dominio, alcance, anti-SSRF; nunca lanza excepciones
    correo.py    dns_correo: MX y proveedor, SPF (conteo recursivo, RFC 7208), DMARC (RFC 9989)
    web.py       tls_certificado: validez y motivo, vencimiento y versión de TLS
  scoring.py     16 reglas deterministas → hallazgos y nivel de riesgo
  agent.py       bucle del agente con topes, detección de repeticiones y validador del informe
  report.py      informe Markdown para el dueño, con el dato técnico exacto por plantilla
  store.py       registro de auditorías en SQLite
  __main__.py    CLI
scripts/
  probar_gateway.py   verificación medida de lo que soporta el gateway
tests/           251 pruebas sin red ni llave (Grok simulado con guiones)
```

**Decisiones de diseño:**
- **Bucle propio sobre la librería `openai`, sin framework:** los topes, el validador del informe y la bitácora son lógica propia en cualquier caso, y así cada parte es visible.
- **Cada auditoría tiene topes:** 15 pasos, USD 0,15 y 180 s. Si Grok repite la misma herramienta con los mismos argumentos, la auditoría se corta.
- **Siempre hay informe:** si la auditoría se corta por un tope o un error, el código arma un informe de respaldo con los hallazgos verificados.
- **El nivel de riesgo lo calcula el código**, no Grok: alto si hay algún hallazgo crítico o alto. En el S1 solo aparecen ALTO y BAJO, porque ninguna regla es de severidad media; el nivel MEDIO llega en el S2 con los dominios parecidos.
- **Identidad de cada ejecución: lote > auditoría > intento.** Una corrida masiva puede reanudarse tras una caída sin contar dos veces la misma auditoría.

## Costo medido

Sobre **26 auditorías reales** por la CLI (15 dominios distintos, octubre de 2026), con grok-4.7, todas cerradas con el informe entregado por Grok y ninguna con informe de respaldo:

| | Mínimo | Mediana | Máximo |
|---|---|---|---|
| Costo por auditoría | USD 0,007 | **USD 0,016** | USD 0,045 |
| Pasos de Grok | 2 | 2 | 4 |
| Duración | 7 s | 26 s | 108 s |

El costo de cada llamada es el que reporta el propio gateway, y coincide con el que calculamos con los precios publicados. Todo queda en la bitácora.

## Instalación y uso (Windows)

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env    # luego escribe tu llave del reto en RETO_KEY
venv\Scripts\python.exe -m pytest -q                      # 251 pruebas, sin red ni llave
venv\Scripts\python.exe -m auditor auditar ejemplo.com.co --verbose
```

Opciones: `--objetivo "texto libre"` (por ejemplo, *"¿Es seguro el sitio de pagos de mi tienda?"*), `--modelo` (uno de los permitidos por el reto; por defecto grok-4.7) y `--verbose` (muestra en vivo cada decisión de Grok con su justificación y su costo).

- **Informe:** `salidas/<dominio>-<fecha>.md`. **Bitácora:** `logs/bitacora-<fecha>.jsonl`. **Registro:** `cache/auditor.db`.
- **Códigos de salida:** 0 bien, 1 dominio inválido, 2 falta configuración (llave o modelo).
- `scripts\probar_gateway.py` repite la verificación del gateway (~USD 0,05).

La llave **nunca** va al repositorio: `.env` está en `.gitignore`, y la bitácora enmascara cualquier texto con forma de llave.

## Estado y hoja de ruta

| Hito | Contenido | Estado |
|---|---|---|
| **S1** · agente corriendo | Gateway verificado, contrato de datos, bitácora, cliente de Grok · herramientas de correo (SPF, DMARC, MX) y TLS · scoring · agente · informe · SQLite · CLI · 6 perfiles de dominio reales verificados | ✅ |
| **S2** · herramientas reales | Dominios parecidos, subdominios en Certificate Transparency, cabeceras, WHOIS, DKIM · informe HTML | ⏳ |
| **S3** · datos reales | Set de evaluación de 30+ casos · costo por tarea · comparación de modelos | ⏳ |
| **S4** · carga | 1.000 auditorías en 12 h desatendido · estadística agregada de dominios `.com.co` | ⏳ |

## Licencia

[MIT](LICENSE).
