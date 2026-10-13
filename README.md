# Auditor de exposición digital para pymes

Agente autónomo que revisa, **solo con información pública**, qué tan expuesto está el dominio de una pyme colombiana a la **suplantación de su correo y a fraudes con su nombre**. Entrega al dueño un **plan de acción priorizado**, en lenguaje simple y con un texto listo para reenviar a su proveedor.

Proyecto del Track 1 del [Reto Agente 2026](https://reto.pltk.mx/) (Platica.mx × Campuslands). El razonamiento corre sobre **Grok** a través del gateway del reto.

> **Estado:** en construcción, hito S1. Ver [Estado y hoja de ruta](#estado-y-hoja-de-ruta).

---

## El problema

Las pymes colombianas usan su dominio para el correo y la web, pero la mayoría no configura las protecciones que permiten a los receptores reconocer un correo falso (SPF, DKIM, DMARC). El resultado:

- **Facturas y cambios de cuenta bancaria "desde" su correo.** Sin DMARC, el dominio no indica a los receptores qué hacer con correos falsificados y el dueño no recibe reportes. Filtrarlos queda a criterio de cada proveedor de correo.
- **Dominios casi idénticos al suyo** (una letra cambiada, otro TLD) que pueden recibir los correos que sus clientes escriban mal.
- **El dueño no lo sabe**, y aunque lo supiera, no sabe qué pedirle a su proveedor.

## Qué lo hace distinto

Herramientas como MXToolbox o internet.nl ya hacen los chequeos técnicos gratis. Este agente aporta dos cosas que ellas no dan:

1. **Dominios parecidos con correo configurado.** Detecta imitaciones del dominio del dueño que tienen registro MX, y las presenta como una señal para verificar, nunca como una acusación.
2. **Un plan, no un tablero.** Prioriza qué hacer primero, explica por qué en lenguaje de dueño y adjunta el dato técnico exacto para su proveedor. Los cambios se proponen de forma gradual, para no mandar a spam correos legítimos como la facturación electrónica.

## Por qué es un agente y no un script

**Grok decide qué investigar; el código decide qué se concluye.**

- **Grok elige el camino** según lo que va encontrando: qué revisar, en qué orden y cuándo tiene suficiente para entregar. Cada auditoría tiene topes (15 pasos, USD 0,15 y 180 s). En esta versión, con dos herramientas, alcanzan con holgura; desde el S2, con subdominios y dominios parecidos por revisar, habrá más candidatos que pasos, y Grok tendrá que priorizar qué investigar y qué dejar declarado como limitación. Cada decisión queda en la bitácora con una justificación de una línea.
- **Las conclusiones las calculan reglas deterministas en el código:** cada hallazgo tiene un id, una severidad y su evidencia exacta. Grok no puede crear hallazgos ni cambiar su severidad.
- **Grok redacta y prioriza el plan para el dueño,** pero los datos técnicos (el registro DNS exacto que hay que publicar) los pone el código, literales.
- **El arnés rechaza un informe** que cite hallazgos inexistentes o que omita uno crítico o alto.
- **Los textos que vienen de afuera** (registros DNS, certificados) se pasan como datos no confiables, de modo que una inyección de prompts no cambia los hallazgos.

## Alcance ético y legal

- Solo **verificaciones pasivas de información pública**: DNS, certificado TLS, cabeceras de la portada, Certificate Transparency, WHOIS y `security.txt`. Sin escaneos de puertos, sin intentos de acceso, sin formularios.
- HTTP solo con GET y HEAD, máximo 3 redirecciones dentro del mismo dominio, y un User-Agent identificable: `AuditorPymeBot/1.0 (+URL de este repo)`.
- **Anti-SSRF:** antes de cada petición se resuelve la IP y se bloquean rangos privados, loopback y link-local.
- **Guarda de alcance:** ninguna herramienta acepta un dominio distinto del objetivo o sus subdominios. La única excepción son las variantes que genera el propio agente para detectar dominios parecidos, y esas solo se consultan por DNS y WHOIS.
- Los ejemplos publicados usan dominios seudonimizados, y las estadísticas se publican solo en agregado.

## Arquitectura

```
auditor/
  config.py      modelos, precios, topes por auditoría y rutas
  modelos.py     contrato de datos (Pydantic): resultado de herramienta, hallazgo, informe
  bitacora.py    bitácora JSONL de esquema fijo; enmascara cualquier llave
  llm.py         cliente de Grok: costo real por llamada, caché por conversación,
                 reintentos con backoff y errores con nombre
  tools/         herramientas pasivas (en construcción)
  scoring.py     reglas deterministas → hallazgos (en construcción)
  agent.py       bucle del agente con topes y validador del informe (en construcción)
  report.py      informe Markdown para el dueño (en construcción)
scripts/
  probar_gateway.py   verificación medida de lo que soporta el gateway
tests/           pruebas sin red ni llave
```

**Decisiones de diseño:**
- **Bucle propio sobre la librería `openai`, sin framework:** los topes, el validador del informe y la bitácora son lógica propia en cualquier caso, y así cada parte es visible.
- **Cada auditoría tiene topes:** 15 pasos, USD 0,15 y 180 s. Si Grok repite la misma herramienta con los mismos argumentos, la auditoría se corta.
- **Identidad de cada ejecución: lote > auditoría > intento.** Una corrida masiva puede reanudarse tras una caída sin contar dos veces la misma auditoría.

## Costo medido

Mediciones del gateway con grok-4.7: cada paso del agente cuesta entre **USD 0,004 y 0,009**. Para cada llamada, el costo que calculamos coincide exactamente con el que reporta el propio gateway. Una auditoría típica de 6 a 10 pasos costaría unos **USD 0,04–0,08**. El costo real por auditoría se publicará al terminar el S1.

## Instalación y uso (Windows)

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env    # luego escribe tu llave del reto en RETO_KEY
venv\Scripts\python.exe -m pytest -q                      # pruebas, sin red ni llave
venv\Scripts\python.exe scripts\probar_gateway.py         # verificación del gateway (~USD 0,05)
```

Cuando el S1 esté completo:

```powershell
venv\Scripts\python.exe -m auditor auditar ejemplo.com.co
```

La llave **nunca** va al repositorio: `.env` está en `.gitignore`, y la bitácora enmascara cualquier texto con forma de llave.

## Estado y hoja de ruta

| Hito | Contenido | Estado |
|---|---|---|
| **S1** · agente corriendo | Gateway verificado, contrato de datos, bitácora, cliente de Grok · herramientas de correo (SPF, DMARC, MX, DKIM) y TLS · scoring · agente · informe · CLI | 🟡 en curso |
| **S2** · herramientas reales | Dominios parecidos, subdominios en Certificate Transparency, cabeceras, WHOIS · informe HTML · video | ⏳ |
| **S3** · datos reales | Set de evaluación de 30+ casos · costo por tarea · comparación de modelos | ⏳ |
| **S4** · carga | 1.000 auditorías en 12 h desatendido · estadística agregada de dominios `.com.co` | ⏳ |

## Licencia

[MIT](LICENSE).
