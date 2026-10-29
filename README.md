# Auditor de exposición digital para pymes

Agente autónomo que revisa, **solo con información pública**, qué tan expuesto está el dominio de una pyme colombiana a la **suplantación de su correo y a fraudes con su nombre**. Entrega al dueño un **plan de acción priorizado**, en lenguaje simple y con un texto listo para reenviar a su proveedor.

Proyecto del Track 1 del [Reto Agente 2026](https://reto.pltk.mx/) (Platica.mx × Campuslands). El razonamiento corre sobre **Grok** a través del gateway del reto.

---

## El problema

Las pymes colombianas usan su dominio para el correo y la web, pero la mayoría no configura las protecciones que permiten a los receptores reconocer un correo falso (SPF, DKIM, DMARC). El resultado:

- **Facturas y cambios de cuenta bancaria "desde" su correo.** Sin DMARC, el dominio no indica a los receptores qué hacer con correos falsificados y el dueño no recibe reportes. Filtrarlos queda a criterio de cada proveedor de correo.
- **Dominios casi idénticos al suyo** (una letra cambiada, otro TLD) que pueden recibir los correos que sus clientes escriban mal.
- **El dueño no lo sabe**, y aunque lo supiera, no sabe qué pedirle a su proveedor.

## Qué lo hace distinto

Herramientas como MXToolbox o internet.nl ya hacen los chequeos técnicos gratis. Este agente aporta dos cosas que ellas no dan:

1. **Un plan, no un tablero.** Prioriza qué hacer primero, explica por qué en lenguaje de dueño y adjunta el dato técnico exacto para su proveedor. Los cambios se proponen de forma gradual, para no mandar a spam correos legítimos como la facturación electrónica. La recomendación se adapta a cada dominio: si ya tiene DMARC en `reject`, lo conserva; si no recibe correo, ofrece cerrar SPF con `-all`.
2. **Dominios parecidos preparados para enviar correo.** El agente genera variantes del dominio del dueño (una letra menos, una `l` por una `i`, el mismo nombre en `.co`) y revisa cuáles existen, tienen correo configurado, se registraron hace poco o publican autorización para enviar correo. Es la señal más cercana a un fraude de facturas antes de que llegue el primer correo falso. Se presenta como una señal para verificar, nunca como una acusación.

Además revisa el trío completo SPF, DKIM y DMARC, el registro del dominio (vencimiento y bloqueo de transferencia), los subdominios que aparecen en los registros públicos de certificados y las cabeceras de seguridad de la portada.

## Por qué es un agente y no un script

**Grok decide qué investigar; el código decide qué se concluye.**

- **Grok elige el camino** según lo que va encontrando: qué revisar, en qué orden y cuándo tiene suficiente para entregar. Cada auditoría tiene topes (20 pasos, USD 0,20 y 300 s). Cada decisión queda en la bitácora con una justificación de una línea.
- **Hay más candidatos que presupuesto.** Grok puede investigar a fondo **4 dominios parecidos** y revisar **10 subdominios** (además del dominio y `www`); el código le marca cuáles tienen sitio web para que no gaste cupo en los que no. El arnés hace cumplir esos cupos, y el código declara en el informe lo que quedó sin revisar.
- **Hay dependencias:** primero ve el proveedor de correo y después elige los selectores DKIM (`google` para Google Workspace; `selector1` y `selector2` para Microsoft 365); primero ve la lista de parecidos y después decide cuáles investigar.
- **Las conclusiones las calculan reglas deterministas en el código:** cada hallazgo tiene un id, una severidad y su evidencia exacta. Grok no puede crear hallazgos ni cambiar su severidad.
- **Grok redacta y prioriza el plan para el dueño,** pero los datos técnicos (el registro DNS exacto que hay que publicar) los pone el código, literales.
- **El arnés rechaza un informe** que cite hallazgos inexistentes o que omita uno crítico o alto.
- **Los textos que vienen de afuera** (registros DNS, certificados) se pasan como datos no confiables, de modo que una inyección de prompts no cambia los hallazgos.

Trayectorias reales distintas (dominios seudonimizados): en `banco-i.com`, los registros de certificados mostraron cientos de subdominios y, con el objetivo *«¿qué tan expuesto está el portal de pagos y el acceso de clientes?»*, Grok eligió los 5 de autenticación y comercios; en `pyme-a.com.co` el sitio redirige a otro dominio, Grok intentó revisarlo, la guarda de alcance se lo impidió y él lo declaró como limitación; en `pyme-g.net` vio que el correo es de Microsoft 365, probó `selector1` y `selector2` y encontró una clave DKIM de 1024 bits; con un dominio inexistente entregó en 2 pasos, sin gastar más.

## Alcance ético y legal

- Solo **verificaciones pasivas de información pública**: consultas DNS, el saludo TLS del certificado, la portada del sitio y `/.well-known/security.txt`, los registros públicos de certificados (Certificate Transparency) y el registro público de dominios (WHOIS y RDAP). Sin escaneos de puertos, sin intentos de acceso, sin formularios.
- HTTP solo con GET y HEAD, como máximo 64 KB por respuesta, 20 s por petición y 3 redirecciones dentro del mismo dominio, con un User-Agent identificable: `AuditorPymeBot/1.0 (+URL de este repo)`.
- **Anti-SSRF:** antes de cada conexión (también en cada redirección) se resuelve la IP, se bloquean rangos privados, loopback y link-local, y se conecta a esa misma IP. La petición lleva el nombre del sitio en la cabecera `Host` y en el saludo TLS, para que funcione con hosting compartido y CDN.
- **Guarda de alcance:** ninguna herramienta acepta un dominio distinto del objetivo o sus subdominios. La única excepción son los **dominios parecidos**:
  1. las variantes las genera el código; ni Grok ni los datos externos pueden pedir otro dominio;
  2. a esos dominios solo se les consulta DNS y el registro público: **nunca se visita su sitio web**;
  3. el informe nunca acusa: pide verificar si el dominio es del dueño o de alguien conocido antes de alertar a sus clientes.
- Los ejemplos publicados usan dominios seudonimizados, y las estadísticas se publican solo en agregado.

## Herramientas

| Herramienta | Qué revisa | Fuente pública | Si falla |
|---|---|---|---|
| `dns_correo` | MX y proveedor, SPF (conteo recursivo, RFC 7208), DMARC (RFC 9989) | DNS | error con nombre (`dominio_no_existe`, `tiempo_agotado`…) |
| `tls_certificado` | validez del certificado, vencimiento, versión de TLS | saludo TLS al puerto 443 | `sin_https`, `sin_direccion_web`… |
| `dkim_selector` | si hay firma DKIM y el tamaño de la clave, en los selectores que elige Grok | DNS (`<selector>._domainkey`) | selector sin respuesta: se declara aparte |
| `whois_dominio` | vencimiento y bloqueo de transferencia del dominio | WHOIS de `.co` (puerto 43) o RDAP de `.com`, `.net` y `.org` | caché de 24 h; pausa entre consultas; `registro_no_responde` |
| `buscar_parecidos` | variantes que existen y tienen correo; si comparten servidores con el dueño | DNS | una variante que no responde queda "sin verificar" |
| `investigar_parecido` | fecha de registro y si el SPF autoriza envío (cupo de 4) | WHOIS/RDAP y DNS | sin fecha: aviso y sigue con lo demás |
| `subdominios_ct` | subdominios con certificado | crt.sh, con Cert Spotter de respaldo | reintento y respaldo automáticos |
| `cabeceras_web` | redirección a HTTPS, HSTS, protección contra marcos, `nosniff`, versión del servidor | un GET a la portada | redirección fuera del dominio: se reporta, no se sigue |
| `security_txt` | contacto para avisar fallas de seguridad (RFC 9116) | un GET a `/.well-known/security.txt` | si no se puede verificar, no hay hallazgo |

Ninguna herramienta lanza excepciones: todo fallo vuelve como resultado con un código y una sugerencia para Grok, y termina en la sección *«Lo que no se pudo verificar»* del informe.

## Arquitectura

```
auditor/
  config.py      modelos, precios, topes por auditoría y rutas
  modelos.py     contrato de datos (Pydantic): resultado de herramienta, hallazgo, informe
  bitacora.py    bitácora JSONL de esquema fijo; enmascara cualquier llave
  llm.py         cliente de Grok: costo real por llamada, caché por conversación,
                 reintentos con backoff y errores con nombre
  tools/
    base.py        guardas: normalización del dominio, alcance (y su excepción), anti-SSRF
    correo.py      dns_correo
    web.py         tls_certificado
    dkim.py        dkim_selector
    registro.py    whois_dominio: WHOIS y RDAP con caché y pausa entre consultas
    parecidos.py   variantes generadas por código, buscar_parecidos, investigar_parecido
    ct.py          subdominios_ct: crt.sh con Cert Spotter de respaldo
    peticiones.py  HTTP seguro: IP validada, Host correcto, topes de tiempo y tamaño
    cabeceras.py   cabeceras_web, security_txt
  scoring.py     31 reglas deterministas → hallazgos y nivel de riesgo
  agent.py       bucle del agente con topes, cupos, revisiones obligatorias y validador del informe
  report.py      contenido del informe (uno solo) y su versión Markdown
  report_html.py el mismo informe en HTML imprimible (A4), sin recursos externos
  store.py       registro de auditorías y caché del registro de dominios en SQLite
  metricas.py    resumen de auditorías desde la bitácora
  __main__.py    CLI
scripts/
  probar_gateway.py     verificación medida de lo que soporta el gateway
  resumen_bitacora.py   pasos, costo y duración de las auditorías
tests/           536 pruebas sin red ni llave (Grok simulado con guiones)
```

**Decisiones de diseño:**
- **Bucle propio sobre la librería `openai`, sin framework:** los topes, el validador del informe y la bitácora son lógica propia en cualquier caso, y así cada parte es visible.
- **Cada auditoría tiene topes:** 20 pasos, USD 0,20 y 300 s. Si Grok repite la misma herramienta con los mismos argumentos, la auditoría se corta.
- **Siempre hay informe:** si la auditoría se corta por un tope o un error, el código arma un informe de respaldo con los hallazgos verificados.
- **El nivel de riesgo lo calcula el código**, no Grok: alto si hay algún hallazgo crítico o alto; medio si lo más grave es de severidad media (por ejemplo, un dominio parecido registrado hace poco o un sitio que no redirige a HTTPS); bajo en otro caso. Se calcula con lo que se revisa en toda auditoría: el correo, el registro del dominio, los dominios parecidos y el sitio del dominio y `www`. Los hallazgos de subdominios siguen en el informe con su severidad, y una línea junto al nivel los cuenta, pero no lo mueven: cuáles se revisan lo elige Grok, y el mismo dominio daría niveles distintos. Si la auditoría se corta, el nivel sale como **provisional**.
- **Un solo contenido, dos formatos:** el informe se arma una vez y se dibuja en Markdown y en HTML, así que nunca dicen cosas distintas. El HTML escapa todo el texto, incluido el que escribe Grok.
- **Identidad de cada ejecución: lote > auditoría > intento.** Una corrida masiva puede reanudarse tras una caída sin contar dos veces la misma auditoría.

## Resultados: 10 ejecuciones reales (hito S2)

Diez dominios reales con perfiles distintos (seudonimizados), con el código final y grok-4.7, uno por uno con la CLI:

| Perfil | Dominio | Riesgo | Pasos | Costo (USD) | Duración |
|---|---|---|---|---|---|
| Pyme `.com.co` con Google Workspace | `pyme-b.com.co` | ALTO | 5 | 0,056 | 69 s |
| Microsoft 365, dominio `.net` | `pyme-g.net` | ALTO | 4 | 0,082 | 66 s |
| Dominio `.com` (registro por RDAP) | `tienda-h.com` | ALTO | 4 | 0,093 | 89 s |
| Marca grande `.com.co` | `pyme-a.com.co` | ALTO | 3 | 0,050 | 105 s |
| Cientos de subdominios con certificado | `banco-i.com` | ALTO | 3 | 0,097 | 64 s |
| Correo bien configurado (DMARC `reject`) | `empresa-d.com.co` | BAJO | 4 | 0,100 | 122 s |
| Sin sitio web en el dominio raíz | `pyme-e.com.co` | ALTO | 4 | 0,106 | 107 s |
| Dominio inexistente | — | (no existe) | 2 | 0,022 | 27 s |
| Pyme sin correo configurado | `pyme-j.com` | ALTO | 3 | 0,046 | 53 s |
| Dominio `.co` | `empresa-k.co` | ALTO | 3 | 0,096 | 61 s |

**Las 10 cerraron con el informe entregado por Grok y ninguna con informe de respaldo.** Costo total USD 0,75; por auditoría: mediana USD 0,088 y máximo USD 0,106 (el tope es 0,20). Pasos: de 2 a 5. Duración: mediana de 68 s. Hallazgos frecuentes: claves DKIM de 1024 bits, sitios o subdominios sin HSTS, dominios sin bloqueo de transferencia y dominios parecidos con correo configurado. En `empresa-d.com.co` el nivel es BAJO porque su correo, su dominio y su sitio principal están bien configurados; los hallazgos de sus subdominios aparecen en el informe y en la línea que acompaña al nivel.

## Costo medido en el hito S1

Sobre **26 auditorías reales** por la CLI (15 dominios distintos), con grok-4.7 y las 2 herramientas del S1, todas cerradas con el informe entregado por Grok y ninguna con informe de respaldo:

| | Mínimo | Mediana | Máximo |
|---|---|---|---|
| Costo por auditoría | USD 0,007 | **USD 0,016** | USD 0,045 |
| Pasos de Grok | 2 | 2 | 4 |
| Duración | 7 s | 26 s | 108 s |

El costo de cada llamada es el que reporta el propio gateway, y coincide con el que calculamos con los precios publicados. Todo queda en la bitácora.

## Instalación y uso

**Windows (PowerShell):**

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env    # luego escribe tu llave del reto en RETO_KEY
venv\Scripts\python.exe -m pytest -q                      # 536 pruebas, sin red ni llave
venv\Scripts\python.exe -m auditor auditar ejemplo.com.co --verbose
```

**macOS y Linux:**

```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt
cp .env.example .env      # luego escribe tu llave del reto en RETO_KEY
venv/bin/python -m pytest -q
venv/bin/python -m auditor auditar ejemplo.com.co --verbose
```

Opciones: `--objetivo "texto libre"` (por ejemplo, *"¿Es seguro el sitio de pagos de mi tienda?"*), `--modelo` (uno de los permitidos por el reto; por defecto grok-4.7) y `--verbose` (muestra en vivo cada decisión de Grok con su justificación y su costo).

- **Informe:** `salidas/<dominio>-<fecha>.md` y, al lado, la versión imprimible `.html`. **Bitácora:** `logs/bitacora-<fecha>.jsonl`. **Registro:** `cache/auditor.db`.
- `scripts/resumen_bitacora.py --desde <instante ISO>` resume pasos, costo y duración de las auditorías.
- **Códigos de salida:** 0 bien, 1 dominio inválido, 2 falta configuración (llave o modelo).
- `scripts\probar_gateway.py` repite la verificación del gateway (~USD 0,05).

La llave **nunca** va al repositorio: `.env` está en `.gitignore`, y la bitácora enmascara cualquier texto con forma de llave.

## Licencia

[MIT](LICENSE).
