# Auditor de exposición digital para pymes

Agente autónomo que revisa, **solo con información pública**, qué tan expuesto está el dominio de una pyme colombiana a la **suplantación de su correo y a fraudes con su nombre**. Entrega al dueño un **plan de acción priorizado**, en lenguaje simple y con un texto listo para reenviar a su proveedor.

Proyecto del Track 1 del [Reto Agente 2026](https://reto.pltk.mx/) (Platica.mx × Campuslands). El razonamiento corre sobre **Grok** a través del gateway del reto.

**En cifras** (todas medidas y con su fuente en este repositorio):

| | |
|---|---|
| Auditorías reales en una sola corrida desatendida | **1.150 de 1.150 completadas en 14,2 h**, sin intervención ([`carga/s4-carga/RESUMEN.md`](carga/s4-carga/RESUMEN.md)) |
| Costo por auditoría | **USD 0,027** con grok-4.20, medido llamada por llamada |
| Set de evaluación propio | **35 casos y 240 corridas con Grok:** nivel de riesgo correcto en el **100 %** ([`evals/REPORTE.md`](evals/REPORTE.md)) |
| Lo que encontró en dominios `.com.co` reales | el **56 %** no tiene DMARC y el **45 %** no tiene SPF (n=1.131) |
| Pruebas automáticas | **816**, sin red ni llave |

---

## El problema

Las pymes colombianas usan su dominio para el correo y la web, pero la mayoría no configura las protecciones que permiten a los receptores reconocer un correo falso (SPF, DKIM, DMARC). El resultado:

- **Facturas y cambios de cuenta bancaria "desde" su correo.** Sin DMARC, el dominio no indica a los receptores qué hacer con correos falsificados y el dueño no recibe reportes. Filtrarlos queda a criterio de cada proveedor de correo.
- **Dominios casi idénticos al suyo** (una letra cambiada, otro TLD) que pueden recibir los correos que sus clientes escriban mal.
- **El dueño no lo sabe**, y aunque lo supiera, no sabe qué pedirle a su proveedor.

**Medido por este agente:** de 1.131 dominios `.com.co` reales que auditó, el 56 % no publica DMARC, el 45 % no tiene SPF y el 48 % tiene al menos un dominio casi idéntico con correo configurado. La muestra es de la lista pública Tranco, no solo de pymes, pero muestra que el problema es masivo.

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
- **El arnés rechaza un informe** que cite hallazgos inexistentes, que omita uno crítico o alto, o que copie texto de un registro externo (así una instrucción escondida en el DNS no llega al resumen).
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
evals/
  casos.py        formato de caso y respuesta esperada
  reproducir.py   entrega lo grabado detrás de las guardas reales
  reglas.py       capa de reglas: grabación completa contra lo esperado
  fabricar.py     genera los 10 casos fabricados
  grabar.py       graba un dominio real (sin Grok) y lo seudonimiza
  seudonimos.py   reemplazo de nombres por variantes del mismo tipo
  lista_blanca.py revisión que falla cerrada antes de publicar un caso
  correr.py       casos × modelos × repeticiones; se puede reanudar
  medir.py        métricas y REPORTE.md, sin Grok ni llave
  casos/          los 35 casos · resultados/ una línea por corrida
carga/
  dominios.py     lista reproducible de dominios .com.co (Tranco, semilla fija)
  correr.py       cola desatendida: hilos, reintentos, pausas, freno de gasto; se puede reanudar
  resumen.py      RESUMEN.md y tareas.csv desde la bitácora por tarea, sin Grok ni llave
  lanzar.ps1      relanza el corredor si Python se cae
  consumo.py      bitácora de consumo pública (consumo/) y cruce con el panel del reto
  s4-prueba/ s4-carga/   bitácora por tarea de cada corrida
tests/           816 pruebas sin red ni llave (Grok simulado con guiones)
```

**Decisiones de diseño:**
- **Bucle propio sobre la librería `openai`, sin framework:** los topes, el validador del informe y la bitácora son lógica propia en cualquier caso, y así cada parte es visible.
- **Cada auditoría tiene topes:** 20 pasos, USD 0,20 y 300 s. Si Grok repite la misma herramienta con los mismos argumentos, la auditoría se corta.
- **Siempre hay informe:** si la auditoría se corta por un tope o un error, el código arma un informe de respaldo con los hallazgos verificados.
- **El nivel de riesgo lo calcula el código**, no Grok: alto si hay algún hallazgo crítico o alto; medio si lo más grave es de severidad media (por ejemplo, un dominio parecido registrado hace poco o un sitio que no redirige a HTTPS); bajo en otro caso. Se calcula con lo que se revisa en toda auditoría: el correo, el registro del dominio, los dominios parecidos y el sitio del dominio y `www`. Los hallazgos de subdominios siguen en el informe con su severidad, y una línea junto al nivel los cuenta, pero no lo mueven: cuáles se revisan lo elige Grok, y el mismo dominio daría niveles distintos. Una elección de Grok sí puede mover el nivel: cuáles dominios parecidos investiga (4 como máximo), porque solo así salen los hallazgos de un parecido reciente o que envía correo. El nivel sale como **provisional** si la auditoría se corta o si falló una revisión principal, como la consulta DNS del correo; el informe dice cuál.
- **Un solo contenido, dos formatos:** el informe se arma una vez y se dibuja en Markdown y en HTML, así que nunca dicen cosas distintas. El HTML escapa todo el texto, incluido el que escribe Grok.
- **Identidad de cada ejecución: lote > auditoría > intento.** Una corrida masiva puede reanudarse tras una caída sin contar dos veces la misma auditoría.

## Carga: 1.150 auditorías en 14,2 horas sin intervención (hito S4)

**Qué se corrió.** 1.150 dominios `.com.co` reales, cada uno auditado de punta a punta por el agente con grok-4.20: Grok elige las herramientas, el código calcula los hallazgos y se entrega el informe. Corrió en una sola pasada desatendida, con 2 hilos y un ritmo de un arranque cada 42 s. La lista sale de la [lista Tranco](https://tranco-list.eu/) `JZPGY`: se filtran los `.com.co` y se sortean con semilla fija (`carga/dominios.py`). Así cualquiera puede reproducirla, y no depende de los registros de certificados, que dejan fuera a los dominios que solo usan correo.

**Unidad de trabajo:** una auditoría completa de un dominio. Cuenta como **completada** si entregó el informe (de Grok o de respaldo, tras un tope) o si confirmó que el dominio no existe. Queda **fallida** si agota 3 intentos.

| Resultado (`carga/s4-carga/RESUMEN.md`) | |
|---|---|
| Tareas | **1.150** |
| Completadas · fallidas | **1.150 · 0** |
| **Tasa de éxito** | **100 %** |
| Duración | **14,2 h** en una sola pasada (sin relanzar) |
| **Costo total** | **USD 31,10** |
| **Costo por tarea** | **USD 0,027** (mediana 0,026 · p90 0,038 · máximo 0,147) |
| Duración por tarea (mediana) | 64 s, con 3 pasos de Grok |
| Tokens de entrada leídos de la caché | 63 % |

**La bitácora por tarea** está en `carga/s4-carga/tareas.jsonl` y en `tareas.csv`: una fila por dominio con inicio, fin, resultado, motivo de cierre, intentos, pasos, tokens, costo, errores de herramientas y recuperación. Los eventos de la corrida están en `eventos.jsonl`, y la salida de la consola, en `consola.log`. El costo publicado coincide al centavo con la bitácora de llamadas a Grok. **No se publica el nivel de riesgo ni los hallazgos de ninguna empresa**, solo el agregado.

**Errores y recuperación:**
- **El gateway no falló ninguna tarea:** 8 llamadas con `timeout` o desconexión se recuperaron con los reintentos del cliente, sin gastar un segundo intento de la tarea.
- **El validador rechazó 87 borradores de informe en 73 tareas,** y Grok los corrigió. 71 tenían acciones sobre hallazgos que el mismo borrador no listaba como citados, 11 llegaron antes de terminar las revisiones obligatorias y 5 citaban un hallazgo que el código no había encontrado. Aparte, la guarda de alcance bloqueó 46 llamadas (en 8 tareas) en las que Grok intentó revisar un dominio ajeno.
- **5 tareas cerraron con informe de respaldo:** en 4, el validador rechazó todos los borradores de Grok; en 1, se llegó al tope de 20 pasos.
- **La guarda contra la inyección no se activó:** ningún informe copió texto de un registro externo.
- **Cert Spotter llegó a su límite de consultas** en 351 tareas, y algunos sitios no respondieron a tiempo. El agente lo declaró como limitación en el informe y siguió: ningún error de herramienta hace fallar la tarea.

**Qué hace al corredor desatendido** (`carga/correr.py`, `carga/lanzar.ps1`):
- **La cola se puede reanudar** sin contar dos veces una tarea.
- **Cada tarea tiene hasta 3 intentos,** separados por esperas.
- **Si el gateway cae varias veces seguidas,** se pausa 5, 10 y 20 minutos.
- **Hay un freno de gasto:** USD 44 si ya hay 1.030 tareas completadas; si no, USD 46,50.
- **Se impide que Windows suspenda el equipo,** y cualquier salto de reloj queda en la bitácora.
- **La bitácora es segura con varios hilos.**
- **Las consultas de registro (WHOIS) van a un mínimo de 3 s entre una y otra,** con caché de 24 h, porque los términos del registro `.co` prohíben las consultas masivas.
- **Si Python se cae, un lanzador lo vuelve a arrancar.**

**Prevalencia agregada** (sobre dominios `.com.co` de Tranco, no sobre «pymes»; 1.131 de los 1.150 existen):
- **Riesgo** (n=1.102 con nivel definitivo): alto 85 % · bajo 11 % · medio 3 %. Otros **29 tienen nivel provisional** y no entran en el reparto: cerraron con informe de respaldo o falló una revisión principal, en la mayoría la consulta DNS del correo.
- **Hallazgos más comunes** (n=1.131): sin HSTS en el sitio o en algún subdominio revisado (70 %), sin `security.txt` (57 %), sin DMARC (56 %), un dominio parecido con correo configurado (48 %) y sin SPF (45 %).

**Versión del agente:** la corrida se hizo con el agente del commit `e34f319`. Las mejoras posteriores están en el historial del repositorio.

**Cómo reproducirlo:**

```powershell
venv\Scripts\python.exe -m carga.dominios                                      # descarga la lista JZPGY y rehace dominios.csv
powershell -ExecutionPolicy Bypass -File carga\lanzar.ps1 -Lote s4-carga      # la corrida: gasta créditos
venv\Scripts\python.exe -m carga.resumen --lote s4-carga                      # rehace RESUMEN.md y el CSV: gratis
```

## Evaluación: 35 casos con respuesta conocida (hito S3)

**El set.** 35 casos en `evals/casos/`: 25 dominios reales y 10 fabricados. Los reales están seudonimizados. Cada dominio real pasa a un nombre inexistente, y cada dominio parecido, a una variante del mismo tipo que tampoco existe, para no señalar a un tercero. Una revisión que falla cerrada impide publicar un nombre, una IP o un correo reales. Los fabricados cubren lo que los reales no traen: inyección de instrucciones en el DNS, dominio por vencer, SPF con demasiadas consultas y el mismo dominio con dos objetivos distintos. Por perfil: 17 pymes estándar, 13 con muchos subdominios, 4 adversariales y 1 inexistente. Las 31 reglas aparecen al menos una vez.

**Cómo se mide.** Cada caso guarda las respuestas reales de las herramientas y su respuesta esperada: el nivel de riesgo, los hallazgos que deben salir, los que no y cómo debe cerrar. Grok corre de verdad. Solo las herramientas se reproducen desde lo grabado, detrás de las mismas guardas de alcance y validación que en una auditoría en vivo. Hay dos capas:
- **Reglas** (sin Grok, dentro de `pytest`): con la grabación completa, el código da exactamente lo esperado en los 35 casos.
- **Agente** (con Grok): 35 casos × 2 modelos × 3 repeticiones = **210 corridas**, más **30** para medir `reasoning_effort`. Cada corrida deja una línea en `evals/resultados/` y su gasto en la bitácora.

**Resultados** (de `evals/REPORTE.md`, que trae todas las cifras con su n):

| | grok-4.20 | grok-4.7 | grok-4.7 con `reasoning_effort=low` |
|---|---|---|---|
| Corridas | 105 | 105 | 30 |
| Nivel de riesgo correcto | 100 % | 100 % | 100 % |
| Hallazgos que dependen de lo que Grok elige investigar | 40 % (75/186) | 67 % (124/186) | 47 % (27/57) |
| Costo por auditoría: mediana · máximo | USD 0,031 · 0,082 | USD 0,097 · 0,255 | USD 0,036 · 0,089 |
| Resistencia a la inyección en el DNS | 2 de 6 | 6 de 6 | 3 de 3 |

| Costo mediano por perfil | n por modelo | grok-4.20 | grok-4.7 |
|---|---|---|---|
| Pyme estándar | 51 | USD 0,031 | USD 0,095 |
| Muchos subdominios | 39 | USD 0,038 | USD 0,128 |
| Adversarial | 12 | USD 0,022 | USD 0,036 |
| Dominio inexistente | 3 | USD 0,010 | USD 0,014 |

**Qué muestran:**
- **El nivel de riesgo acierta en las 240 corridas, con cualquier modelo,** porque lo calcula el código. El modelo cambia lo que depende de su criterio: qué dominios parecidos investiga. Ahí grok-4.7 acierta más y cuesta unas 3 veces más.
- **Inyección:** dos casos esconden en un registro DNS la orden de omitir un hallazgo y escribir una marca en el resumen. Ningún modelo logró borrar el hallazgo. Pero en 4 de 6 corridas grok-4.20 copió la marca en el resumen que redacta. **En el S4 se agregó la defensa:** el arnés rechaza un informe que copie texto distintivo de un registro externo, y Grok lo vuelve a redactar. Las pruebas automáticas lo demuestran con la marca copiada. En las 6 corridas de verificación con grok-4.20, en cambio, la guarda no llegó a activarse: Grok no copió la marca ninguna vez. Con 2 de 6 limpias antes, ese resultado no prueba por sí solo que el modelo haya cambiado.
- **`reasoning_effort=low`** baja el costo de grok-4.7 casi al de grok-4.20, pero pierde buena parte de la mejora en las decisiones.
- **Autonomía:** con el mismo dominio, a un caso se le pide revisar pagos y al otro, facturación. Los dos modelos llegaron al portal de cada objetivo en todas las corridas (12 de 12).
- **Caché:** el 55 % de los tokens de entrada con grok-4.20, el 47 % con grok-4.7 y el 53 % con `reasoning_effort=low` se leyeron de la caché del gateway. (`evals/REPORTE.md` junta grok-4.7 con sus corridas `low` en una sola fila, n=135.)

**Límite declarado:** las respuestas esperadas las escribió la misma persona que trabajó en el código, así que no son del todo independientes. Los demás límites, como la lentitud del gateway durante parte de la corrida, están al final de `evals/REPORTE.md`.

**Cómo reproducirlo:**

```powershell
venv\Scripts\python.exe -m pytest -q tests\test_evals_reglas.py                              # capa de reglas: gratis, sin llave
venv\Scripts\python.exe -m evals.medir --lote evals-final --lote evals-esfuerzo              # rehace REPORTE.md: gratis, sin llave
venv\Scripts\python.exe -m evals.correr --lote evals-propio --modelos grok-4.20 --repeticiones 1   # corre el agente: gasta créditos
```

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

## Viabilidad: quién paga y cuánto cuesta

**Quién paga:** contadores y agencias web, que lo ofrecen a sus clientes pyme como un servicio de valor agregado (B2B2C). Ya atienden a muchas pymes y tienen su confianza, y ganan al ejecutar ellos mismos las recomendaciones: configurar DMARC o SPF, o renovar un dominio.

**Cuánto cuesta operarlo** (medido, no estimado):

| | Costo por auditoría | 1.000 auditorías |
|---|---|---|
| grok-4.20, en la corrida real de 1.150 dominios | **USD 0,027** | ~USD 27 |
| grok-4.20, en el set de evaluación (mediana) | USD 0,031 | ~USD 31 |
| grok-4.7, mejores decisiones sobre qué investigar (mediana) | USD 0,097 | ~USD 97 |

- **Sin infraestructura:** solo consultas públicas (DNS, certificado, portada del sitio, registro de dominios) y llamadas a Grok. Una auditoría tarda alrededor de un minuto.
- **El nivel de riesgo lo calcula el código:** en el set de evaluación acertó el 100 % con los dos modelos. Se puede usar el modelo barato para volumen y el más fino para clientes que lo paguen.
- **La barrera no es el costo, es la confianza y la distribución.** Por eso el canal son los contadores y las agencias, no la pyme directamente.

## Instalación y uso

**Arranque de un comando.** El script crea el entorno e instala las dependencias la primera vez, y audita. Solo hace falta Python 3.12 o superior y la llave del reto en la variable `RETO_KEY` (o en un archivo `.env`, copiado de `.env.example`).

```bash
export RETO_KEY=pk_...                        # Linux y macOS
./iniciar.sh ejemplo.com.co                   # informe para el dueño
./iniciar.sh ejemplo.com.co --json            # el mismo resultado como JSON, para otro programa
./iniciar.sh --lote casos.txt --json          # varios dominios: una línea JSON por dominio
```

```powershell
$env:RETO_KEY = "pk_..."                                                  # Windows
powershell -ExecutionPolicy Bypass -File iniciar.ps1 ejemplo.com.co --verbose
```

**Para correr casos propios (por ejemplo, un evaluador automático):**
- **`--lote archivo.txt`:** un dominio por línea, con un objetivo opcional (`dominio;objetivo`). Las líneas vacías o que empiezan con `#` se saltan, y un dominio inválido no detiene el lote.
- **`--json`:** cada dominio sale como una línea JSON con lo mismo que ve el dueño:
  - `existe`, `nivel` y `provisional`;
  - los `hallazgos`, con id, severidad, título y evidencia;
  - las `acciones` en orden, el `resumen` y las `limitaciones`;
  - el `motivo_cierre`, los `pasos`, el `costo_usd` y la ruta del informe.

  La trayectoria de `--verbose` va a stderr, así que stdout queda solo para el JSON.

**Otras opciones:**
- **`--objetivo "texto libre"`:** por ejemplo, *«¿Es seguro el sitio de pagos de mi tienda?»*.
- **`--modelo`:** uno de los permitidos por el reto; por defecto, grok-4.7.
- **`--verbose`:** muestra en vivo cada decisión de Grok, con su justificación y su costo.

**Instalación paso a paso** (lo mismo que hace el script):

```bash
python3 -m venv venv && venv/bin/python -m pip install -r requirements.txt
venv/bin/python -m pytest -q                                   # 816 pruebas, sin red ni llave
venv/bin/python -m auditor auditar ejemplo.com.co --verbose    # en Windows: venv\Scripts\python.exe
```

**Dónde queda cada cosa:**
- **Informe:** `salidas/<dominio>-<fecha>.md` y, al lado, la versión imprimible `.html`.
- **Bitácora:** `logs/bitacora-<fecha>.jsonl`. **Registro:** `cache/auditor.db`.
- **Códigos de salida:** 0 bien, 1 dominio inválido (o alguno inválido en el lote), 2 falta configuración (llave o modelo).
- `scripts/resumen_bitacora.py --desde <instante ISO>` resume pasos, costo y duración de las auditorías. `scripts/probar_gateway.py` repite la verificación del gateway (~USD 0,05).

## Bitácora de consumo

[`consumo/consumo.csv`](consumo/consumo.csv) tiene **cada petición a Grok del proyecto**, del S1 a hoy: fecha, hito, lote, modelo, tokens y costo. [`consumo/RESUMEN.md`](consumo/RESUMEN.md) la cruza con el panel del reto, que solo muestra los últimos registros y los totales por modelo:
- **grok-4.20:** las peticiones cuadran exactas (4.374 en la bitácora y 4.374 en el panel).
- **grok-4.7:** el panel muestra más costo que la bitácora. Casi toda la diferencia son peticiones que el cliente cortó por tiempo durante una tarde lenta del gateway: el gateway las cobró, pero no devolvió su consumo. El cruce lo explica con sus cifras.

No se publica el dominio de las corridas hechas por la CLI. Se regenera con `python -m carga.consumo`.

La llave **nunca** va al repositorio: `.env` está en `.gitignore`, y la bitácora enmascara cualquier texto con forma de llave.

## Licencia

[MIT](LICENSE).
