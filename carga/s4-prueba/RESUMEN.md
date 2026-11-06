# Resumen de la corrida `s4-prueba`

Generado por `python -m carga.resumen` desde `tareas.jsonl`, `eventos.jsonl` y la bitácora de Grok.

## Unidades de trabajo

| | |
|---|---|
| Tareas intentadas | 3 |
| **Completadas** | **3** |
| Fallidas (3 intentos sin éxito) | 0 |
| **Tasa de éxito** | **100.0 % (3/3)** |
| Dominios que no existen (completadas: el agente lo confirmó) | 1 |
| Completadas con informe de respaldo | 0 (—) |
| Completadas tras reintentar | 0 |

## Duración

| | |
|---|---|
| Primera tarea → última (UTC) | 2026-11-06T02:27+00:00 → 2026-11-06T02:28+00:00 |
| Horas | **0.0** |
| Arranques del corredor | 1 (más de 1 = relanzado por `lanzar.ps1` o reanudado) |
| Duración por tarea (mediana) | 45 s |

## Costo

| | |
|---|---|
| **Costo total** | **USD 0.0593** |
| **Costo por tarea completada** (total / completadas) | **USD 0.0198** |
| Por tarea: promedio · mediana · p90 · máximo | USD 0.0198 · USD 0.0191 · USD 0.0229 · USD 0.0229 |
| Pasos de Grok por tarea (mediana) | 3 |
| Gasto del lote en la bitácora de Grok | USD 0.0593 (incluye intentos cortados por una caída, que no dejan línea de tarea) |

## Tokens

Entrada 42,961 (en caché 19,840, 46 %) · salida 1,864 · razonamiento 8,706.

## Errores y recuperación

| Error | Tareas |
|---|---|
| `security_txt:tiempo_agotado` | 1 |
| `buscar_parecidos:dominio_no_existe` | 1 |
| `cabeceras_web:dominio_no_existe` | 1 |
| `dns_correo:dominio_no_existe` | 1 |
| `security_txt:dominio_no_existe` | 1 |
| `tls_certificado:dominio_no_existe` | 1 |

| Evento de la corrida | Veces |
|---|---|
| `fin_corrida` | 1 |
| `inicio_corrida` | 1 |

> Los errores de herramientas (`tls_certificado:sin_https`, `subdominios_ct:ct_no_responde`…) no son fallos de la tarea: el agente los declara como limitación y sigue. `gateway` cuenta las llamadas a Grok que fallaron después de los reintentos del cliente.

## Prevalencia agregada (dominios que existen, n=2)

Sobre dominios `.com.co` de la lista Tranco, no sobre "pymes". No se publica el resultado de ninguna empresa concreta.

| Nivel de riesgo | Dominios |
|---|---|
| bajo | 50.0 % (1/2) |
| alto | 50.0 % (1/2) |

| Hallazgo más frecuente | Dominios |
|---|---|
| `WEB-SIN-HSTS` | 100.0 % (2/2) |
| `WEB-SIN-SECURITY-TXT` | 100.0 % (2/2) |
| `DOMINIO-SIN-BLOQUEO` | 50.0 % (1/2) |
| `CORREO-DMARC-AUSENTE` | 50.0 % (1/2) |
| `CORREO-SIN-MX` | 50.0 % (1/2) |
| `CORREO-SPF-AUSENTE` | 50.0 % (1/2) |
| `WEB-SIN-NOSNIFF` | 50.0 % (1/2) |
| `WEB-SIN-PROTECCION-MARCOS` | 50.0 % (1/2) |
