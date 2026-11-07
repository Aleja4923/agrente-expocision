# Resumen de la corrida `s4-prueba`

Generado por `python -m carga.resumen` desde `tareas.jsonl`, `eventos.jsonl` y la bitácora de Grok.

## Unidades de trabajo

| | |
|---|---|
| Tareas intentadas | 20 |
| **Completadas** | **20** |
| Fallidas (3 intentos sin éxito) | 0 |
| **Tasa de éxito** | **100.0 % (20/20)** |
| Dominios que no existen (completadas: el agente lo confirmó) | 1 |
| Completadas con informe de respaldo | 0 (—) |
| Completadas tras reintentar | 0 |

## Duración

| | |
|---|---|
| Primera tarea → última (UTC) | 2026-11-06T02:27+00:00 → 2026-11-06T14:22+00:00 |
| Horas | **11.9** |
| Arranques del corredor | 2 (más de 1 = relanzado por `lanzar.ps1` o reanudado) |
| **Pasada más larga sin intervención** | **0.2 h** |
| Duración por tarea (mediana) | 89 s |

| Pasada | Inicio (UTC) | Fin (UTC) | Horas | Cómo terminó |
|---|---|---|---|---|
| 1 | 2026-11-06T02:27:28+00:00 | 2026-11-06T02:28:47+00:00 | 0.0 | fin de la pasada |
| 2 | 2026-11-06T14:09:19+00:00 | 2026-11-06T14:22:06+00:00 | 0.2 | fin de la pasada |

## Costo

| | |
|---|---|
| **Costo total** | **USD 0.5202** |
| **Costo por tarea completada** (total / completadas) | **USD 0.0260** |
| Por tarea: promedio · mediana · p90 · máximo | USD 0.0260 · USD 0.0219 · USD 0.0402 · USD 0.0483 |
| Pasos de Grok por tarea (mediana) | 3.0 |
| Gasto del lote en la bitácora de Grok | USD 0.5202 (incluye intentos cortados por una caída, que no dejan línea de tarea) |

## Tokens

Entrada 425,687 (en caché 233,984, 55 %) · salida 18,393 · razonamiento 75,131.

## Errores y recuperación

| Error | Tareas |
|---|---|
| `cabeceras_web:dominio_no_existe` | 2 |
| `security_txt:dominio_no_existe` | 2 |
| `tls_certificado:dominio_no_existe` | 2 |
| `security_txt:tiempo_agotado` | 1 |
| `buscar_parecidos:dominio_no_existe` | 1 |
| `dns_correo:dominio_no_existe` | 1 |
| `buscar_parecidos:sin_respuesta` | 1 |
| `dns_correo:sin_respuesta` | 1 |
| `tls_certificado:tiempo_agotado` | 1 |
| `subdominios_ct:limite_de_consultas` | 1 |

| Evento de la corrida | Veces |
|---|---|
| `fin_corrida` | 2 |
| `inicio_corrida` | 2 |

> Los errores de herramientas (`subdominios_ct:limite_de_consultas`, `cabeceras_web:tiempo_agotado`…) no son fallos de la tarea: el agente los declara como limitación y sigue. `no_verificable` agrupa los códigos que dirían algo de la seguridad de la empresa (por ejemplo, que su sitio no acepta HTTPS); el código exacto queda en el archivo privado. `gateway` cuenta las llamadas a Grok que fallaron después de los reintentos del cliente.

## Prevalencia agregada (dominios que existen, n=19)

Sobre dominios `.com.co` de la lista Tranco, no sobre "pymes". No se publica el resultado de ninguna empresa concreta.

| Nivel de riesgo (n=18, sin los provisionales) | Dominios |
|---|---|
| alto | 88.9 % (16/18) |
| bajo | 5.6 % (1/18) |
| medio | 5.6 % (1/18) |

Con nivel **provisional** (no entran en la tabla de niveles): **1** dominios. Son los que cerraron con informe de respaldo o en los que falló una revisión principal (por ejemplo, la consulta DNS del correo no respondió a tiempo): su nivel se calculó sin esa revisión.

| Hallazgo más frecuente (n=19) | Dominios |
|---|---|
| `WEB-SIN-HSTS` | 84.2 % (16/19) |
| `WEB-SIN-SECURITY-TXT` | 63.2 % (12/19) |
| `CORREO-DMARC-AUSENTE` | 63.2 % (12/19) |
| `CORREO-SPF-AUSENTE` | 57.9 % (11/19) |
| `CORREO-SIN-MX` | 52.6 % (10/19) |
| `PARECIDO-MX` | 47.4 % (9/19) |
| `WEB-SIN-NOSNIFF` | 42.1 % (8/19) |
| `WEB-SIN-PROTECCION-MARCOS` | 42.1 % (8/19) |
| `CORREO-DMARC-NONE` | 15.8 % (3/19) |
| `CORREO-SPF-SUAVE` | 15.8 % (3/19) |
| `PARECIDO-ENVIA` | 15.8 % (3/19) |
| `CORREO-DKIM-NO-ENCONTRADO` | 15.8 % (3/19) |
| `DOMINIO-SIN-BLOQUEO` | 10.5 % (2/19) |
| `CORREO-DMARC-SIN-REPORTES` | 10.5 % (2/19) |
| `WEB-VERSION-EXPUESTA` | 10.5 % (2/19) |
