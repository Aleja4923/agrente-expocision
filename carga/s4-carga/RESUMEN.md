# Resumen de la corrida `s4-carga`

Generado por `python -m carga.resumen` desde `tareas.jsonl`, `eventos.jsonl` y la bitácora de Grok.

## Unidades de trabajo

| | |
|---|---|
| Tareas intentadas | 1150 |
| **Completadas** | **1150** |
| Fallidas (3 intentos sin éxito) | 0 |
| **Tasa de éxito** | **100.0 % (1150/1150)** |
| Dominios que no existen (completadas: el agente lo confirmó) | 19 |
| Completadas con informe de respaldo | 5 (rechazos_agotados: 4, tope_pasos: 1) |
| Completadas tras reintentar | 0 |

## Duración

| | |
|---|---|
| Primera tarea → última (UTC) | 2026-11-06T14:47+00:00 → 2026-11-07T04:57+00:00 |
| Horas | **14.2** |
| Arranques del corredor | 1 (más de 1 = relanzado por `lanzar.ps1` o reanudado) |
| **Pasada más larga sin intervención** | **14.2 h** |
| Duración por tarea (mediana) | 64 s |

| Pasada | Inicio (UTC) | Fin (UTC) | Horas | Cómo terminó |
|---|---|---|---|---|
| 1 | 2026-11-06T14:47:37+00:00 | 2026-11-07T04:57:43+00:00 | 14.2 | fin de la pasada |

## Costo

| | |
|---|---|
| **Costo total** | **USD 31.0952** |
| **Costo por tarea completada** (total / completadas) | **USD 0.0270** |
| Por tarea: promedio · mediana · p90 · máximo | USD 0.0270 · USD 0.0263 · USD 0.0375 · USD 0.1475 |
| Pasos de Grok por tarea (mediana) | 3.0 |
| Gasto del lote en la bitácora de Grok | USD 31.0952 (incluye intentos cortados por una caída, que no dejan línea de tarea) |

## Tokens

Entrada 28,856,251 (en caché 18,216,960, 63 %) · salida 1,123,911 · razonamiento 4,537,150.

## Errores y recuperación

| Error | Tareas |
|---|---|
| `subdominios_ct:limite_de_consultas` | 351 |
| `tls_certificado:dominio_no_existe` | 74 |
| `tls_certificado:sin_direccion_web` | 72 |
| `cabeceras_web:dominio_no_existe` | 72 |
| `security_txt:dominio_no_existe` | 68 |
| `investigar_parecido:tiempo_agotado` | 63 |
| `cabeceras_web:sin_direccion_web` | 54 |
| `tls_certificado:tiempo_agotado` | 53 |
| `security_txt:sin_direccion_web` | 53 |
| `cabeceras_web:tiempo_agotado` | 45 |
| `security_txt:tiempo_agotado` | 45 |
| `cabeceras_web:respuesta_invalida` | 36 |
| `security_txt:respuesta_invalida` | 33 |
| `tls_certificado:tls_fallido` | 25 |
| `tls_certificado:sin_https` | 19 |
| `buscar_parecidos:dominio_no_existe` | 19 |
| `dns_correo:dominio_no_existe` | 19 |
| `cabeceras_web:tls_fallido` | 17 |
| `buscar_parecidos:sin_respuesta` | 16 |
| `dns_correo:sin_respuesta` | 16 |
| `whois_dominio:registro_no_responde` | 15 |
| `security_txt:tls_fallido` | 14 |
| `cabeceras_web:sin_conexion` | 12 |
| `security_txt:sin_conexion` | 12 |
| `cabeceras_web:fuera_de_alcance` | 7 |
| `tls_certificado:fuera_de_alcance` | 7 |
| `buscar_parecidos:tiempo_agotado` | 7 |
| `dns_correo:tiempo_agotado` | 7 |
| `dns_correo:fuera_de_alcance` | 6 |
| `security_txt:fuera_de_alcance` | 4 |
| `whois_dominio:fuera_de_alcance` | 4 |
| `whois_dominio:no_registrado` | 4 |
| `tls_certificado:ip_bloqueada` | 4 |
| `cabeceras_web:ip_bloqueada` | 3 |
| `dkim_selector:sin_respuesta` | 2 |
| `security_txt:ip_bloqueada` | 2 |
| `dns_correo:dominio_invalido` | 1 |
| `investigar_parecido:sin_respuesta` | 1 |
| `buscar_parecidos:fuera_de_alcance` | 1 |
| `dkim_selector:fuera_de_alcance` | 1 |
| `investigar_parecido:fuera_de_alcance` | 1 |
| `subdominios_ct:fuera_de_alcance` | 1 |
| `dkim_selector:tiempo_agotado` | 1 |

| Evento de la corrida | Veces |
|---|---|
| `fin_corrida` | 1 |
| `inicio_corrida` | 1 |

> Los errores de herramientas (`tls_certificado:sin_https`, `subdominios_ct:ct_no_responde`…) no son fallos de la tarea: el agente los declara como limitación y sigue. `gateway` cuenta las llamadas a Grok que fallaron después de los reintentos del cliente.

## Prevalencia agregada (dominios que existen, n=1131)

Sobre dominios `.com.co` de la lista Tranco, no sobre "pymes". No se publica el resultado de ninguna empresa concreta.

| Nivel de riesgo | Dominios |
|---|---|
| alto | 83.8 % (948/1131) |
| bajo | 12.9 % (146/1131) |
| medio | 3.3 % (37/1131) |

| Hallazgo más frecuente | Dominios |
|---|---|
| `WEB-SIN-HSTS` | 69.8 % (789/1131) |
| `WEB-SIN-SECURITY-TXT` | 56.9 % (644/1131) |
| `CORREO-DMARC-AUSENTE` | 56.2 % (636/1131) |
| `PARECIDO-MX` | 48.4 % (547/1131) |
| `CORREO-SPF-AUSENTE` | 45.3 % (512/1131) |
| `CORREO-SIN-MX` | 43.4 % (491/1131) |
| `WEB-SIN-NOSNIFF` | 35.9 % (406/1131) |
| `WEB-SIN-PROTECCION-MARCOS` | 35.8 % (405/1131) |
| `CORREO-SPF-SUAVE` | 22.4 % (253/1131) |
| `CORREO-DMARC-NONE` | 20.1 % (227/1131) |
| `CORREO-DMARC-SIN-REPORTES` | 17.2 % (194/1131) |
| `WEB-VERSION-EXPUESTA` | 14.1 % (160/1131) |
| `DOMINIO-SIN-BLOQUEO` | 13.9 % (157/1131) |
| `CORREO-DMARC-OBSOLETO` | 13.9 % (157/1131) |
| `WEB-SIN-REDIRECCION-HTTPS` | 12.9 % (146/1131) |
