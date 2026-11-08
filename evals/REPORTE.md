# Reporte de evaluación

Corridas: n=240 · costo total USD 15.3050 (incluye intentos repetidos por el gateway).

## 1. Costo por tarea según perfil

| Perfil | Modelo | n | Mediana USD | Máx. USD | Total USD | Pasos (mediana) |
|---|---|---|---|---|---|---|
| adversarial | grok-4.20 | 12 | 0.0218 | 0.0307 | 0.2587 | 3.0 |
| adversarial | grok-4.7 | 12 | 0.0355 | 0.0466 | 0.4410 | 3.0 |
| inexistente | grok-4.20 | 3 | 0.0096 | 0.0130 | 0.0311 | 2.0 |
| inexistente | grok-4.7 | 3 | 0.0140 | 0.0193 | 0.0442 | 2.0 |
| pyme_estandar | grok-4.20 | 51 | 0.0310 | 0.0670 | 1.6537 | 4.0 |
| pyme_estandar | grok-4.7 | 51 | 0.0952 | 0.2411 | 5.2761 | 3.0 |
| superficie_grande | grok-4.20 | 39 | 0.0381 | 0.0823 | 1.4944 | 3.0 |
| superficie_grande | grok-4.7 | 39 | 0.1280 | 0.2546 | 4.8506 | 4.0 |

## 2. Comparación de modelos

| Grupo | n | Semáforo acierta | Hallazgos por decisión | Estables (3 rep.) | Incompletos | Pasos | Latencia Grok s | Mediana USD | Máx. USD |
|---|---|---|---|---|---|---|---|---|---|
| grok-4.20 | 105 | 100 % (105/105) | 40 % (75/186) | 83 % (29/35) | 0 | 3.0 | 59.8 | 0.0312 | 0.0823 |
| grok-4.7 | 105 | 100 % (105/105) | 67 % (124/186) | 74 % (26/35) | 0 | 3.0 | 108.3 | 0.0972 | 0.2546 |

## 3. `reasoning_effort` (grok-4.7)

| Grupo | n | Semáforo acierta | Hallazgos por decisión | Estables (3 rep.) | Incompletos | Pasos | Latencia Grok s | Mediana USD | Máx. USD |
|---|---|---|---|---|---|---|---|---|---|
| low | 30 | 100 % (30/30) | 47 % (27/57) | 70 % (7/10) | 0 | 3.0 | 22.4 | 0.0360 | 0.0889 |
| sin enviar | 30 | 100 % (30/30) | 68 % (39/57) | 80 % (8/10) | 0 | 3.0 | 72.7 | 0.0894 | 0.1969 |

> El semáforo lo calcula el código, no Grok; solo los dominios parecidos que Grok elige investigar lo hacen depender del modelo. Por eso la diferencia entre modelos se ve sobre todo en los hallazgos por decisión.

## 4. Caché de prompts

| Modelo | n | Tokens de entrada | En caché | Proporción | Ahorro estimado USD |
|---|---|---|---|---|---|
| grok-4.20 | 105 | 3045493 | 1687808 | 55 % | 1.7722 |
| grok-4.7 | 135 | 4734274 | 2279552 | 48 % | 3.4193 |

> Ahorro estimado: tokens en caché × (precio de entrada − precio de caché), frente a un escenario sin caché, con precios provisionales de `config.py`. grok-4.7 no reutiliza caché por debajo de unos 1.150 tokens (`NOTAS_GATEWAY`).

## 5. Seguridad y robustez

| Modelo | n | Entregas limpias | Con cupo agotado | Con repetición | Respaldos | Resistencia a inyección | Intentos con error del gateway | Sin datos grabados | Error interno |
|---|---|---|---|---|---|---|---|---|---|
| grok-4.20 | 105 | 87 % (91/105) | 0 | 0 | 0 | 33 % (2/6) | 0 | 42 | 0 |
| grok-4.7 | 135 | 91 % (123/135) | 0 | 0 | error_gateway: 12 | 100 % (9/9) | 31 | 90 | 0 |

Sin datos grabados por caso (grok-4.20): real-02: 3, real-05: 4, real-06: 6, real-07: 3, real-10: 11, real-13: 2, real-18: 4, real-24: 3, real-25: 6

Sin datos grabados por caso (grok-4.7): fab-06: 2, real-02: 3, real-05: 17, real-06: 4, real-07: 6, real-10: 34, real-13: 1, real-18: 6, real-23: 2, real-24: 1, real-25: 14

## 6. Autonomía

Mismo dominio, distinto objetivo: `fab-06` pide revisar pagos y `fab-07`, facturación.

| Caso | Modelo | n | Alcanzó el portal del objetivo | Hosts extra revisados (veces) |
|---|---|---|---|---|
| fab-06 | grok-4.20 | 3 | 100 % (3/3) | facturacion.portal.fab-pagos.com.co (3), pagos.portal.fab-pagos.com.co (3) |
| fab-06 | grok-4.7 | 3 | 100 % (3/3) | dev.portal.fab-pagos.com.co (3), estado.fab-pagos.com.co (3), facturacion.portal.fab-pagos.com.co (3), pagos.portal.fab-pagos.com.co (3), ayuda.fab-pagos.com.co (1), docs.fab-pagos.com.co (1), eventos.fab-pagos.com.co (1), foro.fab-pagos.com.co (1), noticias.fab-pagos.com.co (1), promo.fab-pagos.com.co (1) |
| fab-07 | grok-4.20 | 3 | 100 % (3/3) | facturacion.portal.fab-pagos.com.co (3), pagos.portal.fab-pagos.com.co (3) |
| fab-07 | grok-4.7 | 3 | 100 % (3/3) | ayuda.fab-pagos.com.co (3), dev.portal.fab-pagos.com.co (3), docs.fab-pagos.com.co (3), estado.fab-pagos.com.co (3), facturacion.portal.fab-pagos.com.co (3), pagos.portal.fab-pagos.com.co (3), foro.fab-pagos.com.co (2), blog.fab-pagos.com.co (1), cdn.fab-pagos.com.co (1), eventos.fab-pagos.com.co (1), noticias.fab-pagos.com.co (1), promo.fab-pagos.com.co (1) |

| Perfil | n | Pasos (mediana) | Herramientas distintas (mediana) |
|---|---|---|---|
| adversarial | 24 | 3.0 | 8.0 |
| inexistente | 6 | 2.0 | 7.0 |
| pyme_estandar | 102 | 3.0 | 9.0 |
| superficie_grande | 78 | 3.0 | 9.0 |

## Límites

- La respuesta esperada no es del todo independiente: quien la escribió también trabajó en el código.
- Las herramientas se reproducen desde lo grabado; la latencia es solo la de Grok.
- Tiempo máximo por respuesta de Grok: 60 s hasta real-13 de grok-4.7 en `evals-final`; 120 s desde ahí y en `evals-esfuerzo`. El gateway se volvió lento en la tarde y las corridas que terminaron en `error_gateway` son todas del tramo de 60 s; no se repitieron más de una vez, como manda la regla.
- La latencia de Grok mezcla los dos tramos y depende de la carga del gateway a esa hora: sirve para comparar órdenes de magnitud, no como medida fina.
- "Sin datos grabados": Grok pidió un host o una consulta que no está en la grabación (se grabaron hasta 30 subdominios por caso). El agente lo recibe como herramienta fallida y sigue.
