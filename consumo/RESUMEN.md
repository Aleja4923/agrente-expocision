# Bitácora de consumo

Generado por `python -m carga.consumo` desde la bitácora del agente. El detalle, una fila por petición a Grok, está en `consumo.csv`.

## Por modelo: bitácora del agente frente al panel del reto

Panel consultado el 2026-11-07, sección «Consumo por modelo» del panel del reto (copiado a mano por la autora).

| Modelo | Peticiones (bitácora · panel) | Tokens entrada (bitácora · panel) | Tokens salida (bitácora · panel) | Costo USD (bitácora · panel) |
|---|---|---|---|---|
| grok-4.20 | 4,379 · 4,379 | 33,444,948 · 33,540,752 | 1,294,791 · 1,298,674 | 36.37 · 36.49 |
| grok-4.6 | 0 · 1 | 0 · 637 | 0 · 12 | 0.00 · 0.00 |
| grok-4.7 | 957 · 1,012 | 7,417,794 · 11,565,526 | 314,741 · 498,674 | 16.22 · 25.95 |
| — | 0 · 2 | 0 · 0 | 0 · 0 | 0.00 · 0.00 |

**Cómo se lee la diferencia:**
- Las peticiones de la bitácora incluyen las que el cliente cortó por tiempo (columna «cortadas» abajo). El gateway las procesó y las cobró, pero el cliente no recibió su consumo, así que en la bitácora tienen costo 0. Con grok-4.20 las peticiones cuadran exactas.
- Con grok-4.7 hay 156 peticiones cortadas, casi todas en la tarde lenta del gateway durante el S3, cuando el tiempo máximo por respuesta era de 60 s. Su costo no se conoce desde la bitácora: es parte de la diferencia de costo con el panel.
- Quedan 55 peticiones de grok-4.7 en el panel sin línea en la bitácora. La causa más probable, no comprobada una por una, es la pérdida de líneas cuando escribían varios hilos o procesos a la vez durante el S3, un problema documentado que se corrigió para el S4. Las peticiones a grok-4.6 y sin modelo del panel tampoco están en la bitácora y no tienen costo.

| Modelo | Peticiones | Cortadas por tiempo (costo no reportado) | Tokens entrada | Tokens salida | Costo USD |
|---|---|---|---|---|---|
| grok-4.20 | 4,379 | 11 | 33,444,948 | 1,294,791 | 36.37 |
| grok-4.7 | 957 | 156 | 7,417,794 | 314,741 | 16.22 |

## Por hito

| Hito | Peticiones | Costo USD |
|---|---|---|
| S1 | 122 | 0.79 |
| S2 | 148 | 2.77 |
| S3 | 1,172 | 17.19 |
| S4 | 3,884 | 31.74 |
| Después del S4 | 10 | 0.09 |
| **Total** | **5,336** | **52.59** |

> Todo el consumo está ligado a tareas reales del agente: auditorías por la CLI (S1 y S2), el set de evaluación (S3), la corrida de carga (S4) y las pruebas del gateway del S1. No se publica el dominio de las corridas por la CLI.
