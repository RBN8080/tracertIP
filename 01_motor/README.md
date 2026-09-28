# 01 · Motor (Fase 1)

El programa central. Le das una IP, traza el camino y, salto por salto, dice de qué red es, dónde está y si algo no cuadra con la física (un proxy o anycast).

Sonda → enriquecedor → juez → salida (tabla en consola y JSON).

- **Entra:** una IP, o una lista en modo lote, y las bases de IP locales.
- **Sale:** cada traza en crudo y ya juzgada.
- Se construye y se afina con los datos reales de `00_verificacion`.

**Entrega a `02_destinos`, `03_observacion` y `04_telemetria`:** el mismo motor; nadie lo reescribe.

**Estado:** siguiente. Aquí solo entra lo planeado para el motor.

*Actualizado: 2026-09-28 18:45 UTC.*
