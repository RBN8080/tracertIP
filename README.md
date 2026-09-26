# tracertIP

**Telemetría en vivo del camino hacia una IP.** Muestra por qué redes pasa el tráfico, en qué tramo se va el tiempo y qué dice la física (la velocidad de la luz en la fibra) de cada salto.

> **Estado: Fase 0, verificación.** Todavía no hay nada que instalar. Este repositorio solo contiene lo estructural: código, scripts y plantillas que sirven en cualquier red.

## Qué hace, y qué no

- Traza de forma continua **solo destinos declarados**, uno por uno y con una tasa acotada. **No escanea**: ni barridos de rangos ni listas de puertos.
- Reúne en una sola vista los saltos y sus redes (ASN), la geografía, los cruces oceánicos, la historia de la ruta con sus cambios y cuántos milisegundos aporta cada tramo.
- Usa la física como juez: una ubicación que viola la velocidad de la luz se marca como imposible.

## Requisitos previstos

- Un equipo Linux siempre encendido, con `systemd` y `nftables`.
- Go, para compilar.

Lo que depende de cada instalación (red local, direcciones, destinos) va en archivos de ajustes, con un `.example` como plantilla.

## Privacidad

Aquí no hay datos de ninguna red concreta. Los ejemplos usan rangos reservados para documentación (RFC 5737, RFC 3849, RFC 7042 y RFC 2606).

Cada commit pasa por un verificador, `.githooks/pre-commit`, que:

- busca IP de host privadas, MAC, llaves, tokens, rutas de usuario y correos;
- compara el contenido contra listas privadas de términos, que viven fuera del repositorio;
- corre [gitleaks](https://github.com/gitleaks/gitleaks).

Si faltan las listas o gitleaks, bloquea el commit.

```sh
git config core.hooksPath .githooks
```

## Datos de terceros

No se redistribuyen: cada instalación los descarga y acepta sus términos.

- IPinfo Lite — CC BY-SA 4.0
- [IP Geolocation by DB-IP](https://db-ip.com) — CC BY 4.0
- TeleGeography Submarine Cable Map — CC BY-NC-SA 3.0 (**uso no comercial**)
- Natural Earth — dominio público

## Licencia

MIT. Ver `LICENSE`.

---

*Actualizado: 2026-09-26 17:09 UTC.*
