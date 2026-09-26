# tracertIP

**Telemetría en vivo del camino hacia una IP.** Muestra por qué redes pasa el tráfico, en qué tramo se va el tiempo y qué dice la física (la velocidad de la luz en la fibra) de cada salto.

> **Estado: Fase 0, verificación.** Aún no hay producto. Este repositorio solo contiene lo estructural: código, scripts y plantillas que sirven en cualquier red.

## Qué hay hoy

`F0/nodo/` contiene lo que corre en el equipo de medición durante la Fase 0 (48 h de datos antes de construir):

| Archivo | Qué hace |
|---|---|
| `recolectar.sh` + `.service` + `.timer` | Cada 15 min traza en secuencia los destinos declarados con `mtr --json` y toma la salud del equipo cada 5 min |
| `vigilar.sh` + `.service` + `.timer` | Revisa cada corrida y alerta si el acceso (router y CGNAT) deja de contestar, si varios destinos pierden paquetes a la vez, si una corrida queda incompleta o si el equipo se calienta |
| `nftables.conf` | Cortafuegos del equipo: entrada cerrada salvo lo necesario |
| `*.example` | Plantillas de los ajustes de cada red (destinos, red local) |

## Qué hace, y qué no

- Traza de forma continua **solo destinos declarados**, uno por uno y con una tasa acotada. **No escanea**: ni barridos de rangos ni listas de puertos.
- Reúne en una sola vista los saltos y sus redes (ASN), la geografía, los cruces oceánicos, la historia de la ruta con sus cambios y cuántos milisegundos aporta cada tramo.
- Usa la física como juez: una ubicación que viola la velocidad de la luz se marca como imposible.

## Requisitos previstos

- Un equipo Linux siempre encendido, con `systemd` y `nftables`.
- Go, para compilar.
- Para `F0/nodo/`: `mtr` 0.96 o posterior y `jq`.

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

*Actualizado: 2026-09-26 20:10 UTC.*
