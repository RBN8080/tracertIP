#!/bin/sh
# tracertIP - F0 - paso 0.2 - una corrida de recoleccion
# La lanza tracertip-f0-recoleccion.timer cada 15 min. Escribe JSON Lines en
# $STATE_DIRECTORY (/var/lib/tracertip-f0): una linea por destino y una de
# salud cada SALUD_CADA_S, tambien a mitad de corrida.
# Destinos: $TRACERTIP_DESTINOS o /etc/tracertip-f0/destinos.conf, una IP por
# linea (plantilla: destinos.conf.example). Frontera: solo IP sueltas, sin
# rangos ni nombres, medidas en secuencia (nunca a la vez), y solo las que
# quepan en PRESUPUESTO_S. Si no se cumple, no mide: falla.
set -u

DIR="${STATE_DIRECTORY:-/var/lib/tracertip-f0}"
CONF="${TRACERTIP_DESTINOS:-/etc/tracertip-f0/destinos.conf}"
CICLOS=10       # sondas por salto en cada corrida
INTERVALO=2     # s entre ciclos    = una ronda cada 2 s por destino
GRACIA=2        # s de espera final ~ plazo de cada sonda
MAXTTL=40       #                   = TTL maximo (calibrado: hay caminos de 31)
ARRANQUE=2      # s por destino, ademas de CICLOS*INTERVALO+GRACIA (medido)
PRESUPUESTO_S=780  # s de sondeo por corrida: menos que TimeoutStartSec (840)
                   # y que el periodo del timer (900), para no encimarse
SALUD_CADA_S=300   # s entre muestras de salud: el umbral de enfriamiento
                   # cuenta 3 seguidas como 15 min

DESTINOS="$(tr -d '\r' < "$CONF" 2>/dev/null | grep -Ev '^[[:space:]]*(#|$)')"
[ -n "$DESTINOS" ] || { echo "sin destinos en $CONF" >&2; exit 1; }
printf '%s\n' "$DESTINOS" | grep -Eqv '^[0-9A-Fa-f.:]+$' && { echo "hay un destino que no es una IP suelta en $CONF" >&2; exit 1; }
N="$(printf '%s\n' "$DESTINOS" | wc -l)"
[ $((N * (CICLOS * INTERVALO + GRACIA + ARRANQUE))) -le "$PRESUPUESTO_S" ] || {
  echo "$N destinos no caben en $PRESUPUESTO_S s por corrida" >&2; exit 1; }

t="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
dia="$(date -u +%Y-%m-%d)"

# Salud del nodo. Lo que no se pueda leer va como NA o null, nunca como 0.
salud() {
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  temp="$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo null)"
  thr="$(vcgencmd get_throttled 2>/dev/null | cut -d= -f2)"
  uv=null  # alarma de subtension del hwmon rpi_volt (1 = ahora), si existe
  for h in /sys/class/hwmon/hwmon*; do
    [ "$(cat "$h/name" 2>/dev/null)" = rpi_volt ] && uv="$(cat "$h/in0_lcrit_alarm" 2>/dev/null || echo null)"
  done
  carga="$(cut -d' ' -f1 /proc/loadavg)"
  ntp="$(timedatectl timesync-status 2>/dev/null | awk '/Offset:/ {print $2}')"
  printf '{"t":"%s","temp_mc":%s,"throttled":"%s","subtension":%s,"carga1":%s,"ntp_offset":"%s"}\n' \
    "$ts" "$temp" "${thr:-NA}" "$uv" "$carga" "${ntp:-NA}" >> "$DIR/salud-$dia.jsonl"
  ultima_salud="$(date +%s)"
}
salud

# t = inicio de la corrida; t_destino = cuando empieza la traza de ese destino
for d in $DESTINOS; do
  [ $(($(date +%s) - ultima_salud)) -ge "$SALUD_CADA_S" ] && salud
  td="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if j="$(mtr --json -n -c "$CICLOS" -i "$INTERVALO" -G "$GRACIA" -m "$MAXTTL" "$d" 2>/dev/null)"; then
    printf '{"t":"%s","t_destino":"%s","destino":"%s","mtr":%s}\n' "$t" "$td" "$d" "$(printf '%s' "$j" | tr -d '\n')"
  else
    printf '{"t":"%s","t_destino":"%s","destino":"%s","mtr":null,"error":%s}\n' "$t" "$td" "$d" "$?"
  fi >> "$DIR/mtr-$dia.jsonl"
done
