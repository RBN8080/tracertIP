#!/bin/sh
# tracertIP - F0 - vigia de la recoleccion. Revisa la ultima corrida y deja un
# veredicto; no sondea nada, solo lee lo recolectado. Lo lanza
# tracertip-f0-vigia.timer 14.5 min despues de cada inicio de corrida, cuando
# esa corrida ya termino o su plazo la corto.
# Alerta si:
#   - el acceso deja de contestar: salto 1 (router) y los saltos privados o de
#     CGNAT que le siguen, con mas de UMBRAL_ACCESO_PCT de sondas sin respuesta;
#   - muchos destinos pierden paquetes en la misma corrida (perdida real en el
#     acceso, no en un tramo lejano);
#   - la corrida quedo incompleta, o no hay corrida reciente con el timer activo;
#   - el nodo pasa el umbral de temperatura, limita su frecuencia o tiene
#     subtension.
# Cada veredicto va a vigia-AAAA-MM-DD.jsonl. Las alertas van tambien al diario
# con prioridad de aviso y, si AVISO_URL existe (ajuste opcional), a esa URL.
set -u

DIR="${STATE_DIRECTORY:-/var/lib/tracertip-f0}"
CONF="${TRACERTIP_DESTINOS:-/etc/tracertip-f0/destinos.conf}"
UMBRAL_ACCESO_PCT=1     # % de sondas sin respuesta en el acceso (linea base: 0)
UMBRAL_DESTINOS_PCT=20  # % de destinos con perdida en una corrida (base: ~1)
UMBRAL_TEMP_MC=75000    # umbral de enfriamiento de la F0, en miligrados C
MAX_EDAD_S=1200         # sin corrida nueva en este tiempo: el instrumento no mide

alertar() {  # $1 = texto sin datos de la red
  echo "<4>ALERTA tracertIP F0: $1" >&2
  if [ -n "${AVISO_URL:-}" ]; then
    curl -fsS -m 10 -d "tracertIP F0: $1" "$AVISO_URL" >/dev/null 2>&1 || echo "<4>no se pudo enviar el aviso" >&2
  fi
}

# Ventana cerrada (el alto detuvo la recoleccion): no hay nada que vigilar.
systemctl is-active --quiet tracertip-f0-recoleccion.timer || exit 0

ahora="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
dia="$(date -u +%Y-%m-%d)"
esperados="$(tr -d '\r' < "$CONF" 2>/dev/null | grep -Evc '^[[:space:]]*(#|$)')"
fm="$(ls "$DIR"/mtr-*.jsonl 2>/dev/null | sort | tail -n 1)"
fs="$(ls "$DIR"/salud-*.jsonl 2>/dev/null | sort | tail -n 1)"
[ -n "$fm" ] || { alertar "no hay datos de recoleccion"; exit 0; }

# Ultima corrida: trazas, acceso, destinos con perdida y edad. Una corrida cabe
# entera en el archivo del dia en que empezo, y ocupa a lo mas 32 lineas.
v="$(tail -n 64 "$fm" | jq -s -r --arg ahora "$ahora" '
  def acceso: test("^(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.])") or . == "???";
  def prefijo: . as $h | reduce range(0; length) as $i ({fin: false, out: []};
    if .fin then . elif ($i == 0 or ($h[$i].host | acceso)) then .out += [$h[$i]] else .fin = true end) | .out;
  (map(.t) | max) as $t
  | map(select(.t == $t)) as $c
  | [$c[] | select(.mtr != null) | .mtr.report.hubs | prefijo[]] as $a
  | [$t, ($c | length),
     ([$a[].Snt] | add // 0),
     ([$a[] | .Snt * .["Loss%"] / 100] | add // 0 | round),
     ([$c[] | select(.mtr == null or (.mtr.report.hubs | last | .host) != .destino
                     or (.mtr.report.hubs | last | .["Loss%"]) > 0)] | length),
     (($ahora | fromdateiso8601) - ($t | fromdateiso8601))] | @tsv')"
[ -n "$v" ] || { alertar "no se pudo leer la ultima corrida"; exit 0; }
set -- $v
corrida="$1"; trazas="$2"; acc_s="$3"; acc_l="$4"; dest_l="$5"; edad="$6"

# Salud durante esa corrida (muestras cada 5 min).
temp_max=null; thr_act=0; sub=0
if [ -n "$fs" ]; then
  tail -n 12 "$fs" | jq -r --arg t "$corrida" 'select(.t >= $t) | [.temp_mc, .throttled, .subtension] | @tsv' > "${TMPDIR:-/tmp}/vigia.$$"
  while IFS="$(printf '\t')" read -r tm th su; do
    [ "$tm" != null ] && { [ "$temp_max" = null ] || [ "$tm" -gt "$temp_max" ]; } && temp_max="$tm"
    case "$th" in 0x*) [ $((th & 15)) -ne 0 ] && thr_act=1 ;; esac
    [ "$su" = 1 ] && sub=1
  done < "${TMPDIR:-/tmp}/vigia.$$"
  rm -f "${TMPDIR:-/tmp}/vigia.$$"
fi

motivos=""
agregar() { motivos="${motivos:+$motivos; }$1"; }
[ "$edad" -gt "$MAX_EDAD_S" ] && agregar "sin corrida nueva desde hace $((edad / 60)) min"
[ "$trazas" -lt "$esperados" ] && agregar "corrida incompleta: $trazas de $esperados trazas"
[ "$acc_s" -gt 0 ] && [ $((acc_l * 100)) -gt $((acc_s * UMBRAL_ACCESO_PCT)) ] && agregar "el acceso (router y CGNAT) dejo sin respuesta $acc_l de $acc_s sondas"
[ "$trazas" -gt 0 ] && [ $((dest_l * 100)) -ge $((trazas * UMBRAL_DESTINOS_PCT)) ] && agregar "$dest_l de $trazas destinos con perdida en la misma corrida"
[ "$temp_max" != null ] && [ "$temp_max" -gt "$UMBRAL_TEMP_MC" ] && agregar "temperatura $((temp_max / 1000)) C"
[ "$thr_act" = 1 ] && agregar "el nodo limito su frecuencia (throttled activo)"
[ "$sub" = 1 ] && agregar "subtension"

estado=ok; [ -n "$motivos" ] && estado=alerta
printf '{"t":"%s","corrida":"%s","trazas":%s,"esperados":%s,"acceso_sondas":%s,"acceso_sin_respuesta":%s,"destinos_con_perdida":%s,"temp_max_mc":%s,"estado":"%s","motivos":"%s"}\n' \
  "$ahora" "$corrida" "$trazas" "$esperados" "$acc_s" "$acc_l" "$dest_l" "$temp_max" "$estado" "$motivos" >> "$DIR/vigia-$dia.jsonl"
[ "$estado" = alerta ] && alertar "$motivos (corrida $corrida)"
exit 0
