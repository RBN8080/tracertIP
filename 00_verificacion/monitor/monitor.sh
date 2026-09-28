#!/bin/sh
# tracertIP - F0 - vistas de monitoreo del nodo, una por ventana.
# Solo lectura: procesos, interfaz, sockets, sensores y diario. No toca la
# recoleccion ni el cortafuegos. Lo despliega y lo abre 00_verificacion/monitor/monitor.ps1
# desde el PC; en el nodo tambien sirve a mano: sh ~/tracertip-monitor.sh <vista>
# Salir de cada vista con Ctrl+C.
set -u

IFAZ="${TRACERTIP_IFAZ:-eth0}"   # interfaz por la que mide el nodo
DATOS=/var/lib/tracertip-f0      # StateDirectory de la recoleccion
CONF=/etc/tracertip-f0/destinos.conf
REFRESCO_S=10                    # tablero; el vigia y la salud ya van a 5 min
# Centinela: lo que NO es la sonda (ICMP de mtr), ni el SSH de estas ventanas,
# ni ruido de la LAN (ARP, multicast y difusion).
CENTINELA='not port 22 and not icmp and not icmp6 and not arp and not ether multicast'

uso() {
  cat >&2 <<'EOF'
uso: monitor.sh <vista>
  proceso    htop de los procesos del usuario de servicio (cuando mide)
  tablero    temperatura, ventilador, limite termico, corrida en curso,
             temporizadores, ultimos veredictos del vigia, NTP y disco
  trafico    caudal de entrada y salida de la interfaz (grafica)
  centinela  todo lo que entra o sale y no es la sonda ni el SSH
  sockets    que proceso tiene sockets abiertos y hacia donde
  alertas    avisos del sistema en vivo: vigia, kernel, USB, energia
  diario     inicio y fin de cada corrida, vigia y alto
  red        caudal y errores o descartes de la interfaz cada 10 s
EOF
}

tablero() {
  t=$(cat /sys/class/thermal/thermal_zone0/temp)
  f=$(echo /sys/devices/platform/cooling_fan/hwmon/hwmon*)
  uv=NA
  for h in /sys/class/hwmon/hwmon*; do
    [ "$(cat "$h/name")" = rpi_volt ] && uv=$(cat "$h/in0_lcrit_alarm")
  done
  echo "$(date -u +%FT%TZ)  $((t / 1000)).$(((t % 1000) / 100)) C  escalon $(cat /sys/class/thermal/cooling_device0/cur_state)  $(cat "$f/fan1_input") rpm  $(/usr/local/bin/vcgencmd get_throttled)  subtension=$uv"
  echo "carga $(cut -d' ' -f1-3 /proc/loadavg)  NTP $(timedatectl timesync-status 2>/dev/null | awk '/Offset:/ {print $2}')  datos $(du -sh "$DATOS" | cut -f1)  disco $(df -h / | awk 'NR == 2 {print $5}')"
  esperados=$(grep -Evc '^[[:space:]]*(#|$)' "$CONF")
  # Solo las ultimas lineas: la corrida en curso cabe en $esperados (barato).
  ultima=$(tail -n "$esperados" "$DATOS/mtr-$(date -u +%F).jsonl" 2>/dev/null |
    jq -r .t | sort | uniq -c | tail -n 1 | awk '{print $2 ", " $1}')
  case "$(systemctl show -p ActiveState --value tracertip-f0-recoleccion.service)" in
    activating) estado=MIDIENDO ;; inactive) estado="en espera" ;; *) estado=REVISAR ;; esac
  echo "recoleccion: $estado  ultima corrida: ${ultima:-sin datos hoy, 0} de $esperados trazas"
  echo
  systemctl list-timers --no-pager 'tracertip*' | head -n -3
  echo
  echo "vigia: corrida  estado  trazas  destinos_con_perdida  temp_max_mc  motivos"
  tail -n 3 "$DATOS/vigia-$(date -u +%F).jsonl" 2>/dev/null |
    jq -r '[.corrida, .estado, .trazas, .destinos_con_perdida, .temp_max_mc, .motivos] | @tsv'
}

case "${1:-}" in
  proceso)   exec htop -u tracertip -t -d 10 ;;
  tablero)   exec sudo watch -t -n "$REFRESCO_S" sh "$0" _tablero ;;
  _tablero)  tablero ;;
  trafico)   exec nload -u k -t 1000 "$IFAZ" ;;
  centinela) exec sudo tcpdump -i "$IFAZ" -nn -q -l -tttt "$CENTINELA" ;;
  sockets)   exec sudo watch -n 2 ss -tunwap ;;
  # Cada inicio de sesion SSH deja un aviso de PAM sin consecuencia: se filtra.
  alertas)   sudo journalctl -f -p warning -o short-iso |
               grep --line-buffered -v 'Debian-PAM-MiniPolicy' ;;
  diario)    exec sudo journalctl -f -o short-iso -u tracertip-f0-recoleccion \
               -u tracertip-f0-vigia -u tracertip-f0-alto ;;
  red)       exec sar -n DEV,EDEV --iface="$IFAZ" 10 ;;
  *)         uso; exit 2 ;;
esac
