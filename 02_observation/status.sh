#!/bin/sh
# One screen on the running study, read-only: the service, the run in
# progress, the last runs and the host's health. Meant for watch(1):
#   watch -n 30 sh status.sh
d=${1:-/var/lib/tracertip/study}

pid=$(systemctl show -p MainPID --value tracertip-study)
printf 'service  %s since %s' "$(systemctl is-active tracertip-study)" \
	"$(systemctl show -p ActiveEnterTimestamp --value tracertip-study)"
[ "${pid:-0}" -gt 0 ] && printf ', memory %s KB' "$(ps -o rss= -p "$pid" | tr -d ' ')"
echo
printf 'host     %.1f °C, %s free, clock synced: %s\n' \
	"$(awk '{print $1 / 1000}' /sys/class/thermal/thermal_zone0/temp)" \
	"$(df -h --output=avail "$d" | tail -1 | tr -d ' ')" \
	"$(timedatectl show -p NTPSynchronized --value)"

cur=$(ls -1t "$d"/runs/*/*.partial 2>/dev/null | head -1)
if [ -n "$cur" ]; then
	printf 'running  %s, %s traced\n' "$(basename "$cur" .jsonl.partial)" "$(grep -c '"type":"end"' "$cur")"
else
	echo 'running  none: waiting for the next slot'
fi

echo 'last runs'
for f in $(ls -1t "$d"/runs/*/*.jsonl 2>/dev/null | head -4); do
	printf '  %s  %s\n' "$(basename "$(dirname "$f")")/$(basename "$f" .jsonl)" \
		"$(grep '"type":"run_end"' "$f" | tail -1 |
			sed -E 's/.*"traced":([0-9]+)(,"skipped":([0-9]+))?,"reached":([0-9]+).*/traced \1, reached \4, skipped \3/; s/skipped $/skipped 0/')"
done
printf 'aborted  %s\n' "$(ls "$d"/runs/*/*.aborted-* 2>/dev/null | wc -l)"
printf 'replaced %s\n' "$(cat "$d"/replacements.jsonl 2>/dev/null | wc -l)"
