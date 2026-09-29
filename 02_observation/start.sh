#!/bin/sh
# Starts the study on a node set up with 01_engine/deploy/install.sh: freezes
# a copy of the bases (the study reads only that copy, with its SHA-256
# list), installs the configuration and the unit, and starts it.
# Run as root from this folder. Undo: stop.sh.
set -eu
targets=${1:?usage: start.sh <targets.json> <config.json>}
config=${2:?usage: start.sh <targets.json> <config.json>}
cd "$(dirname "$0")"
study=/var/lib/tracertip/study

id tracertip >/dev/null 2>&1 || { echo "run 01_engine/deploy/install.sh first" >&2; exit 1; }
install -d -o tracertip -g tracertip -m 0755 "$study"
if [ ! -d "$study/bases" ]; then
	cp -a /var/lib/tracertip/bases "$study/bases.tmp"
	(cd "$study/bases.tmp" && sha256sum -- * > SHA256SUMS)
	chown -R tracertip:tracertip "$study/bases.tmp"
	mv "$study/bases.tmp" "$study/bases"
	sync
fi
install -o tracertip -g tracertip -m 0644 "$targets" "$study/targets-input.json"
install -d -m 0755 /etc/tracertip
install -o root -g tracertip -m 0640 "$config" /etc/tracertip/study.json
install -m 0644 tracertip-study.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now tracertip-study.service
echo "study running; data in $study (bases frozen: $study/bases/SHA256SUMS)"
