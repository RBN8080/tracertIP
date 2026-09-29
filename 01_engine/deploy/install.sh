#!/bin/sh
# Installs tracertip on a systemd Linux node: the binary with CAP_NET_RAW only
# and the daily base update under its own user. Run as root from this folder.
# Undo: uninstall.sh.
set -eu
bin=${1:?usage: install.sh <tracertip binary>}
cd "$(dirname "$0")"

install -m 0755 "$bin" /usr/local/bin/tracertip
setcap cap_net_raw=ep /usr/local/bin/tracertip
id tracertip >/dev/null 2>&1 ||
	useradd --system --home-dir /var/lib/tracertip --no-create-home --shell /usr/sbin/nologin tracertip
install -m 0644 tracertip-update-db.service tracertip-update-db.timer /etc/systemd/system/
systemctl daemon-reload
# Without it, time-sync.target does not wait for NTP.
systemctl enable systemd-time-wait-sync.service
systemctl enable --now tracertip-update-db.timer
echo "installed; bases in /var/lib/tracertip/bases (set \"bases\" in the config to use them)"
