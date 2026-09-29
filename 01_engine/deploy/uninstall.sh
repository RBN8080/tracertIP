#!/bin/sh
# Undoes install.sh. The bases stay in /var/lib/tracertip unless --purge.
# systemd-time-wait-sync stays enabled: other services may rely on it.
set -eu
systemctl disable --now tracertip-update-db.timer 2>/dev/null || true
rm -f /etc/systemd/system/tracertip-update-db.service /etc/systemd/system/tracertip-update-db.timer
systemctl daemon-reload
rm -f /usr/local/bin/tracertip
if [ "${1:-}" = --purge ]; then
	rm -rf /var/lib/tracertip
	userdel tracertip 2>/dev/null || true
fi
