#!/bin/sh
# Undoes start.sh. The data stays in /var/lib/tracertip/study unless --purge.
set -eu
systemctl disable --now tracertip-study.service 2>/dev/null || true
rm -f /etc/systemd/system/tracertip-study.service
systemctl daemon-reload
if [ "${1:-}" = --purge ]; then
	rm -rf /var/lib/tracertip/study
	rm -f /etc/tracertip/study.json
	rmdir /etc/tracertip 2>/dev/null || true
fi
