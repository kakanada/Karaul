#!/bin/bash
# Copy Karaul into place. Does not start the service and does not overwrite an existing config.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root."
  exit 1
fi

root="$(cd "$(dirname "$0")" && pwd)"
install -d -m 755 /opt/karaul /etc/karaul /var/log/karaul /var/lib/karaul
install -m 755 "$root/karaul.py" /opt/karaul/karaul.py
install -m 755 "$root/on_login.sh" /opt/karaul/on_login.sh
install -m 644 "$root/karaul.service" /etc/systemd/system/karaul.service

if [ ! -f /etc/karaul/config.json ]; then
  install -m 600 "$root/config.example.json" /etc/karaul/config.json
  echo "Created /etc/karaul/config.json from the example. Fill in token, owner_id and server before starting."
else
  echo "Left existing /etc/karaul/config.json in place."
fi

if [ ! -f /etc/karaul/whitelist.txt ]; then
  install -m 644 "$root/whitelist.example.txt" /etc/karaul/whitelist.txt
  echo "Created /etc/karaul/whitelist.txt from the example."
else
  echo "Left existing /etc/karaul/whitelist.txt in place."
fi

touch /var/log/karaul/access.log
chmod 644 /var/log/karaul/access.log

pam="/etc/pam.d/common-session"
if ! grep -q "/opt/karaul/on_login.sh" "$pam"; then
  printf '\n# karaul\nsession optional pam_exec.so type=open_session /opt/karaul/on_login.sh\n' >> "$pam"
  echo "Added the PAM hook to $pam."
else
  echo "PAM hook is already present."
fi

systemctl daemon-reload
echo "Next: edit /etc/karaul/config.json, then run: systemctl enable --now karaul.service"
