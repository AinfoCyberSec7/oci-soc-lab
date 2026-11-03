#!/bin/bash
# Lock the unused "opc" account that Oracle's Ubuntu image creates (uid 1000, your SSH key, /bin/sh).
# Run on your Mac, one host at a time:   bash scripts/lock-opc.sh lab-core
# Does NOT delete the account (Oracle tooling may expect it); makes it unusable instead:
#   1. login shell -> nologin     2. password locked + account expired (PAM refuses any login, even with a key)
#   3. its authorized_keys emptied (backup in /var/backups)    4. sshd: DenyUsers opc
# Your own login (ubuntu) is never touched; sshd config is tested before reload; existing sessions stay up.
# Undo on the host: sudo usermod -s /bin/sh -e "" opc; sudo rm /etc/ssh/sshd_config.d/10-deny-opc.conf;
#   restore the key from /var/backups/opc-authorized_keys.*; sudo systemctl reload ssh
set -uo pipefail
H="${1:?usage: $0 lab-core|lab-gw|lab-hp}"

echo "================ $H: lock opc ================"
ssh "$H" 'sudo bash -s' <<'EOF'
set -euo pipefail
id opc >/dev/null 2>&1 || { echo "  no opc account here - nothing to do"; exit 0; }
echo "== before"
echo "   $(getent passwd opc)   groups: $(id -nG opc)"
# uid 1000 is also the uid that Elasticsearch/Kibana use INSIDE their containers. Those processes
# are not opc logging in (no shell, no PAM) and locking the account does not affect them.
# Stop only for processes OUTSIDE containers, or a login session - never print command lines.
INC=0; OUTC=0
for pid in $(pgrep -u opc || true); do
  if grep -qE 'docker|containerd' "/proc/$pid/cgroup" 2>/dev/null; then INC=$((INC+1)); else OUTC=$((OUTC+1)); fi
done
SESS=$(loginctl list-sessions --no-legend 2>/dev/null | awk '$3=="opc"' | wc -l)
echo "   uid-1000 processes inside containers: $INC (Elasticsearch/Kibana, unaffected)"
echo "   opc processes outside containers: $OUTC   opc login sessions: $SESS"
if [ "$OUTC" -ne 0 ] || [ "$SESS" -ne 0 ]; then
  echo "  STOP: opc is active outside containers - not touching it"
  for pid in $(pgrep -u opc); do grep -qE 'docker|containerd' "/proc/$pid/cgroup" || echo "   pid $pid: $(cat /proc/$pid/comm)"; done
  exit 1
fi
for g in sudo admin docker adm lxd; do id -nG opc | tr ' ' '\n' | grep -qx "$g" && echo "   NOTE: opc is in group $g (removing)" && gpasswd -d opc "$g" >/dev/null || true; done

echo "== lock"
usermod -s /usr/sbin/nologin opc
passwd -l opc >/dev/null
usermod -e 1 opc
K=/home/opc/.ssh/authorized_keys
if [ -s "$K" ]; then cp -p "$K" "/var/backups/opc-authorized_keys.$(date +%F)"; : > "$K"; fi
printf '# opc comes with the Oracle Ubuntu image; it is not used in this lab.\nDenyUsers opc\n' > /etc/ssh/sshd_config.d/10-deny-opc.conf
chmod 0644 /etc/ssh/sshd_config.d/10-deny-opc.conf
sshd -t
systemctl try-reload-or-restart ssh.service

echo "== after"
echo "   $(getent passwd opc)"
echo "   password: $(passwd -S opc | awk '{print $2}')  (L = locked)   expires: $(chage -l opc | awk -F': ' '/Account expires/{print $2}')"
echo "   authorized_keys: $(wc -c < "$K") bytes"
echo "   sshd denyusers: $(sshd -T 2>/dev/null | awk '/^denyusers/{print $2}')"
EOF
rc=$?; [ $rc -eq 0 ] || { echo "STOPPED on $H (exit $rc)"; exit $rc; }

echo "== live test from your Mac"
printf '   login as opc (must be refused): '
ssh -o BatchMode=yes -o ConnectTimeout=15 -l opc "$H" true 2>&1 | grep -oE 'Permission denied[^.]*|Connection closed[^.]*' | head -1 || true
printf '   login as ubuntu (must work):    '
ssh -o BatchMode=yes -o ConnectTimeout=15 "$H" 'echo "OK ($(whoami)@$(hostname))"'
echo "LOCK OPC DONE on $H"
