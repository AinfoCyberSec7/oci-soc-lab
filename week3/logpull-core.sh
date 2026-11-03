#!/bin/bash
# core-arm side of the one-way log pull. Run ON core-arm as ubuntu.
#   bash logpull-core.sh key        -> creates user hppull + key, prints ONLY the public key
#   bash logpull-core.sh install    -> pins honeypot host key, installs the 1-minute timer, tests
# core-arm opens every connection; the honeypot never connects into the lab.
set -euo pipefail
HP_IP="${HP_IP:-10.20.1.15}"
HP_PORT="${HP_PORT:-22222}"
ETC=/etc/hppull
DEST=/var/log/honeypot/cowrie
SSH_OPTS="-i $ETC/id_ed25519 -p $HP_PORT -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$ETC/known_hosts -o ConnectTimeout=10"

case "${1:-}" in
key)
  id hppull >/dev/null 2>&1 || sudo useradd --system --no-create-home --home-dir "$ETC" --shell /usr/sbin/nologin hppull
  sudo install -d -o hppull -g hppull -m 0700 "$ETC"
  sudo test -f "$ETC/id_ed25519" || sudo -u hppull ssh-keygen -q -t ed25519 -N "" -C "hppull@core-arm" -f "$ETC/id_ed25519"
  sudo cat "$ETC/id_ed25519.pub"
  ;;
install)
  echo "== 1/4 pin the honeypot's SSH host key"
  ssh-keyscan -T 10 -p "$HP_PORT" -t ed25519 "$HP_IP" 2>/dev/null | sudo tee "$ETC/known_hosts" >/dev/null
  sudo chown hppull:hppull "$ETC/known_hosts"; sudo chmod 0644 "$ETC/known_hosts"
  echo "   pinned: $(sudo ssh-keygen -lf "$ETC/known_hosts" | awk '{print $2}')"

  echo "== 2/4 destination + sandboxed service + 1-minute timer"
  sudo install -d -o hppull -g hppull -m 0750 /var/log/honeypot "$DEST"
  sudo tee /etc/systemd/system/hppull.service >/dev/null <<EOF
[Unit]
Description=Pull Cowrie logs from the honeypot (read-only, lab-initiated)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=hppull
Group=hppull
ExecStart=/usr/bin/rsync -rt --timeout=60 --chmod=D0750,F0640 -e "ssh $SSH_OPTS" logpull@$HP_IP:./ $DEST/
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$DEST
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
EOF
  sudo tee /etc/systemd/system/hppull.timer >/dev/null <<'EOF'
[Unit]
Description=Pull Cowrie logs every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now hppull.timer >/dev/null

  echo "== 3/4 first pull"
  sudo systemctl start hppull.service || true
  echo "   result: $(systemctl show hppull.service -p Result --value)"
  [ "$(systemctl show hppull.service -p Result --value)" = success ] || sudo journalctl -u hppull.service -n 8 --no-pager
  sudo ls -l "$DEST" | tail -n +2 | awk '{print "   "$5" bytes  "$9}'

  echo "== 4/4 the key can do NOTHING else (each must be refused)"
  printf '   run a shell command:  '; sudo -u hppull ssh $SSH_OPTS logpull@"$HP_IP" id 2>&1 | tail -1 || true
  printf '   upload (write):       '; echo test | sudo -u hppull tee /tmp/hppull-probe >/dev/null
  sudo -u hppull rsync -e "ssh $SSH_OPTS" /tmp/hppull-probe logpull@"$HP_IP":./ 2>&1 | head -1 || true; sudo rm -f /tmp/hppull-probe
  printf '   read outside folder:  '; sudo -u hppull rsync -e "ssh $SSH_OPTS" logpull@"$HP_IP":../../../../etc/passwd /tmp/ 2>&1 | head -1 || true
  echo "   timer: $(systemctl is-active hppull.timer); last pull: $(systemctl show hppull.service -p ExecMainExitTimestamp --value)"
  echo "CORE SIDE DONE"
  ;;
*) echo "usage: $0 key|install"; exit 1 ;;
esac
