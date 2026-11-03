#!/bin/bash
# Deploy the Cowrie honeypot container. Run ON the honeypot as the ubuntu user:
#   bash deploy-cowrie.sh
# Idempotent: re-running replaces the container with the same pinned image and config.
# Bait ports 22/23 are published on the host, but stay unreachable from the internet
# until the NSG rule is enabled (terraform var honeypot_bait_enabled = true).
set -euo pipefail

IMAGE="cowrie/cowrie@sha256:797d45ca8823d313bec0994232b982f3b99412d4e68e234608d6c1f78d32e3fe"  # 3.1.5
BASE=/srv/cowrie
APP=/cowrie/cowrie-git          # image workdir (etc/ and var/ are its declared volumes)
# The image's own uid 999 is "ocarun" (Oracle Cloud Agent) on this host, so run as a
# dedicated uid that exists nowhere on the host instead.

echo "== 1/5 image (pinned by digest)"
sudo docker pull -q "$IMAGE" >/dev/null
sudo docker image inspect "$IMAGE" --format '   {{index .RepoDigests 0}}  user={{.Config.User}}  arch={{.Architecture}}'

echo "== 2/5 folders for logs, downloads, TTY recordings (owned by dedicated uid 20999, unused on the host)"
sudo install -d -o 20999 -g 20999 -m 0750 \
  "$BASE/var" "$BASE/var/log/cowrie" "$BASE/var/lib/cowrie" \
  "$BASE/var/lib/cowrie/downloads" "$BASE/var/lib/cowrie/tty" "$BASE/var/run" "$BASE/etc"
sudo chown -R 20999:20999 "$BASE"     # also files written by an earlier run

echo "== 3/5 config (overrides only; everything else keeps Cowrie defaults)"
sudo tee "$BASE/etc/cowrie.cfg" >/dev/null <<'EOF'
# Cowrie overrides for the SOC lab honeypot.
[honeypot]
# name shown to attackers inside the fake shell
hostname = srv04

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
# never let attackers relay traffic through us (would make us an attack source)
forwarding = false
forward_redirect = false
forward_tunnel = false

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
# one JSON event per line in var/log/cowrie/cowrie.json (what the SIEM will ingest)
enabled = true
EOF
sudo chown 20999:20999 "$BASE/etc/cowrie.cfg"; sudo chmod 0640 "$BASE/etc/cowrie.cfg"

echo "== 4/5 run (no capabilities, no privilege escalation, read-only root, memory/pid caps)"
sudo docker rm -f cowrie >/dev/null 2>&1 || true
sudo docker run -d --name cowrie --restart unless-stopped \
  -p 22:2222 -p 23:2223 \
  -v "$BASE/etc/cowrie.cfg:$APP/etc/cowrie.cfg:ro" \
  -v "$BASE/var:$APP/var" \
  --user 20999:20999 --cap-drop ALL --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp:size=16m \
  --memory 384m --memory-swap 512m --pids-limit 128 \
  --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 \
  "$IMAGE" >/dev/null

echo "== 5/5 checks"
# wait for Cowrie itself (not just Docker's port) to answer: up to 60 s
for _ in $(seq 1 30); do
  timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22; head -c 7 <&3' 2>/dev/null | grep -q SSH && break; sleep 2; done
sudo docker ps --filter name=cowrie --format '   {{.Names}}  {{.Status}}  {{.Ports}}'
printf '   ssh banner on :22  -> '; timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22; head -c 40 <&3' | tr -d '\r\n' || true; echo
printf '   telnet on :23      -> '; timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/23; sleep 2; head -c 60 <&3' 2>/dev/null | tr -cd '[:print:]' || true; echo
echo "   real sshd still on: $(sudo ss -tlnpH | awk '/sshd/{print $4}' | sort -u | tr '\n' ' ')"
echo "COWRIE DEPLOY DONE"
