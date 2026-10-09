#!/bin/bash
# Install wstunnel (WireGuard over TLS/TCP) on wg-gw. Idempotent: safe to re-run.
# Usage (from the Mac): ssh ubuntu@<wg-gw> 'sudo bash -s' < scripts/install-wstunnel-server.sh
set -euo pipefail

VER="11.0.0"
ARCH="linux_amd64"
TARBALL="wstunnel_${VER}_${ARCH}.tar.gz"
BASE="https://github.com/erebe/wstunnel/releases/download/v${VER}"
PORT=443

[ -s /etc/wstunnel/env ] || { echo "ERROR: /etc/wstunnel/env missing - copy the secret first"; exit 1; }

echo "== 1/5 download + verify wstunnel v${VER}"
WORK=$(mktemp -d)
cd "$WORK"
curl -fsSLO "${BASE}/${TARBALL}"
curl -fsSLO "${BASE}/checksums.txt"
grep " ${TARBALL}\$" checksums.txt | sha256sum -c -
tar -xzf "$TARBALL" wstunnel
install -m 0755 wstunnel /usr/local/bin/wstunnel
cd / && rm -rf "$WORK"
/usr/local/bin/wstunnel --version

echo "== 2/5 service user"
id wstunnel >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin wstunnel

echo "== 3/5 systemd unit"
cat > /etc/systemd/system/wstunnel.service <<'UNIT'
[Unit]
Description=wstunnel server (WireGuard over TLS/TCP)
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
User=wstunnel
Group=wstunnel
EnvironmentFile=/etc/wstunnel/env
ExecStart=/usr/local/bin/wstunnel server --restrict-to 127.0.0.1:51820 --restrict-http-upgrade-path-prefix ${WSTUNNEL_PREFIX} wss://0.0.0.0:443
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

echo "== 4/5 host firewall: allow TCP ${PORT} (live + persistent)"
RULE="-p tcp -m state --state NEW -m tcp --dport ${PORT} -j ACCEPT"
iptables -C INPUT $RULE 2>/dev/null || iptables -I INPUT 1 $RULE
if [ -f /etc/iptables/rules.v4 ] && ! grep -q -- "--dport ${PORT} -j ACCEPT" /etc/iptables/rules.v4; then
  sed -i "/--dport 22 -j ACCEPT/a -A INPUT ${RULE}" /etc/iptables/rules.v4
fi

echo "== 5/5 start"
systemctl daemon-reload
systemctl enable --now wstunnel
sleep 2
systemctl is-active wstunnel
ss -tlnp | grep ":${PORT} " || { echo "NOT LISTENING"; journalctl -u wstunnel -n 20 --no-pager; exit 1; }
grep -c -- "--dport ${PORT} -j ACCEPT" /etc/iptables/rules.v4 | sed 's/^/persistent rule count: /'
echo "WSTUNNEL SERVER READY"
