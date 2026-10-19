#!/bin/bash
# Install Elastic Agent on core-arm (host install, not a container) as Fleet Server.
# Run on core-arm as the ubuntu user from week2/elastic (uses sudo where needed).
#  - Fleet Server listens on BIND_IP:8220 only, TLS with our private-CA certificate
#  - host firewall: 8220 allowed from the VCN only (live + persistent)
#  - agent tarball verified against Elastic's published SHA-512 before use
#  - service token created via API, kept in memory only, never printed
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a
VER=9.5.5
ARCH=linux-arm64
PKG="elastic-agent-${VER}-${ARCH}"
URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/${PKG}.tar.gz"
CERTDIR=/etc/elastic-agent-certs
VCN=10.10.0.0/16

if systemctl is-active --quiet elastic-agent 2>/dev/null; then
  echo "elastic-agent already installed and running - nothing to do"; exit 0
fi

echo "== 1/6 certificates from the stack's private CA -> $CERTDIR"
sudo install -d -m 0755 "$CERTDIR"
for f in ca/ca.crt fleet-server/fleet-server.crt fleet-server/fleet-server.key; do
  docker compose exec -T es01 cat "config/certs/$f" | sudo tee "$CERTDIR/$(basename "$f")" >/dev/null
done
sudo chmod 0644 "$CERTDIR/ca.crt" "$CERTDIR/fleet-server.crt"; sudo chmod 0600 "$CERTDIR/fleet-server.key"
openssl verify -CAfile "$CERTDIR/ca.crt" "$CERTDIR/fleet-server.crt"

echo "== 2/6 host firewall: TCP 8220 from $VCN only"
RULE="-s $VCN -p tcp -m state --state NEW -m tcp --dport 8220 -j ACCEPT"
sudo iptables -C INPUT $RULE 2>/dev/null || sudo iptables -I INPUT 1 $RULE
if [ -f /etc/iptables/rules.v4 ] && ! sudo grep -q -- "--dport 8220 -j ACCEPT" /etc/iptables/rules.v4; then
  sudo sed -i "/--dport 22 -j ACCEPT/a -A INPUT $RULE" /etc/iptables/rules.v4
fi
sudo iptables -S INPUT | grep -- "--dport 8220"

echo "== 3/6 download + verify $PKG"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
curl -fsSLO "$URL"; curl -fsSLO "$URL.sha512"
sha512sum -c "${PKG}.tar.gz.sha512"
tar -xzf "${PKG}.tar.gz"

echo "== 4/6 Fleet Server service token (in memory only)"
CA="$CERTDIR/ca.crt"; ES="https://${BIND_IP}:9200"
TOKEN_NAME="fleet-core-arm-$(date +%s)"
TOKEN=$(curl -sS --fail-with-body --cacert "$CA" -u "elastic:${ELASTIC_PASSWORD}" -X POST \
  "$ES/_security/service/elastic/fleet-server/credential/token/${TOKEN_NAME}" | jq -r '.token.value')
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "token creation failed"; exit 1; }
echo "   token ${TOKEN_NAME} created (value not shown)"

echo "== 5/6 install elastic-agent as Fleet Server (takes 1-3 min)"
sudo "./${PKG}/elastic-agent" install --non-interactive \
  --url="https://${BIND_IP}:8220" \
  --fleet-server-es="$ES" \
  --fleet-server-service-token="$TOKEN" \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-es-ca="$CA" \
  --certificate-authorities="$CA" \
  --fleet-server-cert="$CERTDIR/fleet-server.crt" \
  --fleet-server-cert-key="$CERTDIR/fleet-server.key" \
  --fleet-server-host="${BIND_IP}" \
  --fleet-server-port=8220
unset TOKEN

echo "== 6/6 checks"
systemctl is-active elastic-agent
# the installer restarts the agent at the end: give Fleet Server up to 60 s to listen
for _ in $(seq 1 30); do sudo ss -tlnH | grep -q ":8220 " && break; sleep 2; done
sudo ss -tlnpH | grep ":8220 " | awk '{print $4, $6}' \
  || { echo "nothing listening on 8220 after 60 s - check: sudo elastic-agent status"; exit 1; }
echo "FLEET SERVER INSTALL DONE"
