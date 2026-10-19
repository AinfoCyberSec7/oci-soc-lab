#!/bin/bash
# Enroll a Linux host into Fleet as a normal Elastic Agent (policy chosen by the token).
# Run ON the target host. The enrollment token is read from STDIN (never an argument,
# never printed). The private CA must already be at /etc/elastic-agent-certs/ca.crt.
#   usage:  <token on stdin> | bash install-agent.sh [fleet_url]
set -euo pipefail
VER=9.5.5
FLEET_URL="${1:-https://10.10.1.129:8220}"
ES_URL="${FLEET_URL%:*}:9200"
CA=/etc/elastic-agent-certs/ca.crt

if systemctl is-active --quiet elastic-agent 2>/dev/null; then
  echo "elastic-agent already installed and running - nothing to do"; exit 0
fi
read -r TOKEN || true
[ -n "${TOKEN:-}" ] || { echo "no enrollment token on stdin"; exit 1; }
[ -s "$CA" ] || { echo "missing $CA"; exit 1; }

case "$(uname -m)" in
  x86_64)  ARCH=linux-x86_64 ;;
  aarch64) ARCH=linux-arm64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac
PKG="elastic-agent-${VER}-${ARCH}"
URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/${PKG}.tar.gz"

echo "== 1/4 preflight on $(hostname) ($ARCH)"
free -m | awk 'NR==2{print "   RAM MB total/avail: "$2"/"$7} NR==3{print "   swap MB total: "$2}'
df -h / | awk 'NR==2{print "   disk free: "$4}'
for u in "$FLEET_URL/api/status" "$ES_URL"; do
  code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' --cacert "$CA" "$u" || true)
  echo "   $u -> HTTP $code (TLS verified with our CA if not 000)"
  [ "$code" != 000 ] || { echo "cannot reach $u with our CA - stopping"; exit 1; }
done

echo "== 2/4 download + verify $PKG"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
curl -fsSLO "$URL"; curl -fsSLO "$URL.sha512"
sha512sum -c "${PKG}.tar.gz.sha512"
tar -xzf "${PKG}.tar.gz"

echo "== 3/4 install + enroll (1-3 min)"
sudo "./${PKG}/elastic-agent" install --non-interactive \
  --url="$FLEET_URL" \
  --enrollment-token="$TOKEN" \
  --certificate-authorities="$CA"
unset TOKEN

echo "== 4/4 checks"
systemctl is-active elastic-agent
echo "AGENT INSTALL DONE"
