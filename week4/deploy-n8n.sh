#!/bin/bash
# Week 4, step 3: deploy n8n on core-arm. Run ON core-arm:  bash ~/soc-lab/week4/deploy-n8n.sh
#   N8N_VERSION=2.47.3 (default) - a current stable release; the image is pinned by its digest.
# Idempotent: the encryption key and certificate are created once and never overwritten
# (a new encryption key would make every stored credential unreadable). Prints no secrets.
set -euo pipefail
cd "$(dirname "$0")/n8n"
VER="${N8N_VERSION:-2.47.3}"
REPO=docker.n8n.io/n8nio/n8n
BIND_IP=10.10.1.129
SEC=/etc/n8n-secrets; TLS=$SEC/tls; GID=20997
ES_IMAGE="docker.elastic.co/elasticsearch/elasticsearch:9.5.5@sha256:13b4a40bb095774f5fda635e45fd5677cc6a26565e42b24997b0c72b88e75984"
CERTVOL=soc-elastic_certs
LABCA=/etc/elastic-agent-certs/ca.crt   # the same lab CA, already world-readable (public cert)

echo "== 1/5 pre-flight"
docker volume inspect "$CERTVOL" >/dev/null || { echo "   STOP: CA volume $CERTVOL not found"; exit 1; }
if getent group "$GID" >/dev/null; then echo "   STOP: gid $GID already used on this host ($(getent group "$GID" | cut -d: -f1))"; exit 1; fi
echo "   CA volume found; gid $GID unused on the host"

echo "== 2/5 image $REPO:$VER, pinned by digest"
docker pull -q "$REPO:$VER" >/dev/null
DIGEST=$(docker image inspect "$REPO:$VER" --format '{{index .RepoDigests 0}}')
ARCH=$(docker image inspect "$REPO:$VER" --format '{{.Architecture}}')
echo "   $DIGEST  arch=$ARCH  user=$(docker image inspect "$REPO:$VER" --format '{{.Config.User}}')"
[ "$ARCH" = arm64 ] || { echo "   STOP: expected arm64"; exit 1; }
umask 077
printf '# written by deploy-n8n.sh - not a secret, but host-specific\nN8N_IMAGE=%s\nBIND_IP=%s\n' "$DIGEST" "$BIND_IP" > .env

echo "== 3/5 secrets (root-owned, group $GID, created once)"
sudo install -d -o root -g root -m 0700 "$SEC"
if sudo test -s "$SEC/encryption-key"; then echo "   encryption key: exists, kept"
else openssl rand -hex 32 | sudo tee "$SEC/encryption-key" >/dev/null; echo "   encryption key: created (64 hex chars, not printed)"; fi
sudo chown root:$GID "$SEC/encryption-key"; sudo chmod 0640 "$SEC/encryption-key"
sudo install -d -o root -g $GID -m 0750 "$TLS"
if sudo test -s "$TLS/n8n.crt"; then echo "   TLS certificate: exists, kept"
else
  W=$(sudo mktemp -d); trap 'sudo rm -rf "$W"' EXIT
  printf 'instances:\n  - name: n8n\n    dns: [n8n, localhost]\n    ip: [127.0.0.1, %s]\n' "$BIND_IP" | sudo tee "$W/instances.yml" >/dev/null
  sudo docker run --rm --user 0 --network none -v "$CERTVOL":/certs:ro -v "$W":/out "$ES_IMAGE" \
    bash -c 'bin/elasticsearch-certutil cert --silent --pem --days 1095 --in /out/instances.yml --ca-cert /certs/ca/ca.crt --ca-key /certs/ca/ca.key -out /out/n8n.zip && cd /out && unzip -q n8n.zip' >/dev/null
  sudo install -o root -g $GID -m 0644 "$W/n8n/n8n.crt" "$TLS/n8n.crt"
  sudo install -o root -g $GID -m 0640 "$W/n8n/n8n.key" "$TLS/n8n.key"
  sudo docker run --rm --network none -v "$CERTVOL":/certs:ro --entrypoint cat "$ES_IMAGE" /certs/ca/ca.crt | sudo tee "$TLS/ca.crt" >/dev/null
  sudo chown root:$GID "$TLS/ca.crt"; sudo chmod 0644 "$TLS/ca.crt"
  echo "   TLS certificate: issued by the lab CA (key not printed)"
fi
echo "   $(sudo openssl x509 -in "$TLS/n8n.crt" -noout -ext subjectAltName | tail -1 | sed 's/^ *//')  valid until $(sudo openssl x509 -in "$TLS/n8n.crt" -noout -enddate | cut -d= -f2)"
echo "   chain: $(sudo openssl verify -CAfile "$TLS/ca.crt" "$TLS/n8n.crt" | sed 's/.*: //')   same CA as Elastic: $(sudo cmp -s "$TLS/ca.crt" "$LABCA" && echo yes || echo NO)"

echo "== 4/5 start"
docker compose up -d 2>&1 | tail -1
printf '   waiting for n8n'
for _ in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$LABCA" "https://$BIND_IP:5678/healthz")" = 200 ] && { echo " - up"; break; }
  printf '.'; sleep 3
done

echo "== 5/5 checks"
C=$(docker compose ps -q n8n)
chk() { printf '   %-44s %s\n' "$1" "$2"; }
chk "HTTPS /healthz with the lab CA"          "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$LABCA" "https://$BIND_IP:5678/healthz") (expect 200)"
chk "plain HTTP refused"                       "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$BIND_IP:5678/" || true) (expect 000)"
chk "listening on"                             "$(sudo ss -tlnH 'sport = :5678' | awk '{print $4}' | sort -u | tr '\n' ' ')(expect only $BIND_IP:5678)"
chk "n8n version"                              "$(docker exec "$C" n8n --version 2>/dev/null | tail -1)"
chk "runs as uid:gid / extra groups"           "$(docker exec "$C" id -u):$(docker exec "$C" id -g) / $(docker exec "$C" id -G)"
chk "capabilities dropped / no-new-privileges" "$(docker inspect "$C" --format '{{.HostConfig.CapDrop}} / {{.HostConfig.SecurityOpt}}')"
chk "memory limit"                             "$(( $(docker inspect "$C" --format '{{.HostConfig.Memory}}') / 1048576 )) MB"
chk "encryption key value in environment"      "$(docker inspect "$C" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -c '^N8N_ENCRYPTION_KEY=' || true) (expect 0: file only)"
chk "encryption key passed as a flag (ps)"      "$(ps -eo args | grep -E 'N8N_ENCRYPTION_KEY=|--encryption' | grep -vc grep || true) (expect 0)"
chk "hardening settings (name=value)"         "$(docker inspect "$C" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -E '^N8N_(DIAGNOSTICS_ENABLED|TEMPLATES_ENABLED|PUBLIC_API_DISABLED|BLOCK_ENV_ACCESS_IN_NODE)=' | sed 's/^N8N_//' | sort | tr '\n' ' ')"
echo "      (expect BLOCK_ENV_ACCESS_IN_NODE=true DIAGNOSTICS_ENABLED=false PUBLIC_API_DISABLED=true TEMPLATES_ENABLED=false)"
echo "   open (with lab up): https://$BIND_IP:5678"
echo "N8N DEPLOY DONE"
