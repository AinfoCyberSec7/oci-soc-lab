#!/bin/bash
# Week 4, step 5: put n8n's least-privilege Elastic API key into n8n's encrypted credential store.
# Run ON core-arm (after the n8n owner account exists):  bash ~/soc-lab/week4/n8n-import-elastic-cred.sh
# The key travels only through pipes: root-only file -> jq -> container memory (/dev/shm) -> n8n,
# which encrypts it with its own key. Never printed, never in a command line, never on disk in clear.
# Safe to re-run (same credential id is updated).
set -euo pipefail
KEYF=/etc/n8n-secrets/elastic-api-key
CID=elasticTiKey0001
NAME="Elastic - n8n threat-intel key (read honeypot, write TI)"
cd ~/soc-lab/week4/n8n
C=$(docker compose ps -q n8n); [ -n "$C" ] || { echo "n8n is not running"; exit 1; }
sudo test -s "$KEYF" || { echo "missing $KEYF - run elastic-ti-setup.sh first"; exit 1; }

echo "== 1/3 import into n8n (encrypted at rest with n8n's key)"
sudo cat "$KEYF" | jq -Rc --arg id "$CID" --arg n "$NAME" \
  '[{id:$id, name:$n, type:"httpHeaderAuth", data:{name:"Authorization", value:("ApiKey " + .)}}]' \
  | docker exec -i "$C" sh -c 'umask 077; cat > /dev/shm/cred.json'
docker exec "$C" sh -c 'n8n import:credentials --input=/dev/shm/cred.json 2>&1; rc=$?; rm -f /dev/shm/cred.json; exit $rc' \
  | { grep -vE '^\s*$' || true; } | tail -3 | sed 's/^/   /'
echo "   temp copy removed from the container: $(docker exec "$C" sh -c 'ls /dev/shm/cred.json 2>/dev/null | wc -l') file(s) left (expect 0)"

echo "== 2/3 what n8n stored (exported WITHOUT decryption)"
docker exec "$C" sh -c 'n8n export:credentials --all --output=/dev/shm/x.json >/dev/null 2>&1; cat /dev/shm/x.json; rm -f /dev/shm/x.json' \
  | jq -r '.[] | "   \(.id)  \(.type)  \(.name)  data stored as: \(.data | type)\(if (.data|type)=="string" then " (ciphertext, \(.data|length) chars)" else " - NOT ENCRYPTED" end)"'

echo "== 3/3 the key really works from inside the n8n container (count only)"
sudo cat "$KEYF" | docker exec -i "$C" node -e '
  let k=""; process.stdin.on("data",d=>k+=d).on("end",async()=>{
    const r = await fetch("https://10.10.1.129:9200/logs-cowrie-default/_count",{headers:{Authorization:"ApiKey "+k.trim()}});
    const j = await r.json(); console.log("   HTTP " + r.status + " over TLS with the lab CA, honeypot events visible: " + j.count);
  });' 2>&1 | tail -1
echo "ELASTIC CREDENTIAL DONE"
