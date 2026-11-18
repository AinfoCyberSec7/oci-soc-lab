#!/bin/bash
# Week 4 end-to-end check. Run on your Mac from the repo root, with the tunnel up:
#   bash week4/verify-week4.sh
# Read-only: changes nothing. Prints no secrets, no chat ID and no admin IP.
cd "$(dirname "$0")/.." || exit 1
ssh lab-core 'bash -s' <<'EOF'
ok() { if [ "$1" = "$2" ]; then echo "OK"; else echo "CHECK (got: $1)"; fi; }
cd ~/soc-lab/week2/elastic && set -a && . ./.env && set +a
N=$(mktemp); trap 'rm -f "$N"' EXIT; chmod 600 "$N"
printf 'machine %s login elastic password %s\n' "$BIND_IP" "$ELASTIC_PASSWORD" > "$N"
CA=/etc/elastic-agent-certs/ca.crt; ES="https://$BIND_IP:9200"
q() { curl -sS --cacert $CA --netrc-file "$N" -H 'Content-Type: application/json' "$@"; }
cd ~/soc-lab/week4/n8n; C=$(docker compose ps -q n8n)

echo "================ 1. n8n service ================"
echo "  container running .................... $(ok "$(docker inspect "$C" --format '{{.State.Status}}')" running)   restarts: $(docker inspect "$C" --format '{{.RestartCount}}')"
echo "  HTTPS /healthz (lab CA) .............. $(ok "$(curl -s -o /dev/null -w '%{http_code}' --cacert $CA "https://$BIND_IP:5678/healthz")" 200)"
echo "  listens only on the private IP ....... $(ok "$(sudo ss -tlnH 'sport = :5678' | awk '{print $4}' | sort -u | tr '\n' ' ')" "$BIND_IP:5678 ")"
echo "  version: $(docker exec "$C" n8n --version 2>/dev/null | tail -1)   memory: $(docker stats --no-stream --format '{{.MemUsage}}' "$C")"
echo "  encryption key in env / flags ........ $(docker inspect "$C" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -c '^N8N_ENCRYPTION_KEY=' || true) / $(ps -eo args | grep -E 'N8N_ENCRYPTION_KEY=' | grep -vc grep || true)  (expect 0 / 0)"
echo "  credentials stored encrypted ......... $(docker exec "$C" sh -c 'n8n export:credentials --all --output=/dev/shm/x.json >/dev/null 2>&1; cat /dev/shm/x.json; rm -f /dev/shm/x.json' | jq '[.[] | select(.data|type=="string")] | length') of $(docker exec "$C" sh -c 'n8n export:credentials --all --output=/dev/shm/x.json >/dev/null 2>&1; cat /dev/shm/x.json; rm -f /dev/shm/x.json' | jq length)"
echo "  n8n database size .................... $(docker exec "$C" sh -c 'du -h /home/node/.n8n/database.sqlite | cut -f1')  (successful scheduled runs are not stored)"
echo "  active workflows:"
docker exec "$C" n8n list:workflow --active=true 2>/dev/null | grep -v 'license SDK' | sed 's/^/    /'

echo "================ 2. threat-intel results in Elastic ================"
q "$ES/honeypot-ti/_search" -d '{"size":0,"aggs":{"t":{"terms":{"field":"indicator_type"},"aggs":{"v":{"terms":{"field":"verdict"}},"last":{"max":{"field":"last_checked"}}}}}}' \
 | jq -r '.aggregations.t.buckets[] | "  \(.key): \(.doc_count) indicators  (\([.v.buckets[] | "\(.key) \(.doc_count)"] | join(", ")))  newest check \(.last.value_as_string[0:16])"'
L=$(q "$ES/honeypot-ti/_search" -d '{"size":0,"query":{"term":{"indicator_type":"ip"}},"aggs":{"m":{"max":{"field":"last_checked"}}}}' | jq -r '.aggregations.m.value // 0')
AGE=$(( ( $(date +%s%3N) - ${L%.*} ) / 60000 ))
U=$(q "$ES/logs-cowrie-*/_search" -d '{"size":0,"query":{"range":{"@timestamp":{"gte":"now-24h"}}},"aggs":{"i":{"cardinality":{"field":"source.ip"}}}}' | jq .aggregations.i.value)
echo "  newest IP verdict age ................ ${AGE} min  $( [ "$AGE" -le 20 ] && echo OK || echo 'CHECK (runs every 15 min; after a re-import the workflow must be published again)')"
echo "  attacker IPs in the last 24 h ........ $U  (enriched at most 10 per run, ~960/day)"
echo "  failed lookups waiting for retry ..... $(q "$ES/honeypot-ti/_count" -d '{"query":{"exists":{"field":"errors"}}}' | jq .count)"
echo "  malware families:"
q "$ES/honeypot-ti/_search" -d '{"size":0,"query":{"term":{"indicator_type":"sha256"}},"aggs":{"f":{"terms":{"field":"virustotal.family","size":15}}}}' | jq -r '.aggregations.f.buckets[] | "    \(.doc_count)  \(.key)"'
echo "  weekly reports stored ................ $(q "$ES/honeypot-reports/_count" | jq .count)"

echo "================ 3. the n8n key is still least-privilege ================"
printf 'header = "Authorization: ApiKey %s"\n' "$(sudo cat /etc/n8n-secrets/elastic-api-key)" > "$N.k"; chmod 600 "$N.k"
k() { curl -sS --cacert $CA -K "$N.k" -o /dev/null -w '%{http_code}' "$@"; }
echo "  read honeypot events ................. $(ok "$(k "$ES/logs-cowrie-default/_count")" 200)"
echo "  read host logs (must be denied) ...... $(ok "$(k "$ES/logs-system.auth-default/_count")" 403)"
echo "  read Kibana internals (denied) ....... $(ok "$(k "$ES/.kibana/_count")" 403)"
rm -f "$N.k"
echo "WEEK 4 VERIFY DONE"
EOF
