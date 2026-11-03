#!/bin/bash
# Import the "Honeypot SOC - live" Kibana dashboard (and its data view, panels and saved search).
# Run ON core-arm:   bash ~/soc-lab/week3/import-dashboard.sh
# Safe to re-run: objects are overwritten by their fixed ids. Prints no secrets.
set -euo pipefail
cd "$(dirname "$0")"
ENVF=~/soc-lab/week2/elastic/.env
set -a; . "$ENVF"; set +a
CA=/etc/elastic-agent-certs/ca.crt; KB="https://${BIND_IP}:5601"; ES="https://${BIND_IP}:9200"
N=$(mktemp); trap 'rm -f "$N"' EXIT; chmod 600 "$N"
printf 'machine %s login elastic password %s\n' "$BIND_IP" "$ELASTIC_PASSWORD" > "$N"
c() { curl -sS --cacert "$CA" --netrc-file "$N" -H 'kbn-xsrf: true' "$@"; }

echo "== 1/2 import"
R=$(c -X POST "$KB/api/saved_objects/_import?overwrite=true" -F "file=@dashboard/honeypot-dashboard.ndjson")
echo "$R" | jq -c '{success, successCount}'
echo "$R" | jq -r '.errors[]? | "   ERROR \(.type) \(.id): \(.error.type) \(.error.message // "")"'

echo "== 2/2 fields the panels use (documents that have each one)"
for f in source.ip network.protocol event.action user.name cowrie.password cowrie.input cowrie.url cowrie.shasum cowrie.session cowrie.version; do
  printf '   %-18s %s\n' "$f" "$(c -H 'Content-Type: application/json' "$ES/logs-cowrie-*/_count" -d "{\"query\":{\"exists\":{\"field\":\"$f\"}}}" | jq .count)"
done
echo "   open: ${KB}/app/dashboards#/view/honeypot-soc"
echo "IMPORT DONE"
