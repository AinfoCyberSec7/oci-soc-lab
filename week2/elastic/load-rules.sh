#!/bin/bash
# Load detection rules from rules/*.json into Kibana (detection-as-code). Idempotent:
# a rule whose rule_id already exists is updated in place, otherwise created.
# Run on core-arm from week2/elastic. Prints no secrets.
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a
CA=/etc/elastic-agent-certs/ca.crt
KB="https://${BIND_IP}:5601/api/detection_engine/rules"
kb() { curl -sS --cacert "$CA" -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' \
            -H 'Content-Type: application/json' "$@"; }

for f in rules/*.json; do
  jq -e . "$f" >/dev/null || { echo "invalid JSON: $f"; exit 1; }
  id=$(jq -r .rule_id "$f")
  if kb -o /dev/null -w '%{http_code}' "$KB?rule_id=$id" | grep -q '^200$'; then
    res=$(kb -X PUT "$KB" -d @"$f")
    action=updated
  else
    res=$(kb -X POST "$KB" -d @"$f")
    action=created
  fi
  echo "$res" | jq -e '.rule_id' >/dev/null \
    || { echo "FAILED $f:"; echo "$res" | jq -c '{status_code, message}'; exit 1; }
  echo "$res" | jq -c --arg a "$action" '{action: $a, rule_id, name, enabled, type, threshold: .threshold.value, interval}'
done
echo "RULES LOADED"
