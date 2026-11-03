#!/bin/bash
# Ingest the pulled Cowrie logs into Elastic: adds a "Custom Logs (Filestream)" integration
# to core-arm's Fleet policy. Idempotent (creates or updates "honeypot-cowrie").
# Run ON core-arm from ~/soc-lab/week2/elastic (needs its .env). Prints no secrets.
#  - reads /var/log/honeypot/cowrie/cowrie.json* (filled every minute by hppull.timer)
#  - each line parsed as JSON under "cowrie.*"; data stream logs-cowrie-default
#  - Cowrie's own timestamp becomes @timestamp; key fields copied to ECS names
#    (source.ip, user.name, event.action) so detections and maps work
#  - file identity by content fingerprint (default): rsync replaces the file every minute,
#    the fingerprint stops it from being re-read from the start (no duplicates)
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a
CA=/etc/elastic-agent-certs/ca.crt
KB="https://${BIND_IP}:5601"
ES="https://${BIND_IP}:9200"
NAME=honeypot-cowrie
kb() { curl -sS --cacert "$CA" -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' "$@"; }

PARSERS='- ndjson:
    target: "cowrie"
    add_error_key: true'

PROCESSORS='- timestamp:
    field: cowrie.timestamp
    layouts:
      - "2006-01-02T15:04:05.999999Z"
      - "2006-01-02T15:04:05Z"
    test:
      - "2026-11-02T23:21:36.397449Z"
    ignore_failure: true
- copy_fields:
    fields:
      - from: cowrie.src_ip
        to: source.ip
      - from: cowrie.src_port
        to: source.port
      - from: cowrie.username
        to: user.name
      - from: cowrie.eventid
        to: event.action
      - from: cowrie.protocol
        to: network.protocol
    fail_on_error: false
    ignore_missing: true
- add_fields:
    target: observer
    fields:
      name: hp-cowrie
      type: honeypot'

BODY=$(jq -n --arg name "$NAME" --arg parsers "$PARSERS" --arg processors "$PROCESSORS" '{
  name: $name,
  description: "Cowrie honeypot events pulled read-only from the isolated honeypot VCN",
  namespace: "default",
  policy_ids: ["fleet-server-policy"],
  package: { name: "filestream", version: "2.5.1" },
  inputs: { "filestream-filestream": { enabled: true, streams: { "filestream.filestream": {
    enabled: true,
    vars: {
      paths: ["/var/log/honeypot/cowrie/cowrie.json*"],
      "data_stream.dataset": "cowrie",
      parsers: $parsers,
      processors: $processors,
      tags: ["honeypot", "cowrie"]
    } } } } }
}')

echo "== 1/3 create or update the integration"
ID=$(kb "$KB/api/fleet/package_policies?perPage=100" | jq -r --arg n "$NAME" '.items[] | select(.name==$n) | .id' | head -1)
if [ -n "$ID" ]; then
  RES=$(kb -X PUT "$KB/api/fleet/package_policies/$ID" -d "$BODY"); ACTION=updated
else
  RES=$(kb -X POST "$KB/api/fleet/package_policies" -d "$BODY"); ACTION=created
fi
echo "$RES" | jq -e '.item.id' >/dev/null || { echo "FAILED:"; echo "$RES" | jq -c '{statusCode, error, message}'; exit 1; }
echo "$RES" | jq -c --arg a "$ACTION" '{action: $a, name: .item.name, policy: .item.policy_ids, package: "\(.item.package.name) \(.item.package.version)"}'

echo "== 2/3 waiting 120 s for the agent to apply the policy and read the files"
sleep 120

echo "== 3/3 what arrived in Elasticsearch"
Q() { curl -sS --cacert "$CA" -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' "$@"; }
echo "   documents in logs-cowrie-default: $(Q "$ES/logs-cowrie-default/_count" | jq -r '.count // "none yet"')"
echo "   lines in the pulled files:        $(sudo sh -c 'cat /var/log/honeypot/cowrie/cowrie.json*' | wc -l)"
echo "   newest event (key fields only):"
Q "$ES/logs-cowrie-default/_search?size=1&sort=@timestamp:desc" \
  | jq -c '.hits.hits[0]._source | {"@timestamp", source_ip: .source.ip, action: .event.action, proto: .network.protocol, observer: .observer.name, parse_error: .error.message}'
echo "COWRIE INGEST DONE"
