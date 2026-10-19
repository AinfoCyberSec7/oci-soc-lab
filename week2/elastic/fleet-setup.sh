#!/bin/bash
# Configure Fleet in Kibana through its API. Idempotent: safe to re-run.
# Run on core-arm from week2/elastic. Prints no secrets.
#   - Fleet Server URL  : https://BIND_IP:8220
#   - Agent output      : https://BIND_IP:9200, trusting ONLY our private CA (file on every
#                         host at CA_PATH, plus pinned fingerprint)
#   - Policies          : fleet-server-policy (core-arm) and hosts-policy (other Linux hosts),
#                         both with the System integration (auth, syslog, metrics)
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./.env; set +a

CA=$(mktemp); trap 'rm -f "$CA"' EXIT
docker compose exec -T es01 cat config/certs/ca/ca.crt > "$CA"
FP=$(openssl x509 -in "$CA" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
KB="https://${BIND_IP}:5601"
CA_PATH=/etc/elastic-agent-certs/ca.crt   # same path on every agent host
kb() { local m=$1 p=$2; shift 2
  curl -sS --fail-with-body --cacert "$CA" -u "elastic:${ELASTIC_PASSWORD}" \
       -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -X "$m" "${KB}${p}" "$@"; }

echo "== 1/5 Fleet setup"
kb POST /api/fleet/setup | jq -c '{isInitialized}'

echo "== 2/5 Fleet Server host"
if ! kb GET /api/fleet/fleet_server_hosts | jq -e '.items[] | select(.id=="core-arm-fleet")' >/dev/null; then
  kb POST /api/fleet/fleet_server_hosts \
    -d "{\"id\":\"core-arm-fleet\",\"name\":\"core-arm\",\"host_urls\":[\"https://${BIND_IP}:8220\"],\"is_default\":true}" >/dev/null
fi
kb GET /api/fleet/fleet_server_hosts | jq -c '.items[] | {name, host_urls, is_default}'

echo "== 3/5 default output -> Elasticsearch on the private IP, trusting only our CA"
# ES presents only its leaf certificate, so a fingerprint alone cannot be matched by
# the agents; they also need the CA file itself (ssl.certificate_authorities).
OUT=$(jq -n --arg h "https://${BIND_IP}:9200" --arg fp "$FP" --arg ca "$CA_PATH" \
  '{name:"default", type:"elasticsearch", hosts:[$h], ca_trusted_fingerprint:$fp,
    config_yaml:("ssl.certificate_authorities: [\"" + $ca + "\"]"),
    is_default:true, is_default_monitoring:true}')
kb PUT /api/fleet/outputs/fleet-default-output -d "$OUT" | jq -c '.item | {name, hosts, config_yaml}'

echo "== 4/5 agent policies (with System integration)"
mkpol() { # id, name, has_fleet_server, monitoring_enabled(json)
  if kb GET "/api/fleet/agent_policies/$1" >/dev/null 2>&1; then echo "  $1: exists"; return; fi
  kb POST "/api/fleet/agent_policies?sys_monitoring=true" \
    -d "{\"id\":\"$1\",\"name\":\"$2\",\"namespace\":\"default\",\"has_fleet_server\":$3,\"monitoring_enabled\":$4}" >/dev/null
  echo "  $1: created"
}
mkpol fleet-server-policy "Fleet Server (core-arm)" true  '["logs","metrics"]'
mkpol hosts-policy        "Linux hosts"             false '["logs"]'
kb GET "/api/fleet/package_policies?perPage=50" \
  | jq -r '.items[] | "  \((.policy_ids // [.policy_id]) | join(",")) <- \(.package.name) \(.package.version)"' | sort

echo "== 5/5 enrollment token for hosts-policy (value NOT printed)"
kb GET "/api/fleet/enrollment_api_keys?perPage=50" \
  | jq -r '[.items[] | select(.policy_id=="hosts-policy" and .active)] | length | "  active tokens: \(.)"'
echo "FLEET SETUP DONE"
