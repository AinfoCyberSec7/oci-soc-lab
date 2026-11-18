#!/bin/bash
# Week 4, step 2: Elastic side of the threat-intel automation. Run ON core-arm:
#   bash ~/soc-lab/week4/elastic-ti-setup.sh
# 1. creates the two indices n8n writes to (honeypot-ti = one cached verdict per IP/hash,
#    honeypot-reports = weekly reports), with explicit mappings
# 2. creates a least-privilege API key for n8n (NOT the elastic superuser):
#      read  logs-cowrie-*, .alerts-security.alerts-*      write  honeypot-ti, honeypot-reports
#    no cluster rights, nothing else readable. Expires after 365 days.
# 3. proves the limits: allowed calls work, everything else gets 403
# The key is stored root-only in /etc/n8n-secrets/elastic-api-key and is never printed.
# Safe to re-run: indices are left as they are; an existing key is kept unless ROTATE=1.
set -euo pipefail
cd ~/soc-lab/week2/elastic
set -a; . ./.env; set +a
CA=/etc/elastic-agent-certs/ca.crt; ES="https://${BIND_IP}:9200"
SEC=/etc/n8n-secrets; KEYF=$SEC/elastic-api-key
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT; chmod 700 "$T"
printf 'machine %s login elastic password %s\n' "$BIND_IP" "$ELASTIC_PASSWORD" > "$T/netrc"
es() { curl -sS --cacert "$CA" --netrc-file "$T/netrc" -H 'Content-Type: application/json' "$@"; }

echo "== 1/3 indices"
mk() {  # $1 index, $2 mapping file
  if [ "$(es -o /dev/null -w '%{http_code}' -I "$ES/$1")" = 200 ]; then echo "   $1: exists, left unchanged"
  else es -X PUT "$ES/$1" -d @"$2" | jq -c --arg i "$1" '{index: $i, created: .acknowledged}' | sed 's/^/   /'; fi
}
cat > "$T/ti.json" <<'EOF'
{"settings":{"number_of_shards":1,"number_of_replicas":0},
 "mappings":{"dynamic":true,"properties":{
  "indicator":{"type":"keyword"},"indicator_type":{"type":"keyword"},
  "first_seen":{"type":"date"},"last_checked":{"type":"date"},"verdict":{"type":"keyword"},
  "abuseipdb":{"properties":{"score":{"type":"integer"},"total_reports":{"type":"integer"},"country":{"type":"keyword"},"isp":{"type":"keyword"},"usage_type":{"type":"keyword"},"domain":{"type":"keyword"}}},
  "greynoise":{"properties":{"classification":{"type":"keyword"},"noise":{"type":"boolean"},"riot":{"type":"boolean"},"name":{"type":"keyword"},"last_seen":{"type":"keyword"}}},
  "otx":{"properties":{"pulse_count":{"type":"integer"},"pulses":{"type":"keyword"},"tags":{"type":"keyword"}}},
  "virustotal":{"properties":{"malicious":{"type":"integer"},"suspicious":{"type":"integer"},"undetected":{"type":"integer"},"family":{"type":"keyword"},"type":{"type":"keyword"},"names":{"type":"keyword"},"first_submission":{"type":"date"}}},
  "errors":{"type":"keyword"}}}}
EOF
cat > "$T/reports.json" <<'EOF'
{"settings":{"number_of_shards":1,"number_of_replicas":0},
 "mappings":{"dynamic":true,"properties":{
  "@timestamp":{"type":"date"},"period_start":{"type":"date"},"period_end":{"type":"date"},
  "events":{"type":"long"},"attacker_ips":{"type":"long"},"sessions":{"type":"long"},
  "summary":{"type":"text"}}}}
EOF
mk honeypot-ti "$T/ti.json"
mk honeypot-reports "$T/reports.json"

echo "== 2/3 least-privilege API key for n8n"
sudo install -d -o root -g root -m 0700 "$SEC"
if sudo test -s "$KEYF" && [ "${ROTATE:-0}" != 1 ]; then
  echo "   key already stored in $KEYF - kept (ROTATE=1 to replace)"
else
  cat > "$T/key.json" <<'EOF'
{"name":"n8n-threat-intel","expiration":"365d",
 "metadata":{"purpose":"n8n threat-intel enrichment (SOC lab week 4)","managed_by":"elastic-ti-setup.sh"},
 "role_descriptors":{"n8n_threat_intel":{"cluster":[],"indices":[
  {"names":["logs-cowrie-*"],"privileges":["read","view_index_metadata"]},
  {"names":[".alerts-security.alerts-*"],"privileges":["read"]},
  {"names":["honeypot-ti","honeypot-reports"],"privileges":["read","write","view_index_metadata"]}]}}}
EOF
  es -X POST "$ES/_security/api_key" -d @"$T/key.json" > "$T/key.out"
  jq -e '.encoded' "$T/key.out" >/dev/null || { echo "   FAILED:"; jq -c '{error: .error.type, reason: .error.reason}' "$T/key.out"; exit 1; }
  jq -r '.encoded' "$T/key.out" | sudo tee "$KEYF" >/dev/null; sudo chmod 0600 "$KEYF"
  echo "   created key \"$(jq -r .name "$T/key.out")\" id $(jq -r .id "$T/key.out"), expires $(date -u -d "@$(( $(jq -r .expiration "$T/key.out") / 1000 ))" +%F)"
  echo "   stored in $KEYF ($(sudo stat -c '%U:%G %a' "$KEYF")), not printed"
fi

echo "== 3/3 prove the limits (as the new key)"
printf 'header = "Authorization: ApiKey %s"\n' "$(sudo cat "$KEYF")" > "$T/keyhdr"
k() { curl -sS --cacert "$CA" -K "$T/keyhdr" -H 'Content-Type: application/json' -o /dev/null -w '%{http_code}' "$@"; }
kc() { curl -sS --cacert "$CA" -K "$T/keyhdr" "$1" | jq -r '.count // "-"'; }
chk() { printf '   %-46s %s  %s\n' "$1" "$2" "$( [ "$2" = "$3" ] && echo OK || echo "CHECK (expected $3)")"; }
# concrete names on purpose: a wildcard would silently skip forbidden indices instead of returning 403
chk "read honeypot events (logs-cowrie-default)" "$(k "$ES/logs-cowrie-default/_count")" 200
echo "      -> $(kc "$ES/logs-cowrie-default/_count") events visible"
chk "read detection alerts"                      "$(k "$ES/.alerts-security.alerts-default/_count")" 200
echo "      -> $(kc "$ES/.alerts-security.alerts-default/_count") alerts visible"
chk "write a test verdict to honeypot-ti"        "$(k -X PUT "$ES/honeypot-ti/_doc/selftest?refresh=true" -d '{"indicator":"selftest","indicator_type":"test"}')" 201
chk "delete the test verdict"                    "$(k -X DELETE "$ES/honeypot-ti/_doc/selftest")" 200
chk "read host logs (logs-system.auth) - denied"  "$(k "$ES/logs-system.auth-default/_count")" 403
chk "read Kibana internals (.kibana) - denied"   "$(k "$ES/.kibana/_count")" 403
chk "create a new index - denied"                "$(k -X PUT "$ES/n8n-should-not-exist")" 403
chk "cluster settings - denied"                  "$(k "$ES/_cluster/settings")" 403
chk "manage users - denied"                      "$(k "$ES/_security/user")" 403
echo "TI SETUP DONE"
