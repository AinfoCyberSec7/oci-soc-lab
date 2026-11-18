#!/bin/bash
# Mark IPs that must NEVER be sent to threat-intel providers (e.g. your own admin egress IP).
# Run from your Mac; the IP comes from your git-ignored terraform.tfvars and travels only via stdin:
#   grep '^admin_cidr' terraform.tfvars | cut -d'"' -f2 | cut -d/ -f1 | ssh lab-core 'bash ~/soc-lab/week4/ti-allowlist.sh'
# Stores an "allowlist" verdict in honeypot-ti; the enrichment workflow skips those IPs.
# The IP itself is never printed and never written to Git.
set -euo pipefail
read -r IP || true
[[ "${IP:-}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "expected one IPv4 address on stdin"; exit 1; }
cd ~/soc-lab/week2/elastic && set -a && . ./.env && set +a
N=$(mktemp); trap 'rm -f "$N"' EXIT; chmod 600 "$N"
printf 'machine %s login elastic password %s\n' "$BIND_IP" "$ELASTIC_PASSWORD" > "$N"
# the IP travels via stdin only (jq input, request body), never in a command line or URL
printf '%s\n' "$IP" | jq -Rc '. as $ip | {index:{_id:("ip:"+$ip)}}, {indicator:$ip, indicator_type:"ip", verdict:"allowlist", note:"own address - never sent to threat-intel providers", last_checked:(now|todate)}' \
 | curl -sS --cacert /etc/elastic-agent-certs/ca.crt --netrc-file "$N" -H 'Content-Type: application/x-ndjson' \
     -X POST "https://$BIND_IP:9200/honeypot-ti/_bulk?refresh=true" --data-binary @- \
 | jq -r '"   allowlist entry: \(.items[0].index.result // .items[0].index.error.type // .error.type)  (IP not printed)"'
