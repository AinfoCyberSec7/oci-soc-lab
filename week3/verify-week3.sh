#!/bin/bash
# Week 3 end-to-end check. Run on your Mac from the repo root, with the tunnel up:
#   bash week3/verify-week3.sh
# Read-only: changes nothing anywhere. Prints no secrets and no public IPs.
# Each line ends in OK or CHECK; anything marked CHECK deserves a look.
cd "$(dirname "$0")/.." || exit 1
ok() { if [ "$1" = "$2" ]; then echo "OK"; else echo "CHECK (got: $1)"; fi; }

echo "================ 1. Honeypot host (hp-cowrie) ================"
ssh lab-hp 'sudo bash -s' <<'EOF'
ok() { if [ "$1" = "$2" ]; then echo "OK"; else echo "CHECK (got: $1)"; fi; }
S=$(docker inspect cowrie --format '{{.State.Status}}' 2>/dev/null)
echo "  cowrie container running ............ $(ok "$S" running)"
echo "    user=$(docker inspect cowrie --format '{{.Config.User}}') read-only=$(docker inspect cowrie --format '{{.HostConfig.ReadonlyRootfs}}') caps-dropped=$(docker inspect cowrie --format '{{.HostConfig.CapDrop}}') restarts=$(docker inspect cowrie --format '{{.RestartCount}}')"
P=$(ss -tlnpH | awk '/sshd/{split($4,a,":"); print a[length(a)]}' | sort -u | tr '\n' ' ' | sed 's/ $//')
echo "  real sshd only on 22222 ............. $(ok "$P" 22222)"
for u in docker-user-guard fail2ban unattended-upgrades; do
  printf '  %-36s %s\n' "service $u" "$(ok "$(systemctl is-active $u)" active)"
done
R1=$(iptables -S OUTPUT | grep -c '10.10.0.0/16.*REJECT')
R2=$(iptables -S DOCKER-USER | grep -c '10.10.0.0/16.*REJECT')
echo "  host -> lab blocked (iptables) ...... $( [ "$R1" -ge 1 ] && echo OK || echo CHECK )"
echo "  containers -> lab blocked ........... $( [ "$R2" -ge 1 ] && echo OK || echo CHECK )"
for port in 22 5601 8220 9200; do
  if timeout 3 bash -c "</dev/tcp/10.10.1.129/$port" 2>/dev/null; then r="CHECK (OPEN)"; else r=OK; fi
  printf '  honeypot -> core-arm:%-5s refused ... %s\n' "$port" "$r"
done
D=/srv/cowrie/var/lib/cowrie/downloads
echo "  captured files: $(find $D -type f | wc -l)  ($(du -sh $D | cut -f1))  - kept on the honeypot, never opened"
echo "  disk /: $(df -h / | awk 'NR==2{print $5" used"}')   memory: $(free -m | awk '/Mem/{print $3"/"$2" MB"}')"
EOF

echo "================ 2. core-arm: pull, ingest, detections ================"
ssh lab-core 'bash -s' <<'EOF'
ok() { if [ "$1" = "$2" ]; then echo "OK"; else echo "CHECK (got: $1)"; fi; }
cd ~/soc-lab/week2/elastic && set -a && . ./.env && set +a
CA=/etc/elastic-agent-certs/ca.crt; ES=https://10.10.1.129:9200; KB=https://10.10.1.129:5601
q() { curl -sS --cacert $CA -u "elastic:$ELASTIC_PASSWORD" -H "Content-Type: application/json" -H "kbn-xsrf: true" "$@"; }
echo "  hppull.timer active ................. $(ok "$(systemctl is-active hppull.timer)" active)"
echo "  last pull succeeded ................. $(ok "$(systemctl show hppull.service -p Result --value)" success)"
STORED=$(q "$ES/logs-cowrie-*/_count" | jq .count)
DISK=$(sudo sh -c 'cat /var/log/honeypot/cowrie/cowrie.json*' | wc -l)
echo "  stored vs on disk ................... $STORED / $DISK  ($(( DISK - STORED )) behind)"
NEWEST=$(q "$ES/logs-cowrie-*/_search?size=1&sort=@timestamp:desc&_source=@timestamp" | jq -r '.hits.hits[0]._source["@timestamp"]')
AGE=$(( $(date +%s) - $(date -d "$NEWEST" +%s) ))
echo "  newest event age .................... ${AGE}s  $( [ "$AGE" -lt 600 ] && echo OK || echo 'CHECK (older than 10 min)')"
ERR=$(q "$ES/logs-cowrie-*/_count" -d '{"query":{"exists":{"field":"error.message"}}}' | jq .count)
echo "  parse errors ........................ $(ok "$ERR" 0)"
echo "  Fleet agents:"
q "$KB/api/fleet/agents?perPage=20" | jq -r '.items[] | "    \(.local_metadata.host.hostname)  \(.status)"'
echo "  detection rules (enabled / last run):"
q "$KB/api/detection_engine/rules/_find?per_page=50" | jq -r '.data[] | "    \(if .enabled then "on " else "OFF" end)  \(.execution_summary.last_execution.status // "not run yet")  \(.name)"'
echo "  alerts per rule, last 24h:"
q -X POST "$KB/api/detection_engine/signals/search" -d '{"size":0,"query":{"range":{"@timestamp":{"gte":"now-24h"}}},"aggs":{"r":{"terms":{"field":"kibana.alert.rule.name"}}}}' \
  | jq -r '.aggregations.r.buckets[]? | "    \(.doc_count)  \(.key)"'
echo "  file transfers since the rules were loaded (the download rule only looks forward):"
q "$ES/logs-cowrie-*/_count" -d '{"query":{"bool":{"filter":[{"terms":{"event.action":["cowrie.session.file_download","cowrie.session.file_upload"]}},{"range":{"@timestamp":{"gte":"now-1h"}}}]}}}' \
  | jq -r '"    \(.count) in the last hour"'
EOF

echo "================ 3. Terraform: infrastructure matches the code ================"
terraform plan -detailed-exitcode -no-color -input=false -lock=false >/dev/null 2>&1
case $? in 0) echo "  terraform plan: no changes ........... OK";;
           2) echo "  terraform plan: DRIFT - run terraform plan to see it ... CHECK";;
           *) echo "  terraform plan: error - run terraform plan to see it ... CHECK";; esac
echo "WEEK 3 VERIFY DONE"
