#!/bin/bash
# Did any attacker get further than the fake shell? Run on your Mac from the repo root (tunnel up):
#   bash week3/check-attacks.sh            (default: last 24 hours)
#   HOURS=6 bash week3/check-attacks.sh
# Read-only: changes nothing. Part 1 hunts for signs of a REAL compromise of the honeypot host.
# Part 2 summarises what attackers did INSIDE Cowrie (attacker data: never run or open any of it).
# The admin egress IP is excluded from part 2 and is never printed.
cd "$(dirname "$0")/.." || exit 1
HOURS="${HOURS:-24}"
ADMIN=$(grep -E '^admin_cidr' terraform.tfvars 2>/dev/null | cut -d'"' -f2 | cut -d/ -f1)

echo "================ 1. Real host: any sign of a breakout? (hp-cowrie, last ${HOURS}h) ================"
# the only keys allowed on the honeypot: your admin key and core-arm's pull key
KEYS="$(ssh-keygen -lf ~/.ssh/oci_lab.pub | awk '{print $2}') $(ssh lab-core 'sudo ssh-keygen -lf /etc/hppull/id_ed25519.pub' | awk '{print $2}')"
ssh lab-hp "sudo HOURS=$HOURS KEYS='$KEYS' bash -s" <<'EOF'
flag() { if [ "$1" = "$2" ]; then echo "OK"; else echo "CHECK"; fi; }
echo "  real sshd logins (port 22222), by source  [expect only 10.10.1.129]:"
journalctl _COMM=sshd --since "$HOURS hours ago" --no-pager 2>/dev/null | grep 'Accepted ' \
  | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | awk '{print "    "$1"  "$2}'
F=$(journalctl _COMM=sshd --since "$HOURS hours ago" --no-pager 2>/dev/null | grep -cE 'Failed|Invalid user')
echo "  real sshd failed attempts ............ $F  $(flag "$F" 0)"
echo "  users logged in right now:"; who | awk '{print "    "$1"  "$2"  "$5}'; [ -z "$(who)" ] && echo "    (nobody)"
echo "  accounts with a login shell  [expect root ubuntu logpull; opc is locked]:"
echo "    $(awk -F: '$7 !~ /(nologin|false|sync)$/{printf "%s ", $1}' /etc/passwd)"
U=0
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /var/lib/logpull/.ssh/authorized_keys; do
  [ -s "$f" ] || continue
  for fp in $(ssh-keygen -lf "$f" 2>/dev/null | awk '{print $2}'); do
    case " $KEYS " in *" $fp "*) ;; *) U=$((U+1)); echo "    UNKNOWN key in $f: $fp";; esac
  done
done
echo "  unknown SSH keys on the host ......... $U  $(flag "$U" 0)"
N=$(ps -o comm= -u 20999 | sort -u | tr '\n' ' ')
echo "  real processes run by Cowrie's uid ... $N  [expect only twistd/python]"
echo "  files changed inside the container ... $(docker diff cowrie | wc -l)  $(flag "$(docker diff cowrie | wc -l)" 0)"
echo "  container image still the pinned one . $(flag "$(docker inspect cowrie --format '{{.Image}}')" "$(docker image inspect cowrie/cowrie@sha256:797d45ca8823d313bec0994232b982f3b99412d4e68e234608d6c1f78d32e3fe --format '{{.Id}}')")"
D=/srv/cowrie/var/lib/cowrie/downloads
echo "  captured files ....................... $(find $D -type f | wc -l)   executable: $(find $D -type f -perm /111 | wc -l)  $(flag "$(find $D -type f -perm /111 | wc -l)" 0)"
echo "  listening ports on the host  [expect 22 23 22222 + local DNS]:"
echo "    $(ss -tulnH | awk '{n=split($5,a,":"); print a[n]"/"$1}' | sort -t/ -k1,1n -u | tr '\n' ' ')"
echo "  established connections made by the host itself (not attacker sessions):"
ss -tnpH state established | grep -vE 'docker-proxy|sshd' | awk '{print "    "$3" -> "$4"  "$5}' | head -10
[ -z "$(ss -tnpH state established | grep -vE 'docker-proxy|sshd')" ] && echo "    (none)"
echo "  blocked attempts towards the lab (packets since boot; includes our own isolation tests):"
echo "    host:       $(iptables -L OUTPUT -v -n | awk '/10.10.0.0\/16/ && /REJECT/{s+=$1} END{print s+0}')"
echo "    containers: $(iptables -L DOCKER-USER -v -n | awk '/10.10.0.0\/16/ && /REJECT/{s+=$1} END{print s+0}')"
echo "  fail2ban currently banned on 22222 ... $(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/{gsub(/ /,"",$2); print $2}')"
EOF

echo "================ 2. Inside the fake shell: what attackers did (Cowrie, last ${HOURS}h) ================"
ssh lab-core "HOURS=$HOURS ADMIN=$ADMIN bash -s" <<'EOF'
cd ~/soc-lab/week2/elastic && set -a && . ./.env && set +a
CA=/etc/elastic-agent-certs/ca.crt; ES=https://10.10.1.129:9200; KB=https://10.10.1.129:5601
q() { curl -sS --cacert $CA -u "elastic:$ELASTIC_PASSWORD" -H "Content-Type: application/json" -H "kbn-xsrf: true" "$@"; }
F="{\"bool\":{\"filter\":[{\"range\":{\"@timestamp\":{\"gte\":\"now-${HOURS}h\"}}}],\"must_not\":[{\"term\":{\"source.ip\":\"${ADMIN:-0.0.0.0}\"}}]}}"
R=$(q "$ES/logs-cowrie-*/_search" -d "{\"size\":0,\"query\":$F,\"aggs\":{
  \"ips\":{\"cardinality\":{\"field\":\"source.ip\"}},
  \"act\":{\"terms\":{\"field\":\"event.action\",\"size\":30}},
  \"proto\":{\"terms\":{\"field\":\"network.protocol\"}},
  \"top\":{\"terms\":{\"field\":\"source.ip\",\"size\":5}},
  \"shells\":{\"filter\":{\"term\":{\"event.action\":\"cowrie.command.input\"}},\"aggs\":{\"s\":{\"cardinality\":{\"field\":\"cowrie.session\"}},\"i\":{\"cardinality\":{\"field\":\"source.ip\"}}}},
  \"logins\":{\"filter\":{\"term\":{\"event.action\":\"cowrie.login.success\"}},\"aggs\":{\"i\":{\"cardinality\":{\"field\":\"source.ip\"}}}}}}")
echo "$R" | jq -r '"  events: \(.hits.total.value)   unique attacker IPs: \(.aggregations.ips.value)",
  "  protocols: \([.aggregations.proto.buckets[] | "\(.key) \(.doc_count)"] | join(", "))",
  "  attacker IPs that got a fake-shell login: \(.aggregations.logins.i.value)",
  "  attacker IPs that typed commands: \(.aggregations.shells.i.value)  (in \(.aggregations.shells.s.value) sessions)",
  "  events by type:", (.aggregations.act.buckets[] | "    \(.doc_count)\t\(.key)"),
  "  top 5 attacker IPs (events):", (.aggregations.top.buckets[] | "    \(.doc_count)\t\(.key)")'
echo "  files fetched (defanged):"
q "$ES/logs-cowrie-*/_search" -d "{\"size\":0,\"query\":{\"bool\":{\"filter\":[{\"range\":{\"@timestamp\":{\"gte\":\"now-${HOURS}h\"}}},{\"term\":{\"event.action\":\"cowrie.session.file_download\"}}]}},\"aggs\":{\"u\":{\"terms\":{\"field\":\"cowrie.url\",\"size\":8}}}}" \
  | jq -r '.aggregations.u.buckets[]? | "    \(.doc_count)\t\(.key)"' | sed -e 's/http/hxxp/' -e 's/\./[.]/g' | cut -c1-100
echo "  alerts per rule:"
q -X POST "$KB/api/detection_engine/signals/search" -d "{\"size\":0,\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"now-${HOURS}h\"}}},\"aggs\":{\"r\":{\"terms\":{\"field\":\"kibana.alert.rule.name\"}}}}" \
  | jq -r '.aggregations.r.buckets[]? | "    \(.doc_count)\t\(.key)"'
EOF
echo "CHECK ATTACKS DONE"
