#!/bin/bash
# Honeypot forensics from your Mac (tunnel up). Read-only except "preserve" and "utc".
#   bash week3/investigate.sh ip <IPv4>        attacker profile: when, how, credentials, commands, files, alerts
#   bash week3/investigate.sh session <id>     one intrusion start to end + replay of the recorded terminal
#   bash week3/investigate.sh hashes           every captured file: hash, first seen, source, size, file type
#   bash week3/investigate.sh hash <sha256>    pivot on one file: every IP and session that delivered it
#   bash week3/investigate.sh preserve         evidence copy of the raw logs on core-arm, SHA-256 manifest, immutable
#   bash week3/investigate.sh utc              how to show all Kibana times in UTC (forensic standard)
# Everything printed is attacker data: control characters are stripped (no terminal escape injection),
# URLs are defanged. Never run a command or open a URL you see here; look up hashes only.
set -uo pipefail
MODE="${1:-}"; ARG="${2:-}"
die() { echo "$*"; exit 1; }

CORE_PRELUDE='cd ~/soc-lab/week2/elastic && set -a && . ./.env && set +a
N=$(mktemp); trap "rm -f $N" EXIT; chmod 600 $N
printf "machine %s login elastic password %s\n" "$BIND_IP" "$ELASTIC_PASSWORD" > $N
ES="https://$BIND_IP:9200"; KB="https://$BIND_IP:5601"
c() { curl -sS --cacert /etc/elastic-agent-certs/ca.crt --netrc-file $N -H "kbn-xsrf: true" -H "Content-Type: application/json" "$@"; }
q() { c "$ES/logs-cowrie-*/_search" -d "$1"; }
JQDEF='"'"'def clean: tostring | gsub("[[:cntrl:]]"; "·") | .[0:140];
def defang: clean | gsub("(?i)http"; "hxxp") | gsub("\\."; "[.]");
def nolink: clean | gsub("://"; "[://]");'"'"'
'

case "$MODE" in
ip)
  [[ "$ARG" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "usage: $0 ip <IPv4 address>"
  ssh lab-core "IP=$ARG bash -s" <<EOF
$CORE_PRELUDE
echo "================ attacker \$IP (times in UTC) ================"
q '{"size":0,"query":{"term":{"source.ip":"'\$IP'"}},"aggs":{
 "first":{"min":{"field":"@timestamp"}},"last":{"max":{"field":"@timestamp"}},
 "sess":{"cardinality":{"field":"cowrie.session"}},
 "proto":{"terms":{"field":"network.protocol"}},
 "client":{"terms":{"field":"cowrie.version","size":5}},
 "logins":{"filter":{"terms":{"event.action":["cowrie.login.success","cowrie.login.failed"]}},"aggs":{"u":{"terms":{"field":"user.name","size":10},"aggs":{"p":{"terms":{"field":"cowrie.password","size":4},"aggs":{"r":{"terms":{"field":"event.action","size":2}}}}}}}},
 "cmds":{"filter":{"term":{"event.action":"cowrie.command.input"}},"aggs":{"c":{"terms":{"field":"cowrie.input","size":15}}}},
 "files":{"filter":{"terms":{"event.action":["cowrie.session.file_download","cowrie.session.file_upload"]}},"aggs":{"h":{"terms":{"field":"cowrie.shasum","size":10},"aggs":{"u":{"terms":{"field":"cowrie.url","size":1}}}}}},
 "recent":{"terms":{"field":"cowrie.session","size":8,"order":{"t":"desc"}},"aggs":{"t":{"max":{"field":"@timestamp"}},"n":{"filter":{"term":{"event.action":"cowrie.command.input"}}}}}}}' \
| jq -r "\$JQDEF"'
 if .hits.total.value == 0 then "  no events from this IP" else
 .aggregations as \$a |
 "  events \(.hits.total.value)   sessions \(\$a.sess.value)",
 "  first seen \(\$a.first.value_as_string)   last seen \(\$a.last.value_as_string)",
 "  protocols: \([\$a.proto.buckets[] | "\(.key) \(.doc_count)"] | join(", "))",
 "  SSH client: \([\$a.client.buckets[] | "\(.key|clean) (\(.doc_count))"] | join(", ") | if .=="" then "-" else . end)",
 "  credentials (user / password -> result):",
 (\$a.logins.u.buckets[] | .key as \$u | .p.buckets[] | "    \(\$u|clean) / \(.key|clean)  ->  \([.r.buckets[].key | sub("cowrie.login.";"")] | join("+"))  x\(.doc_count)"),
 "  commands (top 15):", (\$a.cmds.c.buckets[] | "    \(.doc_count)\t\(.key|nolink)"),
 "  files:", (\$a.files.h.buckets[] | "    \(.key)  \((.u.buckets[0].key // "uploaded by attacker")|defang)"),
 "  most recent sessions (use: investigate.sh session <id>):",
 (\$a.recent.buckets[] | "    \(.key)  last \(.t.value_as_string)  commands \(.n.doc_count)")
 end'
echo "  alerts raised for this IP:"
c -X POST "\$KB/api/detection_engine/signals/search" -d '{"size":0,"query":{"bool":{"should":[{"term":{"source.ip":"'\$IP'"}},{"term":{"kibana.alert.threshold_result.terms.value":"'\$IP'"}}]}},"aggs":{"r":{"terms":{"field":"kibana.alert.rule.name"}}}}' \
 | jq -r '.aggregations.r.buckets[]? | "    \(.doc_count)  \(.key)"'
EOF
  ;;
session)
  [[ "$ARG" =~ ^[0-9a-f]{8,32}$ ]] || die "usage: $0 session <session id, e.g. 1a2b3c4d5e6f>"
  OUT=$(ssh lab-core "SID=$ARG bash -s" <<EOF
$CORE_PRELUDE
echo "================ session \$SID (times in UTC) ================"
q '{"size":1000,"sort":[{"@timestamp":"asc"}],"query":{"term":{"cowrie.session":"'\$SID'"}}}' \
| jq -r "\$JQDEF"'
 if (.hits.hits|length)==0 then "  no events for this session" else
 .hits.hits[]._source | .cowrie as \$c | (.event.action // "" | sub("cowrie.";"")) as \$e |
 "  \(."@timestamp"[0:19]|sub("T";" "))  \(\$e)\(" " * ([20 - (\$e|length), 1]|max))" +
 (if \$e=="session.connect" then "from \(\$c.src_ip):\(\$c.src_port) to port \(\$c.dst_port) (\(\$c.protocol))"
  elif \$e=="client.version" then (\$c.version|clean)
  elif (\$e|startswith("login.")) then "\(\$c.username|clean) / \(\$c.password|clean)"
  elif (\$e|startswith("command.")) then (\$c.input|nolink)
  elif \$e=="session.file_download" then "\(\$c.url|defang)  sha256 \(\$c.shasum)"
  elif \$e=="session.file_download.failed" then (\$c.url|defang)
  elif \$e=="session.file_upload" then "\(\$c.filename|clean)  sha256 \(\$c.shasum)"
  elif \$e=="log.closed" then "terminal recording, \(\$c.size) bytes\nTTYLOG \(\$c.ttylog)"
  elif \$e=="session.closed" then "duration \((\$c.duration // "-")|clean)s"
  else ((\$c.message // "")|clean) end)
 end'
EOF
)
  echo "$OUT" | grep -v '^TTYLOG '
  for t in $(echo "$OUT" | awk '/^TTYLOG /{print $2}'); do
    [[ "$t" =~ ^var/lib/cowrie/tty/[0-9a-f]{64}$ ]] || { echo "  (skipped unexpected recording path)"; continue; }
    echo "================ replay of the attacker's terminal (output as the attacker saw it, sanitised) ================"
    ssh lab-hp "sudo python3 - /srv/cowrie/$t" <<'PY'
import gzip, re, struct, sys
p = sys.argv[1]
try:
    raw = open(p, "rb").read()
except OSError as e:
    sys.exit(f"  recording not found on the honeypot ({e.strerror})")
if raw[:2] == b"\x1f\x8b":
    raw = gzip.decompress(raw)
HDR = struct.Struct("<iLiiLL")          # Cowrie ttylog: op, tty, length, direction, sec, usec
out, keys, i = [], 0, 0
while i + HDR.size <= len(raw):
    op, _, ln, d, _, _ = HDR.unpack_from(raw, i); i += HDR.size
    data = raw[i:i + ln]; i += ln
    if op == 3 and d == 2: out.append(data)   # write, output
    if op == 3 and d == 1: keys += ln         # write, attacker keystrokes
t = b"".join(out).decode("utf-8", "replace")
t = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b.", "", t)   # strip terminal escapes
t = t.replace("\r\n", "\n").replace("\r", "\n")
t = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", t)
lines = t.split("\n")
for l in lines[:200]:
    print("  | " + l[:160])
if len(lines) > 200:
    print(f"  | ... {len(lines) - 200} more lines")
print(f"  ({keys} keystroke bytes typed by the attacker)")
PY
  done
  ;;
hashes)
  OUT=$(ssh lab-core 'bash -s' <<EOF
$CORE_PRELUDE
q '{"size":0,"query":{"terms":{"event.action":["cowrie.session.file_download","cowrie.session.file_upload"]}},"aggs":{"h":{"terms":{"field":"cowrie.shasum","size":100},"aggs":{"f":{"min":{"field":"@timestamp"}},"ip":{"cardinality":{"field":"source.ip"}},"u":{"terms":{"field":"cowrie.url","size":1}},"n":{"terms":{"field":"cowrie.filename","size":1}}}}}}' \
| jq -r "\$JQDEF"'.aggregations.h.buckets[] | "\(.key)\t\(.f.value_as_string[0:16]|sub("T";" "))\t\(.doc_count)\t\(.ip.value)\t\(if .u.buckets[0].key then (.u.buckets[0].key|defang) else "uploaded by attacker as \"\((.n.buckets[0].key // "?")|clean)\"" end)"'
EOF
)
  [ -n "$OUT" ] || die "no captured files yet"
  HASHES=$(echo "$OUT" | cut -f1 | grep -E '^[0-9a-f]{64}$' | tr '\n' ' ')
  INFO=$(ssh lab-hp "sudo bash -s $HASHES" <<'EOF'
# file type is read as Cowrie's unprivileged uid, never as root (the samples are hostile input)
for h in "$@"; do f=/srv/cowrie/var/lib/cowrie/downloads/$h
  if [ -f "$f" ]; then echo -e "$h\t$(stat -c %s "$f") bytes\t$(setpriv --reuid=20999 --regid=20999 --clear-groups file -b "$f" 2>&1 | cut -c1-60)"; else echo -e "$h\t-\tnot stored (empty or duplicate)"; fi
done
EOF
)
  echo "================ captured files (times in UTC; samples stay on the honeypot) ================"
  echo "$OUT" | while IFS=$'\t' read -r h first n ips src; do
    meta=$(echo "$INFO" | awk -F'\t' -v h="$h" '$1==h{print $2"  "$3}')
    echo "  $h"
    echo "     first $first   seen $n x from $ips IP(s)   $meta"
    echo "     source: $src"
    echo "     lookup: https://www.virustotal.com/gui/file/$h"
  done
  ;;
hash)
  [[ "$ARG" =~ ^[0-9a-f]{64}$ ]] || die "usage: $0 hash <sha256 from the hashes list>"
  ssh lab-core "H=$ARG bash -s" <<EOF
$CORE_PRELUDE
echo "================ file \${H:0:16}... (times in UTC) ================"
q '{"size":0,"query":{"bool":{"filter":[{"term":{"cowrie.shasum":"'\$H'"}},{"terms":{"event.action":["cowrie.session.file_download","cowrie.session.file_upload"]}}]}},"aggs":{
 "first":{"min":{"field":"@timestamp"}},"last":{"max":{"field":"@timestamp"}},
 "ip":{"terms":{"field":"source.ip","size":20},"aggs":{"s":{"cardinality":{"field":"cowrie.session"}},"f":{"min":{"field":"@timestamp"}},"l":{"max":{"field":"@timestamp"}}}},
 "name":{"terms":{"field":"cowrie.filename","size":5}},"url":{"terms":{"field":"cowrie.url","size":5}}}}' \
| jq -r "\$JQDEF"'.aggregations as \$a |
 "  delivered \(.hits.total.value) times between \(\$a.first.value_as_string) and \(\$a.last.value_as_string)",
 "  as file name: \([\$a.name.buckets[].key|clean] | join(", ") | if .=="" then "-" else . end)",
 "  from URL:     \([\$a.url.buckets[].key|defang] | join(", ") | if .=="" then "- (uploaded directly)" else . end)",
 "  delivered by (IP, deliveries, sessions, first -> last):",
 (\$a.ip.buckets[] | "    \(.key)\t\(.doc_count)\t\(.s.value)\t\(.f.value_as_string[0:16]) -> \(.l.value_as_string[0:16])")'
EOF
  ;;
preserve)
  ssh lab-core 'sudo bash -s' <<'EOF'
set -euo pipefail
B=/var/lib/honeypot-evidence
D=$B/$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$B" "$D"
cp -p /var/log/honeypot/cowrie/cowrie.json* "$D/"
( cd "$D" && sha256sum cowrie.json* > MANIFEST.sha256 )
echo "collected $(date -u +%FT%TZ) on core-arm from /var/log/honeypot/cowrie (pulled read-only from hp-cowrie)" > "$D/README.txt"
echo "================ evidence preservation (times in UTC) ================"
# lock every collection that is not locked yet (includes one left unlocked by an earlier failed run)
for d in "$B"/*/; do d=${d%/}
  [ -f "$d/MANIFEST.sha256" ] || { echo "  $d: no manifest - incomplete, left as is"; continue; }
  if lsattr "$d/MANIFEST.sha256" 2>/dev/null | cut -c1-20 | grep -q i; then echo "  $(basename "$d"): already locked"; continue; fi
  if ( cd "$d" && sha256sum -c --quiet MANIFEST.sha256 ); then
    chmod 0400 "$d"/*; chattr +i "$d"/*
    echo "  $(basename "$d"): $(ls "$d" | grep -c cowrie.json) log files, $(du -sh "$d" | cut -f1), manifest sha256 $(sha256sum "$d/MANIFEST.sha256" | cut -c1-16)...  integrity OK, now read-only + immutable"
  else
    echo "  $(basename "$d"): MANIFEST MISMATCH - not locked, investigate"
  fi
done
echo "  verify any time:  sudo sh -c 'cd $D && sha256sum -c MANIFEST.sha256'"
EOF
  ;;
utc)
  echo "  Kibana 9 does not allow this setting through its public API. In the browser:"
  echo "  Stack Management > Advanced Settings > search 'Timezone for date formatting' > UTC > Save"
  ;;
*) sed -n '2,9p' "$0"; exit 1 ;;
esac
