#!/bin/bash
# Import one or more n8n workflow files from this repo. Run ON core-arm:
#   bash ~/soc-lab/week4/import-workflow.sh week4/workflows/a.json [b.json ...]
# Files containing the placeholder __TELEGRAM_CHAT_ID__ need your Telegram chat ID on stdin;
# it is inserted only in the copy sent into n8n (never printed, never in a command line, never in Git).
# Imported workflows are INACTIVE (re-importing an active one deactivates it): publish them in the UI.
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <workflow.json> [...]"; exit 1; }
cd ~/soc-lab
C=$(cd week4/n8n && docker compose ps -q n8n); [ -n "$C" ] || { echo "n8n is not running"; exit 1; }
CID=""
if grep -q '__TELEGRAM_CHAT_ID__' "$@"; then
  read -r CID || true
  [[ "$CID" =~ ^-?[0-9]{5,15}$ ]] || { echo "STOP: these files need your Telegram chat ID (digits) on stdin"; exit 1; }
fi
for F in "$@"; do
  jq -e '.id and .name and .nodes' "$F" >/dev/null || { echo "not an n8n workflow file: $F"; exit 1; }
  echo "== import: $(jq -r .name "$F") ($(jq '.nodes|length' "$F") nodes, id $(jq -r .id "$F"))"
  # placeholder replaced inside the pipe; the chat ID reaches jq through a file descriptor, not argv
  jq --rawfile cid /dev/fd/3 'walk(if . == "__TELEGRAM_CHAT_ID__" then ($cid | rtrimstr("\n")) else . end)' "$F" 3<<<"$CID" \
    | docker exec -i "$C" sh -c 'umask 077; cat > /dev/shm/wf.json'
  docker exec "$C" sh -c 'n8n import:workflow --input=/dev/shm/wf.json 2>&1; rc=$?; rm -f /dev/shm/wf.json; exit $rc' \
    | { grep -viE 'license SDK|^\s*$' || true; } | tail -1 | sed 's/^/   /'
done
echo "== workflows in n8n (all inactive after import until published)"
docker exec "$C" sh -c 'n8n list:workflow 2>/dev/null' | { grep -v 'license SDK' || true; } | sed 's/^/   /'
echo "   placeholder left in n8n: $(docker exec "$C" sh -c 'n8n export:workflow --all --output=/dev/shm/a.json >/dev/null 2>&1; grep -c __TELEGRAM_CHAT_ID__ /dev/shm/a.json; rm -f /dev/shm/a.json' || true) (expect 0)"
echo "IMPORT DONE"
