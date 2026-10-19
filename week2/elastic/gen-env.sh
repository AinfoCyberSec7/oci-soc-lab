#!/bin/bash
# Create week2/elastic/.env with fresh random secrets. Run on core-arm, once.
# Never overwrites an existing .env (that would lock you out of the running stack).
# .env is git-ignored and readable by its owner only.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then echo ".env already exists - left unchanged"; exit 0; fi

BIND_IP="${1:-10.10.1.129}"
hex() { openssl rand -hex "$1"; }   # $1 bytes -> 2*$1 hex characters

umask 077
cat > .env <<EOF
# Generated $(date -u +%Y-%m-%dT%H:%MZ) by gen-env.sh - DO NOT COMMIT
BIND_IP=${BIND_IP}
ELASTIC_PASSWORD=$(hex 20)
KIBANA_PASSWORD=$(hex 20)
KIBANA_SECURITY_KEY=$(hex 32)
KIBANA_SAVEDOBJECTS_KEY=$(hex 32)
KIBANA_REPORTING_KEY=$(hex 32)
EOF
echo ".env created ($(wc -l < .env) lines, mode $(stat -c %a .env)); secrets not printed"
