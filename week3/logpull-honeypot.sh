#!/bin/bash
# Honeypot side of the one-way log pull. Run ON the honeypot as ubuntu, with
# core-arm's PUBLIC key on stdin:   <pubkey> | bash logpull-honeypot.sh [core_ip]
# Result: user "logpull" whose key works only from core-arm, only for a READ-ONLY
# rsync of the Cowrie log folder (no shell, no forwarding, no writes).
# Read access is granted with ACLs, NOT via Cowrie's group: that group can write the logs.
set -euo pipefail
CORE_IP="${1:-10.10.1.129}"
SRC=/srv/cowrie/var/log/cowrie
RRSYNC=/usr/bin/rrsync

read -r PUBKEY || true
case "${PUBKEY:-}" in ssh-ed25519\ *) ;; *) echo "expected one ssh-ed25519 public key on stdin"; exit 1 ;; esac
[ -x "$RRSYNC" ] || { echo "missing $RRSYNC (rsync package)"; exit 1; }

echo "== 1/3 user logpull (own group, no password, key only)"
getent group logpull >/dev/null || sudo groupadd --system logpull
if ! id logpull >/dev/null 2>&1; then
  sudo useradd --system --create-home --home-dir /var/lib/logpull --shell /bin/sh --gid logpull logpull
fi
sudo usermod -g logpull -G "" -p '*' logpull      # own group only; no password login
getent group cowrielog >/dev/null && sudo groupdel cowrielog || true   # leftover from v1

echo "== 2/3 read-only access via ACL (also applies to files Cowrie creates later, e.g. rotation)"
command -v setfacl >/dev/null || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq acl >/dev/null
for d in /srv/cowrie /srv/cowrie/var /srv/cowrie/var/log; do sudo setfacl -m u:logpull:--x "$d"; done
sudo setfacl -R -m u:logpull:r-X "$SRC"
sudo setfacl -d -m u:logpull:r-X "$SRC"

sudo install -d -o logpull -g logpull -m 0700 /var/lib/logpull/.ssh
printf 'from="%s",restrict,command="%s -ro %s/" %s\n' "$CORE_IP" "$RRSYNC" "$SRC" "$PUBKEY" \
  | sudo tee /var/lib/logpull/.ssh/authorized_keys >/dev/null
sudo chown logpull:logpull /var/lib/logpull/.ssh/authorized_keys
sudo chmod 0600 /var/lib/logpull/.ssh/authorized_keys

echo "== 3/3 checks"
id logpull
sudo -u logpull test -r "$SRC/cowrie.json" && echo "   logpull can READ cowrie.json" || echo "   logpull CANNOT read cowrie.json"
sudo -u logpull test -w "$SRC/cowrie.json" && echo "   WARNING: logpull can WRITE" || echo "   logpull cannot write (good)"
echo "   key options: $(sudo cut -d' ' -f1-2 /var/lib/logpull/.ssh/authorized_keys | sed 's/ ssh-ed25519//')"
echo "HONEYPOT SIDE DONE"
