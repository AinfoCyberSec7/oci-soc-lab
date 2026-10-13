#!/bin/bash
# core-arm bootstrap: hardening + Docker, ready for Elastic Security (Week 2) and n8n.
set -euxo pipefail
exec > /var/log/lab-bootstrap.log 2>&1
export DEBIAN_FRONTEND=noninteractive

# Retry helper: on first boot, Ubuntu's own apt timers can briefly hold the
# apt/dpkg locks. Without this, "set -e" would abort the whole bootstrap.
retry() { for i in $(seq 1 20); do "$@" && return 0; echo "retry $i: $*"; sleep 15; done; return 1; }

retry apt-get update
retry apt-get -y -o Dpkg::Options::="--force-confold" upgrade
retry apt-get install -y unattended-upgrades fail2ban docker.io docker-compose-v2 jq
echo 'APT::Periodic::Update-Package-Lists "1";'  >  /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";'    >> /etc/apt/apt.conf.d/20auto-upgrades

# --- SSH hardening ---
cat > /etc/ssh/sshd_config.d/99-lab-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
EOF
systemctl restart ssh
systemctl enable --now fail2ban

# --- Remove unneeded listeners: rpcbind (NFS helper, :111 on all interfaces) ---
systemctl stop rpcbind.socket rpcbind.service || true
systemctl mask rpcbind.socket rpcbind.service

# --- Docker ---
systemctl enable --now docker
usermod -aG docker ubuntu

# --- Kernel setting required by Elasticsearch (minimum 262144) ---
# Explicit, so the lab does not depend on the image default.
echo 'vm.max_map_count=1048576' > /etc/sysctl.d/99-elastic.conf
sysctl --system

echo "BOOTSTRAP DONE" > /var/log/lab-bootstrap.done
