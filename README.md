# OCI SOC Lab: a zero-exposure cloud lab on Oracle Always Free

A hardened home-SOC foundation on **Oracle Cloud Always Free**, built with **Terraform**, and reachable **only** through a private WireGuard tunnel. To the rest of the internet the lab does not exist.

> **Cost:** $0. Every resource is Always Free-eligible, and a $1 budget alarm emails on any real spend.

---

## Architecture

```
 Mac ──► Admin VPN ──► VPN egress   ──► Internet ──► Oracle Cloud (Frankfurt)
  │                     (static IP)                         │
  │  WireGuard (oci-lab)                                    │  NSG: TCP 443 from admin IP only
  │     │ UDP                                               ▼
  │     ▼                                     ┌──────────────────────────┐
  │  wstunnel client 127.0.0.1:51820 ═══TLS══►│ wg-gw  (E2.1.Micro, AD-2)│
  │  (launchd, `lab up`)                      │  wstunnel :443 ─► WG :51820 (local)
  │                                           │  WireGuard 10.66.66.1     │
  │                                           └────────────┬─────────────┘
  │                                                        │ NAT, VCN 10.10.0.0/16
  │                                           ┌────────────▼─────────────┐
  └── ssh lab-gw / ssh lab-core ─────────────►│ core-arm (A1.Flex 2/12GB)│
                                              │  Docker - Wazuh (Week 2)  │
                                              └──────────────────────────┘
```

| Resource | Shape | Disk | Role |
|---|---|---|---|
| `core-arm` | VM.Standard.A1.Flex, 2 OCPU / 12 GB | 100 GB | SIEM / workloads (Docker ready) |
| `wg-gw` | VM.Standard.E2.1.Micro | 50 GB | WireGuard + wstunnel gateway |
| (Week 3) honeypot | VM.Standard.E2.1.Micro | 50 GB | Cowrie |

---

## Security model (defense in depth)

| Layer | Control |
|---|---|
| Oracle NSG | The **only** inbound rule from the internet: TCP 443, **from one /32** (admin egress IP). No public SSH. |
| Transport | WireGuard wrapped in **TLS** (wstunnel); looks like HTTPS on the wire |
| Tunnel auth | wstunnel requires a **secret HTTP upgrade path**; anything else is rejected |
| Tunnel scope | `--restrict-to 127.0.0.1:51820`: an authenticated client can reach **only** WireGuard |
| VPN auth | WireGuard public-key crypto (Curve25519); one allowed peer |
| Service sandbox | wstunnel runs as an unprivileged user under systemd hardening (`ProtectSystem=strict`, `NoNewPrivileges`, only `CAP_NET_BIND_SERVICE`) |
| Hosts | Key-only SSH, no root login, fail2ban, unattended security upgrades |
| Supply chain | wstunnel binary verified against the release **SHA-256 checksums**; provider pinned via `.terraform.lock.hcl` |
| Cost guard | $1 monthly budget with actual + forecast alerts |

**Verified from the outside** (Oracle Cloud Shell = "random internet host"): TCP 22 **and** 443 both time out.

---

## The interesting part: when UDP is blocked

WireGuard is UDP-only. During the build, the tunnel never completed a handshake. The steps below isolated the cause **without changing the existing VPN path**:

1. `tcpdump` on the gateway: **0 packets** arrived on UDP 51820 from the Mac
2. Same probe from **Oracle Cloud Shell**: **3/3 arrived**, so Oracle side and server were correct
3. UDP 443 from the Mac: also **0 packets**, so the admin network path blocks **outbound UDP in general**
4. TCP SYN to 443 from the Mac: **arrived**, so TCP is allowed

**Fix:** carry WireGuard inside TLS over TCP 443 with [wstunnel](https://github.com/erebe/wstunnel), restrict the port to the admin egress IP, and remove the UDP rule. The result is stronger than the original design: no UDP exposure, a single locked TCP port, and a tunnel that blends in with HTTPS.

---

## Repository layout

```
main.tf / variables.tf / outputs.tf / versions.tf   # infrastructure
cloud-init/wg-gw.sh.tftpl    # gateway first boot: hardening, WireGuard, wstunnel
cloud-init/core-arm.sh       # core first boot: hardening, Docker
scripts/lab                  # Mac CLI: lab up | down | status | ssh | logs | refresh
scripts/install-lab-cli.sh   # installs lab CLI, launchd agent, SSH shortcuts
scripts/install-wstunnel-server.sh   # (re)installs wstunnel on an existing gateway
```

---

## Daily use (macOS)

```bash
lab up          # start wstunnel + WireGuard tunnel, wait for handshake
ssh lab-core    # or: ssh lab-gw
lab status      # check every link in the chain
lab down        # stop everything
```

---

## Deploy from scratch

**Prerequisites:** Terraform ≥ 1.5, `brew install wstunnel wireguard-tools`, WireGuard app, OCI API key in `~/.oci/`.

```bash
# keys
ssh-keygen -t ed25519 -f ~/.ssh/oci_lab -C oci-soc-lab
mkdir -p ~/.wg-lab && chmod 700 ~/.wg-lab
(umask 077; wg genkey > ~/.wg-lab/client.key; wg pubkey < ~/.wg-lab/client.key > ~/.wg-lab/client.pub)
(umask 077; openssl rand -hex 24 > ~/.wg-lab/wstunnel.secret)

# config: copy terraform.tfvars.example -> terraform.tfvars and fill in
#   admin_cidr = your egress IP/32, allow_public_ssh = true (bootstrap only)
#   wstunnel_prefix = contents of ~/.wg-lab/wstunnel.secret

terraform init
terraform plan -parallelism=2 -out=tfplan && terraform apply -parallelism=2 tfplan
```

Wait about 8 minutes for first boot, then:

```bash
# fetch the gateway's WireGuard public key (bootstrap SSH)
ssh -i ~/.ssh/oci_lab ubuntu@$(terraform output -raw wg_gw_public_ip) \
  'sudo cat /etc/wireguard/server.pub' > ~/.wg-lab/server.pub

# build the tunnel config, then import it in the WireGuard app (Add Empty Tunnel -> paste)
cat > ~/.wg-lab/oci-lab.conf <<EOF
[Interface]
PrivateKey = $(cat ~/.wg-lab/client.key)
Address = 10.66.66.2/32
MTU = 1280

[Peer]
PublicKey = $(cat ~/.wg-lab/server.pub)
Endpoint = 127.0.0.1:51820
AllowedIPs = 10.66.66.0/24, 10.10.0.0/16
PersistentKeepalive = 25
EOF
chmod 600 ~/.wg-lab/oci-lab.conf

bash scripts/install-lab-cli.sh && source ~/.zshrc && lab up

# close the bootstrap door
#   terraform.tfvars: allow_public_ssh = false
terraform plan -parallelism=2 -out=tfplan && terraform apply -parallelism=2 tfplan
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `lab status` shows ✘ on the tunnel | `lab up` |
| Gateway does not answer ping | `lab up` (restarts the client once by itself); still failing: `lab logs`, then `lab down && lab up` |
| `lab logs` shows `Cannot connect to tcp endpoint … timeout` | Packet loss on the admin network path, not the lab. Check with `curl -sk -o /dev/null -w '%{time_connect}\n' https://<gw-ip>/` (healthy ≈ 0.1 s; 1 s / 3 s / 7 s = lost SYNs) and retry later |
| `systemctl` warns *unit changed on disk* | `sudo systemctl daemon-reload && sudo systemctl restart wstunnel` (re-running `install-wstunnel-server.sh` now does this) |
| `terraform plan` shows only `Changes to Outputs` | Not drift: outputs were edited after the last apply. `terraform plan -out=tfplan`, check `0 to add/change/destroy`, `terraform apply tfplan` |
| Terraform: `no such host` / `i/o timeout` | Intermittent DNS on the admin path; re-run (always use `-parallelism=2`) |
| Admin egress IP changed | Update `admin_cidr`, `terraform apply` |
| Gateway public IP changed | `lab refresh` |

---

## Known trade-offs

- **TCP-over-TCP:** slower under packet loss than plain WireGuard. That's fine for admin, SSH and dashboards.
- **Secret in instance metadata:** on a rebuild, `wstunnel_prefix` is passed through cloud-init user data (visible to OCI admins and to local users on the gateway via the metadata service). It is one of several layers; rotate it by changing `/etc/wstunnel/env` and `~/.wg-lab/wstunnel.secret`.
- **Single admin IP:** access depends on the admin egress IP. That is intentional; it is the strongest network filter available.

---

## Roadmap

- [x] **Week 1:** zero-exposure foundation (this repo)
- [ ] **Week 2:** Wazuh SIEM on `core-arm`, agents on all hosts
- [ ] **Week 3:** Cowrie honeypot on an isolated VCN → Wazuh
- [ ] **Week 4:** n8n threat-intel enrichment and weekly report

---

## Author

**AinfoCyberSec7**: Cybersecurity Analyst
GitHub: [github.com/AinfoCyberSec7](https://github.com/AinfoCyberSec7)

## License

[MIT](LICENSE) © 2026 AinfoCyberSec7
