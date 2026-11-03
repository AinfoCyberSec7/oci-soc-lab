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
                                              │  Elastic SIEM (Week 2)    │
                                              └────────────┬─────────────┘
                                                           │ pulls logs (read-only rsync, every minute)
                                                           │ Local Peering Gateway, one way
                                              ┌────────────▼─────────────┐
 Internet attackers ── TCP 22 / 23 ──────────►│ hp-cowrie (E2.1.Micro)   │
                                              │  Cowrie honeypot (Week 3)│
                                              │  own VCN 10.20.0.0/16    │
                                              └──────────────────────────┘
```

| Resource | Shape | Disk | Role |
|---|---|---|---|
| `core-arm` | VM.Standard.A1.Flex, 2 OCPU / 12 GB | 100 GB | SIEM / workloads (Docker ready) |
| `wg-gw` | VM.Standard.E2.1.Micro | 50 GB | WireGuard + wstunnel gateway |
| `hp-cowrie` | VM.Standard.E2.1.Micro | 50 GB | Cowrie SSH/Telnet honeypot (isolated VCN) |

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
scripts/lock-opc.sh                  # locks the unused "opc" image account on a running host
week2/elastic/docker-compose.yml     # Elasticsearch + Kibana 9.5.5, pinned by digest, TLS everywhere
week2/elastic/gen-env.sh             # creates the git-ignored .env with random secrets (on the VM)
week2/elastic/kibana-secrets.sh      # Kibana secrets in a root-only file (not env/ps); render | rotate
week2/elastic/fleet-setup.sh         # Fleet via Kibana API: server host, output, policies
week2/elastic/install-fleet-server.sh  # Fleet Server on core-arm (host install)
week2/elastic/install-agent.sh       # enrolls any Linux host (token read from stdin)
week2/elastic/load-rules.sh          # detection-as-code loader
week2/elastic/rules/*.json           # detection rules (MITRE ATT&CK mapped)
honeypot.tf                          # Week 3: honeypot VCN, peering, NSG, instance
cloud-init/honeypot.sh.tftpl         # honeypot first boot: sshd on 22222, egress guards, Docker
week3/deploy-cowrie.sh               # Cowrie container, pinned by digest, locked down
week3/logpull-honeypot.sh            # honeypot side of the pull: read-only, forced-command key
week3/logpull-core.sh                # core side of the pull: pinned host key, 1-minute timer
week3/cowrie-ingest.sh               # Fleet integration: Cowrie JSON -> logs-cowrie-default
week3/verify-week3.sh                # read-only end-to-end check (run from the Mac)
week3/check-attacks.sh               # read-only breakout hunt on the honeypot + attacker summary
week3/investigate.sh                 # forensics: ip | session (+ terminal replay) | hashes | hash | preserve
week3/import-dashboard.sh            # imports the live Kibana dashboard
week3/dashboard/*.ndjson             # dashboard, panels, saved search, data view
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

## Week 2: Elastic Security (SIEM)

A single-node **Elastic Security 9.5.5** stack on `core-arm`, collecting logs from both hosts with **Elastic Agent + Fleet**, and alerting with **detection-as-code** rules.

```
 wg-gw  (Elastic Agent) ─┐   enroll / policy (TLS)    ┌─ Fleet Server :8220 ─┐
                         ├──────────────────────────► │      core-arm         │
 core-arm (Elastic Agent)┘   logs + metrics (TLS)     └─ Elasticsearch :9200 ─┴─► Kibana :5601 ◄── admin, via the tunnel only
```

| Control | Implementation |
|---|---|
| Patched, pinned images | Elasticsearch / Kibana / Agent **9.5.5** (fixes advisory AV26-1021), images pinned by **sha256 digest** |
| No public exposure | Ports published on the **private IP only** (`10.10.1.129`), never `0.0.0.0`; NSG unchanged |
| TLS everywhere | Private CA created on the VM; HTTP, transport, Kibana and Fleet all TLS; agents trust **only** that CA |
| No default secrets | `gen-env.sh` creates random passwords/keys on the VM (`.env`, mode 600, git-ignored) |
| Secrets not in `ps` | Kibana's password and keys are in a config file (`root:20998 640`), not in env vars, which the image turns into command-line flags readable by every local user |
| Named accounts | Personal admin account for daily use; built-in `elastic` kept as break-glass |
| Least exposure on hosts | Fleet Server bound to the private IP, host firewall allows 8220 **from the VCN only**; unused `rpcbind` masked |
| Supply chain | Agent tarballs verified against Elastic's **SHA-512** before install |
| Secret hygiene | Service and enrollment tokens are created via API and piped, never printed or passed as arguments |
| Resource limits | ES heap 3 GB (container 5 GB), Kibana 2.5 GB, log rotation; agent on the 1 GB gateway uses ~280 MB |

**Detection-as-code:** rules live in `week2/elastic/rules/*.json` and are loaded by `load-rules.sh` (create or update by `rule_id`).

| Rule | Logic | ATT&CK |
|---|---|---|
| Repeated failed SSH logins from one source | Threshold: >= 3 authentication failures, same `source.ip` + `host.name`, 6 min window, runs every minute | T1110.001 Password Guessing |

**Validated end to end:** 5 failed SSH logins with a non-existent user produced 5 stored failure events, **one medium alert about a minute later**, and an automatic **fail2ban ban** of the source: detection and prevention working together.

**Also verified:** SSH from `core-arm` to the gateway over the private network **times out** (the gateway NSG allows only the tunnel port), so a compromised core host cannot pivot to the gateway over SSH.

### Deploy Week 2 (on core-arm, after Week 1)

```bash
scp -r week2 lab-core:~/soc-lab/
ssh lab-core 'cd ~/soc-lab/week2/elastic && ./gen-env.sh && ./kibana-secrets.sh render && docker compose up -d'
ssh lab-core 'cd ~/soc-lab/week2/elastic && ./fleet-setup.sh && ./install-fleet-server.sh && ./load-rules.sh'
# other hosts: copy /etc/elastic-agent-certs/ca.crt to them, then pipe an enrollment token into install-agent.sh
```

Kibana: `https://10.10.1.129:5601` (with `lab up`). Verify the certificate fingerprint before accepting the browser warning.

---

## Week 3: Cowrie honeypot on an isolated network

A **Cowrie 3.1.5** SSH and Telnet honeypot that is deliberately open to the internet, on its **own VCN**, with its logs pulled into Elastic. Attackers get a fake shell; the SIEM gets their passwords, commands and malware URLs.

```
 Internet ── 22 (SSH) / 23 (Telnet) ──► hp-cowrie  10.20.1.15   (VCN 10.20.0.0/16, own subnet + NSG)
                                         │  Docker: cowrie  host 22→2222, 23→2223
                                         │  real sshd on 22222, reachable ONLY from core-arm
                                         │
                core-arm  10.10.1.129 ───┘  hppull.timer: rsync over SSH every minute (lab → honeypot only)
                   │  /var/log/honeypot/cowrie/cowrie.json*
                   ▼
                Elastic Agent (filestream) ──► logs-cowrie-default ──► 3 honeypot detection rules
```

**The design rule:** assume the honeypot is compromised. It can be reached from the lab, but it can never reach into the lab.

| Control | Implementation |
|---|---|
| Network isolation | Separate VCN, joined to the lab by a Local Peering Gateway. The honeypot's host firewall rejects **every new connection to the lab (10.10.0.0/16)**, and its NSG allows only DNS, HTTP/S and metadata egress |
| Container isolation | A `DOCKER-USER` rule (systemd `docker-user-guard`) rejects new connections from containers to the lab, as well |
| Pull, not push | core-arm **pulls** the logs. The honeypot holds no credential for the lab and has nothing to push to |
| Least-privilege pull key | `authorized_keys` on the honeypot: `from="10.10.1.129",restrict,command="rrsync -ro <log dir>"`. That means one source IP, no shell, no forwarding, read-only, one folder |
| Read without write | The pull user reads the logs through a **read-only ACL**, not through Cowrie's group (which could write them) |
| Pinned host key | core-arm checks the honeypot's SSH host key (`StrictHostKeyChecking=yes`, its own known_hosts) |
| Sandboxed puller | `hppull.service` runs as a dedicated user with `ProtectSystem=strict`, `NoNewPrivileges`, no capabilities |
| Locked-down container | Image pinned by **sha256 digest**, `--cap-drop ALL`, `no-new-privileges`, read-only root, 384 MB memory, 128 pids. It runs as **uid 20999**: the image's default uid 999 is already used on the host by the Oracle Cloud Agent |
| No relay | Cowrie's SSH forwarding and tunnelling are off, so attackers can't use the honeypot to attack others |
| Real admin access | sshd moved to **22222**, allowed only from core-arm (NSG + iptables), with fail2ban. Admin path: Mac → tunnel → `ProxyJump lab-core` |
| Egress | Only DNS, HTTP/S and the OCI metadata service. SMTP and other ports are blocked, so a captured bot cannot send spam |
| Bait off by default | `honeypot_bait_enabled = false` until isolation is verified; opening it is one reviewed `terraform apply` |
| Captured malware | Stored by Cowrie as hash-named files on the honeypot, **never executed and never copied off**. Analysis is by hash lookup only |

**Detection-as-code (Week 3 rules):**

| Rule | Logic | Severity | ATT&CK |
|---|---|---|---|
| Attacker logged in with guessed credentials | Threshold: `cowrie.login.success`, per `source.ip` | low | T1110.001, T1078 |
| Attacker ran commands in the fake shell | Threshold: `cowrie.command.input`, per `source.ip` | medium | T1059.004 Unix Shell |
| Attacker transferred a file (malware dropper) | Query: `cowrie.session.file_download` / `file_upload` | high | T1105 Ingress Tool Transfer |

**Verified (with `week3/verify-week3.sh`):**
- Before the bait opened, internet → 22, 23 and 22222 all **timed out**.
- Honeypot → lab and container → lab: **refused** on every tested port.
- Pull: 0 events behind and **0 parse errors**.
- All four rules ran successfully, and all three honeypot rules have **fired on real attacks**.
- `terraform plan`: no changes.

**First hours of real traffic:**
- Thousands of events from automated bots, almost entirely Telnet and SSH IoT botnets.
- Cowrie's default user list rejects only `root/123456` and `root/root`, so most bots "log in" and show their next step.
- **Router breakout:** `sh`, `system`, then a dropper script.
- **Honeypot fingerprinting:** bots check quoting (`printf '%s\n' 'a b;$()'`) and subshell variable scoping, to tell a real shell from an emulated one.
- **Mirai-style loader:** one binary per CPU architecture plus a shell script, from `hxxp://160.119.66[.]206/bins/` (defanged).

### Analysis and forensics

**Live dashboard: "Honeypot SOC - live"** (`week3/import-dashboard.sh`), with a 15 s auto-refresh. It shows totals, SSH vs Telnet, attacker SSH clients, activity over time, top IPs, credentials, commands, captured files (SHA-256) and a live event stream. Every value is clickable to filter all panels. Events appear about 1-2 minutes after the attack (pull every 60 s).

**Forensic toolkit** (`week3/investigate.sh`, run from the Mac):

| Command | Result |
|---|---|
| `ip <IP>` | attacker profile: first/last seen, protocols, SSH client, every credential and result, commands, files, recent sessions, alerts |
| `session <id>` | one intrusion second by second, plus a **replay of the attacker's terminal** rebuilt from Cowrie's recording |
| `hashes` / `hash <sha256>` | every captured file (type, size, source, first seen) / which IPs and sessions delivered one file |
| `preserve` | raw logs copied to a root-only folder with a SHA-256 manifest, then made **immutable** (chain of custody) |

Forensic hygiene built in: control characters stripped (no terminal escape injection), URLs defanged, inputs format-checked, file types read as an unprivileged uid, and **samples never leave the honeypot** (hash lookups only). Times are UTC.

**First-day findings** (all times UTC, 3 Nov 2026):

| Case | Evidence | Assessment |
|---|---|---|
| Recon bot `77.239.124[.]145` | 851 SSH sessions in 85 min, one new credential per session (`root ubuntu admin deploy postgres test claude`...), then only `uname -s -v -n -r -m`, 0 keystrokes | Credential validation + system discovery (T1110.001, T1082). No payload. Its alerts are mostly noise, which is a tuning task |
| Dropper chain, 3 IPs | `92.118.39[.]71`, `92.118.39[.]14` (same /24) and `195.178.110[.]227` uploaded the same 3.3 MB static ELF as `.16` 40 times | One operator or one shared kit, rotating infrastructure |
| Session `02338e639c70` | login → **two batteries of shell tests** (arithmetic, PID, positional args, functions, subshell scope, pipes, exit codes, a `/proc/self/stat` namespace check) with random nonce markers → SFTP upload of `/root/.16` → `sudo -S` with the login password → `chmod +x` | Sandbox and honeypot detection (T1497), ingress tool transfer (T1105), hidden file (T1564.001), sudo abuse (T1548.003). Cowrie's fake filesystem did not have the uploaded file, so `chmod` failed and the bot retried, which explains the 40 uploads |
| Loader `160.119.66[.]206/bins/` | `kla.sh` + `net.x86_64` + `net.x86` | VirusTotal on `3674a103...` (`net.x86_64`): Mirai/Gafgyt-derived bot with DDoS floods, persistence (systemd `.networkd.service`/`netd.service`, `/etc/init.d/sys_daemon`, `/etc/cron.d/netupd`), killing of rival malware, XOR-encrypted C2 |

Same banner, different tools: both bots announce `SSH-2.0-Go`, but their **HASSH** client fingerprints differ (`0a07365cc01fa9fc82608ba4019af499` for the recon bot, `2ec37a7cc8daf20b10e1ad6221061ca5` for the dropper). HASSH survives IP rotation, so it is the better indicator.

**Indicators (defanged):**

| Type | Value |
|---|---|
| SHA-256 | `a151d3f4f2422531f30a843ffb35479596c86722bb103bdf8591105687f9b125` (`.16`, static x86-64 ELF) |
| SHA-256 | `3674a103804cac96027fe1cf62aaab4948c1d547d1c885542177a263103b4260` (`net.x86_64`) |
| SHA-256 | `5d9e4bdee8c8fcb0b534f6336ecace4696d8ed3038de42a969c6e037e41d1de5` (`net.x86`) |
| SHA-256 | `39be6853a8204ce6455a373a6ffb4cb4672d4a62d90be69f7d6eeb66cda10b96` (`kla.sh`) |
| SHA-256 | `fba55fd42a6cb14c417c3922d09fbcd105bdce13aff48ef908e6a201174a535d` (`.b0s`, static x86-64 ELF) |
| URL | `hxxp://160.119.66[.]206/bins/` |
| HASSH | `0a07365cc01fa9fc82608ba4019af499`, `2ec37a7cc8daf20b10e1ad6221061ca5` |
| Host artifacts | `.networkd.service`, `netd.service`, `/etc/init.d/sys_daemon`, `/etc/cron.d/netupd`, `.sys_recovery.sh` |

### Findings from the Week 3 security review (and how they were fixed)

Hunting for a honeypot breakout (`week3/check-attacks.sh`) found no breakout, but it did find three real weaknesses elsewhere:

| Finding | Risk | Fix |
|---|---|---|
| **Kibana secrets in the process list.** The Kibana image turns env vars into command-line flags, so the `kibana_system` password and the three encryption keys were readable by **any local user** via `ps` (for example, the user that pulls data from the attacker-facing honeypot) | Credential theft by a local foothold | Secrets moved to a config file readable only by root and a dedicated group (`kibana-secrets.sh`). All four values **rotated**, saved objects (Fleet, rules) **re-encrypted** with the new key before the old one was dropped. Verified: 0 secrets in `ps`, the old password gets **HTTP 401**, and every rule and agent works on the new key alone |
| **Unused `opc` account** created by Oracle's Ubuntu image on every host, with a login shell and the instance SSH key | A second way in and a quiet place to persist. As uid 1000 it equals the uid of Elasticsearch/Kibana inside their containers, so a shell as opc could read their process environment | Locked on all hosts (`nologin`, password locked, account expired, key removed, `DenyUsers opc`), and locked at first boot in all cloud-init files. Verified live: opc refused, ubuntu works |
| **uid collisions between containers and host accounts** (Cowrie's 999 = `ocarun`, Elastic's 1000 = `opc`) | File and process access that crosses the container boundary | Cowrie runs as the unused uid 20999; Kibana reads its secrets through the unused group 20998 |

### Deploy Week 3 (after Week 2)

```bash
# 1. infrastructure (bait stays closed: honeypot_bait_enabled = false)
terraform plan -parallelism=2 -out=tfplan && terraform apply -parallelism=2 tfplan
```

Add to `~/.ssh/config`:

```
Host lab-hp
  HostName 10.20.1.15
  Port 22222
  User ubuntu
  IdentityFile ~/.ssh/oci_lab
  IdentitiesOnly yes
  ProxyJump lab-core
```

```bash
# 2. Cowrie
scp week3/deploy-cowrie.sh week3/logpull-honeypot.sh lab-hp:~/
ssh lab-hp 'bash deploy-cowrie.sh'

# 3. one-way log pull (only the PUBLIC key crosses over)
scp -r week3 lab-core:~/soc-lab/
ssh lab-core 'bash ~/soc-lab/week3/logpull-core.sh key' | ssh lab-hp 'bash logpull-honeypot.sh'
ssh lab-core 'bash ~/soc-lab/week3/logpull-core.sh install'

# 4. ingest + rules
ssh lab-core 'cd ~/soc-lab && cp week3/cowrie-ingest.sh week2/elastic/ && bash week2/elastic/cowrie-ingest.sh'
scp week2/elastic/rules/hp-*.json lab-core:~/soc-lab/week2/elastic/rules/
ssh lab-core 'cd ~/soc-lab/week2/elastic && ./load-rules.sh'

# 5. verify isolation, then open the bait (terraform.tfvars: honeypot_bait_enabled = true)
bash week3/verify-week3.sh
terraform plan -parallelism=2 -out=tfplan && terraform apply -parallelism=2 tfplan
```

In Kibana: **Discover** → data view **Honeypot (Cowrie)** (`logs-cowrie-*`), or the dashboard:

```bash
scp -r week3 lab-core:~/soc-lab/ && ssh lab-core 'bash ~/soc-lab/week3/import-dashboard.sh'
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
| Agent `DEGRADED`: `x509: certificate signed by unknown authority` | Elasticsearch sends only its leaf certificate, so a CA fingerprint alone cannot be matched. Give agents the CA file (`ssl.certificate_authorities`, set by `fleet-setup.sh`); restart the agent if components stay stuck |
| Kibana menu has no "Alerts" | In 9.x it is **Security → Detections** |
| Terraform: `no such host` / `i/o timeout` | Intermittent DNS on the admin path; re-run (always use `-parallelism=2`) |
| `Permission denied` with `sudo cat file*` or `sudo wc < file` | The shell expands globs and redirects **before** sudo runs. Use `sudo sh -c 'cat /var/log/honeypot/cowrie/cowrie.json*'` |
| Cowrie port is open but sends no banner | Cowrie needs a few seconds after the container starts. `deploy-cowrie.sh` waits up to 60 s for `SSH-` before checking |
| Admin egress IP changed | Update `admin_cidr`, `terraform apply` |
| Gateway public IP changed | `lab refresh` |

---

## Known trade-offs

- **TCP-over-TCP:** slower under packet loss than plain WireGuard. That's fine for admin, SSH and dashboards.
- **Secret in instance metadata:** on a rebuild, `wstunnel_prefix` is passed through cloud-init user data (visible to OCI admins and to local users on the gateway via the metadata service). It is one of several layers; rotate it by changing `/etc/wstunnel/env` and `~/.wg-lab/wstunnel.secret`.
- **The honeypot is meant to be attacked:** its public IP is published to attackers by design, and it stores real malware samples. That's why it has its own VCN, egress filters and a lab-initiated, read-only pull, and why the samples are never moved off it.
- **Cowrie can be fingerprinted:** skilled attackers can detect an emulated shell (some bots already test for this). The lab collects mostly automated botnet activity, not targeted intrusions.
- **Elasticsearch still runs as uid 1000** inside its container (the image's default). With `opc` locked, nothing on the host logs in as that uid.
- **Single admin IP:** access depends on the admin egress IP. That is intentional; it is the strongest network filter available.

---

## Roadmap

- [x] **Week 1:** zero-exposure foundation (this repo)
- [x] **Week 2:** Elastic Security (SIEM) on `core-arm`, Elastic Agent on all hosts, first detection rule
- [x] **Week 3:** Cowrie honeypot on an isolated VCN → Elastic, three honeypot detection rules
- [ ] **Week 4:** n8n threat-intel enrichment and weekly report
- [ ] **Week 5:** same honeypot attacks in Microsoft Sentinel: a two-SIEM comparison

---

## Author

**AinfoCyberSec7**: Cybersecurity Analyst
GitHub: [github.com/AinfoCyberSec7](https://github.com/AinfoCyberSec7)

## License

[MIT](LICENSE) © 2026 AinfoCyberSec7
