# 🔐 CTF Vulnerable Lab — Security Monitoring Environment

A fully containerised CTF lab with **8 intentionally vulnerable targets** that report to your **existing Wazuh SIEM** at `10.0.10.2` on the `10.0.10.0/24` network.

---

## 🏗️ Architecture

```
  10.0.10.0/24  (your flat network)
  ┌─────────────────────────────────────────────────────────┐
  │                                                          │
  │  10.0.10.2   ◄── Wazuh SIEM (your existing VM)         │
  │               │   Dashboard : https://10.0.10.2         │
  │               │   API       : https://10.0.10.2:55000   │
  │               │   Syslog    : 10.0.10.2:514             │
  │               │   Agents    : 10.0.10.2:1514/1515       │
  │               │                                          │
  │  10.0.10.X  ◄── CTF Host (this machine + Docker)       │
  │               │                                          │
  │               ├── WP :8080   ──rsyslog──►  :514         │
  │               ├── DVWA :8081 ──rsyslog──►  :514         │
  │               ├── WebGoat :8082                         │
  │               ├── JuiceShop :8083                       │
  │               ├── Mutillidae :8084 ─rsyslog─► :514      │
  │               ├── phpMyAdmin :8085 ─rsyslog─► :514      │
  │               ├── SSH :2222  ──wazuh-agent──► :1514     │
  │               ├── FTP :2121  ──wazuh-agent──► :1514     │
  │               └── Filebeat   ──logstash──►  :5044       │
  │                                                          │
  └─────────────────────────────────────────────────────────┘
```

**Log shipping methods:**
| Container type | How logs reach Wazuh |
|----------------|----------------------|
| SSH & FTP targets | Full **Wazuh agent** installed inside container – auto-registers on :1515 |
| WordPress, DVWA, Mutillidae, phpMyAdmin | **rsyslog** forwards Apache/auth logs → syslog TCP port 514 |
| All containers | **Filebeat** ships Docker stdout/stderr → Wazuh Logstash input port 5044 |

---

## 🗂️ Project Structure

```
vulnerable/
├── docker-compose.yml              # Targets only – no Wazuh stack here
├── targets/
│   ├── ssh-target/                 # Ubuntu 22.04 + Wazuh agent + weak SSH
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh           # Registers agent at 10.0.10.2 on boot
│   │   └── backup.sh               # World-writable cron (priv-esc vector)
│   └── ftp-target/                 # Ubuntu 22.04 + Wazuh agent + vsftpd
│       ├── Dockerfile
│       ├── entrypoint.sh
│       ├── vsftpd.conf
│       └── backdoor_listener.py    # CVE-2011-2523 bind shell on :6200
├── configs/
│   ├── wordpress/setup.sh          # WP-CLI: flags, vuln plugins, weak creds
│   └── rsyslog/rsyslog-apache.conf # Mounted into pre-built images → syslog to Wazuh
├── monitoring/
│   ├── filebeat/filebeat.yml       # Ships Docker logs → 10.0.10.2:5044
│   └── wazuh/
│       ├── ossec.conf              # Full Wazuh manager config (reference copy)
│       ├── ossec-syslog-remote.conf# <remote> snippet to add to Wazuh VM
│       └── rules/ctf_rules.xml    # 20+ custom rules (pushed via API)
└── scripts/
    ├── setup.sh                    # start / stop / reset / status
    ├── push-rules.sh               # Pushes ctf_rules.xml to Wazuh API
    ├── attack-simulator.sh         # Generates attack traffic to test rules
    └── gen-certs.sh                # (optional) TLS cert generator
```

---

## 🚀 Installation — Step by Step

### PART 1 — Prepare the Wazuh VM (10.0.10.2)

SSH into your Wazuh VM and do the following **once**.

#### 1a. Open the required firewall ports

```bash
# On 10.0.10.2 – allow traffic from the CTF host subnet
sudo ufw allow from 10.0.10.0/24 to any port 514  proto tcp   comment "syslog TCP"
sudo ufw allow from 10.0.10.0/24 to any port 514  proto udp   comment "syslog UDP"
sudo ufw allow from 10.0.10.0/24 to any port 1514 proto tcp   comment "agent events"
sudo ufw allow from 10.0.10.0/24 to any port 1515 proto tcp   comment "agent enrolment"
sudo ufw allow from 10.0.10.0/24 to any port 5044 proto tcp   comment "Filebeat/Logstash"
sudo ufw allow from 10.0.10.0/24 to any port 55000 proto tcp  comment "Wazuh REST API"
sudo ufw reload
```

#### 1b. Enable syslog input in ossec.conf

Add the following blocks inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`.
The easiest way — paste the contents of `monitoring/wazuh/ossec-syslog-remote.conf`
(the file is already in this repo):

```bash
# From your CTF host – copy the snippet to the Wazuh VM
scp monitoring/wazuh/ossec-syslog-remote.conf YOUR_USER@10.0.10.2:/tmp/

# On the Wazuh VM – append it before </ossec_config>
sudo python3 - <<'EOF'
conf = open('/var/ossec/etc/ossec.conf').read()
snippet = open('/tmp/ossec-syslog-remote.conf').read()
conf = conf.replace('</ossec_config>', snippet + '\n</ossec_config>', 1)
open('/var/ossec/etc/ossec.conf', 'w').write(conf)
print('Done')
EOF

sudo systemctl restart wazuh-manager
```

The snippet enables:
- Syslog TCP/UDP on port 514 from `10.0.10.0/24`
- Agent event listener on port 1514

#### 1c. Enable the Logstash/Beats input (for Filebeat)

```bash
# On the Wazuh VM
sudo /var/ossec/bin/ossec-control enable client-syslog
sudo systemctl restart wazuh-manager
```

> ✅ Verify the manager is listening:
> ```bash
> sudo ss -tlnp | grep -E '514|1514|1515|5044'
> ```

---

### PART 2 — Prepare the CTF Host (this machine)

The CTF host is the machine where you cloned this repo and will run Docker.
It must be on the `10.0.10.0/24` network so containers can reach Wazuh at `10.0.10.2`.

#### 2a. Install Docker (if not already installed)

```bash
# Ubuntu / Debian
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker          # or log out and back in
docker --version       # verify
```

#### 2b. Clone / copy this repo onto the CTF host

```bash
git clone <your-repo-url> vulnerable
cd vulnerable
```

#### 2c. Make scripts executable

```bash
chmod +x scripts/*.sh configs/wordpress/setup.sh \
         targets/ssh-target/entrypoint.sh \
         targets/ftp-target/entrypoint.sh
```

---

### PART 3 — Start the Lab

#### 3a. Start all vulnerable targets

```bash
./scripts/setup.sh start
```

This single command will:
1. Check Docker is running
2. Check Wazuh at `10.0.10.2` is reachable
3. Check for port conflicts on the CTF host
4. Patch `rsyslog-apache.conf` with the correct Wazuh IP
5. Build the SSH and FTP custom images (installs Wazuh agent inside each)
6. Start all 8 vulnerable target containers + Filebeat
7. Push `ctf_rules.xml` to the Wazuh REST API automatically

> ⏳ **First run takes ~3–5 minutes** (Docker pulls ~3 GB of images + downloads the Wazuh agent package during build)

#### 3b. Push detection rules (if needed separately)

```bash
# Default Wazuh admin credentials
./scripts/push-rules.sh

# Custom password
WAZUH_PASS="YourPassword" ./scripts/push-rules.sh

# Auto-deploy ossec-syslog-remote.conf via SSH at the same time
WAZUH_SSH_USER=ubuntu WAZUH_PASS="YourPassword" ./scripts/push-rules.sh
```

---

### PART 4 — Verify Everything is Working

#### 4a. Check containers are running

```bash
./scripts/setup.sh status
# or
docker compose ps
```

All 10 services should show `Up`.

#### 4b. Check Wazuh agent registration

On the Wazuh VM:
```bash
sudo /var/ossec/bin/agent_control -l
# Should list:  ssh-target-<hostname>  and  ftp-target-<hostname>
```

Or in the Wazuh Dashboard → **Agents** — you should see the two new agents appear within 30 seconds of starting the lab.

#### 4c. Confirm syslog is arriving

On the Wazuh VM:
```bash
sudo tail -f /var/ossec/logs/ossec.log | grep -i syslog
```

#### 4d. Fire test alerts

```bash
# Run all attack simulations against the local containers
TARGET_HOST=localhost ./scripts/attack-simulator.sh all

# Or individual scenarios
TARGET_HOST=localhost ./scripts/attack-simulator.sh ssh
TARGET_HOST=localhost ./scripts/attack-simulator.sh wordpress
TARGET_HOST=localhost ./scripts/attack-simulator.sh ftp
```

Then open `https://10.0.10.2` → **Security Events** → filter: `rule.groups: ctf`

---

## 🎯 Vulnerable Targets

| Container | Port(s) | CVE / Vulnerability |
|-----------|---------|---------------------|
| WordPress 4.6 / PHP 5.6 | `8080` | See full table below |
| DVWA | `8081` | SQLi, XSS, CSRF, Command Injection, File Upload |
| WebGoat 8.0 | `8082` | Full OWASP Top 10 |
| OWASP Juice Shop v12 | `8083` | Modern web app vulns |
| Mutillidae II | `8084` | All OWASP categories |
| phpMyAdmin 4.8.1 | `8085` | CVE-2018-12613 LFI/RCE |
| SSH target | `2222` | Weak creds, SUID, world-writable cron |
| FTP target | `2121`, `6200` | CVE-2011-2523 vsftpd backdoor |

### WordPress 4.6 — Full Vulnerability Surface

**Core (WordPress 4.6 + PHP 5.6 + Apache 2.4):**

| CVE | Severity | Description |
|-----|----------|-------------|
| CVE-2016-10033 | **Critical** | PHPMailer < 5.2.18 — unauthenticated RCE via `Host:` header injection |
| CVE-2017-9061 | High | SSRF via URL validation bypass |
| CVE-2017-9062 | High | Open redirect via crafted URL |
| CVE-2019-8942 | High | RCE via path traversal in crop-image (also present in 4.6) |
| — | High | Unauthenticated user enumeration via `/wp-json/wp/v2/users` |
| — | High | XML-RPC fully enabled — brute-force / SSRF pivot |
| — | Medium | WP_DEBUG on — stack traces / paths leak to browser |
| — | Medium | `wp-config.php.bak` world-readable in webroot |
| — | Medium | `.env` with DB + SMTP credentials in webroot |
| — | Medium | `.git/config` exposed — repo URL leak |
| — | High | Uploads `.htaccess` allows PHP execution |
| — | Critical | Pre-planted webshell at `/wp-content/uploads/2024/01/image.php` |

**Plugins (all installed + activated):**

| Plugin | Version | CVE | Impact |
|--------|---------|-----|--------|
| WP File Manager | 6.0 | CVE-2020-25213 | **Unauthenticated RCE** / arbitrary file upload |
| Duplicator | 1.3.26 | CVE-2020-11738 | Unauthenticated arbitrary file read (wp-config.php) |
| Ultimate Member | 2.1.3 | CVE-2020-36326/36327 | Privilege escalation + unauth file upload |
| Revolution Slider | 4.2.0 | CVE-2014-9734 | Unauthenticated file download / LFI |
| W3 Total Cache | 0.9.7.3 | CVE-2019-6715 | Unauthenticated arbitrary file read |
| WP Super Cache | 1.6.4 | CVE-2019-20041 | Unauthenticated RCE via cache poisoning |
| WP GDPR Compliance | 1.4.2 | CVE-2018-19207 | Subscriber → admin privilege escalation |
| Contact Form 7 | 5.3.1 | CVE-2020-35489 | Unrestricted file upload (bypass extension check) |
| Easy WP SMTP | 1.3.9 | CVE-2020-35234 | Unauthenticated settings reset / credential theft |
| Ninja Forms | 3.4.24 | CVE-2020-14409/14410 | Unauthenticated stored XSS + SQL injection |
| WooCommerce | 3.4.5 | CVE-2019-20892 | Unauthenticated stored XSS + SQL injection |
| NextGEN Gallery | 3.2.10 | CVE-2020-35943 | Authenticated SQLi (subscriber+) |
| WPForms Lite | 1.5.9 | CVE-2021-20746 | Unauthenticated stored XSS |
| Yoast SEO | 1.2.0 | CVE-2015-4133 | CSRF → stored XSS |
| Akismet | 3.1.5 | CVE-2015-9357 | Reflected XSS |

**Default credentials:**
| Target | User | Password |
|--------|------|----------|
| WordPress (admin) | `admin` | `admin` |
| WordPress (editor) | `editor` | `editor` |
| WordPress (author) | `author` | `author` |
| WordPress (contributor) | `contributor` | `password` |
| WordPress (subscriber) | `subscriber` | `123456` |
| WordPress (test) | `test` | `test` |
| MySQL root | `root` | `root` |
| MySQL wp user | `wordpress` | `wordpress` |
| phpMyAdmin | `root` | `root` |
| DVWA | `admin` | `password` |
| SSH | `admin` | `admin` |
| SSH | `ctfuser` | `password` |
| SSH | `guest` | `guest123` |
| FTP | `anonymous` | *(any)* |
| FTP | `ftpuser` | `ftppass` |

---

## 🏴 CTF Flags

| Flag | Location | How to get it |
|------|----------|---------------|
| `FLAG{ssh_brute_force_success_0x01}` | `/home/ctfuser/flag.txt` | Brute-force SSH on port 2222 |
| `FLAG{root_privilege_escalation_0x02}` | `/root/root_flag.txt` | Exploit world-writable cron or SUID vim |
| `FLAG{ftp_anonymous_access_0x03}` | FTP `/pub/flag.txt` | Anonymous FTP login |
| `FLAG{ftp_backdoor_shell_0x04}` | `/root/flag.txt` on FTP host | CVE-2011-2523 (USER with `:)`) |
| `FLAG{wordpress_hidden_post_0x05}` | WP private post | Login as admin → Posts |
| `FLAG{wordpress_secret_page_0x06}` | `/s3cr3t-notes` | WP page enumeration |
| `FLAG{wordpress_db_enum_0x07}` | WP `options` table | DB access via phpMyAdmin/SQLi |

---

## 🛡️ Custom Wazuh Detection Rules (ctf_rules.xml)

| Rule ID | Level | Trigger | MITRE |
|---------|-------|---------|-------|
| 100001–100005 | 8–12 | WordPress attacks | T1110, T1190, T1505.003 |
| 100010–100011 | 10–12 | SQL Injection | T1190 |
| 100015 | 8 | XSS | T1059.007 |
| 100020–100021 | 10–13 | LFI / Path Traversal | T1083 |
| 100030–100031 | 10–12 | SSH brute force / default creds | T1110, T1078 |
| 100040–100042 | 10–15 | FTP brute / vsftpd backdoor | T1110, T1190 |
| 100050–100051 | 8–10 | Port scan | T1046 |
| 100060–100061 | 8–9 | Web scanner (Nikto/sqlmap) | T1595.002 |
| 100070–100071 | 11–12 | Privilege escalation | T1548 |
| 100080 | 13 | Reverse shell in HTTP | T1059 |
| 100090–100091 | 3–5 | CTF flag file accessed (FIM) | — |

---

## 🔧 Management Commands

```bash
./scripts/setup.sh start                # Build + start all targets
./scripts/setup.sh stop                 # Stop all containers
./scripts/setup.sh reset                # Wipe all containers + volumes
./scripts/setup.sh status               # docker compose ps
./scripts/setup.sh logs                 # Tail all logs
./scripts/setup.sh logs ssh-target      # Tail a single service
./scripts/setup.sh targets              # Print IP/port cheat-sheet

./scripts/push-rules.sh                 # Re-push Wazuh rules via API

# Attack simulator – test that Wazuh alerts fire
TARGET_HOST=localhost ./scripts/attack-simulator.sh all
TARGET_HOST=localhost ./scripts/attack-simulator.sh ssh
TARGET_HOST=localhost ./scripts/attack-simulator.sh wordpress
TARGET_HOST=localhost ./scripts/attack-simulator.sh sqli
TARGET_HOST=localhost ./scripts/attack-simulator.sh ftp

# Override Wazuh host at runtime (if IP ever changes)
WAZUH_HOST=10.0.10.5 ./scripts/setup.sh start
```

---

## 🔎 Wazuh Dashboard Queries

```
rule.groups: ctf                          # All CTF alerts
rule.groups: brute_force                  # All brute-force
rule.groups: wordpress                    # WP-specific
rule.id: 100042                           # FTP backdoor trigger
rule.level: [12 TO 15]                    # Critical only
agent.name: ssh-target*                   # SSH container agent
agent.name: ftp-target*                   # FTP container agent
```

---

## 🩺 Troubleshooting

| Symptom | Check |
|---------|-------|
| Agents not appearing in Wazuh dashboard | `sudo ss -tlnp \| grep 1515` on Wazuh VM – port must be open |
| No syslog alerts from WP/DVWA | `sudo ss -tlnp \| grep 514` on Wazuh VM; check `ossec-syslog-remote.conf` was added |
| Filebeat not shipping logs | `docker compose logs filebeat` – check port 5044 reachable |
| `push-rules.sh` auth fails | Set `WAZUH_PASS=YourActualPassword ./scripts/push-rules.sh` |
| Containers start but Wazuh shows nothing | Run `./scripts/attack-simulator.sh all` to generate traffic |
| Port already in use | `./scripts/setup.sh status` then `docker compose down` to clean up |

---

## ⚠️ Legal Notice

> Intentionally vulnerable software for **CTF / educational use only**.  
> Never expose to the public internet. Run on an isolated lab network only.

---

## 📄 Licence

MIT
