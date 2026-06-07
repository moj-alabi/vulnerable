# 🛡️ Dome WAF

**Dome** is a standalone, lightweight Web Application Firewall built as an async Python reverse proxy. It sits in front of any HTTP server, inspects every request, and either blocks or logs attacks.

Zero dependency on Apache, nginx, or any specific web stack — point it at any upstream and it works.

---

## Architecture

```
  Client
    │
    ▼  :8888 (configurable)
┌─────────────────────────────────┐
│           Dome WAF              │
│                                 │
│  ┌─────────────────────────┐   │
│  │     Rule Engine          │   │
│  │  ┌──────┐ ┌──────────┐  │   │
│  │  │SQLi  │ │  XSS     │  │   │
│  │  ├──────┤ ├──────────┤  │   │
│  │  │ LFI  │ │  RCE     │  │   │
│  │  ├──────┤ ├──────────┤  │   │
│  │  │Scan  │ │RateLimit │  │   │
│  │  └──────┘ └──────────┘  │   │
│  └─────────────────────────┘   │
│           │ BLOCK → 403         │
│           │ ALLOW → forward     │
│           ▼                     │
│       JSON Logger               │
└─────────────────────────────────┘
    │
    ▼  upstream (e.g. http://127.0.0.1:80)
  Your web server
```

---

## Features

| Feature | Details |
|---------|---------|
| **SQLi detection** | UNION SELECT, blind, time-based, hex encoding, schema enum |
| **XSS detection** | Script tags, event handlers, JS/VBS URIs, DOM attacks, entity encoding |
| **LFI/RFI detection** | Path traversal, null bytes, PHP wrappers, remote inclusion |
| **RCE detection** | Shell metacharacters, command substitution, Log4Shell/JNDI, OGNL |
| **Scanner detection** | sqlmap, nikto, Burp, OWASP ZAP, Nuclei, 30+ tools by UA; probe path matching |
| **Rate limiting** | Sliding-window per IP; stricter limits on login/admin paths; auto-ban |
| **IP allowlist/blocklist** | Instant bypass or block by IP |
| **Blocked paths** | Block specific URL prefixes entirely |
| **Two modes** | `block` (return 403) or `detect` (log-only, no blocking) |
| **Structured JSON logs** | Every request logged with action, rules hit, duration, IP |
| **Rotating log file** | Auto-rotated, Filebeat/Wazuh-compatible format |
| **systemd service** | Runs as unprivileged `dome` user, auto-restarts on failure |

---

## Quick Start

### Option A — systemd install (production)

```bash
# Clone or copy Dome to the target machine
git clone https://github.com/yourrepo/vulnerable.git
cd vulnerable/Dome

# Install (proxies port 8888 → your web server on port 80)
sudo bash install.sh

# Custom upstream / port
sudo bash install.sh --upstream http://127.0.0.1:8080 --port 9000
```

After install, traffic hitting `:8888` is inspected before being forwarded to the real server.

### Option B — run manually (dev/test)

```bash
cd Dome
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Edit config.yml first, then:
python waf.py

# Or with CLI overrides:
python waf.py --upstream http://127.0.0.1:80 --port 8888 --mode detect
```

---

## Configuration

Edit `config.yml` (or `/opt/dome/config.yml` after install):

```yaml
proxy:
  listen_host: "0.0.0.0"
  listen_port: 8888
  upstream: "http://127.0.0.1:80"
  upstream_timeout: 30

waf:
  mode: "block"          # block | detect

  allowed_ips:
    - "127.0.0.1"        # always bypass WAF

  blocked_ips: []        # always block

  blocked_paths: []      # block by URL prefix

  rate_limit:
    window_seconds: 60
    max_requests: 200    # per IP, per window
    sensitive_max: 20    # for /login, /admin, etc.
    ban_duration: 300    # seconds banned after exceeding limit

logging:
  path: "/var/log/dome/waf.log"
  max_bytes: 10485760
  backup_count: 5
```

After changing config:
```bash
sudo systemctl restart dome-waf
```

---

## Modes

| Mode | Behaviour |
|------|-----------|
| `block` | Returns **HTTP 403** with a block page. Adds `X-Dome-Action: BLOCK` and `X-Dome-Rules: RULE-IDs` headers. |
| `detect` | Forwards all requests normally but logs every match. Use to tune rules before enforcing. |

---

## Log format

Every request produces a JSON line in `/var/log/dome/waf.log`:

```json
{
  "timestamp": "2026-06-07T21:00:00Z",
  "product": "dome-waf",
  "action": "BLOCK",
  "client_ip": "10.0.1.5",
  "method": "GET",
  "path": "/login.php",
  "status_code": 403,
  "duration_ms": 0.42,
  "hit_count": 2,
  "categories": ["sqli", "ratelimit"],
  "hits": [
    {"rule_id": "SQLI-001", "description": "UNION SELECT injection", "category": "sqli"},
    {"rule_id": "RATE-001", "description": "Rate limit exceeded...", "category": "ratelimit"}
  ]
}
```

**Allowed requests** are also logged with `"action": "ALLOW"` for full audit trail.

---

## Detection rules

### Rule IDs

| Range | Category |
|-------|----------|
| `SQLI-001` – `SQLI-010` | SQL Injection |
| `XSS-001` – `XSS-010` | Cross-Site Scripting |
| `LFI-001` – `LFI-006` | Local File Inclusion / Path Traversal |
| `RFI-001` – `RFI-002` | Remote File Inclusion |
| `RCE-001` – `RCE-010` | Remote Code / Command Execution |
| `SCAN-001` – `SCAN-002` | Scanner / Automated Tool |
| `RATE-001` – `RATE-002` | Rate Limit / Brute Force |
| `IP-001` | IP Blocklist |
| `PATH-001` | Blocked Path |

---

## Service management

```bash
sudo systemctl status dome-waf
sudo systemctl restart dome-waf
sudo systemctl stop dome-waf
sudo journalctl -u dome-waf -f          # live logs
tail -f /var/log/dome/waf.log | python3 -m json.tool   # pretty-print log
```

---

## Uninstall

```bash
sudo systemctl disable --now dome-waf
sudo rm /etc/systemd/system/dome-waf.service
sudo systemctl daemon-reload
sudo rm -rf /opt/dome /var/log/dome
sudo userdel dome
```

---

## Project structure

```
Dome/
├── waf.py                  ← entry point
├── config.yml              ← default configuration
├── requirements.txt        ← aiohttp, PyYAML
├── install.sh              ← systemd installer
├── README.md
└── dome/
    ├── __init__.py
    ├── proxy.py            ← async aiohttp reverse proxy
    ├── logger.py           ← structured JSON + colour logger
    └── rules/
        ├── __init__.py
        ├── engine.py       ← orchestrates all rule modules
        ├── sqli.py
        ├── xss.py
        ├── lfi.py
        ├── rce.py
        ├── scanner.py
        └── ratelimit.py
```
