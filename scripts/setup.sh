#!/bin/bash
# ============================================================
#  CTF Vulnerable Lab – Setup Script
#  Wazuh SIEM is on existing VM: 10.0.10.2
#  Usage: ./scripts/setup.sh [start|stop|reset|status|logs|targets|push-rules]
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WAZUH_HOST="${WAZUH_HOST:-10.0.10.2}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║        CTF Vulnerable Lab  –  by Scrappy         ║"
  echo "  ║   Targets → Wazuh SIEM @ ${WAZUH_HOST}           ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

check_deps() {
  echo -e "${YELLOW}[*] Checking dependencies...${RESET}"
  for cmd in docker curl; do
    if command -v "$cmd" &>/dev/null; then
      echo -e "  ${GREEN}✓${RESET} $cmd"
    else
      echo -e "  ${RED}✗${RESET} $cmd – NOT FOUND"
      [[ "$cmd" == "docker" ]] && { echo -e "${RED}[!] Docker required.${RESET}"; exit 1; }
    fi
  done
  if ! docker info &>/dev/null; then
    echo -e "${RED}[!] Docker daemon not running.${RESET}"; exit 1
  fi
  echo -e "  ${GREEN}✓${RESET} Docker daemon running"
}

check_wazuh() {
  echo -e "${YELLOW}[*] Checking Wazuh connectivity at ${WAZUH_HOST}...${RESET}"
  # Test API port
  if curl -sk --connect-timeout 5 "https://${WAZUH_HOST}:55000" -o /dev/null; then
    echo -e "  ${GREEN}✓${RESET} Wazuh API reachable at https://${WAZUH_HOST}:55000"
  else
    echo -e "  ${YELLOW}⚠${RESET} Wazuh API not reachable – containers will still start"
    echo -e "     (agents will register when Wazuh becomes available)"
  fi
  # Test syslog port
  if nc -z -w2 "${WAZUH_HOST}" 514 2>/dev/null; then
    echo -e "  ${GREEN}✓${RESET} Wazuh syslog port 514 reachable"
  else
    echo -e "  ${YELLOW}⚠${RESET} Wazuh syslog port 514 not reachable"
    echo -e "     Ensure ossec.conf on ${WAZUH_HOST} has: <connection>syslog</connection>"
  fi
}

check_ports() {
  echo -e "${YELLOW}[*] Checking for local port conflicts...${RESET}"
  local ports=(2121 2222 8080 8081 8082 8083 8084 8085)
  for port in "${ports[@]}"; do
    if lsof -i ":$port" &>/dev/null 2>&1; then
      echo -e "  ${YELLOW}⚠${RESET} Port $port already in use"
    else
      echo -e "  ${GREEN}✓${RESET} Port $port free"
    fi
  done
}

patch_rsyslog() {
  # Substitute the real Wazuh IP into the rsyslog config before starting
  echo -e "${YELLOW}[*] Patching rsyslog config with Wazuh IP ${WAZUH_HOST}...${RESET}"
  sed -i.bak "s/WAZUH_MANAGER_IP/${WAZUH_HOST}/g" \
    "$ROOT_DIR/configs/rsyslog/rsyslog-apache.conf" || true
  echo -e "  ${GREEN}✓${RESET} rsyslog-apache.conf → ${WAZUH_HOST}:514"
}

start_lab() {
  banner
  check_deps
  check_wazuh
  check_ports
  patch_rsyslog

  echo ""
  echo -e "${YELLOW}[*] Building custom images (ssh-target, ftp-target)...${RESET}"
  cd "$ROOT_DIR"
  docker compose build \
    --build-arg WAZUH_MANAGER="${WAZUH_HOST}" \
    --parallel 2>&1 | grep -E "Step|Successfully|=>|ERROR|WARNING" || true

  echo ""
  echo -e "${YELLOW}[*] Starting all vulnerable targets...${RESET}"
  docker compose up -d

  echo ""
  echo -e "${GREEN}${BOLD}[✓] CTF Lab is UP!${RESET}"
  print_targets

  echo ""
  echo -e "${YELLOW}[*] Pushing detection rules to Wazuh at ${WAZUH_HOST}...${RESET}"
  bash "$SCRIPT_DIR/push-rules.sh" || \
    echo -e "${YELLOW}[!] Rule push skipped – run manually: ./scripts/push-rules.sh${RESET}"
}

print_targets() {
  local HOST_IP
  HOST_IP=$(ipconfig getifaddr en0 2>/dev/null || \
            ip route get 1 2>/dev/null | awk '{print $7;exit}' || \
            echo "THIS_HOST_IP")

  echo ""
  echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${RESET}"
  echo -e "${CYAN}${BOLD}  VULNERABLE TARGETS  (host IP: ${HOST_IP})${RESET}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════${RESET}"
  printf "  %-34s %s\n" "WordPress 5.0 (CVE-2019-8942)"   "http://${HOST_IP}:8080"
  printf "  %-34s %s\n" "DVWA"                              "http://${HOST_IP}:8081"
  printf "  %-34s %s\n" "WebGoat 8.0"                      "http://${HOST_IP}:8082/WebGoat"
  printf "  %-34s %s\n" "OWASP Juice Shop"                  "http://${HOST_IP}:8083"
  printf "  %-34s %s\n" "Mutillidae II"                     "http://${HOST_IP}:8084"
  printf "  %-34s %s\n" "phpMyAdmin 4.8.1 (CVE-2018-12613)" "http://${HOST_IP}:8085"
  printf "  %-34s %s\n" "SSH Target (weak creds)"           "${HOST_IP}:2222"
  printf "  %-34s %s\n" "FTP Target (vsftpd backdoor)"      "${HOST_IP}:2121  backdoor→:6200"
  echo ""
  echo -e "${CYAN}${BOLD}  SECURITY MONITORING${RESET}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════${RESET}"
  printf "  %-34s %s\n" "Wazuh Dashboard (SIEM)"   "https://${WAZUH_HOST}"
  printf "  %-34s %s\n" "Wazuh API"                "https://${WAZUH_HOST}:55000"
  echo ""
  echo -e "${CYAN}${BOLD}  DEFAULT CREDENTIALS (TARGETS)${RESET}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════${RESET}"
  printf "  %-34s %s\n" "WordPress admin"  "admin / admin123"
  printf "  %-34s %s\n" "DVWA"             "admin / password"
  printf "  %-34s %s\n" "SSH"              "admin:admin  ctfuser:password  guest:guest123"
  printf "  %-34s %s\n" "FTP"              "anonymous  or  ftpuser:ftppass"
  echo ""
  echo -e "${CYAN}${BOLD}  CTF FLAGS${RESET}"
  echo -e "${CYAN}═══════════════════════════════════════════════════════${RESET}"
  echo "  FLAG{ssh_brute_force_success_0x01}   – /home/ctfuser/flag.txt (SSH)"
  echo "  FLAG{root_privilege_escalation_0x02} – /root/root_flag.txt (priv-esc)"
  echo "  FLAG{ftp_anonymous_access_0x03}      – FTP /pub/flag.txt"
  echo "  FLAG{ftp_backdoor_shell_0x04}        – FTP CVE-2011-2523 :)"
  echo "  FLAG{wordpress_hidden_post_0x05}     – WP private post"
  echo "  FLAG{wordpress_secret_page_0x06}     – WP /s3cr3t-notes"
  echo "  FLAG{wordpress_db_enum_0x07}         – WP options table"
  echo -e "${CYAN}═══════════════════════════════════════════════════════${RESET}"
  echo ""
}

stop_lab() {
  echo -e "${YELLOW}[*] Stopping CTF Lab...${RESET}"
  cd "$ROOT_DIR" && docker compose down
  echo -e "${GREEN}[✓] Stopped${RESET}"
}

reset_lab() {
  echo -e "${RED}[!] Destroys ALL containers and volumes.${RESET}"
  read -rp "Sure? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }
  cd "$ROOT_DIR"
  docker compose down -v --rmi local 2>/dev/null || true
  # Restore rsyslog config backup
  mv configs/rsyslog/rsyslog-apache.conf.bak \
     configs/rsyslog/rsyslog-apache.conf 2>/dev/null || true
  echo -e "${GREEN}[✓] Reset complete${RESET}"
}

status_lab() {
  cd "$ROOT_DIR" && docker compose ps
}

logs_lab() {
  local svc="${2:-}"
  cd "$ROOT_DIR"
  [[ -n "$svc" ]] && docker compose logs -f "$svc" || docker compose logs -f --tail=50
}

CMD="${1:-start}"
case "$CMD" in
  start)      start_lab ;;
  stop)       stop_lab ;;
  reset)      reset_lab ;;
  status)     status_lab ;;
  logs)       logs_lab "$@" ;;
  targets)    banner; print_targets ;;
  push-rules) bash "$SCRIPT_DIR/push-rules.sh" ;;
  *)
    echo "Usage: $0 {start|stop|reset|status|logs [svc]|targets|push-rules}"
    exit 1 ;;
esac
