#!/usr/bin/env bash
# =============================================================================
#  install.sh  –  Orchestrator: installs all vulnerable web apps
#
#  Calls individual scripts in apps/ so you can see exactly which one fails.
#  You can also run any app script on its own:
#    sudo bash apps/install-mutillidae.sh
#    sudo bash apps/install-bwapp.sh
#    sudo bash apps/install-webgoat.sh
#    ... etc
#
#  Usage:  sudo bash install.sh
# =============================================================================

# Do NOT use set -e here – we want to continue past individual app failures
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

[[ $EUID -ne 0 ]] && { echo -e "${RED}[ERR]${NC}  Run as root: sudo bash install.sh"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPS_DIR="${SCRIPT_DIR}/apps"
LOG_FILE="/var/log/vuln-apps-install.log"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Vulnerable Apps – Bare-Metal Installer          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Log: ${LOG_FILE}"
echo ""

# ── Install base system dependencies once ────────────────────────────────────
echo -e "${CYAN}[INFO]${NC}  Installing base dependencies…"
apt-get update -qq
apt-get install -y --no-install-recommends \
    git curl wget unzip \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')" \
    "libapache2-mod-php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')" \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-mysql" \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-xml" \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-mbstring" \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-curl" \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-gd" \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-ldap" \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-zip" \
    "php$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')-bcmath" \
    openjdk-17-jre-headless \
    python3 2>&1 | tee -a "$LOG_FILE"

# MySQL: skip if already installed
if mysql --version &>/dev/null 2>&1; then
    echo -e "${CYAN}[INFO]${NC}  MySQL already installed – skipping"
else
    apt-get install -y --no-install-recommends mysql-server 2>&1 | tee -a "$LOG_FILE"
fi

# Node.js: install if missing or upgrade if old
if ! command -v node &>/dev/null || node --version 2>/dev/null | grep -qE '^v1[0-5]\.'; then
    echo -e "${CYAN}[INFO]${NC}  Installing Node.js LTS…"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - 2>&1 | tee -a "$LOG_FILE"
    apt-get install -y nodejs 2>&1 | tee -a "$LOG_FILE"
fi

a2enmod proxy proxy_http rewrite headers &>/dev/null || true

echo ""

# ── Run each app installer, track pass/fail ───────────────────────────────────
PASS=()
FAIL=()

run_installer() {
    local NAME="$1"
    local SCRIPT="${APPS_DIR}/$2"
    echo -e "${CYAN}────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}  Installing: ${NAME}${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────${NC}"

    # Run in a subshell so any 'exit' or unhandled error stays contained.
    # tee exit code is irrelevant; we check the script exit code via PIPESTATUS.
    set +e
    bash "$SCRIPT" 2>&1 | tee -a "$LOG_FILE"
    local EXIT_CODE="${PIPESTATUS[0]}"
    set -e

    if [[ "$EXIT_CODE" -eq 0 ]]; then
        PASS+=("$NAME")
        echo -e "${GREEN}[DONE]${NC}  ${NAME}"
    else
        FAIL+=("$NAME  (exit code ${EXIT_CODE})")
        echo -e "${RED}[FAILED]${NC}  ${NAME} exited with code ${EXIT_CODE}"
        echo -e "${RED}         ${NC}  To retry:  sudo bash apps/$2"
        echo -e "${RED}         ${NC}  Full log:  ${LOG_FILE}"
    fi
    echo ""
}

run_installer "Mutillidae II"      "install-mutillidae.sh"
run_installer "bWAPP"              "install-bwapp.sh"
run_installer "WackoPicko"         "install-wackopicko.sh"
run_installer "Hackazon"           "install-hackazon.sh"
run_installer "OWASP WebGoat 2023" "install-webgoat.sh"
run_installer "OWASP Juice Shop"   "install-juiceshop.sh"
run_installer "OWASP WrongSecrets" "install-wrongsecrets.sh"

# ── Summary ───────────────────────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation Summary${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""

if [[ ${#PASS[@]} -gt 0 ]]; then
    echo -e "${GREEN}  ✓ Installed successfully:${NC}"
    for APP in "${PASS[@]}"; do echo -e "    ● $APP"; done
    echo ""
fi

if [[ ${#FAIL[@]} -gt 0 ]]; then
    echo -e "${RED}  ✗ Failed (run individually to debug):${NC}"
    for APP in "${FAIL[@]}"; do
        SCRIPT=$(echo "$APP" | tr '[:upper:] ' '[:lower:]-' | sed 's/[^a-z0-9-]//g')
        echo -e "    ● $APP  →  sudo bash apps/install-${SCRIPT}.sh"
    done
    echo ""
fi

echo -e "  ${CYAN}URLs (once Apache2 is serving):${NC}"
echo -e "  ● Mutillidae II   →  http://${IP}/mutillidae"
echo -e "  ● bWAPP           →  http://${IP}/bwapp  (seed at /bwapp/install.php)"
echo -e "  ● WackoPicko      →  http://${IP}/wackopicko"
echo -e "  ● Hackazon        →  http://${IP}/hackazon"
echo -e "  ● WebGoat 2023    →  http://${IP}/WebGoat  (~60 s startup)"
echo -e "  ● Juice Shop      →  http://${IP}/juice-shop/"
echo -e "  ● WrongSecrets    →  http://${IP}/wrongsecrets/"
echo ""
echo -e "  ${YELLOW}Existing DVWA → http://${IP}/DVWA${NC}"
echo ""
echo -e "  Full log: ${LOG_FILE}"
echo ""
