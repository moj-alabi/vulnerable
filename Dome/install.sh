#!/usr/bin/env bash
# =============================================================================
#  Dome WAF – Installer
#  Installs Dome as a systemd service on any Linux host.
#  Does NOT require or modify any existing web server.
#
#  Usage:  sudo bash install.sh [--upstream http://127.0.0.1:80] [--port 8888]
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/dome"
SERVICE_USER="dome"
UPSTREAM="http://127.0.0.1:80"
LISTEN_PORT="8888"
LOG_DIR="/var/log/dome"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --upstream) UPSTREAM="$2"; shift 2 ;;
        --port)     LISTEN_PORT="$2"; shift 2 ;;
        *) warn "Unknown arg: $1"; shift ;;
    esac
done

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Dome WAF – Installer                            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
info "Upstream: $UPSTREAM"
info "Listen port: $LISTEN_PORT"
info "Install dir: $INSTALL_DIR"
echo ""

# ── Python 3.11+ check ────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    info "Installing python3…"
    apt-get update -qq && apt-get install -y --no-install-recommends python3 python3-pip python3-venv
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Python $PY_VER detected"

# ── Create install directory ──────────────────────────────────────────────────
info "Copying Dome to $INSTALL_DIR…"
mkdir -p "$INSTALL_DIR"
cp -r "${SCRIPT_DIR}/." "$INSTALL_DIR/"

# ── Create log directory ──────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"

# ── Create virtualenv & install deps ─────────────────────────────────────────
info "Creating Python virtualenv and installing dependencies…"
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"
success "Dependencies installed"

# ── Write config if not already customised ───────────────────────────────────
CONFIG_FILE="${INSTALL_DIR}/config.yml"
info "Writing config to $CONFIG_FILE…"
cat > "$CONFIG_FILE" <<CFGYML
proxy:
  listen_host: "0.0.0.0"
  listen_port: ${LISTEN_PORT}
  upstream: "${UPSTREAM}"
  upstream_timeout: 30

waf:
  mode: "block"
  allowed_ips:
    - "127.0.0.1"
  blocked_ips: []
  blocked_paths: []
  rate_limit:
    window_seconds: 60
    max_requests: 200
    sensitive_max: 20
    ban_duration: 300

logging:
  path: "${LOG_DIR}/waf.log"
  max_bytes: 10485760
  backup_count: 5
CFGYML

# ── Dedicated system user ─────────────────────────────────────────────────────
id -u "$SERVICE_USER" &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "$INSTALL_DIR" "$LOG_DIR"

# ── Systemd service ───────────────────────────────────────────────────────────
info "Installing systemd service…"
cat > /etc/systemd/system/dome-waf.service <<UNIT
[Unit]
Description=Dome WAF – Standalone Reverse Proxy WAF
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/waf.py --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now dome-waf
success "dome-waf service started"

# ── Done ──────────────────────────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Dome WAF installed and running!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Listen:    http://${IP}:${LISTEN_PORT}"
echo -e "  Upstream:  ${UPSTREAM}"
echo -e "  Mode:      BLOCK"
echo -e "  Logs:      ${LOG_DIR}/waf.log"
echo -e "  Config:    ${CONFIG_FILE}"
echo ""
echo -e "  Manage:"
echo -e "    sudo systemctl status dome-waf"
echo -e "    sudo systemctl restart dome-waf"
echo -e "    sudo journalctl -u dome-waf -f"
echo ""
echo -e "  Switch to detect-only mode:"
echo -e "    Edit ${CONFIG_FILE}  →  mode: detect"
echo -e "    sudo systemctl restart dome-waf"
echo ""
