#!/usr/bin/env bash
# =============================================================================
#  Dome WAF (Rust) – Installer
#  Compiles and installs Dome as a systemd service.
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
INSTALL_DIR="/opt/dome-rs"
BIN_PATH="${INSTALL_DIR}/dome"
SERVICE_USER="dome"
UPSTREAM="http://127.0.0.1:80"
LISTEN_PORT="8888"
LOG_DIR="/var/log/dome"

while [[ $# -gt 0 ]]; do
    case $1 in
        --upstream) UPSTREAM="$2"; shift 2 ;;
        --port)     LISTEN_PORT="$2"; shift 2 ;;
        *) warn "Unknown arg: $1"; shift ;;
    esac
done

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Dome WAF (Rust) – Installer                    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── Rust toolchain ────────────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    info "Installing Rust toolchain…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
fi
RUST_VER=$(rustc --version)
info "Rust: $RUST_VER"

# ── Build release binary ──────────────────────────────────────────────────────
info "Building Dome WAF (release, LTO)… this takes ~1-2 min on first build"
cd "$SCRIPT_DIR"
cargo build --release 2>&1

BIN_SRC="${SCRIPT_DIR}/target/release/dome"
[[ -f "$BIN_SRC" ]] || error "Build failed – binary not found at $BIN_SRC"
success "Build complete: $BIN_SRC ($(du -sh "$BIN_SRC" | cut -f1))"

# ── Install ───────────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR" "$LOG_DIR"
cp "$BIN_SRC" "$BIN_PATH"
chmod +x "$BIN_PATH"

# Write config
CONFIG_FILE="${INSTALL_DIR}/config.yml"
cat > "$CONFIG_FILE" <<CFGYML
proxy:
  listen_host: "0.0.0.0"
  listen_port: ${LISTEN_PORT}
  upstream: "${UPSTREAM}"
  upstream_timeout_secs: 30
  body_limit_bytes: 1048576

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
    ban_duration_secs: 300
  blocked_ja3: []
  blocked_ja4_prefixes: []
  reputation_threshold: 150
  reputation_ban_secs: 3600
  challenge_enabled: false
  challenge_categories: ["scanner", "ratelimit"]
  score_threshold: 30

notifications:
  discord_webhook: null
  discord_min_action: "BLOCK"
  webhook_url: null
  webhook_headers: {}
  webhook_min_action: "BLOCK"
  syslog:
    enabled: false
    host: "127.0.0.1"
    port: 514
    proto: "udp"
    min_action: "BLOCK"

logging:
  path: "${LOG_DIR}/waf.log"
  max_bytes: 10485760
  backup_count: 5
CFGYML

# ── System user ───────────────────────────────────────────────────────────────
id -u "$SERVICE_USER" &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "$INSTALL_DIR" "$LOG_DIR"

# ── Systemd ───────────────────────────────────────────────────────────────────
cat > /etc/systemd/system/dome-waf.service <<UNIT
[Unit]
Description=Dome WAF – Rust Standalone Reverse Proxy WAF
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH} --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now dome-waf
success "dome-waf service started"

IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Dome WAF (Rust) installed and running!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Listen:    http://${IP}:${LISTEN_PORT}"
echo -e "  Upstream:  ${UPSTREAM}"
echo -e "  Binary:    ${BIN_PATH}"
echo -e "  Config:    ${CONFIG_FILE}"
echo -e "  Logs:      ${LOG_DIR}/waf.log"
echo ""
echo -e "  sudo systemctl status dome-waf"
echo -e "  sudo journalctl -u dome-waf -f"
echo ""
