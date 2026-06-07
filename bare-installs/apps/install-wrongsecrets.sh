#!/usr/bin/env bash
# Install OWASP WrongSecrets  – run as root
set -euo pipefail
source "$(dirname "$0")/common.sh"
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash apps/install-wrongsecrets.sh"

INSTALL_DIR="/opt/wrongsecrets"
JAR_URL="https://github.com/OWASP/wrongsecrets/releases/download/v1.12.0/wrongsecrets-1.12.0.jar"
JAR="${INSTALL_DIR}/wrongsecrets.jar"

info "=== OWASP WrongSecrets ==="

# ── Java check ────────────────────────────────────────────────────────────────
if ! command -v java &>/dev/null; then
    info "Installing Java 17…"
    apt-get install -y --no-install-recommends openjdk-17-jre-headless
fi

# ── Download JAR ──────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
if [[ -f "$JAR" ]]; then
    warn "JAR already present – skipping download"
else
    info "Downloading WrongSecrets JAR (~80 MB)…"
    wget -q --show-progress -O "$JAR" "$JAR_URL"
fi

# ── System user ───────────────────────────────────────────────────────────────
id -u wrongsecrets &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" wrongsecrets
chown -R wrongsecrets:wrongsecrets "$INSTALL_DIR"

# ── Systemd service ───────────────────────────────────────────────────────────
cat > /etc/systemd/system/wrongsecrets.service <<UNIT
[Unit]
Description=OWASP WrongSecrets
After=network.target

[Service]
User=wrongsecrets
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/java -jar ${JAR} --server.port=8085 --server.address=127.0.0.1
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

enable_service wrongsecrets

# ── Apache2 proxy ─────────────────────────────────────────────────────────────
[[ ! -f "$APACHE_CONF" ]] && echo "# vuln-apps" > "$APACHE_CONF"
if ! grep -q "Location /wrongsecrets" "$APACHE_CONF"; then
    cat >> "$APACHE_CONF" <<'BLOCK'

# ── WrongSecrets (proxy → 127.0.0.1:8085) ───────────────
ProxyRequests Off
<Location /wrongsecrets/>
    ProxyPass        http://127.0.0.1:8085/
    ProxyPassReverse http://127.0.0.1:8085/
    ProxyPreserveHost On
    Require all granted
</Location>

BLOCK
fi
a2enmod proxy proxy_http &>/dev/null || true
a2enconf vuln-apps &>/dev/null || true
reload_apache

success "WrongSecrets ready → http://$(hostname -I | awk '{print $1}')/wrongsecrets/"
