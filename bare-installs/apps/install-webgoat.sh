#!/usr/bin/env bash
# Install OWASP WebGoat 2023  – run as root
set -euo pipefail
source "$(dirname "$0")/common.sh"
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash apps/install-webgoat.sh"

INSTALL_DIR="/opt/webgoat"
JAR_URL="https://github.com/WebGoat/WebGoat/releases/download/v2023.8/webgoat-2023.8.jar"
JAR="${INSTALL_DIR}/webgoat.jar"

info "=== OWASP WebGoat 2023 ==="

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
    info "Downloading WebGoat JAR (~130 MB)…"
    wget -q --show-progress -O "$JAR" "$JAR_URL"
fi

# ── System user ───────────────────────────────────────────────────────────────
id -u webgoat &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" webgoat
chown -R webgoat:webgoat "$INSTALL_DIR"

# ── Systemd service ───────────────────────────────────────────────────────────
cat > /etc/systemd/system/webgoat.service <<UNIT
[Unit]
Description=OWASP WebGoat
After=network.target

[Service]
User=webgoat
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/java -Dfile.encoding=UTF-8 \
    --add-opens java.base/java.lang=ALL-UNNAMED \
    --add-opens java.base/java.util=ALL-UNNAMED \
    -jar ${JAR} \
    --server.port=8080 \
    --server.address=127.0.0.1 \
    --webgoat.host=127.0.0.1 \
    --webgoat.port=8080 \
    --webwolf.host=127.0.0.1 \
    --webwolf.port=9090
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

enable_service webgoat

# ── Apache2 proxy ─────────────────────────────────────────────────────────────
[[ ! -f "$APACHE_CONF" ]] && echo "# vuln-apps" > "$APACHE_CONF"
if ! grep -q "Location /WebGoat" "$APACHE_CONF"; then
    cat >> "$APACHE_CONF" <<'BLOCK'

# ── WebGoat (proxy → 127.0.0.1:8080) ────────────────────
ProxyRequests Off
<Location /WebGoat>
    ProxyPass        http://127.0.0.1:8080/WebGoat
    ProxyPassReverse http://127.0.0.1:8080/WebGoat
    ProxyPreserveHost On
    Require all granted
</Location>

BLOCK
fi
a2enmod proxy proxy_http &>/dev/null || true
a2enconf vuln-apps &>/dev/null || true
reload_apache

success "WebGoat ready → http://$(hostname -I | awk '{print $1}')/WebGoat"
info "  Note: Spring Boot takes ~60 s to start. Check: sudo journalctl -u webgoat -f"
