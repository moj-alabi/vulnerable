#!/usr/bin/env bash
# Install OWASP Juice Shop  – run as root
set -euo pipefail
source "$(dirname "$0")/common.sh"
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash apps/install-juiceshop.sh"

INSTALL_DIR="/opt/juice-shop"
JS_VER="v17.0.0"
TARBALL="juice-shop-${JS_VER}_node20_linux_x64.tgz"
DL_URL="https://github.com/juice-shop/juice-shop/releases/download/${JS_VER}/${TARBALL}"

info "=== OWASP Juice Shop ==="

# ── Node check ────────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
    info "Installing Node.js LTS…"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt-get install -y nodejs
fi

# ── Download & extract ────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
if [[ -f "${INSTALL_DIR}/package.json" ]]; then
    warn "Juice Shop already present – skipping download"
else
    info "Downloading pre-built package (~250 MB)…"
    wget -q --show-progress -O "/tmp/${TARBALL}" "$DL_URL"
    tar -xzf "/tmp/${TARBALL}" -C "$INSTALL_DIR" --strip-components=1
    rm -f "/tmp/${TARBALL}"
fi

# ── System user ───────────────────────────────────────────────────────────────
id -u juiceshop &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" juiceshop
chown -R juiceshop:juiceshop "$INSTALL_DIR"

# ── Systemd service ───────────────────────────────────────────────────────────
NODE_BIN=$(which node)
cat > /etc/systemd/system/juiceshop.service <<UNIT
[Unit]
Description=OWASP Juice Shop
After=network.target

[Service]
User=juiceshop
WorkingDirectory=${INSTALL_DIR}
Environment=PORT=3000
ExecStart=${NODE_BIN} app.js
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

enable_service juiceshop

# ── Apache2 proxy ─────────────────────────────────────────────────────────────
[[ ! -f "$APACHE_CONF" ]] && echo "# vuln-apps" > "$APACHE_CONF"
if ! grep -q "Location /juice-shop" "$APACHE_CONF"; then
    cat >> "$APACHE_CONF" <<'BLOCK'

# ── Juice Shop (proxy → 127.0.0.1:3000) ─────────────────
ProxyRequests Off
<Location /juice-shop/>
    ProxyPass        http://127.0.0.1:3000/
    ProxyPassReverse http://127.0.0.1:3000/
    ProxyPreserveHost On
    Require all granted
</Location>

BLOCK
fi
a2enmod proxy proxy_http &>/dev/null || true
a2enconf vuln-apps &>/dev/null || true
reload_apache

success "Juice Shop ready → http://$(hostname -I | awk '{print $1}')/juice-shop/"
