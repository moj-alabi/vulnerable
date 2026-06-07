#!/usr/bin/env bash
# Install bWAPP  – run as root
set -euo pipefail
source "$(dirname "$0")/common.sh"
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash apps/install-bwapp.sh"

DEST="${WEBROOT}/bwapp"

info "=== bWAPP ==="

# ── MySQL DB & user ───────────────────────────────────────────────────────────
info "Creating MySQL database…"
systemctl start mysql 2>/dev/null || systemctl start mariadb 2>/dev/null || true
mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS bwapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'bwapp'@'localhost' IDENTIFIED BY 'bwapp_pass';
GRANT ALL PRIVILEGES ON bwapp.* TO 'bwapp'@'localhost';
FLUSH PRIVILEGES;
SQL

# ── Clone ─────────────────────────────────────────────────────────────────────
if [[ -d "$DEST" ]]; then
    warn "Already present at $DEST – skipping clone"
else
    info "Cloning raesene/bWAPP (public mirror)…"
    git clone --depth 1 https://github.com/raesene/bWAPP.git /tmp/bwapp-src
    cp -r /tmp/bwapp-src "$DEST"
    rm -rf /tmp/bwapp-src
fi

# ── Patch DB config ───────────────────────────────────────────────────────────
info "Patching DB credentials…"
CFG="${DEST}/app/connect_i.php"
if [[ -f "$CFG" ]]; then
    # double-quote style
    sed -i 's/\$db_username *= *"[^"]*"/\$db_username = "bwapp"/'       "$CFG" || true
    sed -i 's/\$db_password *= *"[^"]*"/\$db_password = "bwapp_pass"/'  "$CFG" || true
    sed -i 's/\$db_name *= *"[^"]*"/\$db_name = "bwapp"/'               "$CFG" || true
    # single-quote style
    sed -i "s/\$db_username *= *'[^']*'/\$db_username = 'bwapp'/"       "$CFG" || true
    sed -i "s/\$db_password *= *'[^']*'/\$db_password = 'bwapp_pass'/"  "$CFG" || true
    sed -i "s/\$db_name *= *'[^']*'/\$db_name = 'bwapp'/"               "$CFG" || true
    info "  Patched $CFG"
else
    warn "app/connect_i.php not found – skipping DB config patch"
fi

# ── Permissions ───────────────────────────────────────────────────────────────
chown -R www-data:www-data "$DEST"
chmod -R 755 "$DEST"

# ── Apache2 ───────────────────────────────────────────────────────────────────
[[ ! -f "$APACHE_CONF" ]] && echo "# vuln-apps" > "$APACHE_CONF"
grep -q "Alias /bwapp" "$APACHE_CONF" || append_php_alias "bwapp"
a2enmod rewrite headers &>/dev/null || true
a2enconf vuln-apps &>/dev/null || true
reload_apache

success "bWAPP ready → http://$(hostname -I | awk '{print $1}')/bwapp"
info "  Visit /bwapp/install.php to seed the database, then login: bee / bug"
