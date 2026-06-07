#!/usr/bin/env bash
# Install Mutillidae II  – run as root
set -euo pipefail
source "$(dirname "$0")/common.sh"
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash apps/install-mutillidae.sh"

DEST="${WEBROOT}/mutillidae"

info "=== Mutillidae II ==="

# ── MySQL DB & user ───────────────────────────────────────────────────────────
info "Creating MySQL database…"
systemctl start mysql 2>/dev/null || systemctl start mariadb 2>/dev/null || true
mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS mutillidae CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidae_pass';
GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';
FLUSH PRIVILEGES;
SQL

# ── Clone ─────────────────────────────────────────────────────────────────────
if [[ -d "$DEST" ]]; then
    warn "Already present at $DEST – skipping clone"
else
    info "Cloning…"
    git clone --depth 1 https://github.com/webpwnized/mutillidae.git "$DEST"
fi

# ── Patch DB config ───────────────────────────────────────────────────────────
info "Patching DB credentials…"
PATCHED=0
for CFG in \
    "${DEST}/includes/database-config.inc" \
    "${DEST}/src/includes/database-config.inc" \
    "${DEST}/classes/MySQLHandler.php"; do
    if [[ -f "$CFG" ]]; then
        sed -i "s/define('DB_USERNAME'.*$/define('DB_USERNAME', 'mutillidae');/"      "$CFG" || true
        sed -i "s/define('DB_PASSWORD'.*$/define('DB_PASSWORD', 'mutillidae_pass');/" "$CFG" || true
        sed -i "s/define('DB_NAME'.*$/define('DB_NAME', 'mutillidae');/"              "$CFG" || true
        sed -i "s/'DB_USERNAME'[^,]*, *'[^']*'/'DB_USERNAME', 'mutillidae'/"          "$CFG" || true
        sed -i "s/'DB_PASSWORD'[^,]*, *'[^']*'/'DB_PASSWORD', 'mutillidae_pass'/"     "$CFG" || true
        info "  Patched $CFG"; PATCHED=1
    fi
done
[[ $PATCHED -eq 0 ]] && warn "No config file found – may need manual edit"

# ── Permissions ───────────────────────────────────────────────────────────────
chown -R www-data:www-data "$DEST"
chmod -R 755 "$DEST"

# ── Apache2 ───────────────────────────────────────────────────────────────────
[[ ! -f "$APACHE_CONF" ]] && echo "# vuln-apps" > "$APACHE_CONF"
grep -q "Alias /mutillidae" "$APACHE_CONF" || append_php_alias "mutillidae"
a2enmod rewrite headers &>/dev/null || true
a2enconf vuln-apps &>/dev/null || true
reload_apache

success "Mutillidae II ready → http://$(hostname -I | awk '{print $1}')/mutillidae"
info "  Click 'Reset DB' on first visit to initialise the database"
