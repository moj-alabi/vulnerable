#!/usr/bin/env bash
# Install Hackazon  – run as root
set -euo pipefail
source "$(dirname "$0")/common.sh"
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash apps/install-hackazon.sh"

DEST="${WEBROOT}/hackazon"

info "=== Hackazon ==="

# ── MySQL DB & user ───────────────────────────────────────────────────────────
info "Creating MySQL database…"
systemctl start mysql 2>/dev/null || systemctl start mariadb 2>/dev/null || true
mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS hackazon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'hackazon'@'localhost' IDENTIFIED BY 'hackazon_pass';
GRANT ALL PRIVILEGES ON hackazon.* TO 'hackazon'@'localhost';
FLUSH PRIVILEGES;
SQL

# ── Clone ─────────────────────────────────────────────────────────────────────
if [[ -d "$DEST" ]]; then
    warn "Already present at $DEST – skipping clone"
else
    info "Cloning…"
    git clone --depth 1 https://github.com/rapid7/hackazon.git "$DEST"
fi

# ── Composer ─────────────────────────────────────────────────────────────────
if command -v composer &>/dev/null; then
    info "Running composer install…"
    (cd "$DEST" && composer install --no-interaction --no-dev 2>/dev/null) || warn "Composer install had errors"
else
    warn "Composer not found – Hackazon may not work. Install with:"
    warn "  curl -sS https://getcomposer.org/installer | sudo php -- --install-dir=/usr/local/bin --filename=composer"
fi

# ── Patch DB config ───────────────────────────────────────────────────────────
info "Patching DB credentials…"
CFG="${DEST}/config/db.php"
[[ ! -f "$CFG" && -f "${DEST}/config/db.php.example" ]] && cp "${DEST}/config/db.php.example" "$CFG"
if [[ -f "$CFG" ]]; then
    sed -i "s/'username' *=> *'.*'/'username' => 'hackazon'/"      "$CFG" || true
    sed -i "s/'password' *=> *'.*'/'password' => 'hackazon_pass'/" "$CFG" || true
    sed -i "s/'dbname'   *=> *'.*'/'dbname'   => 'hackazon'/"      "$CFG" || true
    info "  Patched $CFG"
else
    warn "config/db.php not found – skipping patch"
fi

# ── Permissions ───────────────────────────────────────────────────────────────
chown -R www-data:www-data "$DEST"
chmod -R 755 "$DEST"

# ── Apache2 ───────────────────────────────────────────────────────────────────
[[ ! -f "$APACHE_CONF" ]] && echo "# vuln-apps" > "$APACHE_CONF"
grep -q "Alias /hackazon" "$APACHE_CONF" || append_php_alias "hackazon"
a2enmod rewrite headers &>/dev/null || true
a2enconf vuln-apps &>/dev/null || true
reload_apache

success "Hackazon ready → http://$(hostname -I | awk '{print $1}')/hackazon"
