#!/usr/bin/env bash
# =============================================================================
#  db-fix.sh  –  Fix DB credentials for already-installed bWAPP & Mutillidae
#
#  Run this if the apps were already cloned but are showing DB auth errors
#  (e.g. "Access denied for user 'root'@'localhost'").
#
#  Usage:  sudo bash db-fix.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Please run as root:  sudo bash db-fix.sh"

WEBROOT="/var/www/html"

# ── 1. Ensure DB users & databases exist ─────────────────────────────────────
info "Ensuring MySQL users and databases exist…"
systemctl start mysql 2>/dev/null || systemctl start mariadb 2>/dev/null || true

mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS mutillidae CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidae_pass';
GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';

CREATE DATABASE IF NOT EXISTS bwapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'bwapp'@'localhost' IDENTIFIED BY 'bwapp_pass';
GRANT ALL PRIVILEGES ON bwapp.* TO 'bwapp'@'localhost';

FLUSH PRIVILEGES;
SQL
success "MySQL users ready"

# ── 2. Fix Mutillidae ─────────────────────────────────────────────────────────
MUTI="${WEBROOT}/mutillidae"
if [[ -d "$MUTI" ]]; then
    info "Patching Mutillidae DB config…"

    # Try all known config file locations across repo versions
    PATCHED=0
    for CFG in \
        "${MUTI}/includes/database-config.inc" \
        "${MUTI}/src/includes/database-config.inc" \
        "${MUTI}/classes/MySQLHandler.php"; do

        if [[ -f "$CFG" ]]; then
            info "  Found config: $CFG"

            # database-config.inc style  →  define('DB_USERNAME', '...');
            sed -i "s/define('DB_USERNAME'.*$/define('DB_USERNAME', 'mutillidae');/"     "$CFG" 2>/dev/null || true
            sed -i "s/define('DB_PASSWORD'.*$/define('DB_PASSWORD', 'mutillidae_pass');/" "$CFG" 2>/dev/null || true
            sed -i "s/define('DB_NAME'.*$/define('DB_NAME', 'mutillidae');/"              "$CFG" 2>/dev/null || true

            # MySQLHandler.php style  →  'DB_USERNAME', 'root'
            sed -i "s/'DB_USERNAME'[^,]*, *'[^']*'/'DB_USERNAME', 'mutillidae'/"     "$CFG" 2>/dev/null || true
            sed -i "s/'DB_PASSWORD'[^,]*, *'[^']*'/'DB_PASSWORD', 'mutillidae_pass'/" "$CFG" 2>/dev/null || true

            PATCHED=1
            success "  Patched $CFG"
        fi
    done

    [[ $PATCHED -eq 0 ]] && warn "Mutillidae config file not found – may need manual edit"

    chown -R www-data:www-data "$MUTI"
    success "Mutillidae DB config fixed"
else
    warn "Mutillidae not found at $MUTI – skipping"
fi

# ── 3. Fix bWAPP ──────────────────────────────────────────────────────────────
BWAPP="${WEBROOT}/bwapp"
if [[ -d "$BWAPP" ]]; then
    info "Patching bWAPP DB config…"

    # raesene/bWAPP mirror uses app/connect_i.php
    CFG="${BWAPP}/app/connect_i.php"
    if [[ -f "$CFG" ]]; then
        info "  Found config: $CFG"

        # Double-quote style
        sed -i 's/\$db_username *= *"[^"]*"/\$db_username = "bwapp"/'       "$CFG" || true
        sed -i 's/\$db_password *= *"[^"]*"/\$db_password = "bwapp_pass"/'  "$CFG" || true
        sed -i 's/\$db_name *= *"[^"]*"/\$db_name = "bwapp"/'               "$CFG" || true
        # Single-quote style
        sed -i "s/\$db_username *= *'[^']*'/\$db_username = 'bwapp'/"       "$CFG" || true
        sed -i "s/\$db_password *= *'[^']*'/\$db_password = 'bwapp_pass'/"  "$CFG" || true
        sed -i "s/\$db_name *= *'[^']*'/\$db_name = 'bwapp'/"               "$CFG" || true

        success "  Patched $CFG"
    else
        warn "bWAPP: app/connect_i.php not found – trying admin/settings.php…"
        CFG="${BWAPP}/admin/settings.php"
        if [[ -f "$CFG" ]]; then
            sed -i "s/\$db_username = .*/\$db_username = 'bwapp';/"      "$CFG" || true
            sed -i "s/\$db_password = .*/\$db_password = 'bwapp_pass';/" "$CFG" || true
            sed -i "s/\$db_name = .*/\$db_name = 'bwapp';/"              "$CFG" || true
            success "  Patched $CFG"
        else
            warn "bWAPP config not found – try manually editing $BWAPP/app/connect_i.php"
        fi
    fi

    chown -R www-data:www-data "$BWAPP"
    success "bWAPP DB config fixed"
else
    warn "bWAPP not found at $BWAPP – skipping"
fi

# ── 4. Print current config so you can verify ────────────────────────────────
echo ""
info "Current Mutillidae config values:"
for CFG in \
    "${MUTI}/includes/database-config.inc" \
    "${MUTI}/src/includes/database-config.inc" \
    "${MUTI}/classes/MySQLHandler.php"; do
    [[ -f "$CFG" ]] && grep -E "DB_USERNAME|DB_PASSWORD|DB_NAME" "$CFG" | head -5 && break
done

echo ""
info "Current bWAPP config values:"
for CFG in "${BWAPP}/app/connect_i.php" "${BWAPP}/admin/settings.php"; do
    [[ -f "$CFG" ]] && grep -E "db_username|db_password|db_name" "$CFG" | head -5 && break
done

echo ""
echo -e "${GREEN}Done.${NC}  Next steps:"
echo "  1. Visit  http://<ip>/mutillidae  → click 'Reset DB' to initialise"
echo "  2. Visit  http://<ip>/bwapp/install.php  → click 'here' to seed the DB"
echo "  3. Log into bWAPP with  bee / bug"
