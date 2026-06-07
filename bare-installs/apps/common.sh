#!/usr/bin/env bash
# =============================================================================
#  common.sh  –  Shared helpers sourced by every individual install script
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

WEBROOT="/var/www/html"
APACHE_CONF="/etc/apache2/conf-available/vuln-apps.conf"

# Detect PHP version (set once when sourced)
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)

enable_service() {
    local NAME="$1"
    systemctl daemon-reload
    systemctl enable --now "$NAME"
    success "Service $NAME started"
}

append_php_alias() {
    local APP="$1"
    local DIR="${WEBROOT}/${APP}"
    cat >> "$APACHE_CONF" <<PHPBLOCK

# ── ${APP} ────────────────────────────────────────────────
Alias /${APP} ${DIR}
<Directory ${DIR}>
    Options FollowSymLinks
    AllowOverride All
    Require all granted
    DirectoryIndex index.php index.html
</Directory>

PHPBLOCK
}

reload_apache() {
    if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
        systemctl reload apache2
        success "Apache2 reloaded"
    else
        warn "Apache2 config test warnings – check syntax"
        apache2ctl configtest
    fi
}
