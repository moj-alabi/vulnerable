#!/usr/bin/env bash
# =============================================================================
#  reset.sh  –  Remove all vuln apps installed by install.sh
#
#  Run this before a fresh install.sh to wipe everything cleanly.
#  Your existing DVWA and Wazuh are NOT touched.
#
#  Usage:  sudo bash reset.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }

[[ $EUID -ne 0 ]] && { echo -e "${RED}[ERR]${NC}  Please run as root: sudo bash reset.sh"; exit 1; }

echo ""
echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║   Vuln Apps – Full Reset                          ║${NC}"
echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Stop & remove systemd services ────────────────────────────────────────
info "Stopping and removing systemd services…"
for SVC in webgoat juiceshop wrongsecrets; do
    if systemctl list-unit-files "${SVC}.service" &>/dev/null 2>&1; then
        systemctl disable --now "$SVC" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SVC}.service"
        success "  Removed service: $SVC"
    else
        warn "  Service not found: $SVC (skipping)"
    fi
done
systemctl daemon-reload

# ── 2. Remove PHP app directories from /var/www/html ─────────────────────────
info "Removing PHP app directories…"
for APP in mutillidae bwapp wackopicko hackazon; do
    if [[ -d "/var/www/html/${APP}" ]]; then
        rm -rf "/var/www/html/${APP}"
        success "  Removed /var/www/html/${APP}"
    else
        warn "  Not found: /var/www/html/${APP} (skipping)"
    fi
done

# ── 3. Remove standalone app directories from /opt ───────────────────────────
info "Removing standalone app directories…"
for DIR in /opt/webgoat /opt/juice-shop /opt/wrongsecrets; do
    if [[ -d "$DIR" ]]; then
        rm -rf "$DIR"
        success "  Removed $DIR"
    else
        warn "  Not found: $DIR (skipping)"
    fi
done

# ── 4. Remove dedicated system users ─────────────────────────────────────────
info "Removing dedicated system users…"
for USR in webgoat juiceshop wrongsecrets; do
    if id "$USR" &>/dev/null; then
        userdel "$USR" 2>/dev/null || true
        success "  Removed user: $USR"
    fi
done

# ── 5. Disable & remove Apache2 conf ─────────────────────────────────────────
info "Removing Apache2 vuln-apps conf…"
if [[ -f /etc/apache2/conf-enabled/vuln-apps.conf ]] || \
   [[ -f /etc/apache2/conf-available/vuln-apps.conf ]]; then
    a2disconf vuln-apps 2>/dev/null || true
    rm -f /etc/apache2/conf-available/vuln-apps.conf
    apache2ctl configtest 2>/dev/null && systemctl reload apache2 || true
    success "  Apache2 conf removed and reloaded"
else
    warn "  Apache2 vuln-apps conf not found (skipping)"
fi

# ── 6. Drop MySQL databases ───────────────────────────────────────────────────
info "Dropping MySQL databases and users…"
mysql -u root 2>/dev/null <<'SQL' || warn "MySQL cleanup failed – may need manual drop"
DROP DATABASE IF EXISTS mutillidae;
DROP DATABASE IF EXISTS bwapp;
DROP DATABASE IF EXISTS hackazon;
DROP USER IF EXISTS 'mutillidae'@'localhost';
DROP USER IF EXISTS 'bwapp'@'localhost';
DROP USER IF EXISTS 'hackazon'@'localhost';

FLUSH PRIVILEGES;
SQL
success "  MySQL databases dropped"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Reset complete. Ready for a fresh install.${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  Run:  sudo bash install.sh"
echo ""
