#!/usr/bin/env bash
# Install WackoPicko  – run as root
set -euo pipefail
source "$(dirname "$0")/common.sh"
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash apps/install-wackopicko.sh"

DEST="${WEBROOT}/wackopicko"

info "=== WackoPicko ==="

# ── Clone ─────────────────────────────────────────────────────────────────────
if [[ -d "$DEST" ]]; then
    warn "Already present at $DEST – skipping clone"
else
    info "Cloning…"
    git clone --depth 1 https://github.com/adamdoupe/WackoPicko.git "$DEST"
fi

# ── Permissions ───────────────────────────────────────────────────────────────
chown -R www-data:www-data "$DEST"
chmod -R 755 "$DEST"

# ── Apache2 ───────────────────────────────────────────────────────────────────
[[ ! -f "$APACHE_CONF" ]] && echo "# vuln-apps" > "$APACHE_CONF"
grep -q "Alias /wackopicko" "$APACHE_CONF" || append_php_alias "wackopicko"
a2enmod rewrite headers &>/dev/null || true
a2enconf vuln-apps &>/dev/null || true
reload_apache

success "WackoPicko ready → http://$(hostname -I | awk '{print $1}')/wackopicko"
