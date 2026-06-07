#!/usr/bin/env bash
# =============================================================================
#  Vulnerable Web Apps – Bare-Metal Installer (no Docker)
#  Installs alongside an existing Apache2 + DVWA setup.
#
#  Apps installed
#  ─────────────────────────────────────────────────────
#  PHP  (served via Apache2 at  http://<ip>/<app>)
#    • Mutillidae II        → /mutillidae
#    • bWAPP                → /bwapp
#    • WackoPicko           → /wackopicko
#    • Hackazon             → /hackazon
#
#  Standalone  (Apache2 reverse-proxied to a sub-path)
#    • OWASP WebGoat 2023   → /WebGoat          (Java, port 8080)
#    • OWASP Juice Shop     → /juice-shop       (Node, port 3000)
#    • WrongSecrets         → /wrongsecrets     (Java, port 8085)
#
#  Run as root on a Debian/Ubuntu host that already has Apache2 + PHP.
# =============================================================================

set -euo pipefail

### ── colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

### ── sanity checks ───────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Please run as root:  sudo bash install.sh"

WEBROOT="/var/www/html"
LOG_FILE="/var/log/vuln-apps-install.log"
APACHE_CONF="/etc/apache2/conf-available/vuln-apps.conf"

info "Logging to $LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

### ── detect PHP version ─────────────────────────────────────────────────────
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)
[[ -z "$PHP_VER" ]] && error "PHP not found. Install it first: apt install php libapache2-mod-php"
info "Detected PHP $PHP_VER"

### ── helper: enable + start a systemd unit ──────────────────────────────────
enable_service() {
    local NAME="$1"
    systemctl daemon-reload
    systemctl enable --now "$NAME"
    success "Service $NAME started"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 1 – System dependencies
# ═════════════════════════════════════════════════════════════════════════════
section_deps() {
    info "Installing system dependencies…"
    apt-get update -qq

    # ── PHP extensions ──────────────────────────────────────────────────────
    apt-get install -y --no-install-recommends \
        git curl wget unzip \
        "php${PHP_VER}" \
        "libapache2-mod-php${PHP_VER}" \
        "php${PHP_VER}-mysql" "php${PHP_VER}-xml" "php${PHP_VER}-mbstring" \
        "php${PHP_VER}-curl" "php${PHP_VER}-gd" "php${PHP_VER}-ldap" \
        "php${PHP_VER}-zip" "php${PHP_VER}-bcmath"

    # ── MySQL / MariaDB – only install if nothing is already present ────────
    if mysql --version &>/dev/null 2>&1 || mysqld --version &>/dev/null 2>&1; then
        info "MySQL/MariaDB already installed – skipping database server install"
    else
        info "Installing MySQL server…"
        if apt-cache show mysql-server &>/dev/null 2>&1; then
            apt-get install -y --no-install-recommends mysql-server
        else
            apt-get install -y --no-install-recommends mariadb-server
        fi
    fi

    # ── Java 17 ─────────────────────────────────────────────────────────────
    apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless \
        python3 python3-pip

    # ── Node.js ─────────────────────────────────────────────────────────────
    if ! command -v node &>/dev/null; then
        apt-get install -y --no-install-recommends nodejs npm
    fi
    if node --version 2>/dev/null | grep -qE '^v1[0-5]\.'; then
        warn "Node.js is old; installing LTS via NodeSource…"
        curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
        apt-get install -y nodejs
    fi

    # ── Apache2 modules ─────────────────────────────────────────────────────
    a2enmod proxy proxy_http rewrite headers
    success "Dependencies ready"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 2 – MySQL: create databases & users
# ═════════════════════════════════════════════════════════════════════════════
section_mysql() {
    info "Configuring MySQL databases…"
    systemctl start mysql 2>/dev/null || systemctl start mariadb 2>/dev/null || true

    mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS mutillidae CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidae_pass';
GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';

CREATE DATABASE IF NOT EXISTS bwapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'bwapp'@'localhost' IDENTIFIED BY 'bwapp_pass';
GRANT ALL PRIVILEGES ON bwapp.* TO 'bwapp'@'localhost';

CREATE DATABASE IF NOT EXISTS hackazon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'hackazon'@'localhost' IDENTIFIED BY 'hackazon_pass';
GRANT ALL PRIVILEGES ON hackazon.* TO 'hackazon'@'localhost';

FLUSH PRIVILEGES;
SQL
    success "MySQL databases created"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 3 – Apache2 config helpers
#  All location/alias blocks are written to a single conf file and enabled.
# ═════════════════════════════════════════════════════════════════════════════
init_apache_conf() {
    # Start fresh each run
    cat > "$APACHE_CONF" <<'APACHEHDR'
# Auto-generated by bare-installs/install.sh
# Included globally – works inside the default VirtualHost.

APACHEHDR
    info "Initialised Apache2 conf at $APACHE_CONF"
}

append_php_alias() {
    local APP="$1"   # e.g. mutillidae
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

append_proxy() {
    local APP="$1"   # e.g. dvna
    local PORT="$2"  # e.g. 9001
    local UPSTREAM_PATH="${3:-/${APP}/}"  # path the upstream app actually listens on

    cat >> "$APACHE_CONF" <<PROXYBLOCK

# ── ${APP} (proxy → 127.0.0.1:${PORT}) ───────────────────
ProxyRequests Off
<Location /${APP}/>
    ProxyPass        http://127.0.0.1:${PORT}${UPSTREAM_PATH}
    ProxyPassReverse http://127.0.0.1:${PORT}${UPSTREAM_PATH}
    ProxyPreserveHost On
    Require all granted
</Location>

PROXYBLOCK
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 4 – Mutillidae II  (PHP)
# ═════════════════════════════════════════════════════════════════════════════
install_mutillidae() {
    info "Installing Mutillidae II…"
    local DEST="${WEBROOT}/mutillidae"

    if [[ -d "$DEST" ]]; then
        warn "Mutillidae already present – skipping clone"
    else
        git clone --depth 1 \
            https://github.com/webpwnized/mutillidae.git \
            "$DEST"
    fi

    # Mutillidae stores DB creds in includes/database-config.inc
    # (classes/MySQLHandler.php just reads those constants)
    local CFG="${DEST}/includes/database-config.inc"
    if [[ -f "$CFG" ]]; then
        # Use the dedicated 'mutillidae' DB user (root auth_socket won't work on Ubuntu 22.04+)
        sed -i "s/define('DB_USERNAME'.*$/define('DB_USERNAME', 'mutillidae');/"    "$CFG" || true
        sed -i "s/define('DB_PASSWORD'.*$/define('DB_PASSWORD', 'mutillidae_pass');/" "$CFG" || true
        sed -i "s/define('DB_NAME'.*$/define('DB_NAME', 'mutillidae');/"             "$CFG" || true
    else
        warn "Mutillidae: database-config.inc not found at $CFG – checking alternate paths…"
        # Older repo layout puts it in src/
        for ALT in "${DEST}/src/includes/database-config.inc" \
                   "${DEST}/classes/MySQLHandler.php"; do
            if [[ -f "$ALT" ]]; then
                sed -i "s/'DB_USERNAME'[^,]*, *'[^']*'/'DB_USERNAME', 'mutillidae'/"    "$ALT" || true
                sed -i "s/'DB_PASSWORD'[^,]*, *'[^']*'/'DB_PASSWORD', 'mutillidae_pass'/" "$ALT" || true
                info "Patched $ALT"
                break
            fi
        done
    fi

    chown -R www-data:www-data "$DEST"
    chmod -R 755 "$DEST"

    append_php_alias "mutillidae"
    success "Mutillidae II installed → http://<ip>/mutillidae"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 5 – bWAPP  (PHP)
# ═════════════════════════════════════════════════════════════════════════════
install_bwapp() {
    info "Installing bWAPP…"
    local DEST="${WEBROOT}/bwapp"

    if [[ -d "$DEST" ]]; then
        warn "bWAPP already present – skipping"
    else
        # Public mirror of bWAPP (no auth required)
        git clone --depth 1 \
            https://github.com/raesene/bWAPP.git \
            /tmp/bwapp-src

        # The repo root IS the web app
        cp -r /tmp/bwapp-src "$DEST"
        rm -rf /tmp/bwapp-src
    fi

    # raesene/bWAPP stores creds in app/connect_i.php  (not admin/settings.php)
    local CFG="${DEST}/app/connect_i.php"
    if [[ -f "$CFG" ]]; then
        sed -i "s/\$db_username *= *\"[^\"]*\"/\$db_username = \"bwapp\"/"       "$CFG" || true
        sed -i "s/\$db_password *= *\"[^\"]*\"/\$db_password = \"bwapp_pass\"/"  "$CFG" || true
        sed -i "s/\$db_name *= *\"[^\"]*\"/\$db_name = \"bwapp\"/"               "$CFG" || true
        # Also handle single-quote style
        sed -i "s/\$db_username *= *'[^']*'/\$db_username = 'bwapp'/"       "$CFG" || true
        sed -i "s/\$db_password *= *'[^']*'/\$db_password = 'bwapp_pass'/"  "$CFG" || true
        sed -i "s/\$db_name *= *'[^']*'/\$db_name = 'bwapp'/"               "$CFG" || true
    else
        warn "bWAPP: app/connect_i.php not found – skipping DB config patch"
    fi

    chown -R www-data:www-data "$DEST"
    chmod -R 755 "$DEST"

    append_php_alias "bwapp"
    success "bWAPP installed → http://<ip>/bwapp  (visit /bwapp/install.php to seed DB)"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 6 – WackoPicko  (PHP)
# ═════════════════════════════════════════════════════════════════════════════
install_wackopicko() {
    info "Installing WackoPicko…"
    local DEST="${WEBROOT}/wackopicko"

    if [[ -d "$DEST" ]]; then
        warn "WackoPicko already present – skipping"
    else
        git clone --depth 1 \
            https://github.com/adamdoupe/WackoPicko.git \
            "$DEST"
    fi

    chown -R www-data:www-data "$DEST"
    chmod -R 755 "$DEST"

    append_php_alias "wackopicko"
    success "WackoPicko installed → http://<ip>/wackopicko"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 7 – Hackazon  (PHP)
# ═════════════════════════════════════════════════════════════════════════════
install_hackazon() {
    info "Installing Hackazon…"
    local DEST="${WEBROOT}/hackazon"

    if [[ -d "$DEST" ]]; then
        warn "Hackazon already present – skipping"
    else
        git clone --depth 1 \
            https://github.com/rapid7/hackazon.git \
            "$DEST"
    fi

    if command -v composer &>/dev/null; then
        (cd "$DEST" && composer install --no-interaction --no-dev 2>/dev/null) || true
    else
        warn "Composer not found – Hackazon may need manual 'composer install'"
    fi

    local CFG="${DEST}/config/db.php"
    if [[ ! -f "$CFG" && -f "${DEST}/config/db.php.example" ]]; then
        cp "${DEST}/config/db.php.example" "$CFG"
    fi
    [[ -f "$CFG" ]] && {
        sed -i "s/'username' *=> *'.*'/'username' => 'hackazon'/"       "$CFG" || true
        sed -i "s/'password' *=> *'.*'/'password' => 'hackazon_pass'/"  "$CFG" || true
        sed -i "s/'dbname'   *=> *'.*'/'dbname'   => 'hackazon'/"       "$CFG" || true
    }

    chown -R www-data:www-data "$DEST"
    chmod -R 755 "$DEST"

    append_php_alias "hackazon"
    success "Hackazon installed → http://<ip>/hackazon"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 8 – OWASP WebGoat 2023  (Java – port 8080)
# ═════════════════════════════════════════════════════════════════════════════
install_webgoat() {
    info "Installing OWASP WebGoat…"
    local INSTALL_DIR="/opt/webgoat"
    local JAR_URL="https://github.com/WebGoat/WebGoat/releases/download/v2023.8/webgoat-2023.8.jar"
    local JAR="${INSTALL_DIR}/webgoat.jar"

    mkdir -p "$INSTALL_DIR"

    if [[ -f "$JAR" ]]; then
        warn "WebGoat JAR already present – skipping download"
    else
        info "Downloading WebGoat JAR (~130 MB)…"
        wget -q --show-progress -O "$JAR" "$JAR_URL"
    fi

    id -u webgoat &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" webgoat
    chown -R webgoat:webgoat "$INSTALL_DIR"

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

    # WebGoat serves at /WebGoat (capital W) on its own
    cat >> "$APACHE_CONF" <<'WGBLOCK'

# ── WebGoat (proxy → 127.0.0.1:8080) ────────────────────
ProxyRequests Off
<Location /WebGoat>
    ProxyPass        http://127.0.0.1:8080/WebGoat
    ProxyPassReverse http://127.0.0.1:8080/WebGoat
    ProxyPreserveHost On
    Require all granted
</Location>

WGBLOCK

    success "WebGoat installed → http://<ip>/WebGoat  (Java; ~60 s startup)"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 10 – OWASP Juice Shop  (Node – port 3000)
# ═════════════════════════════════════════════════════════════════════════════
install_juiceshop() {
    info "Installing OWASP Juice Shop…"
    local INSTALL_DIR="/opt/juice-shop"
    local JS_VER="v17.0.0"
    local TARBALL="juice-shop-${JS_VER}_node20_linux_x64.tgz"
    local DL_URL="https://github.com/juice-shop/juice-shop/releases/download/${JS_VER}/${TARBALL}"

    mkdir -p "$INSTALL_DIR"

    if [[ -f "${INSTALL_DIR}/package.json" ]]; then
        warn "Juice Shop already present – skipping download"
    else
        info "Downloading Juice Shop pre-built package (~250 MB)…"
        wget -q --show-progress -O "/tmp/${TARBALL}" "$DL_URL"
        tar -xzf "/tmp/${TARBALL}" -C "$INSTALL_DIR" --strip-components=1
        rm -f "/tmp/${TARBALL}"
    fi

    id -u juiceshop &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" juiceshop
    chown -R juiceshop:juiceshop "$INSTALL_DIR"

    cat > /etc/systemd/system/juiceshop.service <<UNIT
[Unit]
Description=OWASP Juice Shop
After=network.target

[Service]
User=juiceshop
WorkingDirectory=${INSTALL_DIR}
Environment=PORT=3000
ExecStart=$(which node) app.js
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

    enable_service juiceshop

    cat >> "$APACHE_CONF" <<'JSBLOCK'

# ── Juice Shop (proxy → 127.0.0.1:3000) ─────────────────
ProxyRequests Off
<Location /juice-shop/>
    ProxyPass        http://127.0.0.1:3000/
    ProxyPassReverse http://127.0.0.1:3000/
    ProxyPreserveHost On
    Require all granted
</Location>

JSBLOCK

    success "Juice Shop installed → http://<ip>/juice-shop/"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 11 – WrongSecrets  (Java – port 8085)
# ═════════════════════════════════════════════════════════════════════════════
install_wrongsecrets() {
    info "Installing OWASP WrongSecrets…"
    local INSTALL_DIR="/opt/wrongsecrets"
    local JAR_URL="https://github.com/OWASP/wrongsecrets/releases/download/v1.12.0/wrongsecrets-1.12.0.jar"
    local JAR="${INSTALL_DIR}/wrongsecrets.jar"

    mkdir -p "$INSTALL_DIR"

    if [[ -f "$JAR" ]]; then
        warn "WrongSecrets JAR already present – skipping"
    else
        info "Downloading WrongSecrets JAR (~80 MB)…"
        wget -q --show-progress -O "$JAR" "$JAR_URL"
    fi

    id -u wrongsecrets &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" wrongsecrets
    chown -R wrongsecrets:wrongsecrets "$INSTALL_DIR"

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

    cat >> "$APACHE_CONF" <<'WSBLOCK'

# ── WrongSecrets (proxy → 127.0.0.1:8085) ───────────────
ProxyRequests Off
<Location /wrongsecrets/>
    ProxyPass        http://127.0.0.1:8085/
    ProxyPassReverse http://127.0.0.1:8085/
    ProxyPreserveHost On
    Require all granted
</Location>

WSBLOCK

    success "WrongSecrets installed → http://<ip>/wrongsecrets/"
}

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 12 – Enable Apache2 conf and reload
# ═════════════════════════════════════════════════════════════════════════════
finalize_apache() {
    info "Finalising Apache2 configuration…"

    # Enable the conf
    a2enconf vuln-apps

    # Test config before reloading
    if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
        systemctl reload apache2
        success "Apache2 reloaded"
    else
        warn "Apache2 config test had warnings – attempting graceful reload anyway…"
        apache2ctl configtest
        systemctl reload apache2
    fi
}

# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════
main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   Vulnerable Apps – Bare-Metal Installer          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""

    section_deps
    section_mysql
    init_apache_conf

    install_mutillidae
    install_bwapp
    install_wackopicko
    install_hackazon

    install_webgoat
    install_juiceshop
    install_wrongsecrets

    finalize_apache

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Installation complete!  Summary:${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
    local IP
    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "  ${CYAN}PHP apps (served directly by Apache2)${NC}"
    echo -e "  ● Mutillidae II   →  http://${IP}/mutillidae"
    echo -e "  ● bWAPP           →  http://${IP}/bwapp   (visit /bwapp/install.php first)"
    echo -e "  ● WackoPicko      →  http://${IP}/wackopicko"
    echo -e "  ● Hackazon        →  http://${IP}/hackazon"
    echo ""
    echo -e "  ${CYAN}Standalone apps (reverse-proxied through Apache2)${NC}"
    echo -e "  ● WebGoat 2023    →  http://${IP}/WebGoat   (Java, ~60 s startup)"
    echo -e "  ● Juice Shop      →  http://${IP}/juice-shop/"
    echo -e "  ● WrongSecrets    →  http://${IP}/wrongsecrets/"
    echo ""
    echo -e "  ${YELLOW}Your existing DVWA should still be at http://${IP}/DVWA${NC}"
    echo ""
    echo -e "  Full log: ${LOG_FILE}"
    echo ""
}

main "$@"
