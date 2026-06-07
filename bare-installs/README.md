# Vulnerable Web Apps – Bare-Metal Installer

Installs 8 intentionally-vulnerable web applications directly onto a **Debian/Ubuntu** host that already has **nginx + PHP-FPM** running (same setup as your existing DVWA at `http://<ip>/DVWA`).

No Docker required. Each app runs as its own unprivileged system user and is registered as a `systemd` service where needed.

---

## Apps installed

| App | Type | URL path | Notes |
|-----|------|----------|-------|
| **Mutillidae II** | PHP | `/mutillidae` | OWASP Top-10 training app |
| **bWAPP** | PHP | `/bwapp` | 100+ web bugs in one app |
| **WackoPicko** | PHP | `/wackopicko` | Realistic e-commerce target |
| **Hackazon** | PHP | `/hackazon` | Amazon-like vulnerable store |
| **OWASP WebGoat 2023** | Java (JAR) | `/WebGoat` | Guided security lessons |
| **DVNA** | Node.js | `/dvna` | OWASP Top-10 Node app |
| **OWASP Juice Shop** | Node.js | `/juice-shop/` | Modern SPA with 100+ challenges |
| **OWASP WrongSecrets** | Java (JAR) | `/wrongsecrets` | Secrets management challenges |

Your existing DVWA stays untouched at `http://<ip>/DVWA`.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Debian 11/12 or Ubuntu 22.04/24.04 | Other distros need minor tweaks |
| nginx already running | The script adds location blocks to your existing server |
| PHP-FPM already installed | Script installs extra PHP extensions if needed |
| MySQL / MariaDB | Script installs `mysql-server` if absent |
| Java 17 JRE | Auto-installed via `openjdk-17-jre-headless` |
| Node.js ≥ 18 | Auto-upgraded via NodeSource if older version found |
| Internet access | Downloads git repos and release JARs |

---

## Usage

```bash
# 1. Copy this folder to your VM (or just scp the two files)
scp -r bare-installs/  user@<vm-ip>:~/

# 2. SSH into the VM
ssh user@<vm-ip>

# 3. Run the installer as root
cd ~/bare-installs
sudo bash install.sh
```

The script is **idempotent** – running it again skips already-installed components.

A full log is written to `/var/log/vuln-apps-install.log`.

---

## What the script does, step by step

1. **System deps** – `apt-get install` for PHP extensions, Java 17, Node.js, MySQL
2. **MySQL** – creates isolated DB + user for each PHP app
3. **PHP apps** – `git clone` → `/var/www/html/<app>`, patches DB config, sets `www-data` ownership
4. **Java apps** – downloads pre-built JARs to `/opt/<app>`, creates `systemd` service listening on `127.0.0.1`
5. **Node apps** – `git clone` / tarball to `/opt/<app>`, `npm install`, creates `systemd` service
6. **nginx** – writes location blocks into `/etc/nginx/snippets/vuln-apps.conf` and inserts `include` into your default server block, then `nginx -t && systemctl reload nginx`

---

## Manual nginx wiring (if auto-inject fails)

If the script can't find your server block automatically it will print a warning. In that case:

```bash
sudo cp nginx-snippet.conf /etc/nginx/snippets/vuln-apps.conf
```

Then open your main nginx site config (usually `/etc/nginx/sites-available/default`) and add **inside** the `server { }` block:

```nginx
include snippets/vuln-apps.conf;
```

Then test and reload:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

The `nginx-snippet.conf` file in this directory is a human-readable reference copy with comments. Remember to change the PHP-FPM socket path if you're not on PHP 8.3:

```
# php8.3-fpm.sock  →  php8.1-fpm.sock  etc.
```

---

## Post-install steps

### bWAPP – seed the database
Visit `http://<ip>/bwapp/install.php` in your browser once to initialise the DB.

### Hackazon – composer
If `composer` was not found during install:
```bash
curl -sS https://getcomposer.org/installer | sudo php -- --install-dir=/usr/local/bin --filename=composer
cd /var/www/html/hackazon
sudo -u www-data composer install --no-dev
```

### WebGoat startup time
WebGoat (Spring Boot) takes **~60 seconds** to start. Check status with:
```bash
sudo systemctl status webgoat
sudo journalctl -u webgoat -f
```

---

## Service management

```bash
# Status of all vuln app services
sudo systemctl status webgoat dvna juiceshop wrongsecrets

# Restart a single service
sudo systemctl restart juice-shop

# View live logs
sudo journalctl -u webgoat -f
sudo journalctl -u dvna -f
sudo journalctl -u juiceshop -f
sudo journalctl -u wrongsecrets -f
```

---

## Port reference

| Service | Internal port | Exposed via |
|---------|--------------|-------------|
| nginx | 80 | direct |
| PHP-FPM | unix socket | nginx fastcgi |
| WebGoat | 8080 (loopback) | nginx proxy → `/WebGoat` |
| DVNA | 9001 (loopback) | nginx proxy → `/dvna/` |
| Juice Shop | 3000 (loopback) | nginx proxy → `/juice-shop/` |
| WrongSecrets | 8085 (loopback) | nginx proxy → `/wrongsecrets/` |

All standalone services bind to `127.0.0.1` only – they are not directly reachable from outside the VM.

---

## Uninstall

```bash
# Stop and remove services
sudo systemctl disable --now webgoat dvna juiceshop wrongsecrets
sudo rm /etc/systemd/system/{webgoat,dvna,juiceshop,wrongsecrets}.service
sudo systemctl daemon-reload

# Remove app files
sudo rm -rf /opt/webgoat /opt/dvna /opt/juice-shop /opt/wrongsecrets
sudo rm -rf /var/www/html/{mutillidae,bwapp,wackopicko,hackazon}

# Remove nginx snippet
sudo rm /etc/nginx/snippets/vuln-apps.conf
# Then manually remove:  include snippets/vuln-apps.conf;  from your server block
sudo nginx -t && sudo systemctl reload nginx

# Drop MySQL databases (optional)
sudo mysql -u root -e "
  DROP DATABASE IF EXISTS mutillidae;
  DROP DATABASE IF EXISTS bwapp;
  DROP DATABASE IF EXISTS hackazon;
  DROP DATABASE IF EXISTS dvna;
"
```
