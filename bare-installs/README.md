# Vulnerable Web Apps – Bare-Metal Installer

Installs 8 intentionally-vulnerable web applications directly onto a **Debian/Ubuntu** host that already has **Apache2 + PHP** running (same setup as your existing DVWA at `http://<ip>/DVWA`).

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
| **OWASP Juice Shop** | Node.js | `/juice-shop/` | Modern SPA with 100+ challenges |
| **OWASP WrongSecrets** | Java (JAR) | `/wrongsecrets/` | Secrets management challenges |

Your existing DVWA stays untouched at `http://<ip>/DVWA`.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Debian 11/12 or Ubuntu 22.04/24.04 | Other distros need minor tweaks |
| **Apache2** already running | Script enables required modules and drops a conf into `conf-available/` |
| PHP + `libapache2-mod-php` installed | Script installs extra PHP extensions if needed |
| MySQL 8.0 or MariaDB | Script skips install if already present (e.g. your existing MySQL) |
| Java 17 JRE | Auto-installed via `openjdk-17-jre-headless` |
| Node.js ≥ 18 | Auto-upgraded via NodeSource if older version found |
| Internet access | Downloads git repos and release JARs |

---

## Usage

```bash
# 1. Copy this folder to your VM
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

1. **System deps** – `apt-get install` for PHP extensions (`libapache2-mod-php`), Java 17, Node.js
2. **MySQL** – creates isolated DB + user for each PHP app (skips if MySQL already present)
3. **Apache2 modules** – `a2enmod proxy proxy_http rewrite headers`
4. **PHP apps** – `git clone` → `/var/www/html/<app>`, patches DB config, sets `www-data` ownership, writes `Alias` + `<Directory>` blocks
5. **Java apps** – downloads pre-built JARs to `/opt/<app>`, creates `systemd` service listening on `127.0.0.1`
6. **Node apps** – `git clone` / tarball to `/opt/<app>`, `npm install`, creates `systemd` service
7. **Apache2 conf** – writes all blocks to `/etc/apache2/conf-available/vuln-apps.conf`, runs `a2enconf vuln-apps`, then `apache2ctl configtest && systemctl reload apache2`

---

## Manual Apache2 wiring (if auto-apply fails)

```bash
sudo cp apache-snippet.conf /etc/apache2/conf-available/vuln-apps.conf
sudo a2enmod proxy proxy_http rewrite headers
sudo a2enconf vuln-apps
sudo apache2ctl configtest && sudo systemctl reload apache2
```

The `apache-snippet.conf` in this directory is a human-readable reference copy with comments.

---

## Post-install steps

### bWAPP – seed the database
Visit `http://<ip>/bwapp/install.php` once in your browser to initialise the DB.

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
# Status of all standalone services
sudo systemctl status webgoat dvna juiceshop wrongsecrets

# Restart a service
sudo systemctl restart juiceshop

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
| Apache2 | 80 | direct |
| PHP | mod_php (in-process) | Apache2 `Alias` |
| WebGoat | 8080 (loopback) | Apache2 `ProxyPass` → `/WebGoat` |
| Juice Shop | 3000 (loopback) | Apache2 `ProxyPass` → `/juice-shop/` |
| WrongSecrets | 8085 (loopback) | Apache2 `ProxyPass` → `/wrongsecrets/` |

All standalone services bind to `127.0.0.1` only – not reachable directly from outside the VM.

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

# Remove Apache2 conf
sudo a2disconf vuln-apps
sudo rm /etc/apache2/conf-available/vuln-apps.conf
sudo systemctl reload apache2

# Drop MySQL databases (optional)
sudo mysql -u root -e "
  DROP DATABASE IF EXISTS mutillidae;
  DROP DATABASE IF EXISTS bwapp;
  DROP DATABASE IF EXISTS hackazon;
"
```
