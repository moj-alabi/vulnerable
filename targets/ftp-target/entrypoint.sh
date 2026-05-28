#!/bin/bash
set -e

WAZUH_MGR="${WAZUH_MANAGER:-10.0.10.2}"

# ── Register + start Wazuh agent ─────────────────────────
sed -i "s|<address>.*</address>|<address>${WAZUH_MGR}</address>|g" \
    /var/ossec/etc/ossec.conf 2>/dev/null || true

/var/ossec/bin/agent-auth \
    -m "${WAZUH_MGR}" \
    -p 1515 \
    -A "ftp-target-$(hostname)" \
    -G "ctf-targets" 2>/dev/null || true

/var/ossec/bin/wazuh-control start 2>/dev/null || true

# ── Start rsyslog ─────────────────────────────────────────
service rsyslog start 2>/dev/null || true

# ── Start backdoor listener in background ─────────────────
python3 /usr/local/bin/backdoor_listener.py &

# ── Start vsftpd ─────────────────────────────────────────
exec /usr/sbin/vsftpd /etc/vsftpd.conf
