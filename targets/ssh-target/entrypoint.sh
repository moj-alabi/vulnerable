#!/bin/bash
set -e

# ── Register + start Wazuh agent ─────────────────────────
WAZUH_MGR="${WAZUH_MANAGER:-10.0.10.2}"

# Update manager IP in case it was passed via env at runtime
sed -i "s|<address>.*</address>|<address>${WAZUH_MGR}</address>|g" \
    /var/ossec/etc/ossec.conf 2>/dev/null || true

# Register agent (auto-enrolment via port 1515)
/var/ossec/bin/agent-auth \
    -m "${WAZUH_MGR}" \
    -p 1515 \
    -A "ssh-target-$(hostname)" \
    -G "ctf-targets" 2>/dev/null || true

# Start Wazuh agent in background
/var/ossec/bin/wazuh-control start 2>/dev/null || true

# ── Start rsyslog ─────────────────────────────────────────
service rsyslog start 2>/dev/null || true

# ── Start SSH daemon ──────────────────────────────────────
exec /usr/sbin/sshd -D
