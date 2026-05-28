#!/bin/bash
# ============================================================
#  Push custom CTF detection rules to existing Wazuh manager
#  at 10.0.10.2 via the Wazuh REST API (port 55000)
#
#  Usage:
#    ./scripts/push-rules.sh
#    WAZUH_USER=admin WAZUH_PASS=MyPass ./scripts/push-rules.sh
# ============================================================
set -euo pipefail

WAZUH_HOST="${WAZUH_HOST:-10.0.10.2}"
WAZUH_PORT="${WAZUH_PORT:-55000}"
WAZUH_USER="${WAZUH_USER:-admin}"
WAZUH_PASS="${WAZUH_PASS:-SecureAdmin1!}"   # change to match your install
WAZUH_SSH_USER="${WAZUH_SSH_USER:-}"        # set to deploy ossec.conf via SSH e.g. ubuntu
RULES_FILE="$(cd "$(dirname "$0")/.." && pwd)/monitoring/wazuh/rules/ctf_rules.xml"
SYSLOG_CONF="$(cd "$(dirname "$0")/.." && pwd)/monitoring/wazuh/ossec-syslog-remote.conf"

API="https://${WAZUH_HOST}:${WAZUH_PORT}"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
info() { echo -e "${YELLOW}[*]${RESET} $*"; }
err()  { echo -e "${RED}[!]${RESET} $*"; }

# ── 1. Get JWT token ──────────────────────────────────────
info "Authenticating to Wazuh API at ${API}..."
TOKEN=$(curl -sk -u "${WAZUH_USER}:${WAZUH_PASS}" \
    -X POST "${API}/security/user/authenticate" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null)

if [[ -z "$TOKEN" ]]; then
  err "Failed to authenticate. Check WAZUH_USER / WAZUH_PASS and that ${API} is reachable."
  err "Try: curl -sk -u admin:YOURPASS -X POST ${API}/security/user/authenticate"
  exit 1
fi
ok "Authenticated – token obtained"

# ── 2. Upload CTF rules file ──────────────────────────────
info "Uploading ctf_rules.xml..."
RULES_B64=$(base64 < "${RULES_FILE}")

RESP=$(curl -sk -X POST "${API}/rules/files/ctf_rules.xml" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${RULES_FILE}")

STATUS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','?'))" 2>/dev/null || echo "?")

if [[ "$STATUS" == "0" ]]; then
  ok "ctf_rules.xml uploaded successfully"
else
  # Try PUT (overwrite) if POST fails (file already exists)
  info "  Trying overwrite (PUT)..."
  RESP=$(curl -sk -X PUT "${API}/rules/files/ctf_rules.xml?overwrite=true" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${RULES_FILE}")
  STATUS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','?'))" 2>/dev/null || echo "?")
  if [[ "$STATUS" == "0" ]]; then
    ok "ctf_rules.xml overwritten successfully"
  else
    err "Rule upload failed. Response: $RESP"
    err "You can manually copy the file to the Wazuh manager:"
    err "  scp ${RULES_FILE} user@${WAZUH_HOST}:/var/ossec/etc/rules/ctf_rules.xml"
    err "  ssh user@${WAZUH_HOST} 'sudo systemctl restart wazuh-manager'"
    exit 1
  fi
fi

# ── 3. Create ctf-targets agent group ────────────────────
info "Ensuring 'ctf-targets' agent group exists..."
curl -sk -X POST "${API}/groups" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"group_id":"ctf-targets"}' > /dev/null 2>&1 || true
ok "Agent group 'ctf-targets' ready"

# ── 4. Deploy syslog remote config to Wazuh VM ───────────
# Merges the <remote> syslog/agent blocks into ossec.conf on the Wazuh VM
# via SSH if WAZUH_SSH_USER is set; otherwise prints manual instructions.
REMOTE_MARKER="<!-- CTF-syslog-remote: deployed by push-rules.sh -->"

if [[ -n "${WAZUH_SSH_USER}" ]]; then
  info "Deploying ossec-syslog-remote.conf to ${WAZUH_SSH_USER}@${WAZUH_HOST}..."

  # Check if the marker already exists (idempotent)
  ALREADY=$(ssh -o StrictHostKeyChecking=no \
      "${WAZUH_SSH_USER}@${WAZUH_HOST}" \
      "sudo grep -c 'CTF-syslog-remote' /var/ossec/etc/ossec.conf 2>/dev/null || echo 0")

  if [[ "$ALREADY" -gt 0 ]]; then
    ok "syslog remote config already present in ossec.conf – skipping"
  else
    # Upload the snippet and inject it before </ossec_config>
    scp -q "${SYSLOG_CONF}" "${WAZUH_SSH_USER}@${WAZUH_HOST}:/tmp/ctf-syslog-remote.conf"
    ssh -o StrictHostKeyChecking=no "${WAZUH_SSH_USER}@${WAZUH_HOST}" bash <<'ENDSSH'
set -e
MARKER="<!-- CTF-syslog-remote: deployed by push-rules.sh -->"
SNIPPET=$(cat /tmp/ctf-syslog-remote.conf)
# Inject snippet + marker just before closing tag
sudo python3 - <<PYEOF
import re, sys
conf = open('/var/ossec/etc/ossec.conf').read()
inject = "\n${MARKER}\n" + open('/tmp/ctf-syslog-remote.conf').read() + "\n"
conf = conf.replace('</ossec_config>', inject + '</ossec_config>', 1)
open('/var/ossec/etc/ossec.conf', 'w').write(conf)
print('Injected CTF syslog remote blocks into ossec.conf')
PYEOF
rm -f /tmp/ctf-syslog-remote.conf
ENDSSH
    ok "syslog remote config injected into /var/ossec/etc/ossec.conf"
  fi
else
  # ── Manual instructions ──────────────────────────────
  echo ""
  echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${RESET}"
  echo -e "${YELLOW}│  ACTION REQUIRED on Wazuh VM (10.0.10.2)                    │${RESET}"
  echo -e "${YELLOW}│                                                              │${RESET}"
  echo -e "${YELLOW}│  The snippet below must be inside <ossec_config> in         │${RESET}"
  echo -e "${YELLOW}│  /var/ossec/etc/ossec.conf on 10.0.10.2                     │${RESET}"
  echo -e "${YELLOW}│                                                              │${RESET}"
  echo -e "${YELLOW}│  Option A – automatic (set WAZUH_SSH_USER and re-run):      │${RESET}"
  echo -e "${YELLOW}│    WAZUH_SSH_USER=ubuntu ./scripts/push-rules.sh            │${RESET}"
  echo -e "${YELLOW}│                                                              │${RESET}"
  echo -e "${YELLOW}│  Option B – manual copy:                                    │${RESET}"
  echo -e "${YELLOW}│    scp monitoring/wazuh/ossec-syslog-remote.conf \\          │${RESET}"
  echo -e "${YELLOW}│        USER@10.0.10.2:/tmp/                                 │${RESET}"
  echo -e "${YELLOW}│    Then paste its contents into /var/ossec/etc/ossec.conf   │${RESET}"
  echo -e "${YELLOW}│    and run: sudo systemctl restart wazuh-manager            │${RESET}"
  echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${RESET}"
  echo ""
  info "Continuing – rules will still be uploaded; only syslog input config is missing."
fi

# ── 5. Restart Wazuh manager to load new rules ───────────
info "Restarting Wazuh manager to apply rules..."
RESP=$(curl -sk -X PUT "${API}/manager/restart" \
    -H "Authorization: Bearer ${TOKEN}")
STATUS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','?'))" 2>/dev/null || echo "?")
if [[ "$STATUS" == "0" ]]; then
  ok "Wazuh manager restarting – rules will be active in ~30s"
else
  err "Restart call failed (may need manual restart): $RESP"
fi

# ── 6. Verify rules loaded ────────────────────────────────
info "Waiting 35s for manager to restart..."
sleep 35

info "Verifying CTF rules are loaded..."
RULE_CHECK=$(curl -sk -X GET "${API}/rules?rule_ids=100001,100030,100042" \
    -H "Authorization: Bearer ${TOKEN}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['affected_items_total_items'])" 2>/dev/null || echo "0")

if [[ "$RULE_CHECK" -ge 3 ]]; then
  ok "CTF rules confirmed active (${RULE_CHECK}/3 spot-checked)"
else
  err "Could not verify rules – check manager logs: sudo tail -f /var/ossec/logs/ossec.log"
fi

# ── 7. Print summary ──────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}  Rules pushed to Wazuh at ${WAZUH_HOST}${RESET}"
echo -e "${GREEN}══════════════════════════════════════════════════${RESET}"
echo ""
echo "  CTF rule range : 100001 – 100091"
echo "  Agent group    : ctf-targets"
echo ""
echo "  Open dashboard : https://${WAZUH_HOST}"
echo "  Filter alerts  : rule.groups: ctf"
echo ""
echo "  To re-run with different credentials:"
echo "  WAZUH_USER=admin WAZUH_PASS=newpass $0"
echo ""
