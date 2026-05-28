#!/bin/bash
# ============================================================
#  Generate self-signed TLS certificates for Wazuh stack
#  Output: monitoring/wazuh/certs/
# ============================================================
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/monitoring/wazuh/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[certs] Generating certificates in $CERT_DIR"

# ── Root CA ───────────────────────────────────────────────
openssl genrsa -out root-ca-key.pem 2048 2>/dev/null
openssl req -new -x509 -sha256 \
  -key root-ca-key.pem \
  -out root-ca.pem \
  -days 3650 \
  -subj "/C=US/L=California/O=Wazuh/OU=CTFLab/CN=root-ca" 2>/dev/null
echo "[certs] ✓ Root CA"

# ── Helper: issue a cert signed by root CA ────────────────
issue_cert() {
  local name="$1"
  local cn="$2"
  openssl genrsa -out "${name}-key.pem" 2048 2>/dev/null
  openssl req -new -sha256 \
    -key "${name}-key.pem" \
    -out "${name}.csr" \
    -subj "/C=US/L=California/O=Wazuh/OU=CTFLab/CN=${cn}" 2>/dev/null
  openssl x509 -req -sha256 \
    -in "${name}.csr" \
    -CA root-ca.pem \
    -CAkey root-ca-key.pem \
    -CAcreateserial \
    -out "${name}.pem" \
    -days 3650 2>/dev/null
  rm -f "${name}.csr"
  echo "[certs] ✓ ${name}"
}

# ── Node certificates ─────────────────────────────────────
issue_cert "indexer"   "wazuh-indexer"
issue_cert "dashboard" "wazuh-dashboard"
issue_cert "filebeat"  "wazuh-manager"
issue_cert "admin"     "admin"

# ── Fix permissions ───────────────────────────────────────
chmod 600 ./*-key.pem
chmod 644 ./*.pem 2>/dev/null || true

echo ""
echo "[certs] All certificates generated:"
ls -1 "$CERT_DIR"
