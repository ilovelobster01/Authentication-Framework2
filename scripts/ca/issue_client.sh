#!/usr/bin/env bash
set -euo pipefail

# Issue a client certificate for a user and export as PKCS#12
# Usage: issue_client.sh <username> <email> [p12_password]

if [ $# -lt 2 ]; then
  echo "Usage: $0 <username> <email> [p12_password]" >&2
  exit 1
fi
USERNAME="$1"
EMAIL="$2"
P12PASS_IN="${3:-}"
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_DIR="$ROOT_DIR/ca"
OPENSSL_CONF_CA="$ROOT_DIR/openssl_ca.cnf"
OPENSSL_CONF_CLIENT="$ROOT_DIR/openssl_client.cnf"
OUT_DIR="$ROOT_DIR/out/clients/$USERNAME"

mkdir -p "$OUT_DIR"

# Require OpenSSL with -addext support (OpenSSL >= 1.1.1; LibreSSL not supported)
require_openssl_addext() {
  local v
  v="$(openssl version 2>&1 || true)"
  if echo "$v" | grep -qi 'LibreSSL'; then
    echo "Error: LibreSSL detected. Please use OpenSSL >= 1.1.1 (prefer OpenSSL 3.x)." >&2
    echo "On macOS: brew install openssl@3; then run scripts with /opt/homebrew/opt/openssl@3/bin/openssl" >&2
    exit 1
  fi
  if echo "$v" | grep -qi '^OpenSSL'; then
    local nums M m p
    nums=$(echo "$v" | sed -n 's/^OpenSSL \([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2 \3/p')
    if [ -n "$nums" ]; then
      set -- $nums
      M=$1; m=$2; p=$3
      if [ "$M" -gt 1 ] || { [ "$M" -eq 1 ] && { [ "$m" -gt 1 ] || { [ "$m" -eq 1 ] && [ "$p" -ge 1 ]; }; }; }; then
        :
      else
        echo "Error: OpenSSL $M.$m.$p does not support -addext. Require >= 1.1.1. Detected: $v" >&2
        exit 1
      fi
    fi
    return 0
  fi
  echo "Error: Unknown OpenSSL provider/version: $v. Require OpenSSL >= 1.1.1 with -addext support." >&2
  exit 1
}

require_openssl_addext

KEY="$OUT_DIR/$USERNAME.key"
CSR="$OUT_DIR/$USERNAME.csr"
CRT="$OUT_DIR/$USERNAME.crt"
P12="$OUT_DIR/$USERNAME.p12"

# Generate key and CSR (CN=username), add SAN email
openssl req -new -newkey rsa:4096 -nodes \
  -keyout "$KEY" \
  -out "$CSR" \
  -config "$OPENSSL_CONF_CLIENT" \
  -addext "subjectAltName=email:$EMAIL" \
  -subj "/CN=$USERNAME"

# Sign client cert (optionally pass CA password via env CA_PASS or 4th arg)
CA_PASS_IN="${4:-${CA_PASS:-}}"
if [ -n "${CA_PASS_IN}" ]; then
  (
    cd "$ROOT_DIR" && \
    openssl ca -batch -config "$OPENSSL_CONF_CA" -extensions usr_cert -in "$CSR" -out "$CRT" -passin pass:"${CA_PASS_IN}"
  )
else
  (
    cd "$ROOT_DIR" && \
    openssl ca -batch -config "$OPENSSL_CONF_CA" -extensions usr_cert -in "$CSR" -out "$CRT"
  )
fi

# Export PKCS#12 for browser import
if [ -z "${P12PASS_IN}" ]; then
  read -rsp "Enter export password for PKCS#12 bundle: " P12PASS
  printf "\n"
else
  P12PASS="$P12PASS_IN"
fi
openssl pkcs12 -export -out "$P12" -inkey "$KEY" -in "$CRT" -passout pass:"$P12PASS" -name "$USERNAME-client"
# Print SHA-256 fingerprint
FPR=$(openssl x509 -noout -fingerprint -sha256 -in "$CRT" | sed 's/.*=//;s/:/-/g')
echo "SHA256 Fingerprint: $FPR"
