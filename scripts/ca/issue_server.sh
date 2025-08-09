#!/usr/bin/env bash
set -euo pipefail

# Issue a dev server certificate for given DNS name (SAN)
# Usage: issue_server.sh dev.localhost

if [ $# -lt 1 ]; then
  echo "Usage: $0 <DNS_NAME>" >&2
  exit 1
fi
DNS_NAME="$1"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_DIR="$ROOT_DIR/ca"
OPENSSL_CONF_CA="$ROOT_DIR/openssl_ca.cnf"
OPENSSL_CONF_SERVER="$ROOT_DIR/openssl_server.cnf"
OUT_DIR="$ROOT_DIR/out/server/$DNS_NAME"

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

KEY="$OUT_DIR/server.key"
CSR="$OUT_DIR/server.csr"
CRT="$OUT_DIR/server.crt"

# Generate key and CSR with SAN
openssl req -new -newkey rsa:4096 -nodes \
  -keyout "$KEY" \
  -out "$CSR" \
  -config "$OPENSSL_CONF_SERVER" \
  -addext "subjectAltName=DNS:$DNS_NAME" \
  -subj "/CN=$DNS_NAME"

# Sign via CA (use CA dir relative paths)
(
  cd "$ROOT_DIR" && \
  openssl ca -batch -config "$OPENSSL_CONF_CA" -extensions server_cert -in "$CSR" -out "$CRT"
)

# Copy for nginx mount (avoid absolute symlinks)
cp -f "$CRT" "$ROOT_DIR/out/server/server.crt"
cp -f "$KEY" "$ROOT_DIR/out/server/server.key"

echo "Server cert issued at $OUT_DIR"
