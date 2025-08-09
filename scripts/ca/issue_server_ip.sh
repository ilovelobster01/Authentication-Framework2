#!/usr/bin/env bash
set -euo pipefail
# Issue a dev server certificate with both DNS and IP SANs
# Usage: issue_server_ip.sh <DNS_NAME> <IP_ADDR>

if [ $# -lt 2 ]; then
  echo "Usage: $0 <DNS_NAME> <IP_ADDR>" >&2
  exit 1
fi
DNS_NAME="$1"
IP_ADDR="$2"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPENSSL_CONF_CA="$ROOT_DIR/openssl_ca.cnf"
OUT_DIR="$ROOT_DIR/out/server/$DNS_NAME"
mkdir -p "$OUT_DIR"
KEY="$OUT_DIR/server.key"
CSR="$OUT_DIR/server.csr"
CRT="$OUT_DIR/server.crt"

# Check OpenSSL version for -addext support
v="$(openssl version 2>&1 || true)"
case "$v" in
  *LibreSSL* ) echo "LibreSSL not supported; need OpenSSL >= 1.1.1" >&2; exit 1;;
  OpenSSL\ 0.*|OpenSSL\ 1.0.* ) echo "OpenSSL too old; need >= 1.1.1" >&2; exit 1;;
esac

# Generate key and CSR with SANs
openssl req -new -newkey rsa:4096 -nodes \
  -keyout "$KEY" \
  -out "$CSR" \
  -subj "/CN=$DNS_NAME" \
  -addext "subjectAltName=DNS:$DNS_NAME,IP:$IP_ADDR"

# Sign via CA
(
  cd "$ROOT_DIR" && \
  openssl ca -batch -config "$OPENSSL_CONF_CA" -extensions server_cert -in "$CSR" -out "$CRT"
)

echo "Server cert issued at $OUT_DIR"
