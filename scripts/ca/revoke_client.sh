#!/usr/bin/env bash
set -euo pipefail

# Revoke a client certificate and regenerate CRL
# Usage: revoke_client.sh /path/to/user.crt

if [ $# -lt 1 ]; then
  echo "Usage: $0 <path-to-client-cert.crt>" >&2
  exit 1
fi
CRT="$1"

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPENSSL_CONF_CA="$ROOT_DIR/openssl_ca.cnf"
CA_DIR="$ROOT_DIR/ca"

(
  cd "$ROOT_DIR" && \
  openssl ca -config "$OPENSSL_CONF_CA" -revoke "$CRT"
  openssl ca -config "$OPENSSL_CONF_CA" -gencrl -out "$CA_DIR/crl/ca.crl"
)
echo "Revoked $CRT and updated CRL at $CA_DIR/crl/ca.crl"
