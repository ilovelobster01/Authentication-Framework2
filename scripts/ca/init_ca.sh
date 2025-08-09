#!/usr/bin/env bash
set -euo pipefail

# Initialize a simple self-signed CA with OpenSSL classic layout
# Creates:
# scripts/ca/ca/{certs,crl,newcerts,private}
# scripts/ca/ca/index.txt, serial, crlnumber
# Root key (password-protected) and root cert

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_DIR="$ROOT_DIR/ca"
OPENSSL_CONF_CA="$ROOT_DIR/openssl_ca.cnf"

mkdir -p "$CA_DIR"/{certs,crl,newcerts,private}
chmod 700 "$CA_DIR/private"
: > "$CA_DIR/index.txt"
echo "unique_subject = no" > "$CA_DIR/index.txt.attr"
[ -f "$CA_DIR/serial" ] || echo "1000" > "$CA_DIR/serial"
[ -f "$CA_DIR/crlnumber" ] || echo "1000" > "$CA_DIR/crlnumber"

if [ ! -f "$CA_DIR/private/ca.key.pem" ]; then
  echo "Generating CA private key (password-protected)"
  openssl genrsa -aes256 -out "$CA_DIR/private/ca.key.pem" 4096
  chmod 400 "$CA_DIR/private/ca.key.pem"
fi

if [ ! -f "$CA_DIR/certs/ca.crt" ]; then
  echo "Generating self-signed CA certificate"
  openssl req -config "$OPENSSL_CONF_CA" \
    -key "$CA_DIR/private/ca.key.pem" \
    -new -x509 -days 3650 -sha256 -extensions v3_ca \
    -out "$CA_DIR/certs/ca.crt"
  chmod 444 "$CA_DIR/certs/ca.crt"
fi

# Generate initial CRL
(
  cd "$ROOT_DIR" && \
  openssl ca -config "$OPENSSL_CONF_CA" -gencrl -out "$CA_DIR/crl/ca.crl"
)
echo "CA initialized under $CA_DIR"
