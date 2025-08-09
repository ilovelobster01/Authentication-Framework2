#!/usr/bin/env bash
set -euo pipefail

# Run with sudo: sudo bash fix.sh
# Purpose: Reset Nginx to a known-good config for this app and make HTTPS reachable without a client cert.

# Resolve repo dir to where this script lives
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE_AVAIL="/etc/nginx/sites-available"
SITE_EN="/etc/nginx/sites-enabled"
SITE_NAME="mtls_flask"
REDIR_NAME="http_redirect"

CA_CRT_SRC="$REPO_DIR/scripts/ca/ca/certs/ca.crt"
CA_CRL_SRC="$REPO_DIR/scripts/ca/ca/crl/ca.crl"
SRV_CRT_SRC="$REPO_DIR/scripts/ca/out/server/localhost/server.crt"
SRV_KEY_SRC="$REPO_DIR/scripts/ca/out/server/localhost/server.key"

# Where nginx can safely read them
NGX_CERT_DIR="/etc/nginx/certs"
NGX_CA_CERT_DIR="/etc/nginx/ca/certs"
NGX_CA_CRL_DIR="/etc/nginx/ca/crl"
SRV_CRT="$NGX_CERT_DIR/server.crt"
SRV_KEY="$NGX_CERT_DIR/server.key"
CA_CRT="$NGX_CA_CERT_DIR/ca.crt"
CA_CRL="$NGX_CA_CRL_DIR/ca.crl"

info() { echo "[INFO]  $*" >&2; }
err()  { echo "[ERROR] $*" >&2; exit 1; }

[ "${EUID:-$(id -u)}" -eq 0 ] || err "Run with sudo: sudo bash fix.sh"

# Ensure helper scripts are executable
chmod +x "$REPO_DIR"/scripts/ca/*.sh 2>/dev/null || true

# Ensure CA and server cert exist
if [ ! -f "$SRV_CRT" ] || [ ! -f "$SRV_KEY" ]; then
  info "Server cert not found. Initializing CA and issuing server cert for 'localhost'."
  bash "$REPO_DIR/scripts/ca/init_ca.sh"
  bash "$REPO_DIR/scripts/ca/issue_server.sh" localhost
fi

# Copy certs/keys into nginx-owned dirs with correct permissions
mkdir -p "$NGX_CERT_DIR" "$NGX_CA_CERT_DIR" "$NGX_CA_CRL_DIR"
install -m 644 "$CA_CRT_SRC" "$CA_CRT"
install -m 644 "$CA_CRL_SRC" "$CA_CRL"
install -m 644 "$SRV_CRT_SRC" "$SRV_CRT"
install -m 640 -g www-data "$SRV_KEY_SRC" "$SRV_KEY"

# Write Nginx HTTPS site config (always overwrite to ensure consistency)
mkdir -p "$SITE_AVAIL" "$SITE_EN"
cat >"$SITE_AVAIL/$SITE_NAME" <<EOF
upstream flask_local {
    server 127.0.0.1:8000;
}

# HTTP redirect (ensure only one redirect server is enabled)
server {
    listen 80 default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate     $SRV_CRT;
    ssl_certificate_key $SRV_KEY;

    # Client CA and CRL
    ssl_client_certificate $CA_CRT;
    ssl_crl               $CA_CRL;
    # For setup, do not require a client cert
    ssl_verify_client off;

    # Allow large forwarded cert headers
    large_client_header_buffers 8 32k;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy strict-origin-when-cross-origin;
    add_header Content-Security-Policy "default-src 'self'";

    location /healthz {
        proxy_pass http://flask_local/healthz;
    }

    location / {
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_set_header X-Client-Verify \$ssl_client_verify;
        proxy_set_header X-Client-Cert-Fingerprint \$ssl_client_fingerprint;
        proxy_set_header X-Client-Cert-Serial \$ssl_client_serial;
        proxy_set_header X-Client-Cert-Subject \$ssl_client_s_dn;
        proxy_set_header X-Client-Cert-Issuer \$ssl_client_i_dn;
        proxy_set_header X-Client-Cert \$ssl_client_escaped_cert;

        proxy_pass http://flask_local;
    }
}
EOF

# Enable only our HTTPS site (redirect included within it)
rm -f "$SITE_EN"/*
ln -sf "$SITE_AVAIL/$SITE_NAME" "$SITE_EN/$SITE_NAME"

# Open firewall (if ufw exists)
if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
fi

# Enable and reload nginx
systemctl enable nginx || true
nginx -t
systemctl reload nginx

info "Nginx reset complete. HTTPS on 443 is reachable without a client certificate."
info "Now visit: https://<vm-ip>/login (no cert required). After binding your cert from the admin UI, lock down with:"
info "  sudo bash set-auth-mode.sh on"
