Security-first dev setup: mTLS with a self-signed CA, Nginx, and a minimal Flask app

Overview
This repository contains:
- scripts/ca: Helper scripts and OpenSSL configs to create a self-signed CA, issue/revoke client and server certificates, and maintain a CRL.
- nginx/dev: An Nginx configuration that enforces mutual TLS (client certificates) and forwards sanitized certificate metadata to the upstream app.
- app: A minimal Flask app (served by gunicorn) to validate header propagation and show how the app would consume certificate headers.
- docker-compose.yml: Runs the app and Nginx together for local development. Alternatively, see README_HOST_NGINX.md for a native (no-Docker) setup.

High-level flow
- Nginx terminates TLS using a dev server cert.
- Nginx verifies client certificates against your self-signed CA and checks CRL.
- If the client is verified, Nginx forwards headers like X-Client-Cert-Fingerprint to the Flask app.
- The Flask app reads these headers; in the real system, it will bind cert fingerprints to user accounts and enforce checks at login.

Prerequisites
- docker and docker compose plugin
- openssl (for running CA scripts)
- bash (for helper scripts)

Quick start
1) Initialize the CA and create a dev server cert

   bash scripts/ca/init_ca.sh
   bash scripts/ca/issue_server.sh localhost

   This will create the CA under scripts/ca/ca and a server cert/key under scripts/ca/out/server/localhost.

2) Issue a client certificate for your browser

   bash scripts/ca/issue_client.sh alice alice@example.com

   This produces a PKCS#12 bundle (alice.p12) under scripts/ca/out/clients/. Import this into your browser (you will be prompted for the export password you entered during issuance).

3) Start the stack

   docker compose up --build

4) Visit the app
- Open https://localhost:8443/debug/identity in your browser.
- Your browser should prompt for a certificate; select the one you imported.
- You should see JSON showing ssl client verification state and the forwarded fingerprint/serial headers.

5) Revoke a client cert (optional)

   bash scripts/ca/revoke_client.sh scripts/ca/out/clients/alice/alice.crt

   Restart Nginx (docker compose restart nginx). Now the revoked cert should be rejected at the TLS layer.

Directory layout
- scripts/ca/
  - init_ca.sh: Initialize CA (root key/cert, index, serial, CRL).
  - issue_server.sh: Issue a server cert for a given DNS name (SAN) and export key/cert for Nginx.
  - issue_client.sh: Issue a client cert (CN=username, SAN=email) and export as PKCS#12.
  - revoke_client.sh: Revoke a client cert and regenerate CRL.
  - print_fingerprint.sh: Compute SHA-256 fingerprint of a cert.
  - openssl_*.cnf: OpenSSL configs for CA, server, and client issuance.
  - ca/: CA private and db files (private key is password-protected).
  - out/: Issued certs and artifacts (server and client outputs).

- nginx/dev/nginx.conf: mTLS enabled config with security headers and header forwarding to app.
- app/: Minimal Flask app to show incoming headers and health check.
- docker-compose.yml: Wiring for app and Nginx.

Security notes (dev)
- The root CA key is password-protected and kept in scripts/ca/ca/private/. Do not commit real secrets.
- The server key is generated per issuance; for dev, it is stored under scripts/ca/out/server/.
- Client PKCS#12 bundles contain private keys; protect them and remove after import if needed.
- Nginx is configured with conservative TLS parameters and HSTS (for localhost this is safe in dev).

Next steps
- Once mTLS is verified, we’ll bind the client fingerprint to user accounts in the Flask app and make it a mandatory factor alongside password + TOTP.
- Then we’ll build admin UI for cert management (bind/unbind/revoke) and integrate with CA/CRL updates.
