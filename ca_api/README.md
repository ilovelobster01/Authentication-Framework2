CA API microservice

Purpose
- Provide a minimal API to issue and revoke client certificates without exposing the CA password to the main app.
- Returns artifacts (crt, key, p12) as base64. Optionally removes them from disk after issuance.

Endpoints
- POST /api/issue (Bearer token required)
  - body: { "username": "alice", "email": "alice@example.com", "p12_password": "strongpass" }
  - response: { "crt": "base64...", "key": "base64...", "p12": "base64..." }
- POST /api/revoke (Bearer token required)
  - body: { "username": "alice" }
  - response: { "status": "revoked" }
- GET /api/health

Configuration (env)
(see .env.example) including IP allowlist controls
- CA_API_TOKEN: required. Bearer token clients must present.
- CA_SCRIPTS_DIR: path to scripts/ca (default: ../scripts/ca)
- CA_PASS: CA signing password (kept private to this service)
- ALLOWED_EMAIL_DOMAIN: optional email domain restriction.
- CA_API_PERSIST_OUTPUT: set to 1 to keep artifacts on disk; default 0 (remove).

Run locally
(FreeIPA backend requires that this host can kinit with a service principal & keytab, and that the ipa CLI is installed)
- cd ca_api
- ./run.sh
- Example invocation from main app:
  - CA_ISSUER=http
  - CA_API_URL=http://127.0.0.1:9000/api
  - CA_API_TOKEN=<same token configured here>

Security notes
- This service should run with minimal OS privileges, ideally as its own user, and only on a trusted network interface.
- Consider placing behind a reverse proxy with TLS and IP allowlists.
- For production, consider using a dedicated CA/HSM or a PKI platform rather than OpenSSL shell scripts.
