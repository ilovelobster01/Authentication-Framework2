App-side certificate enforcement plan

Current state
- Nginx enforces mTLS, forwards sanitized certificate metadata and an escaped PEM certificate to the Flask app.
- Minimal Flask app exposes /debug/identity and provides endpoints to bind/unbind the presented certificate to a user.
- SQLAlchemy models include User and UserCertificate.

Next steps to complete cert enforcement
1) Database migrations
   - Use Flask-Migrate to create initial tables for users and user_certificates.

2) Seed an admin user (dev only)
   - For now, add a temporary /dev/create_user endpoint or a one-off script to create a user so you can bind a cert. Later, replace with proper admin UI.

3) Enforce cert presence for privileged endpoints
   - Add a before_request check for routes that require a valid (non-revoked, within validity window) certificate bound to the user once login is integrated.

4) Normalize fingerprints
   - Use SHA-256 from the PEM (preferred). Store uppercase hex without separators. Use a consistent canonical form.

5) Admin management flows (coming soon)
   - List a user's cert bindings, revoke/unbind, and audit.

How to try binding now
- Create the DB and tables:
  docker compose up --build
  docker compose exec app flask --app wsgi db init
  docker compose exec app flask --app wsgi db migrate -m "init"
  docker compose exec app flask --app wsgi db upgrade

- Seed a user (temporary): use a one-time script or interactively attach to the Python shell.

- With your browser cert selected, POST to bind:
  curl -k -X POST https://localhost:8443/cert/bind/alice --cert-type P12 --cert ./scripts/ca/out/clients/alice/alice.p12:EXPORT_PASSWORD
  (or use the browser devtools/Fetch/XHR from a page, though we have no UI yet.)

Security notes
- We do not trust any cert metadata without Nginx verification; app enforces X-Client-Verify=SUCCESS.
- In production, block direct app access and only allow traffic through the mTLS reverse proxy.
- We use the escaped PEM to compute SHA-256 to avoid ambiguity about hash algorithm.
