Checkpoint summary (to be pushed to GitHub)

Scope of changes since initial:
- Added robust certificate parsing (app/cert_utils.py) that handles URL-escaped PEM, tabs/spaces, and base64 DER fallback.
- mTLS header propagation validated and debug endpoint improved (/debug/identity shows SHA-256 from PEM).
- Admin UX:
  - User detail now previews currently presented certificate before binding.
  - Users list shows presented cert summary.
  - New Certificate Management section (/admin/certs) to issue client certificates and download .p12/.crt.
  - Auto-bind issued certs to user if user exists; refresh metadata if already bound.
- Login policy hardening:
  - If a cert is presented, it must belong to the user attempting to log in.
  - With REQUIRE_MTLS_FOR_LOGIN=1, a bound, valid cert is required.
- Routes:
  - Root redirects to /login; logout accepts GET/POST.
- Nginx (host): added reference mtls_flask.conf.
- Fix cryptography naive datetime deprecation: use not_valid_before_utc / not_valid_after_utc; store as naive UTC.
- Added stop.sh and run.sh stop support for native dev.

Notes and TODOs:
- For production, consider moving CA key operations behind a service or approval flow. Avoid passing CA passwords via form in long term.
- Consider strict optional-mTLS mode (reject login if presented cert is unbound).
- Optionally add audit logging of cert issuance, binding, and login attempts.

How to run:
- Native dev: ./setup.sh (once), then ./run.sh dev (./run.sh stop to stop). App on http://127.0.0.1:8000.
- With host Nginx mTLS: configure nginx/host/mtls_flask.conf and http_redirect.conf; reload Nginx.
- Admin UI: /admin (login first).
