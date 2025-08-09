Native Nginx mTLS setup (no Docker)

Prereqs
- Ubuntu with nginx installed: sudo apt-get update && sudo apt-get install -y nginx
- CA initialized and server/client certs issued (see README.md):
  - bash scripts/ca/init_ca.sh
  - bash scripts/ca/issue_server.sh localhost
  - bash scripts/ca/issue_client.sh alice alice@example.com

Configure Nginx
1) Copy the provided config (adjust repo path if different):
   sudo cp nginx/host/mtls_flask.conf /etc/nginx/sites-available/mtls_flask

2) Enable the site and HTTP->HTTPS redirect:
   sudo ln -sf /etc/nginx/sites-available/mtls_flask /etc/nginx/sites-enabled/mtls_flask
   sudo cp nginx/host/http_redirect.conf /etc/nginx/sites-available/http_redirect
   sudo ln -sf /etc/nginx/sites-available/http_redirect /etc/nginx/sites-enabled/http_redirect
   # Optionally disable the default site
   sudo rm -f /etc/nginx/sites-enabled/default

3) During initial setup, Nginx is configured with ssl_verify_client optional; after you bind your cert, edit mtls_flask to set ssl_verify_client on and reload Nginx.

4) Test and reload:
   sudo nginx -t
   sudo systemctl reload nginx

Run the Flask app locally
- In a separate terminal:
  python3 -m venv .venv && source .venv/bin/activate
  pip install -r app/requirements.txt
  cd app && python app.py

Test
- Visit https://localhost/debug/identity
- Your browser should prompt for the client certificate you issued.
- You should see JSON with ssl_client_verify=SUCCESS and forwarded cert metadata.

Notes
- The config references certs under /flaskapp/rovo1/scripts/ca/... Adjust the paths if your repo is in a different location.
- To revoke a client cert: bash scripts/ca/revoke_client.sh <path-to-crt> && sudo systemctl reload nginx
- For server changes, re-issue server cert if needed and reload nginx.
