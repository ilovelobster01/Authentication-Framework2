#!/usr/bin/env bash
set -euo pipefail

# Setup dev environment: venv + requirements + DB migrations
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r app/requirements.txt

# Initialize DB
flask --app app.wsgi db init || true
flask --app app.wsgi db migrate -m "init" || true
flask --app app.wsgi db upgrade

echo "Setup complete. Activate with: source .venv/bin/activate && (cd app && python app.py)"
