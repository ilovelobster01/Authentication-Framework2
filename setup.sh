#!/usr/bin/env bash
set -euo pipefail

# Setup dev environment: venv + requirements + DB migrations
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r app/requirements.txt

# Initialize or upgrade DB using the venv's Python to ensure the right environment
if [ ! -d migrations ]; then
  python -m flask --app app.wsgi db init
fi
python -m flask --app app.wsgi db migrate -m "auto" || true
python -m flask --app app.wsgi db upgrade

echo "Setup complete. Activate with: source .venv/bin/activate && (cd app && python app.py)"
