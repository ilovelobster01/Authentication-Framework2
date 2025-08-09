#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
# Load .env if present
if [ -f .env ]; then
  set -a; . ./.env; set +a
fi
export FLASK_APP=app.py
export FLASK_RUN_HOST=127.0.0.1
export FLASK_RUN_PORT=${PORT:-9000}
flask run
