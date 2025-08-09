#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv || true
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
export FLASK_APP=app.py
export FLASK_RUN_HOST=127.0.0.1
export FLASK_RUN_PORT=${PORT:-9100}
flask run
