#!/usr/bin/env bash
set -euo pipefail

# Stop Flask app and any related processes

echo "Stopping Flask authentication app..."

# Find and kill Flask development server
FLASK_PIDS=$(pgrep -f "python.*app\.py" || true)
if [ -n "$FLASK_PIDS" ]; then
    echo "Found Flask dev server processes: $FLASK_PIDS"
    kill $FLASK_PIDS
    echo "Stopped Flask dev server"
fi

# Find and kill gunicorn processes
GUNICORN_PIDS=$(pgrep -f "gunicorn.*app\.wsgi" || true)
if [ -n "$GUNICORN_PIDS" ]; then
    echo "Found Gunicorn processes: $GUNICORN_PIDS"
    kill $GUNICORN_PIDS
    echo "Stopped Gunicorn"
fi

# Find and kill any python processes running our app
APP_PIDS=$(pgrep -f "python.*wsgi" || true)
if [ -n "$APP_PIDS" ]; then
    echo "Found app processes: $APP_PIDS"
    kill $APP_PIDS
    echo "Stopped app processes"
fi

# Check if anything is still running on port 8000
PORT_USAGE=$(lsof -ti:8000 || true)
if [ -n "$PORT_USAGE" ]; then
    echo "Warning: Something is still using port 8000 (PID: $PORT_USAGE)"
    echo "You may need to manually kill it: kill $PORT_USAGE"
fi

echo "Stop complete."