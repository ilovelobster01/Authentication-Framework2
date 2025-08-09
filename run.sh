#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-dev}"

# Function to stop the app
stop_app() {
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
  
  # Check if anything is still running on port 8000
  PORT_USAGE=$(lsof -ti:8000 || true)
  if [ -n "$PORT_USAGE" ]; then
    echo "Warning: Something is still using port 8000 (PID: $PORT_USAGE)"
    echo "You may need to manually kill it: kill $PORT_USAGE"
  fi
  
  echo "Stop complete."
  exit 0
}

# Handle stop command
if [ "$MODE" = "stop" ]; then
  stop_app
fi

if [ ! -d .venv ]; then
  echo "Virtualenv not found. Run ./setup.sh first." >&2
  exit 1
fi

source .venv/bin/activate
# Load .env if present to configure app behavior (e.g., REQUIRE_MTLS_FOR_LOGIN, ADMIN_REQUIRE_MTLS)
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs -r)
fi

if [ "$MODE" = "dev" ]; then
  export FLASK_ENV=development
  echo "Starting Flask app in development mode on port 8000..."
  echo "Press Ctrl+C to stop, or run './run.sh stop' from another terminal"
  python -m app.app
elif [ "$MODE" = "prod" ]; then
  echo "Starting Flask app in production mode with Gunicorn on port 8000..."
  echo "Run './run.sh stop' to stop the server"
  exec gunicorn -w 4 -b 0.0.0.0:8000 app.wsgi:app
else
  echo "Usage: $0 [dev|prod|stop]" >&2
  echo "  dev  - Start in development mode (default)"
  echo "  prod - Start in production mode with Gunicorn"
  echo "  stop - Stop any running Flask/Gunicorn processes"
  exit 1
fi
