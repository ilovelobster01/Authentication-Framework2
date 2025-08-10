#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-dev}"
shift || true
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$ROOT_DIR/.run"
LOG_DIR="$ROOT_DIR/.run"
mkdir -p "$RUN_DIR" "$LOG_DIR"

# Load .env if present to configure app behavior
if [ -f "$ROOT_DIR/.env" ]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$ROOT_DIR/.env" | xargs -r)
fi

need_venv() {
  if [ ! -d "$ROOT_DIR/.venv" ]; then
    echo "Virtualenv not found. Run ./setup.sh first." >&2
    exit 1
  fi
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.venv/bin/activate"
  export PYTHONPATH="$ROOT_DIR:${PYTHONPATH:-}"
}

ensure_deps() {
  need_venv
  # Install main app deps
  if [ -f "$ROOT_DIR/app/requirements.txt" ]; then
    pip show -q requests >/dev/null 2>&1 || pip install -r "$ROOT_DIR/app/requirements.txt"
  # Ensure worker deps like yt-dlp present
  pip show -q yt_dlp >/dev/null 2>&1 || pip install -r "$ROOT_DIR/app/requirements.txt"
  fi
}

pid_is_alive() {
  local pid="$1"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

write_pid() {
  echo "$2" > "$RUN_DIR/$1.pid"
}

read_pid() {
  [ -f "$RUN_DIR/$1.pid" ] && cat "$RUN_DIR/$1.pid" || true
}

start_app_dev() {
  ensure_deps
  need_venv
  export FLASK_ENV=development
  echo "Starting Flask app (dev) on 8000..."
  nohup python -m app.app >"$LOG_DIR/app.log" 2>&1 &
  write_pid app "$!"
  echo "App PID: $(read_pid app) (logs: $LOG_DIR/app.log)"
}

start_app_prod() {
  ensure_deps
  need_venv
  echo "Starting Flask app (prod) on 8000 via gunicorn..."
  nohup gunicorn -w 4 -b 0.0.0.0:8000 app.wsgi:app >"$LOG_DIR/app.log" 2>&1 &
  write_pid app "$!"
  echo "App PID: $(read_pid app) (logs: $LOG_DIR/app.log)"
}

start_worker() {
  need_venv
  export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
  echo "Starting RQ worker (REDIS_URL=$REDIS_URL)..."
  nohup python "$ROOT_DIR/app/tasks/worker.py" >"$LOG_DIR/worker.log" 2>&1 &
  write_pid worker "$!"
  echo "Worker PID: $(read_pid worker) (logs: $LOG_DIR/worker.log)"
}

start_mcp() {
  need_venv
  pip install -r "$ROOT_DIR/mcp_server/requirements.txt" >/dev/null
  export FLASK_APP=mcp_server.app
  export FLASK_RUN_HOST=127.0.0.1
  # choose an available port starting at MCP_PORT or 9100
  base_port=${MCP_PORT:-9100}
  chosen_port=""
  for p in $(seq "$base_port" $((base_port+50))); do
    if ! lsof -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
      chosen_port="$p"
      break
    fi
  done
  if [ -z "$chosen_port" ]; then
    echo "No free port found for MCP in range $base_port-$((base_port+50))" >&2
    exit 1
  fi
  export FLASK_RUN_PORT="$chosen_port"
  echo "$chosen_port" > "$RUN_DIR/mcp.port"
  export MCP_PORT="$chosen_port"
  export MCP_URL="http://127.0.0.1:$chosen_port/api"
  echo "Starting MCP server on $FLASK_RUN_HOST:$FLASK_RUN_PORT... (MCP_URL=$MCP_URL)"
  nohup python -m flask run >"$LOG_DIR/mcp.log" 2>&1 &
  write_pid mcp "$!"
  echo "MCP PID: $(read_pid mcp) (logs: $LOG_DIR/mcp.log)"
  if [ "$chosen_port" != "$base_port" ]; then
    echo "Note: requested port $base_port was busy; started on $chosen_port instead."
  fi
}

set_mcp_from_file() {
  if [ -f "$RUN_DIR/mcp.port" ]; then
    local p
    p=$(cat "$RUN_DIR/mcp.port")
    if [ -n "$p" ]; then
      export MCP_PORT="$p"
      : "${MCP_URL:=http://127.0.0.1:$p/api}"
    fi
  fi
}

stop_one() {
  local name="$1"
  local pid
  pid=$(read_pid "$name")
  if [ -n "$pid" ] && pid_is_alive "$pid"; then
    echo "Stopping $name (PID $pid)"
    kill "$pid" || true
    sleep 1
    if pid_is_alive "$pid"; then
      echo "Force killing $name (PID $pid)"
      kill -9 "$pid" || true
    fi
    rm -f "$RUN_DIR/$name.pid"
  else
    echo "$name not running"
  fi
}

status() {
  for n in app worker mcp; do
    pid=$(read_pid "$n")
    if [ -n "$pid" ] && pid_is_alive "$pid"; then
      echo "$n: running (PID $pid)"
    else
      echo "$n: stopped"
    fi
  done
}

case "$MODE" in
  dev)
    start_app_dev ;;
  prod)
    start_app_prod ;;
  worker)
    start_worker ;;
  mcp)
    start_mcp ;;
  all|up)
    start_mcp
    set_mcp_from_file
    start_app_dev
    start_worker ;;
  stop)
    # Strong stop: stop known PIDs, then kill by pattern and ports
    stop_one mcp || true
    stop_one worker || true
    stop_one app || true
    # Kill lingering processes by pattern
    pkill -f "python -m app.app" 2>/dev/null || true
    pkill -f "gunicorn .*app.wsgi" 2>/dev/null || true
    pkill -f "flask run.*mcp_server.app" 2>/dev/null || true
    # Free ports
    fuser -k 8000/tcp 2>/dev/null || true
    if [ -f "$RUN_DIR/mcp.port" ]; then
      MCP_P=$(cat "$RUN_DIR/mcp.port")
      fuser -k "$MCP_P"/tcp 2>/dev/null || true
    fi
    echo "All services stopped." ;;
  status)
    status ;;
  *)
    cat >&2 <<EOF
Usage: $0 [dev|prod|worker|mcp|all|up|stop|status]
  dev     Start Flask app (development)
  prod    Start Flask app (gunicorn)
  worker  Start RQ worker
  mcp     Start MCP server
  all|up  Start app (dev), worker, MCP
  stop    Stop MCP, worker, app (if running)
  status  Show process status
EOF
    exit 1 ;;
 esac
