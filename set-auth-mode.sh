#!/usr/bin/env bash
set -euo pipefail

# set-auth-mode.sh — robustly switch Nginx client cert verification mode
# Modes:
#   on       -> ssl_verify_client on;
#   optional -> ssl_verify_client optional;
#   off      -> ssl_verify_client off;
#   show     -> print current directive from the active site file
# Usage:
#   sudo bash set-auth-mode.sh on|optional|off|show
# Site file assumed: /etc/nginx/sites-available/mtls_flask

SITE_AVAIL="/etc/nginx/sites-available/mtls_flask"
SITE_ENABLED="/etc/nginx/sites-enabled/mtls_flask"
MODE="${1:-show}"

err() { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*" >&2; }

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "Run this script with sudo or as root"
  fi
}

require_any_file() {
  [ -f "$SITE_AVAIL" ] || [ -f "$SITE_ENABLED" ] || err "Site config not found: $SITE_AVAIL or $SITE_ENABLED"
}

show_mode() {
  require_any_file
  local file
  if [ -f "$SITE_ENABLED" ]; then file="$SITE_ENABLED"; else file="$SITE_AVAIL"; fi
  local line
  line=$(grep -E "^\s*ssl_verify_client\b" "$file" || true)
  if [ -z "$line" ]; then
    echo "(no ssl_verify_client directive found)"
  else
    echo "$line" | sed -E 's/^\s*ssl_verify_client\s+([a-zA-Z]+);.*/\1/'
  fi
}

apply_to_file() {
  local new="$1"; shift
  local file="$1"
  [ -f "$file" ] || return 0
  # Only adjust files that define a TLS server (listen 443)
  if ! grep -qE "^\s*listen\s+.*443\b" "$file"; then
    return 0
  fi
  if grep -qE "^\s*ssl_verify_client\b" "$file"; then
    # Robustly replace entire directive line
    sed -i -E "s/^\s*ssl_verify_client\b.*/    ssl_verify_client ${new};/" "$file"
  else
    # Insert after ssl_client_certificate if present, else before ssl_protocols
    if grep -qE "^\s*ssl_client_certificate\b" "$file"; then
      sed -i -E "/^\s*ssl_client_certificate\b.*/a \
    ssl_verify_client ${new};" "$file"
    else
      sed -i -E "/^\s*ssl_protocols\b.*/i \
    ssl_verify_client ${new};" "$file"
    fi
  fi
}

set_mode() {
  local new="$1"
  require_any_file
  # Apply to common nginx site locations
  local files=()
  [ -d /etc/nginx/sites-enabled ] && files+=(/etc/nginx/sites-enabled/*)
  [ -d /etc/nginx/sites-available ] && files+=(/etc/nginx/sites-available/*)
  [ -d /etc/nginx/conf.d ] && files+=(/etc/nginx/conf.d/*.conf)
  for f in "${files[@]}"; do
    [ -e "$f" ] || continue
    apply_to_file "$new" "$f"
  done
  nginx -t
  systemctl reload nginx
  info "Set ssl_verify_client to: $new across enabled sites"
}

main() {
  case "$MODE" in
    show)
      show_mode
      ;;
    on|optional|off)
      require_root
      set_mode "$MODE"
      ;;
    *)
      err "Usage: sudo bash set-auth-mode.sh on|optional|off|show"
      ;;
  esac
}

main "$@"
