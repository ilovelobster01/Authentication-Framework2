#!/usr/bin/env bash
set -euo pipefail

# set-nginx-auth-mode.sh — switch Nginx client cert verification mode
# Modes:
#   on       -> ssl_verify_client on;
#   optional -> ssl_verify_client optional;
#   off      -> ssl_verify_client off;
#   show     -> print current directive from the active site files
# Usage:
#   sudo bash set-nginx-auth-mode.sh on|optional|off|show

MODE="${1:-show}"

err() { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[INFO]  $*" >&2; }

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "Run this script with sudo or as root"
  fi
}

show_mode() {
  local files=()
  [ -d /etc/nginx/sites-enabled ] && files+=(/etc/nginx/sites-enabled/*)
  [ -d /etc/nginx/sites-available ] && files+=(/etc/nginx/sites-available/*)
  [ -d /etc/nginx/conf.d ] && files+=(/etc/nginx/conf.d/*.conf)
  local shown=0
  for f in "${files[@]}"; do
    [ -e "$f" ] || continue
    if grep -qE "^\s*listen\s+.*443\b" "$f"; then
      local line
      line=$(grep -E "^\s*ssl_verify_client\b" "$f" || true)
      if [ -n "$line" ]; then
        printf "%s: %s\n" "$f" "$(echo "$line" | sed -E "s/^\s*ssl_verify_client\s+([a-zA-Z]+);.*/\1/")"
        shown=1
      fi
    fi
  done
  if [ "$shown" -eq 0 ]; then
    echo "(no ssl_verify_client directive found in TLS server blocks)"
  fi
}

apply_to_file() {
  local new="$1"; shift
  local file="$1"
  [ -f "$file" ] || return 0
  if ! grep -qE "^\s*listen\s+.*443\b" "$file"; then
    return 0
  fi
  if grep -qE "^\s*ssl_verify_client\b" "$file"; then
    sed -i -E "s/^\s*ssl_verify_client\b.*/    ssl_verify_client ${new};/" "$file"
  else
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
  local files=()
  [ -d /etc/nginx/sites-enabled ] && files+=(/etc/nginx/sites-enabled/*)
  [ -d /etc/nginx/sites-available ] && files+=(/etc/nginx/sites-available/*)
  [ -d /etc/nginx/conf.d ] && files+=(/etc/nginx/conf.d/*.conf)
  for f in "${files[@]}"; do
    [ -e "$f" ] || continue
    apply_to_file "$new" "$f"
  done
  nginx -t
  systemctl reload nginx || service nginx reload
  info "Set ssl_verify_client to: $new across enabled sites"
}

case "$MODE" in
  show)
    show_mode ;;
  on|optional|off)
    require_root
    set_mode "$MODE" ;;
  *)
    err "Usage: sudo bash set-nginx-auth-mode.sh on|optional|off|show" ;;
 esac
