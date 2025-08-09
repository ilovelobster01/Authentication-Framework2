#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <cert.crt>" >&2
  exit 1
fi
openssl x509 -noout -fingerprint -sha256 -in "$1" | sed 's/.*=//;s/:/-/g'
