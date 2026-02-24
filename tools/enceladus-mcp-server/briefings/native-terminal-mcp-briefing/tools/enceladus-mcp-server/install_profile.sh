#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANONICAL_INSTALLER="${SCRIPT_DIR}/../../../../install_profile.sh"

if [ ! -f "${CANONICAL_INSTALLER}" ]; then
  echo "[ERROR] Canonical installer not found at ${CANONICAL_INSTALLER}" >&2
  echo "[INFO] Use the full repo checkout and run tools/enceladus-mcp-server/install_profile.sh" >&2
  exit 1
fi

exec "${CANONICAL_INSTALLER}" "$@"
