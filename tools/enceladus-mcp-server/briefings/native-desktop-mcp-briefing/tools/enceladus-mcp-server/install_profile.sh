#!/usr/bin/env bash
# Briefing wrapper to avoid profile configuration drift.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANONICAL_INSTALLER="${SCRIPT_DIR}/../../../../install_profile.sh"

if [[ ! -x "${CANONICAL_INSTALLER}" ]]; then
  echo "[ERROR] Canonical installer not found or not executable: ${CANONICAL_INSTALLER}" >&2
  echo "[INFO] Use the full repo checkout and run tools/enceladus-mcp-server/install_profile.sh" >&2
  exit 1
fi

exec "${CANONICAL_INSTALLER}" "$@"
