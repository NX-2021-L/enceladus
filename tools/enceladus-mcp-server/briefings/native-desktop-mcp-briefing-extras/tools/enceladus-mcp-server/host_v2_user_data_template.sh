#!/usr/bin/env bash
# Briefing wrapper to keep user-data bootstrap in lockstep with canonical assets.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANONICAL_SCRIPT="${SCRIPT_DIR}/../../../../host_v2_user_data_template.sh"

if [[ ! -x "${CANONICAL_SCRIPT}" ]]; then
  echo "[ERROR] Canonical user-data script not found or not executable: ${CANONICAL_SCRIPT}" >&2
  exit 1
fi

exec "${CANONICAL_SCRIPT}" "$@"
