#!/usr/bin/env bash
# host_v2_user_data_template.sh
#
# Launch-template user-data payload for host-v2 fleet nodes.
# Ensures Enceladus MCP connector is provisioned on first boot.

set -euo pipefail

HOST_USER="${HOST_V2_USER:-ec2-user}"
HOST_HOME="${HOST_V2_HOME:-/home/${HOST_USER}}"
WORK_ROOT="${HOST_V2_WORK_ROOT:-${HOST_HOME}/claude-code-dev}"
BOOTSTRAP_SCRIPT="${HOST_V2_MCP_BOOTSTRAP_SCRIPT:-${WORK_ROOT}/tools/enceladus-mcp-server/host_v2_first_bootstrap.sh}"
LOG_FILE="${HOST_V2_BOOTSTRAP_LOG_FILE:-/var/log/enceladus-host-v2-bootstrap.log}"

mkdir -p "$(dirname "${LOG_FILE}")"
touch "${LOG_FILE}"
chmod 644 "${LOG_FILE}"

{
  echo "[START] host-v2 fleet first-boot bootstrap"
  echo "[INFO] host_user=${HOST_USER}"
  echo "[INFO] work_root=${WORK_ROOT}"
  echo "[INFO] bootstrap_script=${BOOTSTRAP_SCRIPT}"

  if [[ ! -x "${BOOTSTRAP_SCRIPT}" ]]; then
    echo "[ERROR] bootstrap script missing or not executable: ${BOOTSTRAP_SCRIPT}"
    exit 1
  fi

  if [[ "$(id -un)" == "${HOST_USER}" ]]; then
    bash -lc "cd '${WORK_ROOT}' && HOST_V2_HOME='${HOST_HOME}' HOST_V2_WORK_ROOT='${WORK_ROOT}' '${BOOTSTRAP_SCRIPT}'"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "${HOST_USER}" -H bash -lc "cd '${WORK_ROOT}' && HOST_V2_HOME='${HOST_HOME}' HOST_V2_WORK_ROOT='${WORK_ROOT}' '${BOOTSTRAP_SCRIPT}'"
  else
    echo "[ERROR] cannot switch to ${HOST_USER}; sudo unavailable"
    exit 2
  fi

  echo "[DONE] host-v2 fleet first-boot bootstrap"
} | tee -a "${LOG_FILE}"
