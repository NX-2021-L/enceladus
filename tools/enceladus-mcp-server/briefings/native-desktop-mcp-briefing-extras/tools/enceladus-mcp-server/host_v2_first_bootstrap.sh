#!/usr/bin/env bash
# host_v2_first_bootstrap.sh
#
# One-time MCP connector provisioning for host-v2 instances.
# Safe to rerun; skips installer when both profile + marker are present.

set -euo pipefail

WORK_ROOT="${HOST_V2_WORK_ROOT:-/home/ec2-user/claude-code-dev}"
HOST_HOME="${HOST_V2_HOME:-/home/ec2-user}"
MCP_PROFILE_PATH_RAW="${HOST_V2_MCP_PROFILE_PATH:-.claude/mcp.json}"
MCP_MARKER_PATH_RAW="${HOST_V2_MCP_MARKER_PATH:-.cache/enceladus/mcp-profile-installed-v1.json}"
MCP_INSTALLER="${HOST_V2_ENCELADUS_MCP_INSTALLER:-$WORK_ROOT/tools/enceladus-mcp-server/install_profile.sh}"

if [[ "${MCP_PROFILE_PATH_RAW}" = /* ]]; then
  MCP_PROFILE_PATH="${MCP_PROFILE_PATH_RAW}"
else
  MCP_PROFILE_PATH="${HOST_HOME}/${MCP_PROFILE_PATH_RAW}"
fi

if [[ "${MCP_MARKER_PATH_RAW}" = /* ]]; then
  MCP_MARKER_PATH="${MCP_MARKER_PATH_RAW}"
else
  MCP_MARKER_PATH="${HOST_HOME}/${MCP_MARKER_PATH_RAW}"
fi

if [[ -f "${MCP_PROFILE_PATH}" ]] && grep -q '"enceladus"' "${MCP_PROFILE_PATH}" 2>/dev/null && [[ -f "${MCP_MARKER_PATH}" ]]; then
  echo "[INFO] host-v2 MCP bootstrap already complete (warm skip)"
  echo "COORDINATION_PREFLIGHT_MCP_PROFILE_MODE=warm_skip"
  exit 0
fi

if [[ ! -x "${MCP_INSTALLER}" ]]; then
  echo "[ERROR] Enceladus MCP installer not found or not executable: ${MCP_INSTALLER}"
  exit 23
fi

echo "[INFO] Running host-v2 MCP bootstrap installer: ${MCP_INSTALLER}"
HOME="${HOST_HOME}" ENCELADUS_WORKSPACE_ROOT="${WORK_ROOT}" "${MCP_INSTALLER}"

if [[ ! -f "${MCP_PROFILE_PATH}" ]] || ! grep -q '"enceladus"' "${MCP_PROFILE_PATH}"; then
  echo "[ERROR] Enceladus MCP profile validation failed after bootstrap"
  exit 25
fi

mkdir -p "$(dirname "${MCP_MARKER_PATH}")"
printf '{"installed_at":"%s","installer":"%s","profile":"%s"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "${MCP_INSTALLER}" \
  "${MCP_PROFILE_PATH}" \
  > "${MCP_MARKER_PATH}"

echo "[SUCCESS] host-v2 MCP bootstrap complete"
echo "COORDINATION_PREFLIGHT_MCP_PROFILE_MODE=cold_install"
