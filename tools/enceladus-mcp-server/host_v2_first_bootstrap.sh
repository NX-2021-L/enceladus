#!/usr/bin/env bash
# host_v2_first_bootstrap.sh
#
# Idempotent host-v2 bootstrap/self-heal entrypoint.
# Enforces MCP profile readiness plus runtime/ownership checks required for
# deterministic remote Codex sessions.

set -euo pipefail

WORK_ROOT="${HOST_V2_WORK_ROOT:-/home/ec2-user/claude-code-dev}"
HOST_HOME="${HOST_V2_HOME:-/home/ec2-user}"
HOST_USER="${HOST_V2_USER:-ec2-user}"
MCP_PROFILE_PATH_RAW="${HOST_V2_MCP_PROFILE_PATH:-.claude/mcp.json}"
MCP_MARKER_PATH_RAW="${HOST_V2_MCP_MARKER_PATH:-.cache/enceladus/mcp-profile-installed-v1.json}"
MCP_INSTALLER="${HOST_V2_ENCELADUS_MCP_INSTALLER:-$WORK_ROOT/tools/enceladus-mcp-server/install_profile.sh}"
CODEX_FALLBACK_BIN="${HOST_V2_CODEX_FALLBACK_BIN:-${HOST_HOME}/.local/bin/codex}"
CODEX_RUNTIME_CHECK_LOG="${HOST_V2_CODEX_RUNTIME_CHECK_LOG:-/tmp/enceladus-codex-runtime-check.log}"
CODEX_SESSIONS_DIR="${HOST_V2_CODEX_SESSIONS_DIR:-${HOST_HOME}/.codex/sessions}"
SELF_HEAL_MARKER_PATH="${HOST_V2_SELF_HEAL_MARKER_PATH:-${HOST_HOME}/.cache/enceladus/host-v2-self-heal-v1.json}"

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

ensure_path_writable() {
  local target="$1"
  mkdir -p "${target}" || true
  if [[ -w "${target}" ]]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo chown -R "$(id -un):$(id -gn)" "${target}" >/dev/null 2>&1 || true
  fi
  [[ -w "${target}" ]]
}

validate_codex_runtime() {
  local codex_bin
  codex_bin="$(command -v codex || true)"

  if [[ -n "${codex_bin}" ]]; then
    if "${codex_bin}" --version >"${CODEX_RUNTIME_CHECK_LOG}" 2>&1; then
      echo "[INFO] codex runtime check passed (${codex_bin})"
      return 0
    fi

    if grep -qi "GLIBC_" "${CODEX_RUNTIME_CHECK_LOG}" 2>/dev/null && [[ -x "${CODEX_FALLBACK_BIN}" ]]; then
      mkdir -p "${HOST_HOME}/.local/bin"
      ln -sf "${CODEX_FALLBACK_BIN}" "${HOST_HOME}/.local/bin/codex"
      if "${HOST_HOME}/.local/bin/codex" --version >"${CODEX_RUNTIME_CHECK_LOG}" 2>&1; then
        echo "[WARNING] codex system binary incompatible; fallback runtime activated"
        return 0
      fi
    fi

    echo "[ERROR] codex runtime check failed"
    tail -n 20 "${CODEX_RUNTIME_CHECK_LOG}" || true
    return 1
  fi

  if [[ -x "${CODEX_FALLBACK_BIN}" ]]; then
    mkdir -p "${HOST_HOME}/.local/bin"
    ln -sf "${CODEX_FALLBACK_BIN}" "${HOST_HOME}/.local/bin/codex"
    if "${HOST_HOME}/.local/bin/codex" --version >"${CODEX_RUNTIME_CHECK_LOG}" 2>&1; then
      echo "[INFO] codex fallback runtime activated (${CODEX_FALLBACK_BIN})"
      return 0
    fi
    echo "[ERROR] codex fallback binary exists but failed runtime check"
    tail -n 20 "${CODEX_RUNTIME_CHECK_LOG}" || true
    return 1
  fi

  echo "[WARNING] codex binary not found during bootstrap; preflight-only mode may still succeed"
  return 0
}

run_self_heal() {
  mkdir -p "${HOST_HOME}/.codex" || true
  if ! ensure_path_writable "${CODEX_SESSIONS_DIR}"; then
    echo "[ERROR] codex sessions directory is not writable: ${CODEX_SESSIONS_DIR}"
    return 1
  fi
  if ! ensure_path_writable "$(dirname "${SELF_HEAL_MARKER_PATH}")"; then
    echo "[ERROR] self-heal marker directory is not writable: $(dirname "${SELF_HEAL_MARKER_PATH}")"
    return 1
  fi
  if ! validate_codex_runtime; then
    return 1
  fi

  printf '{"healed_at":"%s","host_user":"%s","sessions_dir":"%s","workspace":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    "${HOST_USER}" \
    "${CODEX_SESSIONS_DIR}" \
    "${WORK_ROOT}" \
    > "${SELF_HEAL_MARKER_PATH}"
  return 0
}

if ! run_self_heal; then
  echo "[ERROR] host-v2 self-heal failed"
  exit 22
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
