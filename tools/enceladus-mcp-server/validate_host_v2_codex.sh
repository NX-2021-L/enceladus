#!/usr/bin/env bash
# validate_host_v2_codex.sh
#
# End-to-end proof harness for ENC-TSK-636.
# Connects to a host-v2 SSH target, runs bootstrap, executes a non-interactive
# Codex prompt, and collects evidence artifacts locally.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  validate_host_v2_codex.sh --ssh-target ec2-user@host-or-ip [options]

Required:
  --ssh-target TARGET        SSH target (e.g. ec2-user@1.2.3.4)

Optional:
  --ssh-key PATH             SSH private key path
  --workspace PATH           Remote workspace root (default: /home/ec2-user/claude-code-dev)
  --prompt TEXT              Prompt to submit (default uses a verification token)
  --output-dir PATH          Local output base dir (default: artifacts/enc-tsk-636)
  --ssh-port PORT            SSH port (default: 22)
  --bootstrap-script PATH    Remote bootstrap script path
                             (default: {workspace}/tools/enceladus-mcp-server/host_v2_first_bootstrap.sh)
  --help                     Show this help text
EOF
}

SSH_TARGET=""
SSH_KEY=""
SSH_PORT="22"
WORKSPACE="/home/ec2-user/claude-code-dev"
PROMPT=""
OUTPUT_DIR="artifacts/enc-tsk-636"
BOOTSTRAP_SCRIPT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-target)
      SSH_TARGET="${2:-}"
      shift 2
      ;;
    --ssh-key)
      SSH_KEY="${2:-}"
      shift 2
      ;;
    --workspace)
      WORKSPACE="${2:-}"
      shift 2
      ;;
    --prompt)
      PROMPT="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --ssh-port)
      SSH_PORT="${2:-}"
      shift 2
      ;;
    --bootstrap-script)
      BOOTSTRAP_SCRIPT="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${SSH_TARGET}" ]]; then
  echo "[ERROR] --ssh-target is required" >&2
  usage
  exit 2
fi

if [[ -z "${BOOTSTRAP_SCRIPT}" ]]; then
  BOOTSTRAP_SCRIPT="${WORKSPACE}/tools/enceladus-mcp-server/host_v2_first_bootstrap.sh"
fi

TOKEN="ENC_TSK_636_$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "${PROMPT}" ]]; then
  PROMPT="Return exactly this token on one line and one short confirmation sentence on line two: ${TOKEN}"
fi

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOCAL_RUN_DIR="${OUTPUT_DIR}/${RUN_TS}"
mkdir -p "${LOCAL_RUN_DIR}"

REMOTE_RUN_DIR="/tmp/enc_tsk_636_${RUN_TS}"
REMOTE_PROMPT_FILE="${REMOTE_RUN_DIR}/prompt.txt"
REMOTE_LAST_MESSAGE="${REMOTE_RUN_DIR}/codex_last_message.txt"
REMOTE_EVENTS="${REMOTE_RUN_DIR}/codex_events.jsonl"
REMOTE_BOOTSTRAP_LOG="${REMOTE_RUN_DIR}/bootstrap.log"
REMOTE_VERSION_LOG="${REMOTE_RUN_DIR}/codex_version.txt"
REMOTE_SUMMARY_JSON="${REMOTE_RUN_DIR}/summary.json"

SSH_OPTS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=12
  -o ControlMaster=auto
  -o ControlPersist=300
  -p "${SSH_PORT}"
)
if [[ -n "${SSH_KEY}" ]]; then
  SSH_OPTS+=(-i "${SSH_KEY}")
fi

CONTROL_PATH="/tmp/enc_tsk_636_ssh_${RUN_TS}_%r@%h:%p"
SSH_OPTS+=(-o "ControlPath=${CONTROL_PATH}")

REMOTE_SCRIPT=$(cat <<EOF
set -euo pipefail
mkdir -p "${REMOTE_RUN_DIR}"
cd "${WORKSPACE}"

if [[ -x "${BOOTSTRAP_SCRIPT}" ]]; then
  "${BOOTSTRAP_SCRIPT}" > "${REMOTE_BOOTSTRAP_LOG}" 2>&1 || true
else
  printf '[WARNING] bootstrap script not found: %s\n' "${BOOTSTRAP_SCRIPT}" > "${REMOTE_BOOTSTRAP_LOG}"
fi

if ! command -v codex >/dev/null 2>&1; then
  echo "[ERROR] codex binary not found on remote host" >&2
  exit 31
fi

codex --version > "${REMOTE_VERSION_LOG}" 2>&1

cat > "${REMOTE_PROMPT_FILE}" <<'PROMPT_EOF'
${PROMPT}
PROMPT_EOF

codex exec \
  --skip-git-repo-check \
  --json \
  --output-last-message "${REMOTE_LAST_MESSAGE}" \
  - < "${REMOTE_PROMPT_FILE}" > "${REMOTE_EVENTS}" 2>&1

python3 - <<'PY'
import json
import pathlib

summary = {
    "token": "${TOKEN}",
    "workspace": "${WORKSPACE}",
    "bootstrap_log": "${REMOTE_BOOTSTRAP_LOG}",
    "codex_version_log": "${REMOTE_VERSION_LOG}",
    "events_log": "${REMOTE_EVENTS}",
    "last_message_path": "${REMOTE_LAST_MESSAGE}",
}

last_message_path = pathlib.Path("${REMOTE_LAST_MESSAGE}")
if last_message_path.exists():
    summary["last_message_preview"] = last_message_path.read_text(errors="replace")[:500]

pathlib.Path("${REMOTE_SUMMARY_JSON}").write_text(json.dumps(summary, indent=2) + "\n")
PY
EOF
)

echo "[INFO] Running host-v2 validation against ${SSH_TARGET}"
if ! ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "${REMOTE_SCRIPT}" | tee "${LOCAL_RUN_DIR}/ssh_stdout.log"; then
  echo "[ERROR] Remote validation command failed" >&2
fi

echo "[INFO] Pulling evidence artifacts"
pull_remote_file() {
  local remote_path="$1"
  local local_path="$2"
  if ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "test -f '${remote_path}'"; then
    ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "cat '${remote_path}'" > "${local_path}"
  fi
}

pull_remote_file "${REMOTE_SUMMARY_JSON}" "${LOCAL_RUN_DIR}/summary.json"
pull_remote_file "${REMOTE_BOOTSTRAP_LOG}" "${LOCAL_RUN_DIR}/bootstrap.log"
pull_remote_file "${REMOTE_VERSION_LOG}" "${LOCAL_RUN_DIR}/codex_version.txt"
pull_remote_file "${REMOTE_EVENTS}" "${LOCAL_RUN_DIR}/codex_events.jsonl"
pull_remote_file "${REMOTE_LAST_MESSAGE}" "${LOCAL_RUN_DIR}/codex_last_message.txt"

ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "ls -la '${REMOTE_RUN_DIR}'" > "${LOCAL_RUN_DIR}/remote_artifact_listing.txt" 2>&1 || true
ssh "${SSH_OPTS[@]}" -O exit "${SSH_TARGET}" >/dev/null 2>&1 || true

VALIDATION_RESULT="failed"
if [[ -f "${LOCAL_RUN_DIR}/codex_last_message.txt" ]] && grep -q "${TOKEN}" "${LOCAL_RUN_DIR}/codex_last_message.txt"; then
  VALIDATION_RESULT="passed"
fi

cat > "${LOCAL_RUN_DIR}/proof_summary.md" <<EOF
# ENC-TSK-636 Host-v2 Codex Validation

- run_utc: ${RUN_TS}
- ssh_target: ${SSH_TARGET}
- workspace: ${WORKSPACE}
- verification_token: ${TOKEN}
- result: ${VALIDATION_RESULT}

## Artifacts
- summary.json
- bootstrap.log
- codex_version.txt
- codex_events.jsonl
- codex_last_message.txt
- ssh_stdout.log
- remote_artifact_listing.txt
EOF

echo "[INFO] Validation result: ${VALIDATION_RESULT}"
echo "[INFO] Evidence directory: ${LOCAL_RUN_DIR}"

if [[ "${VALIDATION_RESULT}" != "passed" ]]; then
  echo "[ERROR] Token not found in codex_last_message.txt" >&2
  exit 41
fi

echo "[SUCCESS] Host-v2 Codex proof complete"
