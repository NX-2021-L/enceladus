#!/usr/bin/env bash
set -euo pipefail

# Sync API and MCP source mirrors from canonical devops tools paths.
# Default source root assumes this repo lives at projects/enceladus/repo.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SOURCE_TOOLS="${1:-${REPO_ROOT}/../../devops/tools}"

if [[ ! -d "${SOURCE_TOOLS}" ]]; then
  echo "[ERROR] Source tools path not found: ${SOURCE_TOOLS}" >&2
  exit 1
fi

echo "[INFO] Repo root: ${REPO_ROOT}"
echo "[INFO] Source tools: ${SOURCE_TOOLS}"

mkdir -p "${REPO_ROOT}/api/lambda"

LAMBDA_DIRS=(
  "coordination_api"
  "coordination_monitor_api"
  "dispatch_orchestrator"
  "bedrock_agent_actions"
  "document_api"
  "project_service"
  "reference_search"
  "tracker_mutation"
  "deploy_intake"
)

for name in "${LAMBDA_DIRS[@]}"; do
  src="${SOURCE_TOOLS}/lambda/${name}/"
  dst="${REPO_ROOT}/api/lambda/${name}/"
  if [[ ! -d "${src}" ]]; then
    echo "[WARNING] Missing source directory, skipping: ${src}"
    continue
  fi
  echo "[INFO] Syncing ${name}"
  rsync -a --delete \
    --exclude "__pycache__/" \
    --exclude ".pytest_cache/" \
    --exclude "*.pyc" \
    --exclude ".DS_Store" \
    "${src}" "${dst}"
done

echo "[INFO] Syncing mcp-server"
rsync -a --delete \
  --exclude "README.md" \
  --exclude "__pycache__/" \
  --exclude ".pytest_cache/" \
  --exclude "*.pyc" \
  --exclude ".DS_Store" \
  "${SOURCE_TOOLS}/enceladus-mcp-server/" "${REPO_ROOT}/mcp-server/"

echo "[DONE] Non-UI source sync complete"
