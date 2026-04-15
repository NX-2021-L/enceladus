#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
REGION="${REGION:-us-east-1}"
FUNCTION_NAME="${FUNCTION_NAME:-enceladus-auth-edge${ENVIRONMENT_SUFFIX}}"
RUNTIME="${RUNTIME:-nodejs18.x}"
ARCHITECTURE="${ARCHITECTURE:-x86_64}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

package_lambda() {
  local zip_path
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  (
    cd "${SCRIPT_DIR}"
    zip -qj "${zip_path}" index.js
  )

  echo "${zip_path}"
}

deploy_lambda() {
  local zip_path="$1"

  aws lambda get-function \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" >/dev/null

  log "[START] updating Lambda code: ${FUNCTION_NAME}"
  # ENC-TSK-E19: verify package arch matches Lambda runtime before upload
  E19_REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
  E19_EXPECTED_ARCH="x86_64"
  [ -n "${ENVIRONMENT_SUFFIX:-}" ] && E19_EXPECTED_ARCH="arm64"
  python3 "${E19_REPO_ROOT}/tools/verify_lambda_package_arch.py" \
    --package "${zip_path}" \
    --expected-arch "${E19_EXPECTED_ARCH}"
  aws lambda update-function-code \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --zip-file "fileb://${zip_path}" >/dev/null

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  log "[START] updating Lambda configuration: ${FUNCTION_NAME}"
  aws lambda update-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --runtime "${RUNTIME}" >/dev/null

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  log "[END] Lambda updated: ${FUNCTION_NAME}"
}

main() {
  local zip_path
  zip_path="$(package_lambda)"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"
  log "[SUCCESS] auth_edge Lambda deployed"
}

main "$@"
