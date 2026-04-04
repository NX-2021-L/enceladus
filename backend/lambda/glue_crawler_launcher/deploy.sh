#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
REGION="${REGION:-us-west-2}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-glue-crawler-launcher${ENVIRONMENT_SUFFIX}}"
RUNTIME="${RUNTIME:-python3.11}"
ARCHITECTURE="${ARCHITECTURE:-x86_64}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

package_lambda() {
  local zip_path
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  (
    cd "${SCRIPT_DIR}"
    zip -qj "${zip_path}" handler.py
  )

  echo "${zip_path}"
}

deploy_lambda() {
  local zip_path="$1"

  aws lambda get-function \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" >/dev/null

  log "[START] updating Lambda code: ${FUNCTION_NAME}"
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
    --runtime "${RUNTIME}" \
    --architectures "${ARCHITECTURE}" >/dev/null

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
  log "[SUCCESS] glue_crawler_launcher Lambda deployed"
}

main "$@"
