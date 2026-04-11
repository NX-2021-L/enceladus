#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
REGION="${REGION:-us-west-2}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-doc-prep${ENVIRONMENT_SUFFIX}}"
# Env-conditional: gamma=arm64/py3.12, prod=x86_64/py3.11
if [ -n "${ENVIRONMENT_SUFFIX:-}" ]; then
  RUNTIME="${RUNTIME:-python3.12}"
  ARCHITECTURE="${ARCHITECTURE:-arm64}"
else
  RUNTIME="${RUNTIME:-python3.11}"
  ARCHITECTURE="${ARCHITECTURE:-x86_64}"
fi

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

package_lambda() {
  local zip_path
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  (
    cd "${SCRIPT_DIR}"
    zip -qj "${zip_path}" lambda_function.py
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
  log "[SUCCESS] doc_prep Lambda deployed"
}

main "$@"
