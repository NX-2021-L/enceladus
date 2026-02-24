#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy tracker_mutation Lambda (devops-tracker-mutation-api)
#
# Updates the Lambda code only. Infrastructure (IAM role, API Gateway
# route PATCH /api/v1/tracker/{projectId}/{recordType}/{recordId},
# CloudFront behavior) already exists.
#
# The Lambda handles PATCH requests to update tracker records (close, note, reopen)
# and validates JWT tokens from Cognito.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
FUNCTION_NAME="devops-tracker-mutation-api"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  # NOTE: PyJWT is provided by the enceladus-shared Lambda layer (shared_layer/deploy.sh).
  # Do NOT bundle dependencies here - cross-platform binary compatibility issues.
  # This script may run on macOS but Lambda runs on Linux; ensure layer is attached.

  (
    cd "${build_dir}"
    zip -qr "${zip_path}" .
  )

  rm -rf "${build_dir}"
  echo "${zip_path}"
}

deploy_lambda() {
  local zip_path="$1"

  log "[START] updating Lambda code: ${FUNCTION_NAME}"
  aws lambda update-function-code \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --zip-file "fileb://${zip_path}" >/dev/null

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  log "[END] Lambda updated: ${FUNCTION_NAME}"
}

main() {
  log "=========================================="
  log "Deploying tracker_mutation Lambda (ENC-ISS-041)"
  log "=========================================="

  log ""
  log "--- Packaging ---"
  local zip_path
  zip_path="$(package_lambda)"
  log "[OK] Package: ${zip_path}"

  log ""
  log "--- Deploying ---"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"

  log ""
  log "=========================================="
  log "[SUCCESS] tracker_mutation Lambda deployed"
  log "=========================================="
}

main "$@"
