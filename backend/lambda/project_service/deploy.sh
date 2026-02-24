#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy project_service Lambda (devops-project-service-api)
#
# Updates the Lambda code only. Infrastructure (IAM role, API Gateway
# routes GET/POST /api/v1/projects, CloudFront behavior) already exists.
#
# The Lambda handles project lifecycle management and validates JWT tokens
# from Cognito.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
FUNCTION_NAME="devops-project-service-api"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  # Install dependencies (PyJWT with crypto support for Cognito JWT validation)
  python3 -m pip install \
    --quiet \
    --upgrade \
    PyJWT>=2.8.0 \
    cryptography>=41.0.0 \
    -t "${build_dir}" >/dev/null

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
  log "Deploying project_service Lambda (DVP-TSK-426+)"
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
  log "[SUCCESS] project_service Lambda deployed"
  log "=========================================="
}

main "$@"
