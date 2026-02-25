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

# ─────────────────────────────────────────────────────────────────────────────
# CRITICAL: Cognito environment variables (see DOC-246A21EF24FB)
# These MUST be set on the Lambda. If deployment overwrites env vars,
# the Lambda returns "COGNITO_USER_POOL_ID not set" and ALL mutations fail.
# ─────────────────────────────────────────────────────────────────────────────
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"

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

# ─────────────────────────────────────────────────────────────────────────────
# ensure_env_vars — Verify/set Cognito env vars on the Lambda after deploy.
# Without these, JWT validation fails and ALL authenticated requests return 401.
# See: DOC-246A21EF24FB (JWT Authentication Forensics)
# ─────────────────────────────────────────────────────────────────────────────
ensure_env_vars() {
  log "[START] Verifying Lambda environment variables"

  local current_env
  current_env=$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null || echo '{}')

  local current_pool_id
  current_pool_id=$(echo "${current_env}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('COGNITO_USER_POOL_ID',''))" 2>/dev/null || echo "")

  if [[ "${current_pool_id}" != "${COGNITO_USER_POOL_ID}" ]]; then
    log "[WARN] COGNITO_USER_POOL_ID missing or wrong — setting env vars"
    local merged_env
    merged_env=$(echo "${current_env}" | python3 -c "
import sys, json
d = json.load(sys.stdin) if sys.stdin.readable() else {}
d['COGNITO_USER_POOL_ID'] = '${COGNITO_USER_POOL_ID}'
d['COGNITO_CLIENT_ID'] = '${COGNITO_CLIENT_ID}'
print(json.dumps({'Variables': d}))
" 2>/dev/null)

    aws lambda update-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --environment "${merged_env}" >/dev/null

    aws lambda wait function-updated-v2 \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}"

    log "[SUCCESS] Environment variables updated"
  else
    log "[OK] Cognito env vars already correct"
  fi
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
  log "--- Verifying Env Vars ---"
  ensure_env_vars

  log ""
  log "=========================================="
  log "[SUCCESS] tracker_mutation Lambda deployed"
  log "=========================================="
}

main "$@"
