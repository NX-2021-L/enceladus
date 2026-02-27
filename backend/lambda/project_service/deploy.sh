#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy project_service Lambda (devops-project-service)
#
# Updates the Lambda code only. Infrastructure (IAM role, API Gateway
# routes GET/POST /api/v1/projects, CloudFront behavior) already exists.
#
# The Lambda handles project lifecycle management and validates JWT tokens
# from Cognito.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-project-service}"
COORDINATION_API_FUNCTION_NAME="${COORDINATION_API_FUNCTION_NAME:-devops-coordination-api}"
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
COORDINATION_INTERNAL_API_KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES:-}"

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
  local effective_internal_key
  local env_file

  effective_internal_key="${COORDINATION_INTERNAL_API_KEY}"
  if [[ -z "${effective_internal_key}" ]]; then
    effective_internal_key="$(aws lambda get-function-configuration \
      --function-name "${COORDINATION_API_FUNCTION_NAME}" \
      --region "${REGION}" \
      --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY' \
      --output text 2>/dev/null || true)"
    [[ "${effective_internal_key}" == "None" ]] && effective_internal_key=""
  fi
  if [[ -z "${effective_internal_key}" ]]; then
    effective_internal_key="$(aws lambda get-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY' \
      --output text 2>/dev/null || true)"
    [[ "${effective_internal_key}" == "None" ]] && effective_internal_key=""
  fi
  if [[ -z "${effective_internal_key}" ]]; then
    log "[WARNING] COORDINATION_INTERNAL_API_KEY unresolved; service-to-service auth may remain disabled."
  fi

  log "[START] updating Lambda code: ${FUNCTION_NAME}"
  aws lambda update-function-code \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --zip-file "fileb://${zip_path}" >/dev/null

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  env_file="$(mktemp /tmp/${FUNCTION_NAME}-env-XXXXXX.json)"
  EXISTING_ENV_JSON="$(aws lambda get-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --query 'Environment.Variables' \
      --output json 2>/dev/null || echo '{}')" \
  EFFECTIVE_INTERNAL_KEY="${effective_internal_key}" \
  INTERNAL_KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES}" \
  python3 - <<'PY' > "${env_file}"
import json
import os

existing = json.loads(os.environ.get("EXISTING_ENV_JSON", "{}"))
if not isinstance(existing, dict):
    existing = {}
key = os.environ.get("EFFECTIVE_INTERNAL_KEY", "")
scopes = os.environ.get("INTERNAL_KEY_SCOPES", "")
if key:
    existing["COORDINATION_INTERNAL_API_KEY"] = key
if scopes:
    existing["COORDINATION_INTERNAL_API_KEY_SCOPES"] = scopes
print(json.dumps({"Variables": existing}, separators=(",", ":")))
PY

  log "[START] updating Lambda configuration: ${FUNCTION_NAME}"
  aws lambda update-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --environment "file://${env_file}" >/dev/null

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"
  rm -f "${env_file}"

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
