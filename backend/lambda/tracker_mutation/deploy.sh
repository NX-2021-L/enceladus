#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy tracker_mutation Lambda (devops-tracker-mutation-api)
#
# Manages: Lambda code, environment variables, API Gateway routes.
# Full CRUD API for the Enceladus project tracker.
#
# Related: ENC-TSK-564 (Phase 2a)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="devops-tracker-mutation-api"
API_ID="${API_ID:-8nkzqkmxqc}"

# Cognito config
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"

# Internal API key (resolved from env or existing Lambda config)
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

resolve_internal_api_key() {
  if [[ -n "${COORDINATION_INTERNAL_API_KEY}" ]]; then
    printf '%s' "${COORDINATION_INTERNAL_API_KEY}"
    return
  fi
  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" == "None" || -z "${existing}" ]]; then
    existing=""
  fi
  printf '%s' "${existing}"
}

package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  # NOTE: PyJWT is provided by the enceladus-shared Lambda layer (shared_layer/deploy.sh).
  # Do NOT bundle dependencies here - cross-platform binary compatibility issues.

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

ensure_env_vars() {
  log "[START] Setting Lambda environment variables"

  local effective_key
  effective_key="$(resolve_internal_api_key)"

  local env_json
  env_json=$(python3 -c "
import json
env = {
    'COGNITO_USER_POOL_ID': '${COGNITO_USER_POOL_ID}',
    'COGNITO_CLIENT_ID': '${COGNITO_CLIENT_ID}',
    'DYNAMODB_TABLE': 'devops-project-tracker',
    'DYNAMODB_REGION': '${REGION}',
    'PROJECTS_TABLE': 'projects',
    'COORDINATION_INTERNAL_API_KEY': '${effective_key}',
    'CORS_ORIGIN': 'https://jreese.net',
}
print(json.dumps({'Variables': env}))
")

  aws lambda update-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --environment "${env_json}" >/dev/null

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  if [[ -n "${effective_key}" ]]; then
    log "[OK] COORDINATION_INTERNAL_API_KEY set"
  else
    log "[WARN] COORDINATION_INTERNAL_API_KEY empty — internal-key auth disabled"
  fi
  log "[END] Environment variables configured"
}

ensure_api_routes() {
  local target_arn integration_id
  target_arn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"

  # Find existing integration
  integration_id="$(aws apigatewayv2 get-integrations \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --no-paginate \
    --query "Items[?IntegrationUri=='${target_arn}'].IntegrationId | [0]" \
    --output text)"

  if [[ -z "${integration_id}" || "${integration_id}" == "None" ]]; then
    log "[START] creating API integration for ${FUNCTION_NAME}"
    integration_id="$(aws apigatewayv2 create-integration \
      --region "${REGION}" \
      --api-id "${API_ID}" \
      --integration-type AWS_PROXY \
      --integration-uri "${target_arn}" \
      --integration-method POST \
      --payload-format-version 2.0 \
      --query 'IntegrationId' \
      --output text)"
    log "[END] API integration created: ${integration_id}"
  else
    log "[OK] API integration exists: ${integration_id}"
  fi

  local routes=(
    # Existing PWA routes
    "PATCH /api/v1/tracker/{projectId}/{recordType}/{recordId}"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}"
    # New CRUD routes (Phase 2a)
    "GET /api/v1/tracker/pending-updates"
    "GET /api/v1/tracker/{projectId}"
    "GET /api/v1/tracker/{projectId}/{recordType}/{recordId}"
    "POST /api/v1/tracker/{projectId}/{recordType}"
    "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/log"
    "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout"
    "DELETE /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout"
    "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/acceptance-evidence"
    # OPTIONS for new routes
    "OPTIONS /api/v1/tracker/pending-updates"
    "OPTIONS /api/v1/tracker/{projectId}"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/log"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/acceptance-evidence"
  )

  local existing_route_keys
  existing_route_keys="$(aws apigatewayv2 get-routes \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --query 'Items[].RouteKey' \
    --output text | tr '\t' '\n')"

  for route_key in "${routes[@]}"; do
    if ! printf '%s\n' "${existing_route_keys}" | grep -Fqx "${route_key}"; then
      log "[START] creating route: ${route_key}"
      aws apigatewayv2 create-route \
        --region "${REGION}" \
        --api-id "${API_ID}" \
        --route-key "${route_key}" \
        --target "integrations/${integration_id}" >/dev/null
      log "[END] route created: ${route_key}"
      existing_route_keys="${existing_route_keys}"$'\n'"${route_key}"
    else
      log "[OK] route exists: ${route_key}"
    fi
  done

  # Ensure Lambda invoke permission for API Gateway
  local stmt_id
  stmt_id="allow-apigw-${API_ID}-tracker-crud"
  if aws lambda add-permission \
    --region "${REGION}" \
    --function-name "${FUNCTION_NAME}" \
    --statement-id "${stmt_id}" \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/tracker/*" >/dev/null 2>&1; then
    log "[OK] lambda invoke permission added"
  else
    log "[OK] lambda invoke permission already present"
  fi

  # Deploy API changes
  aws apigatewayv2 create-deployment \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --description "Deploy tracker CRUD routes $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null || true

  log "[END] API routes ready"
}

main() {
  log "=========================================="
  log "Deploying tracker_mutation Lambda"
  log "=========================================="

  log ""
  log "--- Packaging ---"
  local zip_path
  zip_path="$(package_lambda)"
  log "[OK] Package: ${zip_path}"

  log ""
  log "--- Deploying Code ---"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"

  log ""
  log "--- Configuring Env Vars ---"
  ensure_env_vars

  log ""
  log "--- Configuring API Routes ---"
  ensure_api_routes

  log ""
  log "=========================================="
  log "[SUCCESS] tracker_mutation Lambda deployed"
  log "=========================================="
}

main "$@"
