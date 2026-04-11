#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"

# ---------------------------------------------------------------------------
# deploy.sh — Deploy checkout_service Lambda (enceladus-checkout-service)
#
# Creates:
#   - Lambda function: enceladus-checkout-service
#   - Lambda function: enceladus-checkout-service-auto (EventBridge auto-checkout)
#   - DynamoDB table: enceladus-checkout-tokens (if not exists)
#   - API Gateway routes under /api/v1/checkout/**
#   - EventBridge rule: enceladus-checkout-auto (every 5 minutes)
#
# Related: ENC-FTR-037
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="enceladus-checkout-service${ENVIRONMENT_SUFFIX}"
AUTO_FUNCTION_NAME="enceladus-checkout-service-auto${ENVIRONMENT_SUFFIX}"
API_ID="${API_ID:-8nkzqkmxqc}"
TOKENS_TABLE="${TOKENS_TABLE:-enceladus-checkout-tokens${ENVIRONMENT_SUFFIX}}"

COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
CHECKOUT_SERVICE_KEY="${CHECKOUT_SERVICE_KEY:-}"
GITHUB_APP_ID="${GITHUB_APP_ID:-}"
GITHUB_INSTALLATION_ID="${GITHUB_INSTALLATION_ID:-}"
GITHUB_PRIVATE_KEY_SECRET="${GITHUB_PRIVATE_KEY_SECRET:-devops/github-app/enceladus-private-key}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

# ---------------------------------------------------------------------------
# Resolve internal API key from coordination_api Lambda (same pattern as tracker_mutation)
# ---------------------------------------------------------------------------
COORDINATION_API_FUNCTION_NAME="${COORDINATION_API_FUNCTION_NAME:-devops-coordination-api${ENVIRONMENT_SUFFIX}}"

resolve_internal_api_key() {
  if [[ -n "${COORDINATION_INTERNAL_API_KEY}" ]]; then
    printf '%s' "${COORDINATION_INTERNAL_API_KEY}"
    return
  fi
  local coord_env_json
  coord_env_json="$(aws lambda get-function-configuration \
    --function-name "${COORDINATION_API_FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null || echo '{}')"
  [[ "${coord_env_json}" == "None" || -z "${coord_env_json}" ]] && coord_env_json='{}'

  COORD_ENV_JSON="${coord_env_json}" python3 - <<'PY'
import json, os
env = json.loads(os.environ.get("COORD_ENV_JSON", "{}"))
if not isinstance(env, dict): env = {}
for name in ("ENCELADUS_COORDINATION_API_INTERNAL_API_KEY", "COORDINATION_INTERNAL_API_KEY"):
    value = str(env.get(name, "")).strip()
    if value:
        print(value)
        break
PY
}

# ---------------------------------------------------------------------------
# Resolve GitHub App ID and Installation ID from github_integration Lambda
# ---------------------------------------------------------------------------
resolve_github_app_id() {
  if [[ -n "${GITHUB_APP_ID}" ]]; then
    printf '%s' "${GITHUB_APP_ID}"
    return
  fi
  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "devops-github-integration${ENVIRONMENT_SUFFIX}" \
    --region "${REGION}" \
    --query 'Environment.Variables.GITHUB_APP_ID' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" != "None" && -n "${existing}" ]]; then
    printf '%s' "${existing}"
    return
  fi
  log "[WARN] Could not resolve GITHUB_APP_ID"
}

resolve_github_installation_id() {
  if [[ -n "${GITHUB_INSTALLATION_ID}" ]]; then
    printf '%s' "${GITHUB_INSTALLATION_ID}"
    return
  fi
  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "devops-github-integration${ENVIRONMENT_SUFFIX}" \
    --region "${REGION}" \
    --query 'Environment.Variables.GITHUB_INSTALLATION_ID' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" != "None" && -n "${existing}" ]]; then
    printf '%s' "${existing}"
    return
  fi
  log "[WARN] Could not resolve GITHUB_INSTALLATION_ID"
}

# ---------------------------------------------------------------------------
# Resolve or generate checkout service key
# ---------------------------------------------------------------------------
resolve_checkout_key() {
  if [[ -n "${CHECKOUT_SERVICE_KEY}" ]]; then
    printf '%s' "${CHECKOUT_SERVICE_KEY}"
    return
  fi
  # Try reading from existing Lambda env
  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.CHECKOUT_SERVICE_KEY' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" != "None" && -n "${existing}" ]]; then
    printf '%s' "${existing}"
    return
  fi
  # Generate a new key
  python3 -c "import secrets; print('csk-' + secrets.token_hex(32))"
}

# ---------------------------------------------------------------------------
# Ensure DynamoDB token table exists
# ---------------------------------------------------------------------------
ensure_tokens_table() {
  log "[START] Ensuring DynamoDB table: ${TOKENS_TABLE}"
  if aws dynamodb describe-table \
    --table-name "${TOKENS_TABLE}" \
    --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] Table exists: ${TOKENS_TABLE}"
  else
    log "[INFO] Creating table: ${TOKENS_TABLE}"
    aws dynamodb create-table \
      --table-name "${TOKENS_TABLE}" \
      --region "${REGION}" \
      --attribute-definitions AttributeName=pk,AttributeType=S \
      --key-schema AttributeName=pk,KeyType=HASH \
      --billing-mode PAY_PER_REQUEST \
      --sse-specification Enabled=true >/dev/null

    aws dynamodb wait table-exists --table-name "${TOKENS_TABLE}" --region "${REGION}"
    log "[OK] Table created: ${TOKENS_TABLE}"
  fi

  # Ensure TTL is enabled (idempotent — runs for both new and existing tables)
  local ttl_status
  ttl_status="$(aws dynamodb describe-time-to-live \
    --table-name "${TOKENS_TABLE}" \
    --region "${REGION}" \
    --query 'TimeToLiveDescription.TimeToLiveStatus' \
    --output text 2>/dev/null || echo "UNKNOWN")"

  if [[ "${ttl_status}" != "ENABLED" && "${ttl_status}" != "ENABLING" ]]; then
    log "[INFO] Enabling TTL on ${TOKENS_TABLE} (current status: ${ttl_status})"
    if ! aws dynamodb update-time-to-live \
      --table-name "${TOKENS_TABLE}" \
      --region "${REGION}" \
      --time-to-live-specification Enabled=true,AttributeName=ttl >/dev/null; then
      log "[WARN] Unable to enable TTL on ${TOKENS_TABLE}; continuing without TTL."
    else
      log "[OK] TTL enabled on ${TOKENS_TABLE}"
    fi
  else
    log "[OK] TTL already enabled on ${TOKENS_TABLE}"
  fi

  log "[END] Table ready: ${TOKENS_TABLE}"
}

# ---------------------------------------------------------------------------
# Package Lambda (same pattern as tracker_mutation — PyJWT from shared layer)
# ---------------------------------------------------------------------------
package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  # NOTE: PyJWT provided by enceladus-shared Lambda layer — do not bundle here.

  (cd "${build_dir}" && zip -qr "${zip_path}" .)
  rm -rf "${build_dir}"
  echo "${zip_path}"
}

# ---------------------------------------------------------------------------
# Ensure Lambda execution role exists
# ---------------------------------------------------------------------------
ensure_lambda_role() {
  local role_name="enceladus-checkout-service-role${ENVIRONMENT_SUFFIX}"
  local role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${role_name}"

  if aws iam get-role --role-name "${role_name}" >/dev/null 2>&1; then
    echo "${role_arn}"
    return
  fi

  log "[START] Creating IAM role: ${role_name}" >&2
  aws iam create-role \
    --role-name "${role_name}" \
    --assume-role-policy-document '{
      "Version":"2012-10-17",
      "Statement":[{
        "Effect":"Allow",
        "Principal":{"Service":"lambda.amazonaws.com"},
        "Action":"sts:AssumeRole"
      }]
    }' >/dev/null

  aws iam attach-role-policy \
    --role-name "${role_name}" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

  # Inline policy for DynamoDB token table
  aws iam put-role-policy \
    --role-name "${role_name}" \
    --policy-name "checkout-tokens-policy${ENVIRONMENT_SUFFIX}" \
    --policy-document "{
      \"Version\":\"2012-10-17\",
      \"Statement\":[{
        \"Effect\":\"Allow\",
        \"Action\":[
          \"dynamodb:GetItem\",
          \"dynamodb:PutItem\",
          \"dynamodb:DeleteItem\"
        ],
        \"Resource\":\"arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TOKENS_TABLE}\"
      }]
    }"

  # Inline policy for Secrets Manager (GitHub App private key) — ENC-TSK-B26
  aws iam put-role-policy \
    --role-name "${role_name}" \
    --policy-name "checkout-secrets-policy${ENVIRONMENT_SUFFIX}" \
    --policy-document "{
      \"Version\":\"2012-10-17\",
      \"Statement\":[{
        \"Effect\":\"Allow\",
        \"Action\":[\"secretsmanager:GetSecretValue\"],
        \"Resource\":\"arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:devops/github-app/enceladus-private-key-*\"
      }]
    }"

  # Brief wait for role propagation
  sleep 10
  log "[END] IAM role created: ${role_name}" >&2
  echo "${role_arn}"
}

# ---------------------------------------------------------------------------
# Deploy or update Lambda function
# ---------------------------------------------------------------------------
deploy_lambda() {
  local zip_path="$1"
  local fn_name="$2"
  local handler="$3"
  local role_arn="$4"
  local env_json="$5"
  local layer_arn="$6"

  if aws lambda get-function --function-name "${fn_name}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] Updating code: ${fn_name}"
    aws lambda update-function-code \
      --function-name "${fn_name}" \
      --region "${REGION}" \
      --zip-file "fileb://${zip_path}" >/dev/null
    aws lambda wait function-updated-v2 --function-name "${fn_name}" --region "${REGION}"

    aws lambda update-function-configuration \
      --function-name "${fn_name}" \
      --region "${REGION}" \
      --handler "${handler}" \
      --runtime python3.12 \
      --timeout 30 \
      --memory-size 256 \
      --environment "${env_json}" \
      --layers "${layer_arn}" >/dev/null
    aws lambda wait function-updated-v2 --function-name "${fn_name}" --region "${REGION}"
  else
    log "[INFO] Creating function: ${fn_name}"
    aws lambda create-function \
      --function-name "${fn_name}" \
      --region "${REGION}" \
      --runtime python3.12 \
      --architectures arm64 \
      --role "${role_arn}" \
      --handler "${handler}" \
      --zip-file "fileb://${zip_path}" \
      --environment "${env_json}" \
      --layers "${layer_arn}" \
      --timeout 30 \
      --memory-size 256 >/dev/null
    aws lambda wait function-active-v2 --function-name "${fn_name}" --region "${REGION}"
  fi

  log "[END] Lambda deployed: ${fn_name}"
}

# ---------------------------------------------------------------------------
# API Gateway routes for checkout service
# ---------------------------------------------------------------------------
ensure_api_routes() {
  local target_arn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"

  # Find or create API integration
  local integration_id
  integration_id="$(aws apigatewayv2 get-integrations \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --query "Items[?IntegrationUri=='${target_arn}'].IntegrationId | [0]" \
    --output text 2>/dev/null || echo "None")"

  if [[ -z "${integration_id}" || "${integration_id}" == "None" ]]; then
    log "[START] Creating API integration for ${FUNCTION_NAME}"
    integration_id="$(aws apigatewayv2 create-integration \
      --region "${REGION}" \
      --api-id "${API_ID}" \
      --integration-type AWS_PROXY \
      --integration-uri "${target_arn}" \
      --integration-method POST \
      --payload-format-version 2.0 \
      --query 'IntegrationId' \
      --output text)"
    log "[END] Integration created: ${integration_id}"
  else
    log "[OK] Integration exists: ${integration_id}"
  fi

  local routes=(
    # Task routes
    "POST /api/v1/checkout/{project}/task/{taskId}/checkout"
    "DELETE /api/v1/checkout/{project}/task/{taskId}/checkout"
    "POST /api/v1/checkout/{project}/task/{taskId}/advance"
    "POST /api/v1/checkout/{project}/task/{taskId}/log"
    "GET /api/v1/checkout/{project}/task/{taskId}/status"
    "GET /api/v1/checkout/validate/commit-complete/{cciId}"
    "OPTIONS /api/v1/checkout/{project}/task/{taskId}/checkout"
    "OPTIONS /api/v1/checkout/{project}/task/{taskId}/advance"
    "OPTIONS /api/v1/checkout/{project}/task/{taskId}/log"
    "OPTIONS /api/v1/checkout/{project}/task/{taskId}/status"
    "OPTIONS /api/v1/checkout/validate/commit-complete/{cciId}"
    # Plan routes managed by CloudFormation 03-api.yaml (ENC-ISS-169)
  )

  local existing_route_keys
  existing_route_keys="$(aws apigatewayv2 get-routes \
    --region "${REGION}" --api-id "${API_ID}" \
    --query 'Items[].RouteKey' --output text | tr '\t' '\n')"

  for route_key in "${routes[@]}"; do
    if ! printf '%s\n' "${existing_route_keys}" | grep -Fqx "${route_key}"; then
      log "[START] Creating route: ${route_key}"
      aws apigatewayv2 create-route \
        --region "${REGION}" --api-id "${API_ID}" \
        --route-key "${route_key}" \
        --target "integrations/${integration_id}" >/dev/null
      log "[END] Route created: ${route_key}"
    else
      log "[OK] Route exists: ${route_key}"
    fi
  done

  # Lambda invoke permission for API Gateway
  local stmt_id="allow-apigw-${API_ID}-checkout-service"
  if aws lambda add-permission \
    --region "${REGION}" \
    --function-name "${FUNCTION_NAME}" \
    --statement-id "${stmt_id}" \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/checkout/*" \
    >/dev/null 2>&1; then
    log "[OK] Lambda invoke permission added"
  else
    log "[OK] Lambda invoke permission already present"
  fi

  # Deploy API changes
  aws apigatewayv2 create-deployment \
    --region "${REGION}" --api-id "${API_ID}" \
    --description "Deploy checkout_service routes $(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >/dev/null || true

  log "[END] API routes ready"
}

# ---------------------------------------------------------------------------
# EventBridge rule for auto-checkout (every 5 minutes)
# ---------------------------------------------------------------------------
ensure_eventbridge_rule() {
  local rule_name="enceladus-checkout-auto${ENVIRONMENT_SUFFIX}"
  local auto_fn_arn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${AUTO_FUNCTION_NAME}"

  log "[START] Ensuring EventBridge rule: ${rule_name}"

  aws events put-rule \
    --name "${rule_name}" \
    --region "${REGION}" \
    --schedule-expression "rate(5 minutes)" \
    --state ENABLED \
    --description "Auto-checkout Enceladus tasks after 15-minute window (ENC-FTR-037)" \
    >/dev/null

  aws events put-targets \
    --rule "${rule_name}" \
    --region "${REGION}" \
    --targets "[{\"Id\":\"checkout-auto-target\",\"Arn\":\"${auto_fn_arn}\"}]" \
    >/dev/null

  # Permission for EventBridge to invoke the auto Lambda
  local stmt_id="allow-eventbridge-checkout-auto"
  if aws lambda add-permission \
    --region "${REGION}" \
    --function-name "${AUTO_FUNCTION_NAME}" \
    --statement-id "${stmt_id}" \
    --action lambda:InvokeFunction \
    --principal events.amazonaws.com \
    --source-arn "arn:aws:events:${REGION}:${ACCOUNT_ID}:rule/${rule_name}" \
    >/dev/null 2>&1; then
    log "[OK] EventBridge invoke permission added"
  else
    log "[OK] EventBridge invoke permission already present"
  fi

  log "[END] EventBridge rule ready: ${rule_name}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  log "=========================================="
  log "Deploying checkout_service Lambda"
  log "=========================================="

  # Resolve keys
  local effective_key
  effective_key="$(resolve_internal_api_key)"
  local checkout_key
  checkout_key="$(resolve_checkout_key)"

  if [[ -z "${effective_key}" ]]; then
    log "[ERROR] Could not resolve COORDINATION_INTERNAL_API_KEY"
    exit 1
  fi
  if [[ -z "${checkout_key}" ]]; then
    log "[ERROR] Could not resolve CHECKOUT_SERVICE_KEY"
    exit 1
  fi

  # Resolve GitHub App config
  local effective_app_id
  effective_app_id="$(resolve_github_app_id)"
  local effective_install_id
  effective_install_id="$(resolve_github_installation_id)"
  if [[ -z "${effective_app_id}" || -z "${effective_install_id}" ]]; then
    log "[WARN] GitHub App not fully configured — commit/PR validation will be unauthenticated"
  fi

  # Shared layer ARN (PyJWT + cryptography)
  local layer_arn
  layer_arn="$(aws lambda list-layer-versions \
    --layer-name "enceladus-shared${ENVIRONMENT_SUFFIX}" \
    --region "${REGION}" \
    --query 'LayerVersions[0].LayerVersionArn' \
    --output text 2>/dev/null || echo "None")"
  if [[ "${layer_arn}" == "None" || -z "${layer_arn}" ]]; then
    log "[WARN] enceladus-shared layer not found — deploying without shared layer"
    layer_arn=""
  fi

  # Ensure infrastructure
  ensure_tokens_table

  local role_arn
  role_arn="$(ensure_lambda_role)"

  # Build env JSON for HTTP handler
  local env_json
  env_json="$(python3 - <<PY
import json
print(json.dumps({"Variables": {
    "COGNITO_USER_POOL_ID": "${COGNITO_USER_POOL_ID}",
    "COGNITO_CLIENT_ID": "${COGNITO_CLIENT_ID}",
    "COORDINATION_INTERNAL_API_KEY": "${effective_key}",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY": "${effective_key}",
    "CHECKOUT_SERVICE_KEY": "${checkout_key}",
    "GITHUB_APP_ID": "${effective_app_id}",
    "GITHUB_INSTALLATION_ID": "${effective_install_id}",
    "GITHUB_PRIVATE_KEY_SECRET": "${GITHUB_PRIVATE_KEY_SECRET}",
    "CHECKOUT_TOKENS_TABLE": "${TOKENS_TABLE}",
    "CHECKOUT_TOKENS_REGION": "${REGION}",
    "TRACKER_API_BASE": "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker",
    "CORS_ORIGIN": "https://jreese.net",
}}, separators=(',', ':')))
PY
)"

  log ""
  log "--- Packaging ---"
  local zip_path
  zip_path="$(package_lambda)"
  log "[OK] Package: ${zip_path}"

  log ""
  log "--- Deploying HTTP handler ---"
  deploy_lambda "${zip_path}" "${FUNCTION_NAME}" \
    "lambda_function.lambda_handler" "${role_arn}" "${env_json}" "${layer_arn}"

  log ""
  log "--- Deploying auto-checkout handler ---"
  deploy_lambda "${zip_path}" "${AUTO_FUNCTION_NAME}" \
    "lambda_function.handler_auto_checkout" "${role_arn}" "${env_json}" "${layer_arn}"

  rm -f "${zip_path}"

  if [[ -z "${ENVIRONMENT_SUFFIX}" ]]; then
    log ""
    log "--- Configuring API routes ---"
    ensure_api_routes

    log ""
    log "--- Configuring EventBridge rule ---"
    ensure_eventbridge_rule
  else
    log ""
    log "[INFO] Skipping API route and EventBridge configuration for gamma (ENVIRONMENT_SUFFIX=${ENVIRONMENT_SUFFIX})"
  fi

  log ""
  log "=========================================="
  log "[SUCCESS] checkout_service deployed"
  log "  HTTP handler:   ${FUNCTION_NAME}"
  log "  Auto handler:   ${AUTO_FUNCTION_NAME}"
  log "  Tokens table:   ${TOKENS_TABLE}"
  log "  Checkout key:   (stored in Lambda env)"
  log "=========================================="
}

main "$@"
