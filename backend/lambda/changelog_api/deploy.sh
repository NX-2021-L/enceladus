#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy devops-changelog-api Lambda (ENC-FTR-033 Phase 1)
#
# Creates/updates:
#   - IAM role for the Lambda function
#   - Lambda function (devops-changelog-api)
#   - API Gateway integration + 4 routes on existing HTTP API
#   - Lambda invoke permission for API Gateway
#   - CloudFront behavior for /api/v1/changelog/*
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
API_ID="${API_ID:-8nkzqkmxqc}"
CF_DIST_ID="${CF_DIST_ID:-E2BOQXCW1TA6Y4}"

FUNCTION_NAME="devops-changelog-api"
ROLE_NAME="devops-changelog-api-lambda-role"

DEPLOY_TABLE="${DEPLOY_TABLE:-devops-deployment-manager}"
CONFIG_BUCKET="${CONFIG_BUCKET:-jreese-net}"
CONFIG_PREFIX="${CONFIG_PREFIX:-deploy-config}"
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"
COORDINATION_API_FUNCTION_NAME="${COORDINATION_API_FUNCTION_NAME:-devops-coordination-api}"
CORS_ORIGIN="${CORS_ORIGIN:-https://jreese.net}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

# ---------------------------------------------------------------------------
# IAM Role
# ---------------------------------------------------------------------------

ensure_role() {
  if ! aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
    log "[START] creating IAM role ${ROLE_NAME}"
    aws iam create-role \
      --role-name "${ROLE_NAME}" \
      --assume-role-policy-document '{
        "Version":"2012-10-17",
        "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
      }' >/dev/null
    log "[END] created IAM role ${ROLE_NAME}"
    sleep 5
  else
    log "[OK] IAM role exists: ${ROLE_NAME}"
  fi

  local policy_file
  policy_file="$(mktemp /tmp/changelog-api-policy-XXXXXX.json)"
  cat > "${policy_file}" <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:/aws/lambda/${FUNCTION_NAME}*"
    },
    {
      "Sid": "DeployTableRead",
      "Effect": "Allow",
      "Action": ["dynamodb:Query"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DEPLOY_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DEPLOY_TABLE}/index/*"
      ]
    },
    {
      "Sid": "S3VersionRead",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::${CONFIG_BUCKET}/${CONFIG_PREFIX}/*"
    }
  ]
}
POLICY

  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "${FUNCTION_NAME}-policy" \
    --policy-document "file://${policy_file}" >/dev/null

  rm -f "${policy_file}"
  log "[OK] IAM inline policy updated for ${ROLE_NAME}"
}

# ---------------------------------------------------------------------------
# Resolve internal API key
# ---------------------------------------------------------------------------

resolve_internal_api_key() {
  local key
  key="$(aws lambda get-function-configuration \
    --function-name "${COORDINATION_API_FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY' \
    --output text 2>/dev/null || true)"
  if [[ "${key}" == "None" || -z "${key}" ]]; then
    key=""
  fi
  printf '%s' "${key}"
}

# ---------------------------------------------------------------------------
# Lambda Packaging + Deployment
# ---------------------------------------------------------------------------

deploy_lambda() {
  local build_dir zip_path role_arn
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"
  role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  python3 -m pip install \
    --quiet \
    --upgrade \
    "PyJWT[crypto]>=2.8.0" \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python-version 3.11 \
    --only-binary=:all: \
    -t "${build_dir}" >/dev/null

  (
    cd "${build_dir}"
    zip -qr "${zip_path}" .
  )
  rm -rf "${build_dir}"

  local internal_key
  internal_key="$(resolve_internal_api_key)"

  local env_vars
  env_vars="{DEPLOY_TABLE=${DEPLOY_TABLE},DYNAMODB_REGION=${REGION},CONFIG_BUCKET=${CONFIG_BUCKET},CONFIG_PREFIX=${CONFIG_PREFIX},COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID},COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID},COORDINATION_INTERNAL_API_KEY=${internal_key},CORS_ORIGIN=${CORS_ORIGIN}}"

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[START] updating Lambda code: ${FUNCTION_NAME}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --zip-file "fileb://${zip_path}" >/dev/null
    aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"

    aws lambda update-function-configuration \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --role "${role_arn}" \
      --handler "lambda_function.lambda_handler" \
      --runtime python3.11 \
      --timeout 30 \
      --memory-size 256 \
      --environment "Variables=${env_vars}" >/dev/null
  else
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime python3.11 \
      --handler "lambda_function.lambda_handler" \
      --role "${role_arn}" \
      --timeout 30 \
      --memory-size 256 \
      --zip-file "fileb://${zip_path}" \
      --environment "Variables=${env_vars}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  log "[END] Lambda ready: ${FUNCTION_NAME}"
  rm -f "${zip_path}"
}

# ---------------------------------------------------------------------------
# API Gateway Routes
# ---------------------------------------------------------------------------

ensure_api_routes() {
  local target_arn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"

  # Find or create integration
  local integration_id
  integration_id="$(aws apigatewayv2 get-integrations \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --max-results 100 \
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
    "GET /api/v1/changelog/history/{projectId}"
    "GET /api/v1/changelog/history"
    "GET /api/v1/changelog/version/{projectId}"
    "GET /api/v1/changelog/versions"
  )

  for route_key in "${routes[@]}"; do
    local existing
    existing="$(aws apigatewayv2 get-routes \
      --region "${REGION}" \
      --api-id "${API_ID}" \
      --max-results 100 \
      --query "Items[?RouteKey=='${route_key}'].RouteId | [0]" \
      --output text)"

    if [[ -z "${existing}" || "${existing}" == "None" ]]; then
      log "[START] creating route: ${route_key}"
      aws apigatewayv2 create-route \
        --region "${REGION}" \
        --api-id "${API_ID}" \
        --route-key "${route_key}" \
        --target "integrations/${integration_id}" >/dev/null
      log "[END] route created: ${route_key}"
    else
      log "[OK] route exists: ${route_key}"
    fi
  done

  # Lambda invoke permission
  local stmt_id="allow-apigw-${API_ID}-${FUNCTION_NAME}"
  if aws lambda add-permission \
    --region "${REGION}" \
    --function-name "${FUNCTION_NAME}" \
    --statement-id "${stmt_id}" \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/changelog/*" >/dev/null 2>&1; then
    log "[OK] Lambda invoke permission added"
  else
    log "[OK] Lambda invoke permission already present"
  fi

  # Deploy the API
  aws apigatewayv2 create-deployment \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --description "Deploy ${FUNCTION_NAME} $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null || true

  log "[END] API routes ready"
}

# ---------------------------------------------------------------------------
# CloudFront behavior for /api/v1/changelog/*
# ---------------------------------------------------------------------------

ensure_cloudfront_behavior() {
  log "[START] checking CloudFront behavior for /api/v1/changelog/*"

  local etag config_file updated_file cf_err_file
  config_file="$(mktemp /tmp/cf-config-XXXXXX.json)"
  updated_file="$(mktemp /tmp/cf-config-updated-XXXXXX.json)"
  cf_err_file="$(mktemp /tmp/cf-err-XXXXXX.log)"

  if ! aws cloudfront get-distribution-config \
    --id "${CF_DIST_ID}" > "${config_file}" 2>"${cf_err_file}"; then
    if grep -qi "AccessDenied" "${cf_err_file}"; then
      log "[WARNING] skipping CloudFront behavior update: missing cloudfront:GetDistributionConfig permission for ${CF_DIST_ID}"
      rm -f "${config_file}" "${updated_file}" "${cf_err_file}"
      return
    fi
    log "[ERROR] failed reading CloudFront distribution config"
    cat "${cf_err_file}" >&2
    rm -f "${config_file}" "${updated_file}" "${cf_err_file}"
    return 1
  fi
  rm -f "${cf_err_file}"

  etag="$(python3 -c "import json; d=json.load(open('${config_file}')); print(d['ETag'])")"

  local has_behavior
  has_behavior="$(python3 -c "
import json
d = json.load(open('${config_file}'))
items = d['DistributionConfig'].get('CacheBehaviors', {}).get('Items', [])
found = any(b['PathPattern'] == '/api/v1/changelog/*' for b in items)
print('true' if found else 'false')
")"

  if [[ "${has_behavior}" == "true" ]]; then
    log "[OK] CloudFront behavior exists: /api/v1/changelog/*"
    rm -f "${config_file}" "${updated_file}"
    return
  fi

  log "[START] adding CloudFront behavior: /api/v1/changelog/*"

  python3 - "${config_file}" "${updated_file}" <<'PYEOF'
import json, sys, copy

config_file = sys.argv[1]
updated_file = sys.argv[2]

d = json.load(open(config_file))
dc = d["DistributionConfig"]
behaviors = dc.get("CacheBehaviors", {"Quantity": 0, "Items": []})
items = behaviors.get("Items", [])

# Find an existing /api/* behavior to use as template
template = None
for b in items:
    if b["PathPattern"].startswith("/api/v1/"):
        template = b
        break

if not template:
    print("[ERROR] No existing /api/* behavior found to use as template")
    sys.exit(1)

# Clone the template and set CachingDisabled path
new_behavior = copy.deepcopy(template)
new_behavior["PathPattern"] = "/api/v1/changelog/*"

items.append(new_behavior)
behaviors["Items"] = items
behaviors["Quantity"] = len(items)
dc["CacheBehaviors"] = behaviors

with open(updated_file, "w") as f:
    json.dump(dc, f, indent=2)

print("[OK] Updated config written")
PYEOF

  cf_err_file="$(mktemp /tmp/cf-err-XXXXXX.log)"
  if ! aws cloudfront update-distribution \
    --id "${CF_DIST_ID}" \
    --if-match "${etag}" \
    --distribution-config "file://${updated_file}" >/dev/null 2>"${cf_err_file}"; then
    if grep -qi "AccessDenied" "${cf_err_file}"; then
      log "[WARNING] skipping CloudFront behavior update: missing cloudfront:UpdateDistribution permission for ${CF_DIST_ID}"
      rm -f "${config_file}" "${updated_file}" "${cf_err_file}"
      return
    fi
    log "[ERROR] failed updating CloudFront distribution config"
    cat "${cf_err_file}" >&2
    rm -f "${config_file}" "${updated_file}" "${cf_err_file}"
    return 1
  fi

  rm -f "${config_file}" "${updated_file}" "${cf_err_file}"
  log "[END] CloudFront behavior added: /api/v1/changelog/*"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  log "=========================================="
  log "Deploying Changelog API (ENC-FTR-033)"
  log "=========================================="

  log ""
  log "--- IAM Role ---"
  ensure_role

  log ""
  log "--- Lambda ---"
  deploy_lambda

  log ""
  log "--- API Gateway ---"
  ensure_api_routes

  log ""
  log "--- CloudFront ---"
  ensure_cloudfront_behavior

  log ""
  log "=========================================="
  log "[SUCCESS] Changelog API deployed"
  log "  Function: ${FUNCTION_NAME}"
  log "  Routes:   GET /api/v1/changelog/history/{projectId}"
  log "            GET /api/v1/changelog/history"
  log "            GET /api/v1/changelog/version/{projectId}"
  log "            GET /api/v1/changelog/versions"
  log "  CF:       /api/v1/changelog/*"
  log "=========================================="
}

main "$@"
