#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy reference_search Lambda + API Gateway route (DVP-TSK-292)
#
# Creates/updates:
#   - IAM role for Lambda (S3 read + CloudWatch logs)
#   - Lambda function (devops-reference-search)
#   - API Gateway route (GET /api/v1/reference/search)
#   - CloudFront behavior for /api/v1/reference*
#   - Lambda invoke permission for API Gateway
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
API_ID="${API_ID:-8nkzqkmxqc}"
CF_DIST_ID="${CF_DIST_ID:-E2BOQXCW1TA6Y4}"

FUNCTION_NAME="devops-reference-search"
ROLE_NAME="devops-reference-search-lambda-role"
S3_BUCKET="jreese-net"
S3_REFERENCE_PREFIX="mobile/v1/reference"

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
  policy_file="$(mktemp /tmp/refsearch-policy-XXXXXX.json)"
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
      "Sid": "S3ReferenceRead",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::${S3_BUCKET}/${S3_REFERENCE_PREFIX}/*"
    }
  ]
}
POLICY
  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "devops-reference-search-inline" \
    --policy-document "file://${policy_file}" >/dev/null
  rm -f "${policy_file}"
  log "[OK] IAM inline policy updated for ${ROLE_NAME}"
}

# ---------------------------------------------------------------------------
# Lambda Packaging + Deployment
# ---------------------------------------------------------------------------

package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  # Install PyJWT with crypto support
  python3 -m pip install \
    --quiet \
    --upgrade \
    "PyJWT[crypto]>=2.8.0" \
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
  local role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

  local env_vars="{S3_BUCKET=${S3_BUCKET},S3_REFERENCE_PREFIX=${S3_REFERENCE_PREFIX},COGNITO_USER_POOL_ID=us-east-1_b2D0V3E1k,COGNITO_CLIENT_ID=6q607dk3liirhtecgps7hifmlk}"

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
      --timeout 10 \
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
      --timeout 10 \
      --memory-size 256 \
      --zip-file "fileb://${zip_path}" \
      --environment "Variables=${env_vars}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  log "[END] Lambda ready: ${FUNCTION_NAME}"
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

  # Routes
  local routes=(
    "GET /api/v1/reference/search"
    "OPTIONS /api/v1/reference/search"
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
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/reference/*" >/dev/null 2>&1; then
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
# CloudFront behavior for /api/v1/reference*
# ---------------------------------------------------------------------------

ensure_cloudfront_behavior() {
  log "[START] checking CloudFront behavior for /api/v1/reference*"

  local etag config_file updated_file
  config_file="$(mktemp /tmp/cf-config-XXXXXX.json)"
  updated_file="$(mktemp /tmp/cf-config-updated-XXXXXX.json)"

  aws cloudfront get-distribution-config \
    --id "${CF_DIST_ID}" > "${config_file}"

  etag="$(python3 -c "import json; d=json.load(open('${config_file}')); print(d['ETag'])")"

  local has_behavior
  has_behavior="$(python3 -c "
import json
d = json.load(open('${config_file}'))
items = d['DistributionConfig'].get('CacheBehaviors', {}).get('Items', [])
found = any(b['PathPattern'] == '/api/v1/reference*' for b in items)
print('true' if found else 'false')
")"

  if [[ "${has_behavior}" == "true" ]]; then
    log "[OK] CloudFront behavior exists: /api/v1/reference*"
    rm -f "${config_file}" "${updated_file}"
    return
  fi

  log "[START] adding CloudFront behavior: /api/v1/reference*"

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

new_behavior = copy.deepcopy(template)
new_behavior["PathPattern"] = "/api/v1/reference*"

items.append(new_behavior)
behaviors["Quantity"] = len(items)
behaviors["Items"] = items
dc["CacheBehaviors"] = behaviors

json.dump(dc, open(updated_file, "w"), indent=2)
print("[OK] Behavior added to config")
PYEOF

  aws cloudfront update-distribution \
    --id "${CF_DIST_ID}" \
    --if-match "${etag}" \
    --distribution-config "file://${updated_file}" >/dev/null

  rm -f "${config_file}" "${updated_file}"
  log "[END] CloudFront behavior added: /api/v1/reference*"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  log "=========================================="
  log "Deploying Reference Search Lambda (DVP-TSK-292)"
  log "=========================================="

  log ""
  log "--- Phase 1: IAM Role ---"
  ensure_role

  log ""
  log "--- Phase 2: Lambda Function ---"
  local zip_path
  zip_path="$(package_lambda)"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"

  log ""
  log "--- Phase 3: API Gateway Routes ---"
  ensure_api_routes

  log ""
  log "--- Phase 4: CloudFront Behavior ---"
  ensure_cloudfront_behavior

  log ""
  log "=========================================="
  log "[SUCCESS] Reference Search Lambda fully deployed"
  log "=========================================="
  log ""
  log "Test: curl -H 'Cookie: enceladus_id_token=...' 'https://jreese.net/api/v1/reference/search?project=devops&query=deployment'"
}

main "$@"
