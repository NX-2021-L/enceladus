#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
API_ID="${API_ID:-8nkzqkmxqc}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-github-integration}"
ROLE_NAME="${ROLE_NAME:-devops-github-integration-lambda-role}"
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
GITHUB_APP_ID="${GITHUB_APP_ID:-}"
GITHUB_INSTALLATION_ID="${GITHUB_INSTALLATION_ID:-}"
ALLOWED_REPOS="${ALLOWED_REPOS:-NX-2021-L/enceladus}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

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

  log "[START] updating IAM inline policy for ${ROLE_NAME}"
  local policy_file
  policy_file="$(mktemp /tmp/github-integration-policy-XXXXXX.json)"
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
      "Sid": "SecretsManagerGitHubKey",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:devops/github-app/*"
    }
  ]
}
POLICY
  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "devops-github-integration-inline" \
    --policy-document "file://${policy_file}" >/dev/null
  rm -f "${policy_file}"
  log "[END] IAM inline policy updated"
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
  if [[ "${existing}" == "None" ]]; then
    existing=""
  fi
  printf '%s' "${existing}"
}

resolve_github_app_id() {
  if [[ -n "${GITHUB_APP_ID}" ]]; then
    printf '%s' "${GITHUB_APP_ID}"
    return
  fi
  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.GITHUB_APP_ID' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" == "None" ]]; then
    existing=""
  fi
  printf '%s' "${existing}"
}

resolve_github_installation_id() {
  if [[ -n "${GITHUB_INSTALLATION_ID}" ]]; then
    printf '%s' "${GITHUB_INSTALLATION_ID}"
    return
  fi
  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.GITHUB_INSTALLATION_ID' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" == "None" ]]; then
    existing=""
  fi
  printf '%s' "${existing}"
}

package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/github-integration-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  cp "${ROOT_DIR}/lambda_function.py" "${build_dir}/"

  python3 -m pip install \
    --quiet \
    --upgrade \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python-version 3.11 \
    --abi cp311 \
    --only-binary=:all: \
    -r "${ROOT_DIR}/requirements.txt" \
    -t "${build_dir}" >/dev/null

  (
    cd "${build_dir}"
    zip -qr "${zip_path}" .
  )

  rm -rf "${build_dir}"
  echo "${zip_path}"
}

ensure_lambda() {
  local zip_path role_arn effective_key effective_app_id effective_install_id env_file
  zip_path="$(package_lambda)"
  role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[START] updating Lambda code: ${FUNCTION_NAME}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --zip-file "fileb://${zip_path}" >/dev/null
  else
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime python3.11 \
      --handler lambda_function.lambda_handler \
      --role "${role_arn}" \
      --timeout 30 \
      --memory-size 256 \
      --zip-file "fileb://${zip_path}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"

  effective_key="$(resolve_internal_api_key)"
  effective_app_id="$(resolve_github_app_id)"
  effective_install_id="$(resolve_github_installation_id)"

  if [[ -z "${effective_app_id}" ]]; then
    log "[WARNING] GITHUB_APP_ID resolved empty; GitHub API calls will fail."
  fi
  if [[ -z "${effective_install_id}" ]]; then
    log "[WARNING] GITHUB_INSTALLATION_ID resolved empty; GitHub API calls will fail."
  fi

  env_file="$(mktemp /tmp/${FUNCTION_NAME}-env-XXXXXX.json)"
  cat > "${env_file}" <<ENV_JSON
{
  "Variables": {
    "COGNITO_USER_POOL_ID": "us-east-1_b2D0V3E1k",
    "COGNITO_CLIENT_ID": "6q607dk3liirhtecgps7hifmlk",
    "COORDINATION_INTERNAL_API_KEY": "${effective_key}",
    "GITHUB_APP_ID": "${effective_app_id}",
    "GITHUB_INSTALLATION_ID": "${effective_install_id}",
    "GITHUB_PRIVATE_KEY_SECRET": "devops/github-app/private-key",
    "DYNAMODB_REGION": "${REGION}",
    "ALLOWED_REPOS": "${ALLOWED_REPOS}"
  }
}
ENV_JSON

  local cfg_attempt=1 cfg_max=6 cfg_sleep=10
  while :; do
    if aws lambda update-function-configuration \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --role "${role_arn}" \
      --timeout 30 \
      --memory-size 256 \
      --environment "file://${env_file}" >/dev/null; then
      break
    fi
    if [[ "${cfg_attempt}" -ge "${cfg_max}" ]]; then
      echo "[ERROR] update-function-configuration failed after ${cfg_attempt} attempts" >&2
      rm -f "${env_file}"
      return 1
    fi
    log "[WARNING] update-function-configuration conflict; retrying in ${cfg_sleep}s (attempt ${cfg_attempt}/${cfg_max})"
    sleep "${cfg_sleep}"
    aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}" || true
    cfg_attempt=$((cfg_attempt + 1))
  done
  rm -f "${env_file}"

  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  log "[END] Lambda ready: ${FUNCTION_NAME}"
}

ensure_api_route() {
  local target_arn integration_id
  target_arn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"

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
    "POST /api/v1/github/issues"
    "OPTIONS /api/v1/github/{proxy+}"
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
    else
      log "[OK] route exists: ${route_key}"
    fi
  done

  # Lambda invoke permission
  local stmt_id="allow-apigw-${API_ID}-github"
  if aws lambda add-permission \
    --region "${REGION}" \
    --function-name "${FUNCTION_NAME}" \
    --statement-id "${stmt_id}" \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/github/*" >/dev/null 2>&1; then
    log "[OK] lambda invoke permission added: ${stmt_id}"
  else
    log "[OK] lambda invoke permission already present: ${stmt_id}"
  fi

  aws apigatewayv2 create-deployment \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --description "Deploy ${FUNCTION_NAME} $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null || true

  log "[END] API routes and permissions ready"
}

main() {
  ensure_role
  ensure_lambda
  ensure_api_route
  log "[SUCCESS] github-integration deploy complete"
}

main "$@"
