#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"

# ENC-ISS-224 / ENC-FTR-072: architecture bifurcation for gamma (arm64/py3.12) vs prod (x86_64/py3.11)
if [ -n "${ENVIRONMENT_SUFFIX:-}" ]; then
  pip_platform="manylinux2014_aarch64"; pip_pyver="3.12"; pip_abi="cp312"; DEPLOY_RUNTIME="python3.12"
else
  pip_platform="manylinux2014_x86_64"; pip_pyver="3.11"; pip_abi="cp311"; DEPLOY_RUNTIME="python3.11"
fi
REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
source "${REPO_ROOT}/tools/lambda_artifact_helper.sh"

# ---------------------------------------------------------------------------
# deploy.sh — Deploy deploy_intake Lambda (ENC-TSK-506)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-deploy-intake${ENVIRONMENT_SUFFIX}}"
ROLE_NAME="${ROLE_NAME:-devops-deploy-intake-lambda-role${ENVIRONMENT_SUFFIX}}"
ROLE_POLICY_NAME="${ROLE_POLICY_NAME:-devops-deploy-intake-inline${ENVIRONMENT_SUFFIX}}"

DEPLOY_TABLE="${DEPLOY_TABLE:-devops-deployment-manager${ENVIRONMENT_SUFFIX}}"
PROJECTS_TABLE="${PROJECTS_TABLE:-projects${ENVIRONMENT_SUFFIX}}"
CONFIG_BUCKET="${CONFIG_BUCKET:-jreese-net}"
CONFIG_PREFIX="${CONFIG_PREFIX:-deploy-config}"
SQS_QUEUE_URL="${SQS_QUEUE_URL:-https://sqs.us-west-2.amazonaws.com/356364570033/devops-deploy-queue${ENVIRONMENT_SUFFIX}.fifo}"
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
COORDINATION_INTERNAL_API_KEY_PREVIOUS="${COORDINATION_INTERNAL_API_KEY_PREVIOUS:-}"
COORDINATION_INTERNAL_API_KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES:-}"
COORDINATION_API_FUNCTION_NAME="${COORDINATION_API_FUNCTION_NAME:-devops-coordination-api${ENVIRONMENT_SUFFIX}}"
DOC_PREP_LAMBDA_NAME="${DOC_PREP_LAMBDA_NAME:-devops-doc-prep${ENVIRONMENT_SUFFIX}}"
CORS_ORIGIN="${CORS_ORIGIN:-https://jreese.net}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

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

  local policy_file
  policy_file="$(mktemp /tmp/deploy-intake-policy-XXXXXX.json)"
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
      "Sid": "DeployTableAccess",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DEPLOY_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DEPLOY_TABLE}/index/*"
      ]
    },
    {
      "Sid": "ProjectsTableRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${PROJECTS_TABLE}"
    },
    {
      "Sid": "S3ConfigAccess",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::${CONFIG_BUCKET}/${CONFIG_PREFIX}/*"
    },
    {
      "Sid": "SQSSendMessage",
      "Effect": "Allow",
      "Action": ["sqs:SendMessage", "sqs:GetQueueUrl"],
      "Resource": "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:devops-deploy-queue${ENVIRONMENT_SUFFIX}.fifo"
    },
    {
      "Sid": "InvokeDocPrepLambda",
      "Effect": "Allow",
      "Action": ["lambda:InvokeFunction"],
      "Resource": [
        "arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${DOC_PREP_LAMBDA_NAME}",
        "arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${DOC_PREP_LAMBDA_NAME}:*"
      ]
    }
  ]
}
POLICY

  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "${ROLE_POLICY_NAME}" \
    --policy-document "file://${policy_file}" >/dev/null
  rm -f "${policy_file}"
  log "[OK] IAM inline policy updated for ${ROLE_NAME}"
}

package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"
  # ENC-TSK-E27: try S3 artifact first
  local resolved_zip
  if resolved_zip="$(resolve_artifact "${FUNCTION_NAME}" "${zip_path}")"; then
    echo "${resolved_zip}"
    return 0
  fi


  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
    python3 -m pip install \
      --quiet \
      --upgrade \
      -r "${SCRIPT_DIR}/requirements.txt" \
      --platform "${pip_platform}" \
      --implementation cp \
      --python-version "${pip_pyver}" \
      --only-binary=:all: \
      -t "${build_dir}" >/dev/null
  fi

  (
    cd "${build_dir}"
    zip -qr "${zip_path}" .
  )
  rm -rf "${build_dir}"
  echo "${zip_path}"
}

resolve_internal_api_key() {
  if [[ -n "${COORDINATION_INTERNAL_API_KEY}" ]]; then
    printf '%s' "${COORDINATION_INTERNAL_API_KEY}"
    return
  fi

  local coordination_key
  coordination_key="$(aws lambda get-function-configuration \
    --function-name "${COORDINATION_API_FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY' \
    --output text 2>/dev/null || true)"
  if [[ "${coordination_key}" == "None" ]]; then
    coordination_key=""
  fi
  if [[ -n "${coordination_key}" ]]; then
    printf '%s' "${coordination_key}"
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

resolve_github_token() {
  # Resolve GITHUB_TOKEN for PR merge validation against private repos.
  # Fallback: read from enceladus-checkout-service Lambda (same token, Secrets Manager sourced).
  if [[ -n "${GITHUB_TOKEN}" ]]; then
    printf '%s' "${GITHUB_TOKEN}"
    return
  fi

  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "enceladus-checkout-service${ENVIRONMENT_SUFFIX}" \
    --region "${REGION}" \
    --query 'Environment.Variables.GITHUB_TOKEN' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" == "None" ]]; then
    existing=""
  fi
  printf '%s' "${existing}"
}

deploy_lambda() {
  local zip_path="$1"
  local role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
  local effective_internal_key
  effective_internal_key="$(resolve_internal_api_key)"
  if [[ -z "${effective_internal_key}" ]]; then
    log "[WARNING] COORDINATION_INTERNAL_API_KEY resolved empty; deploy_intake will remain cookie-only."
  fi
  local effective_github_token
  effective_github_token="$(resolve_github_token)"
  if [[ -z "${effective_github_token}" ]]; then
    log "[WARNING] GITHUB_TOKEN resolved empty; PR merge validation will fail for private repos."
  fi
  local env_vars
  env_vars="{DEPLOY_TABLE=${DEPLOY_TABLE},DEPLOY_REGION=${REGION},PROJECTS_TABLE=${PROJECTS_TABLE},CONFIG_BUCKET=${CONFIG_BUCKET},CONFIG_PREFIX=${CONFIG_PREFIX},SQS_QUEUE_URL=${SQS_QUEUE_URL},COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID},COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID},COORDINATION_INTERNAL_API_KEY=${effective_internal_key},COORDINATION_INTERNAL_API_KEY_PREVIOUS=${COORDINATION_INTERNAL_API_KEY_PREVIOUS},COORDINATION_INTERNAL_API_KEY_SCOPES=${COORDINATION_INTERNAL_API_KEY_SCOPES},DOC_PREP_LAMBDA_NAME=${DOC_PREP_LAMBDA_NAME},CORS_ORIGIN=${CORS_ORIGIN},GITHUB_TOKEN=${effective_github_token}}"

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[START] updating Lambda code: ${FUNCTION_NAME}"
    # ENC-TSK-E19: verify package arch matches Lambda runtime before upload
    E19_REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
    E19_EXPECTED_ARCH="x86_64"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && E19_EXPECTED_ARCH="arm64"
    python3 "${E19_REPO_ROOT}/tools/verify_lambda_package_arch.py" \
      --package "${zip_path}" \
      --expected-arch "${E19_EXPECTED_ARCH}"
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
      --runtime "${DEPLOY_RUNTIME}" \
      --timeout 120 \
      --memory-size 512 \
      --environment "Variables=${env_vars}" >/dev/null
  else
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${DEPLOY_RUNTIME}" \
      --handler "lambda_function.lambda_handler" \
      --role "${role_arn}" \
      --timeout 120 \
      --memory-size 512 \
      --zip-file "fileb://${zip_path}" \
      --environment "Variables=${env_vars}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  log "[END] Lambda ready: ${FUNCTION_NAME}"
}

main() {
  ensure_role
  local zip_path
  zip_path="$(package_lambda)"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"
  log "[SUCCESS] deploy_intake Lambda deployed"
}

main "$@"
