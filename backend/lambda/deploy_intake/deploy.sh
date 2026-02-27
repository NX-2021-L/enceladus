#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy deploy_intake Lambda (ENC-TSK-506)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-deploy-intake}"
ROLE_NAME="${ROLE_NAME:-devops-deploy-intake-lambda-role}"
ROLE_POLICY_NAME="${ROLE_POLICY_NAME:-devops-deploy-intake-inline}"

DEPLOY_TABLE="${DEPLOY_TABLE:-devops-deployment-manager}"
PROJECTS_TABLE="${PROJECTS_TABLE:-projects}"
CONFIG_BUCKET="${CONFIG_BUCKET:-jreese-net}"
CONFIG_PREFIX="${CONFIG_PREFIX:-deploy-config}"
SQS_QUEUE_URL="${SQS_QUEUE_URL:-https://sqs.us-west-2.amazonaws.com/356364570033/devops-deploy-queue.fifo}"
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
COORDINATION_INTERNAL_API_KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES:-}"
COORDINATION_API_FUNCTION_NAME="${COORDINATION_API_FUNCTION_NAME:-devops-coordination-api}"
DOC_PREP_LAMBDA_NAME="${DOC_PREP_LAMBDA_NAME:-devops-doc-prep}"
CORS_ORIGIN="${CORS_ORIGIN:-https://jreese.net}"

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
      "Resource": "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:devops-deploy-queue.fifo"
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

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
    python3 -m pip install \
      --quiet \
      --upgrade \
      -r "${SCRIPT_DIR}/requirements.txt" \
      --platform manylinux2014_x86_64 \
      --implementation cp \
      --python-version 3.11 \
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

  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" == "None" ]]; then
    existing=""
  fi
  if [[ -n "${existing}" ]]; then
    printf '%s' "${existing}"
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
  printf '%s' "${coordination_key}"
}

deploy_lambda() {
  local zip_path="$1"
  local role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
  local effective_internal_key
  effective_internal_key="$(resolve_internal_api_key)"
  if [[ -z "${effective_internal_key}" ]]; then
    log "[WARNING] COORDINATION_INTERNAL_API_KEY resolved empty; deploy_intake will remain cookie-only."
  fi
  local env_vars
  env_vars="{DEPLOY_TABLE=${DEPLOY_TABLE},DEPLOY_REGION=${REGION},PROJECTS_TABLE=${PROJECTS_TABLE},CONFIG_BUCKET=${CONFIG_BUCKET},CONFIG_PREFIX=${CONFIG_PREFIX},SQS_QUEUE_URL=${SQS_QUEUE_URL},COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID},COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID},COORDINATION_INTERNAL_API_KEY=${effective_internal_key},COORDINATION_INTERNAL_API_KEY_SCOPES=${COORDINATION_INTERNAL_API_KEY_SCOPES},DOC_PREP_LAMBDA_NAME=${DOC_PREP_LAMBDA_NAME},CORS_ORIGIN=${CORS_ORIGIN}}"

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
      --runtime "python3.11" \
      --timeout 120 \
      --memory-size 512 \
      --environment "Variables=${env_vars}" >/dev/null
  else
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime "python3.11" \
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
