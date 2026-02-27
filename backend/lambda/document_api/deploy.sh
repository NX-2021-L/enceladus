#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy document_api Lambda (ENC-TSK-506)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-document-api}"
ROLE_NAME="${ROLE_NAME:-devops-document-api-lambda-role}"
ROLE_POLICY_NAME="${ROLE_POLICY_NAME:-devops-document-api-inline}"

DOCUMENTS_TABLE="${DOCUMENTS_TABLE:-documents}"
PROJECTS_TABLE="${PROJECTS_TABLE:-projects}"
TRACKER_TABLE="${TRACKER_TABLE:-devops-project-tracker}"
DYNAMODB_REGION="${DYNAMODB_REGION:-us-west-2}"
S3_BUCKET="${S3_BUCKET:-jreese-net}"
S3_PREFIX="${S3_PREFIX:-agent-documents}"
S3_REFERENCE_PREFIX="${S3_REFERENCE_PREFIX:-mobile/v1/reference}"
S3_GOVERNANCE_PREFIX="${S3_GOVERNANCE_PREFIX:-governance/live}"
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
COORDINATION_INTERNAL_API_KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES:-}"
COORDINATION_API_FUNCTION_NAME="${COORDINATION_API_FUNCTION_NAME:-devops-coordination-api}"
GOVERNANCE_PROJECT_ID="${GOVERNANCE_PROJECT_ID:-devops}"
GOVERNANCE_KEYWORD="${GOVERNANCE_KEYWORD:-governance-file}"
PROJECT_REFERENCE_KEYWORD="${PROJECT_REFERENCE_KEYWORD:-project-reference}"

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
  policy_file="$(mktemp /tmp/document-api-policy-XXXXXX.json)"
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
      "Sid": "DynamoDBDocuments",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DOCUMENTS_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DOCUMENTS_TABLE}/index/*"
      ]
    },
    {
      "Sid": "DynamoDBProjectsRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${PROJECTS_TABLE}"
    },
    {
      "Sid": "DynamoDBTrackerRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TRACKER_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TRACKER_TABLE}/index/*"
      ]
    },
    {
      "Sid": "S3DocumentsObjectAccess",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::${S3_BUCKET}/${S3_PREFIX}/*"
    },
    {
      "Sid": "S3ReferenceRead",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}/${S3_REFERENCE_PREFIX}/*",
        "arn:aws:s3:::${S3_BUCKET}/${S3_GOVERNANCE_PREFIX}/*"
      ]
    },
    {
      "Sid": "S3ListPrefixes",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::${S3_BUCKET}",
      "Condition": {
        "StringLike": {
          "s3:prefix": [
            "${S3_PREFIX}/*",
            "${S3_REFERENCE_PREFIX}/*",
            "${S3_GOVERNANCE_PREFIX}/*"
          ]
        }
      }
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

  python3 -m pip install \
    --quiet \
    --upgrade \
    -r "${SCRIPT_DIR}/requirements.txt" \
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
    log "[WARNING] COORDINATION_INTERNAL_API_KEY resolved empty; document_api will remain cookie-only."
  fi
  local env_vars
  env_vars="{DOCUMENTS_TABLE=${DOCUMENTS_TABLE},PROJECTS_TABLE=${PROJECTS_TABLE},TRACKER_TABLE=${TRACKER_TABLE},DYNAMODB_REGION=${DYNAMODB_REGION},S3_BUCKET=${S3_BUCKET},S3_PREFIX=${S3_PREFIX},S3_REFERENCE_PREFIX=${S3_REFERENCE_PREFIX},S3_GOVERNANCE_PREFIX=${S3_GOVERNANCE_PREFIX},COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID},COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID},COORDINATION_INTERNAL_API_KEY=${effective_internal_key},COORDINATION_INTERNAL_API_KEY_SCOPES=${COORDINATION_INTERNAL_API_KEY_SCOPES},GOVERNANCE_PROJECT_ID=${GOVERNANCE_PROJECT_ID},GOVERNANCE_KEYWORD=${GOVERNANCE_KEYWORD},PROJECT_REFERENCE_KEYWORD=${PROJECT_REFERENCE_KEYWORD}}"

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
      --timeout 30 \
      --memory-size 256 \
      --environment "Variables=${env_vars}" >/dev/null
  else
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime "python3.11" \
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
}

main() {
  ensure_role
  local zip_path
  zip_path="$(package_lambda)"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"
  log "[SUCCESS] document_api Lambda deployed"
}

main "$@"
