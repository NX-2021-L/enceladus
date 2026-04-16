#!/usr/bin/env bash
# ENC-TSK-E69 / ENC-PLN-031 Phase 4 — deploy_capability_auditor Lambda.
#
# Pattern mirrors backend/lambda/prod_health_monitor/deploy.sh: self-managed
# IAM role, code-only package (lambda_function.py + boto3 from runtime layer),
# daily EventBridge schedule configured via CFN (05-monitoring.yaml).

set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GITHUB_WORKSPACE:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
source "${REPO_ROOT}/tools/lambda_artifact_helper.sh"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-enceladus-deploy-capability-auditor${ENVIRONMENT_SUFFIX}}"
ROLE_NAME="${ROLE_NAME:-enceladus-deploy-capability-auditor-role${ENVIRONMENT_SUFFIX}}"
ZIP_FILE="/tmp/${FUNCTION_NAME}.zip"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

ensure_role() {
  if aws iam get-role --role-name "${ROLE_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] Role ${ROLE_NAME} exists"
    return
  fi
  log "[INFO] Creating role ${ROLE_NAME}"
  aws iam create-role \
    --role-name "${ROLE_NAME}" \
    --assume-role-policy-document '{
      "Version":"2012-10-17",
      "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
    }' \
    --region "${REGION}" >/dev/null

  aws iam attach-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
    --region "${REGION}" >/dev/null

  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name ReadOnlyCapabilityAudit \
    --policy-document '{
      "Version":"2012-10-17",
      "Statement":[
        {"Effect":"Allow","Action":[
          "lambda:GetFunctionConfiguration",
          "lambda:ListFunctions",
          "apigatewayv2:GetRoutes",
          "apigatewayv2:GetApis",
          "cloudformation:ListStackResources",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "secretsmanager:ListSecrets"
        ],"Resource":"*"}
      ]
    }' \
    --region "${REGION}" >/dev/null

  log "[INFO] Waiting 10s for IAM propagation"
  sleep 10
}

package_lambda() {
  local resolved_zip
  if resolved_zip="$(resolve_artifact "${FUNCTION_NAME}" "${ZIP_FILE}")"; then
    echo "${resolved_zip}"
    return 0
  fi
  local build_dir
  build_dir="$(mktemp -d /tmp/build-${FUNCTION_NAME}-XXXXXX)"
  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"
  (
    cd "${build_dir}"
    zip -qr "${ZIP_FILE}" .
  )
  rm -rf "${build_dir}"
}

deploy_lambda() {
  local role_arn
  role_arn="$(aws iam get-role --role-name "${ROLE_NAME}" --region "${REGION}" --query 'Role.Arn' --output text)"

  local arch_flag="x86_64" runtime_flag="python3.11"
  if [ -n "${ENVIRONMENT_SUFFIX}" ]; then
    arch_flag="arm64"
    runtime_flag="python3.12"
  fi

  local env_vars
  env_vars=$(jq -n --arg key "${COORDINATION_INTERNAL_API_KEY:-}" \
    --arg region "${REGION}" \
    --arg project "enceladus" \
    --arg manifest "${MANIFEST_DOC_ID:-}" \
    --arg apigw "${APIGW_API_ID:-}" \
    '{Variables: {
      COORDINATION_INTERNAL_API_KEY: $key,
      AWS_REGION: $region,
      PROJECT_ID: $project,
      MANIFEST_DOC_ID: $manifest,
      APIGW_API_ID: $apigw
    }}')

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] Updating ${FUNCTION_NAME}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --zip-file "fileb://${ZIP_FILE}" \
      --architectures "${arch_flag}" >/dev/null
    aws lambda wait function-updated-v2 \
      --function-name "${FUNCTION_NAME}" --region "${REGION}"
    aws lambda update-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --role "${role_arn}" \
      --handler "lambda_function.lambda_handler" \
      --runtime "${runtime_flag}" \
      --timeout 300 \
      --memory-size 512 \
      --environment "${env_vars}" >/dev/null
  else
    log "[INFO] Creating ${FUNCTION_NAME}"
    aws lambda create-function \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --runtime "${runtime_flag}" \
      --architectures "${arch_flag}" \
      --role "${role_arn}" \
      --handler "lambda_function.lambda_handler" \
      --zip-file "fileb://${ZIP_FILE}" \
      --timeout 300 \
      --memory-size 512 \
      --environment "${env_vars}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
}

main() {
  log "[START] Deploy capability auditor → ${FUNCTION_NAME}"
  ensure_role
  package_lambda
  deploy_lambda
  rm -f "${ZIP_FILE}"
  log "[SUCCESS] ${FUNCTION_NAME} deployed"
}

main "$@"
