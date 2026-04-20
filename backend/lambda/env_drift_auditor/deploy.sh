#!/usr/bin/env bash
# ENC-TSK-F73 / ENC-PLN-042 Stage 4 — env_drift_auditor Lambda (F57 AC-5).
#
# Pattern mirrors backend/lambda/deploy_capability_auditor/deploy.sh: self-
# managed IAM role created via deploy.sh ensure_role (so that the live role
# matches the inline policy stamped in 02-compute.yaml EnvDriftAuditorRole),
# code-only package bundling lambda_function.py + env_drift_registry.json,
# EventBridge schedule maintained out-of-band (devops-env-drift-auditor-hourly).

set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${GITHUB_WORKSPACE:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
source "${REPO_ROOT}/tools/lambda_artifact_helper.sh"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-env-drift-auditor${ENVIRONMENT_SUFFIX}}"
ROLE_NAME="${ROLE_NAME:-devops-env-drift-auditor-role${ENVIRONMENT_SUFFIX}}"
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

  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name env-drift-auditor-inline \
    --policy-document '{
      "Version":"2012-10-17",
      "Statement":[
        {"Sid":"CloudWatchLogs","Effect":"Allow","Action":[
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],"Resource":"arn:aws:logs:*:*:*"},
        {"Sid":"LambdaConfigRead","Effect":"Allow","Action":[
          "lambda:GetFunctionConfiguration",
          "lambda:ListFunctions"
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
  cp "${SCRIPT_DIR}/env_drift_registry.json" "${build_dir}/"
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
    --arg tracker "${TRACKER_API_BASE:-https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/tracker}" \
    --arg project "${ISSUE_PROJECT_ID:-enceladus}" \
    --arg severity "${DRIFT_SEVERITY:-P0}" \
    --arg dry "${DRY_RUN:-false}" \
    '{Variables: {
      TRACKER_API_BASE: $tracker,
      COORDINATION_INTERNAL_API_KEY: $key,
      ISSUE_PROJECT_ID: $project,
      DRIFT_SEVERITY: $severity,
      DRY_RUN: $dry
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
      --timeout 60 \
      --memory-size 256 \
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
      --timeout 60 \
      --memory-size 256 \
      --environment "${env_vars}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
}

main() {
  log "[START] Deploy env drift auditor → ${FUNCTION_NAME}"
  ensure_role
  package_lambda
  deploy_lambda
  rm -f "${ZIP_FILE}"
  log "[SUCCESS] ${FUNCTION_NAME} deployed"
}

main "$@"
