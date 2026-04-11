#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-enceladus-prod-health-monitor${ENVIRONMENT_SUFFIX}}"
ROLE_NAME="${ROLE_NAME:-enceladus-prod-health-monitor-role${ENVIRONMENT_SUFFIX}}"
MANIFEST="${REPO_ROOT}/infrastructure/lambda_workflow_manifest.json"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# Read function names from manifest (source of truth)
read_function_names() {
  if [ ! -f "${MANIFEST}" ]; then
    log "[ERROR] Manifest not found: ${MANIFEST}"
    exit 1
  fi
  jq -c '[.functions[].function_name]' "${MANIFEST}"
}

ensure_role() {
  if aws iam get-role --role-name "${ROLE_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] Role ${ROLE_NAME} exists"
  else
    log "[INFO] Creating role ${ROLE_NAME}"
    aws iam create-role \
      --role-name "${ROLE_NAME}" \
      --assume-role-policy-document '{
        "Version":"2012-10-17",
        "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
      }' \
      --region "${REGION}" >/dev/null

    # Attach policies for Lambda basics + CloudWatch + Lambda read
    aws iam attach-role-policy \
      --role-name "${ROLE_NAME}" \
      --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole" \
      --region "${REGION}" 2>/dev/null || true

    aws iam attach-role-policy \
      --role-name "${ROLE_NAME}" \
      --policy-arn "arn:aws:iam::aws:policy/CloudWatchFullAccess" \
      --region "${REGION}" 2>/dev/null || true

    sleep 10
  fi
}

build_package() {
  log "[INFO] Building deployment package"
  local build_dir
  build_dir="$(mktemp -d)"
  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  (cd "${build_dir}" && zip -q -r "${SCRIPT_DIR}/deploy-package.zip" .)
  rm -rf "${build_dir}"
  log "[INFO] Package built: deploy-package.zip"
}

deploy_function() {
  local zip_path="${SCRIPT_DIR}/deploy-package.zip"
  local role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
  local fn_names
  fn_names="$(read_function_names)"

  # Build JSON environment block — fn_names is a JSON array that must be stored as string env var
  local env_json
  env_json=$(python3 -c "
import json, sys
fn = json.loads(sys.argv[1])
env = {'Variables': {'FUNCTION_NAMES': json.dumps(fn), 'AWS_REGION': sys.argv[2]}}
print(json.dumps(env))
" "${fn_names}" "${REGION}")

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] Updating existing function ${FUNCTION_NAME}"
    local arch_flag="x86_64"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && arch_flag="arm64"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --zip-file "fileb://${zip_path}" \
      --architectures "${arch_flag}" \
      --region "${REGION}" >/dev/null

    aws lambda wait function-updated-v2 \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}"

    # Environment-conditional runtime
    local runtime="python3.11"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && runtime="python3.12"

    aws lambda update-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${runtime}" \
      --environment "${env_json}" \
      --region "${REGION}" >/dev/null

    aws lambda wait function-updated-v2 \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}"
  else
    local runtime="python3.11" arch="x86_64"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && runtime="python3.12" && arch="arm64"
    log "[INFO] Creating new function ${FUNCTION_NAME}"
    aws lambda create-function \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${runtime}" \
      --handler lambda_function.handler \
      --role "${role_arn}" \
      --zip-file "fileb://${zip_path}" \
      --timeout 120 \
      --memory-size 256 \
      --architectures "${arch}" \
      --environment "${env_json}" \
      --region "${REGION}" >/dev/null
  fi
  log "[SUCCESS] Function ${FUNCTION_NAME} deployed"
}

main() {
  log "[START] Deploying ${FUNCTION_NAME}"
  ensure_role
  build_package
  deploy_function
  rm -f "${SCRIPT_DIR}/deploy-package.zip"
  log "[END] Deployment complete"
}

main "$@"
