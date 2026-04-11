#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-enceladus-graph-health-metrics${ENVIRONMENT_SUFFIX}}"
ROLE_NAME="${ROLE_NAME:-enceladus-graph-health-metrics-role${ENVIRONMENT_SUFFIX}}"
NEO4J_SECRET_NAME="${NEO4J_SECRET_NAME:-enceladus/neo4j/auradb-credentials}"
CLOUDWATCH_NAMESPACE="${CLOUDWATCH_NAMESPACE:-Enceladus/GraphHealth}"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

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
    sleep 10
  fi
}

build_package() {
  log "[INFO] Building deployment package"
  local build_dir
  build_dir="$(mktemp -d)"
  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  # Install neo4j driver for Linux Lambda runtime
  pip install \
    --platform manylinux2014_aarch64 \
    --implementation cp \
    --python-version 3.12 \
    --abi cp312 \
    --only-binary=:all: \
    neo4j -t "${build_dir}" --quiet 2>/dev/null || true

  (cd "${build_dir}" && zip -q -r "${SCRIPT_DIR}/deploy-package.zip" .)
  rm -rf "${build_dir}"
  log "[INFO] Package built: deploy-package.zip"
}

deploy_function() {
  local zip_path="${SCRIPT_DIR}/deploy-package.zip"
  local role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] Updating existing function ${FUNCTION_NAME}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --zip-file "fileb://${zip_path}" \
      --region "${REGION}" >/dev/null
  else
    log "[INFO] Creating new function ${FUNCTION_NAME}"
    aws lambda create-function \
      --function-name "${FUNCTION_NAME}" \
      --runtime python3.12 \
      --handler lambda_function.handler \
      --role "${role_arn}" \
      --zip-file "fileb://${zip_path}" \
      --timeout 120 \
      --memory-size 256 \
      --architectures arm64 \
      --environment "Variables={NEO4J_SECRET_NAME=${NEO4J_SECRET_NAME},CLOUDWATCH_NAMESPACE=${CLOUDWATCH_NAMESPACE},PROJECT_ID=enceladus,SECRETS_REGION=${REGION}}" \
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
