#!/usr/bin/env bash
# Deploy the enceladus-mcp-streamable Lambda function.
#
# Remediates ENC-ISS-060 by supporting first deploy when the Lambda does not
# yet exist: create function + function URL if missing, then update code/config.

set -euo pipefail

FUNCTION_NAME="${FUNCTION_NAME:-enceladus-mcp-streamable}"
SOURCE_FUNCTION_NAME="${SOURCE_FUNCTION_NAME:-devops-coordination-api}"
REGION="${AWS_REGION:-us-west-2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ZIP_FILE="/tmp/${FUNCTION_NAME}.zip"

MCP_TRANSPORT="${ENCELADUS_MCP_TRANSPORT:-streamable_http}"
MCP_API_KEY="${ENCELADUS_MCP_API_KEY:-${COORDINATION_INTERNAL_API_KEY:-}}"
ROLE_ARN="${LAMBDA_ROLE_ARN:-}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

function_exists() {
  aws lambda get-function \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" >/dev/null 2>&1
}

resolve_role_arn() {
  if [[ -n "${ROLE_ARN}" ]]; then
    printf '%s' "${ROLE_ARN}"
    return
  fi

  local source_role
  source_role="$(aws lambda get-function-configuration \
    --function-name "${SOURCE_FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Role' \
    --output text 2>/dev/null || true)"
  if [[ -z "${source_role}" || "${source_role}" == "None" ]]; then
    echo ""  # caller validates
    return
  fi

  printf '%s' "${source_role}"
}

build_environment_payload() {
  local out_file="$1"
  local source_json='{}'
  local existing_json='{}'

  source_json="$(aws lambda get-function-configuration \
    --function-name "${SOURCE_FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null || echo '{}')"
  [[ "${source_json}" == "None" ]] && source_json='{}'

  if function_exists; then
    existing_json="$(aws lambda get-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --query 'Environment.Variables' \
      --output json 2>/dev/null || echo '{}')"
    [[ "${existing_json}" == "None" ]] && existing_json='{}'
  fi

  python3 - <<'PY' > "${out_file}"
import json
import os

source_env = json.loads(os.environ.get("SOURCE_ENV_JSON", "{}"))
existing_env = json.loads(os.environ.get("EXISTING_ENV_JSON", "{}"))

merged = {}
merged.update(source_env if isinstance(source_env, dict) else {})
merged.update(existing_env if isinstance(existing_env, dict) else {})
merged["ENCELADUS_MCP_TRANSPORT"] = os.environ["MCP_TRANSPORT"]

mcp_api_key = os.environ.get("MCP_API_KEY", "")
if mcp_api_key:
    merged["ENCELADUS_MCP_API_KEY"] = mcp_api_key

print(json.dumps({"Variables": merged}, separators=(",", ":")))
PY
}

package_lambda() {
  local build_dir
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"

  cp "${REPO_ROOT}/tools/enceladus-mcp-server/server.py" "${build_dir}/server.py"

  python3 -m pip install \
    --quiet \
    --upgrade \
    -r "${SCRIPT_DIR}/requirements.txt" \
    --platform manylinux2014_aarch64 \
    --implementation cp \
    --python-version 3.12 \
    --only-binary=:all: \
    -t "${build_dir}" >/dev/null

  (
    cd "${build_dir}"
    zip -qr "${ZIP_FILE}" .
  )

  rm -rf "${build_dir}"
}

ensure_function_url() {
  if aws lambda get-function-url-config \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] Function URL exists for ${FUNCTION_NAME}"
  else
    log "[START] creating Function URL (NONE auth): ${FUNCTION_NAME}"
    aws lambda create-function-url-config \
      --function-name "${FUNCTION_NAME}" \
      --auth-type NONE \
      --region "${REGION}" >/dev/null
    log "[END] created Function URL: ${FUNCTION_NAME}"
  fi

  if aws lambda add-permission \
    --function-name "${FUNCTION_NAME}" \
    --statement-id FunctionURLAllowPublicAccess \
    --action lambda:InvokeFunctionUrl \
    --principal "*" \
    --function-url-auth-type NONE \
    --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] Function URL invoke permission added"
  else
    log "[OK] Function URL invoke permission already present"
  fi
}

deploy_lambda() {
  local role_arn env_file
  role_arn="$(resolve_role_arn)"
  if [[ -z "${role_arn}" ]]; then
    echo "Unable to resolve Lambda role. Set LAMBDA_ROLE_ARN or ensure ${SOURCE_FUNCTION_NAME} exists." >&2
    exit 1
  fi

  env_file="$(mktemp /tmp/${FUNCTION_NAME}-env-XXXXXX.json)"
  SOURCE_ENV_JSON="$(aws lambda get-function-configuration \
      --function-name "${SOURCE_FUNCTION_NAME}" \
      --region "${REGION}" \
      --query 'Environment.Variables' \
      --output json 2>/dev/null || echo '{}')" \
  EXISTING_ENV_JSON="$(aws lambda get-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --query 'Environment.Variables' \
      --output json 2>/dev/null || echo '{}')" \
  MCP_TRANSPORT="${MCP_TRANSPORT}" \
  MCP_API_KEY="${MCP_API_KEY}" \
  build_environment_payload "${env_file}"

  if function_exists; then
    log "[START] updating Lambda code: ${FUNCTION_NAME}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --zip-file "fileb://${ZIP_FILE}" >/dev/null
    aws lambda wait function-updated-v2 \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}"

    log "[START] updating Lambda configuration: ${FUNCTION_NAME}"
    aws lambda update-function-configuration \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --role "${role_arn}" \
      --handler "server.lambda_handler" \
      --runtime "python3.12" \
      --architectures arm64 \
      --timeout 30 \
      --memory-size 512 \
      --environment "file://${env_file}" >/dev/null
  else
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime "python3.12" \
      --architectures arm64 \
      --handler "server.lambda_handler" \
      --role "${role_arn}" \
      --timeout 30 \
      --memory-size 512 \
      --zip-file "fileb://${ZIP_FILE}" \
      --environment "file://${env_file}" >/dev/null
  fi

  aws lambda wait function-active-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"
  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  ensure_function_url
  rm -f "${env_file}"

  log "[END] Lambda ready: ${FUNCTION_NAME}"
}

main() {
  log "[START] Deploying ${FUNCTION_NAME}"
  package_lambda
  deploy_lambda
  rm -f "${ZIP_FILE}"
  log "[SUCCESS] ${FUNCTION_NAME} deployed"
}

main "$@"
