#!/usr/bin/env bash
# Deploy the enceladus-mcp-code Lambda function (ENC-FTR-045).
#
# Code-mode-only MCP endpoint with Cognito-direct OAuth.
# Clone of mcp_streamable/deploy.sh with Cognito env vars and CORS Function URL.

set -euo pipefail

FUNCTION_NAME="${FUNCTION_NAME:-enceladus-mcp-code}"
SOURCE_FUNCTION_NAME="${SOURCE_FUNCTION_NAME:-devops-coordination-api}"
REGION="${AWS_REGION:-us-west-2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
source "${REPO_ROOT}/tools/lambda_artifact_helper.sh"
ZIP_FILE="/tmp/${FUNCTION_NAME}.zip"

MCP_TRANSPORT="${ENCELADUS_MCP_TRANSPORT:-streamable_http}"
COGNITO_USER_POOL_ID="${ENCELADUS_COGNITO_USER_POOL_ID:-}"
COGNITO_REGION="${ENCELADUS_COGNITO_REGION:-us-east-1}"
COGNITO_CLIENT_ID="${ENCELADUS_COGNITO_CLIENT_ID:-}"
COGNITO_CLIENT_SECRET="${ENCELADUS_COGNITO_CLIENT_SECRET:-}"
COGNITO_DOMAIN="${ENCELADUS_COGNITO_DOMAIN:-}"
CUSTOM_DOMAIN="${ENCELADUS_CUSTOM_DOMAIN:-mcp.jreese.net}"
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

preflight_merge_live_env_vars() {
  # ENC-ISS-258 Bug 1 fix: source Cognito env vars from the live Lambda's
  # Environment.Variables when the operator's shell did not set them.
  # Lets any product-lead operator deploy without out-of-band secret retrieval.
  # No-op on first deploy (live Lambda absent); the validation block refuses
  # as before if the secret is still empty after the merge attempt.
  if ! function_exists; then
    return 0
  fi

  _merge_one() {
    local shell_var="$1" lambda_key="$2" value
    if [[ -z "${!shell_var}" ]]; then
      value="$(aws lambda get-function-configuration \
        --function-name "${FUNCTION_NAME}" --region "${REGION}" \
        --query "Environment.Variables.${lambda_key}" \
        --output text 2>/dev/null || true)"
      if [[ -n "${value}" && "${value}" != "None" ]]; then
        printf -v "${shell_var}" '%s' "${value}"
        log "[INFO] ${shell_var} sourced from live Lambda ${FUNCTION_NAME}"
      fi
    fi
  }

  _merge_one COGNITO_USER_POOL_ID  ENCELADUS_COGNITO_USER_POOL_ID
  _merge_one COGNITO_CLIENT_ID     ENCELADUS_COGNITO_CLIENT_ID
  _merge_one COGNITO_CLIENT_SECRET ENCELADUS_COGNITO_CLIENT_SECRET
  _merge_one COGNITO_DOMAIN        ENCELADUS_COGNITO_DOMAIN
  unset -f _merge_one
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

# Only keep env vars the MCP server actually reads (ENCELADUS_*, COORDINATION_*,
# and a few infrastructure keys). The source function carries many vars that
# push the merged set past Lambda's 4KB limit.
ALLOWED_PREFIXES = (
    "ENCELADUS_",
    "COORDINATION_",
    "DYNAMODB_REGION",
    "TRACKER_TABLE",
    "PROJECTS_TABLE",
    "DOCUMENTS_TABLE",
    "S3_BUCKET",
    "S3_GOVERNANCE",
    "GOVERNANCE_",
    "CORS_ORIGIN",
    "SECRETS_REGION",
    "MCP_AUDIT_",
    "MCP_SERVER_",
    "ENABLE_",
)

merged = {}
for env in [existing_env, source_env]:
    if not isinstance(env, dict):
        continue
    for k, v in env.items():
        if any(k.startswith(p) or k == p for p in ALLOWED_PREFIXES):
            merged[k] = v

# Force code-mode settings
merged["ENCELADUS_MCP_TRANSPORT"] = os.environ["MCP_TRANSPORT"]
merged["ENCELADUS_MCP_INTERFACE_MODE"] = "code"
# ENC-FTR-049: Typed relationship feature flag
merged["ENABLE_TYPED_RELATIONSHIPS"] = "true"
# ENC-FTR-050: Context Node feature flag
merged["ENABLE_CONTEXT_NODES"] = "true"
# ENC-FTR-052: Governed Lesson Primitive feature flag
merged["ENABLE_LESSON_PRIMITIVE"] = "true"

# Cognito OAuth vars
cognito_pool = os.environ.get("COGNITO_USER_POOL_ID", "")
if cognito_pool:
    merged["ENCELADUS_COGNITO_USER_POOL_ID"] = cognito_pool
cognito_region = os.environ.get("COGNITO_REGION", "")
if cognito_region:
    merged["ENCELADUS_COGNITO_REGION"] = cognito_region
cognito_client_id = os.environ.get("COGNITO_CLIENT_ID", "")
if cognito_client_id:
    merged["ENCELADUS_COGNITO_CLIENT_ID"] = cognito_client_id
cognito_client_secret = os.environ.get("COGNITO_CLIENT_SECRET", "")
if cognito_client_secret:
    merged["ENCELADUS_COGNITO_CLIENT_SECRET"] = cognito_client_secret
cognito_domain = os.environ.get("COGNITO_DOMAIN", "")
if cognito_domain:
    merged["ENCELADUS_COGNITO_DOMAIN"] = cognito_domain
custom_domain = os.environ.get("CUSTOM_DOMAIN", "")
if custom_domain:
    merged["CUSTOM_DOMAIN"] = custom_domain

print(json.dumps({"Variables": merged}, separators=(",", ":")))
PY
}

package_lambda() {
  # ENC-TSK-E27: try S3 artifact first
  local resolved_zip
  if resolved_zip="$(resolve_artifact "${FUNCTION_NAME}" "/tmp/${FUNCTION_NAME}.zip")"; then
    echo "${resolved_zip}"
    return 0
  fi

  local build_dir
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"

  cp "${REPO_ROOT}/tools/enceladus-mcp-server/server.py" "${build_dir}/server.py"
  # ENC-FTR-050: Context Node scoring engine (imported dynamically by server.py)
  cp "${REPO_ROOT}/backend/lambda/coordination_api/context_node_scoring.py" "${build_dir}/context_node_scoring.py"

  # Env-conditional: gamma=arm64/py3.12, prod=x86_64/py3.11
  local pip_platform pip_pyver pip_abi
  if [ -n "${ENVIRONMENT_SUFFIX:-}" ]; then
    pip_platform="manylinux2014_aarch64"; pip_pyver="3.12"; pip_abi="cp312"
  else
    pip_platform="manylinux2014_x86_64"; pip_pyver="3.11"; pip_abi="cp311"
  fi

  python3 -m pip install \
    --quiet \
    --upgrade \
    -r "${SCRIPT_DIR}/requirements.txt" \
    --platform "${pip_platform}" \
    --implementation cp \
    --python-version "${pip_pyver}" \
    --only-binary=:all: \
    -t "${build_dir}" >/dev/null

  (
    cd "${build_dir}"
    zip -qr "${ZIP_FILE}" .
  )

  rm -rf "${build_dir}"
}

ensure_function_url() {
  # CORS config: use ["*"] for AllowMethods (individual method names like "OPTIONS"
  # exceed the 6-char member limit); use exact origin (no wildcard subdomains).
  local cors_config='{"AllowOrigins":["https://claude.ai"],"AllowMethods":["*"],"AllowHeaders":["Content-Type","Authorization","Accept","Mcp-Session-Id"],"ExposeHeaders":["Mcp-Session-Id"],"AllowCredentials":true,"MaxAge":86400}'

  if aws lambda get-function-url-config \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] Function URL exists for ${FUNCTION_NAME}"

    # Update CORS on existing Function URL
    log "[START] updating Function URL CORS: ${FUNCTION_NAME}"
    aws lambda update-function-url-config \
      --function-name "${FUNCTION_NAME}" \
      --auth-type NONE \
      --cors "${cors_config}" \
      --region "${REGION}" >/dev/null || log "[WARNING] unable to update CORS"
  else
    log "[START] creating Function URL (NONE auth) with CORS: ${FUNCTION_NAME}"
    if ! aws lambda create-function-url-config \
      --function-name "${FUNCTION_NAME}" \
      --auth-type NONE \
      --cors "${cors_config}" \
      --region "${REGION}" >/dev/null; then
      log "[WARNING] unable to create Function URL (missing lambda:CreateFunctionUrlConfig?)."
      log "[WARNING] Lambda code/config deployment succeeded; configure Function URL separately."
      return 0
    fi
    log "[END] created Function URL: ${FUNCTION_NAME}"
  fi

  # Statement 1: lambda:InvokeFunctionUrl (required for NONE auth Function URLs)
  if aws lambda add-permission \
    --function-name "${FUNCTION_NAME}" \
    --statement-id FunctionURLAllowPublicAccess \
    --action lambda:InvokeFunctionUrl \
    --principal "*" \
    --function-url-auth-type NONE \
    --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] Function URL invoke permission added (InvokeFunctionUrl)"
  else
    log "[INFO] InvokeFunctionUrl permission already exists or could not be added."
  fi

  # Statement 2: lambda:InvokeFunction with InvokedViaFunctionUrl condition
  # Required for Function URL to actually invoke the Lambda (AWS CLI 2.34+)
  if aws lambda add-permission \
    --function-name "${FUNCTION_NAME}" \
    --statement-id FunctionURLAllowPublicInvoke \
    --action lambda:InvokeFunction \
    --principal "*" \
    --invoked-via-function-url \
    --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] Function URL invoke permission added (InvokeFunction)"
  else
    log "[INFO] InvokeFunction permission already exists or could not be added."
  fi
}

ALIAS_NAME="${ALIAS_NAME:-live}"
PROVISIONED_CONCURRENCY="${PROVISIONED_CONCURRENCY:-1}"

publish_version_and_alias() {
  # Non-blocking: alias/version/provisioned-concurrency require permissions
  # that may not be available in all deploy roles. Warn and continue so the
  # core code+config deployment is not blocked.
  log "[START] publishing Lambda version: ${FUNCTION_NAME}"
  local version
  version="$(aws lambda publish-version \
    --function-name "${FUNCTION_NAME}" \
    --description "v4-arm64-$(date -u +%Y%m%d-%H%M%S)" \
    --region "${REGION}" \
    --query 'Version' --output text 2>&1)" || {
    log "[WARNING] unable to publish version (missing lambda:PublishVersion?). Configure alias manually."
    return 0
  }
  log "[OK] published version: ${version}"

  if aws lambda get-alias \
    --function-name "${FUNCTION_NAME}" \
    --name "${ALIAS_NAME}" \
    --region "${REGION}" >/dev/null 2>&1; then
    log "[START] updating alias '${ALIAS_NAME}' -> version ${version}"
    aws lambda update-alias \
      --function-name "${FUNCTION_NAME}" \
      --name "${ALIAS_NAME}" \
      --function-version "${version}" \
      --region "${REGION}" >/dev/null 2>&1 || log "[WARNING] unable to update alias."
  else
    log "[START] creating alias '${ALIAS_NAME}' -> version ${version}"
    if ! aws lambda create-alias \
      --function-name "${FUNCTION_NAME}" \
      --name "${ALIAS_NAME}" \
      --function-version "${version}" \
      --description "Alias for provisioned concurrency" \
      --region "${REGION}" >/dev/null 2>&1; then
      log "[WARNING] unable to create alias (missing lambda:CreateAlias?). Configure alias manually."
      return 0
    fi
  fi
  log "[OK] alias '${ALIAS_NAME}' points to version ${version}"

  if [[ "${PROVISIONED_CONCURRENCY}" -gt 0 ]]; then
    log "[START] configuring provisioned concurrency: ${PROVISIONED_CONCURRENCY} on ${ALIAS_NAME}"
    aws lambda put-provisioned-concurrency-config \
      --function-name "${FUNCTION_NAME}" \
      --qualifier "${ALIAS_NAME}" \
      --provisioned-concurrent-executions "${PROVISIONED_CONCURRENCY}" \
      --region "${REGION}" >/dev/null 2>&1 \
      || log "[WARNING] unable to configure provisioned concurrency."
    log "[OK] provisioned concurrency config submitted"
  fi

  # Ensure Function URL on alias (so provisioned instances serve traffic)
  ensure_alias_function_url
}

ensure_alias_function_url() {
  local cors_config='{"AllowOrigins":["https://claude.ai"],"AllowMethods":["*"],"AllowHeaders":["Content-Type","Authorization","Accept","Mcp-Session-Id"],"ExposeHeaders":["Mcp-Session-Id"],"AllowCredentials":true,"MaxAge":86400}'

  if aws lambda get-function-url-config \
    --function-name "${FUNCTION_NAME}" \
    --qualifier "${ALIAS_NAME}" \
    --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] Function URL exists for ${FUNCTION_NAME}:${ALIAS_NAME}"
    aws lambda update-function-url-config \
      --function-name "${FUNCTION_NAME}" \
      --qualifier "${ALIAS_NAME}" \
      --auth-type NONE \
      --cors "${cors_config}" \
      --region "${REGION}" >/dev/null || log "[WARNING] unable to update alias Function URL CORS"
  else
    log "[START] creating Function URL for alias ${ALIAS_NAME}"
    if ! aws lambda create-function-url-config \
      --function-name "${FUNCTION_NAME}" \
      --qualifier "${ALIAS_NAME}" \
      --auth-type NONE \
      --cors "${cors_config}" \
      --invoke-mode BUFFERED \
      --region "${REGION}" >/dev/null; then
      log "[WARNING] unable to create alias Function URL."
      return 0
    fi
    log "[END] created alias Function URL: ${FUNCTION_NAME}:${ALIAS_NAME}"
  fi

  aws lambda add-permission \
    --function-name "${FUNCTION_NAME}" \
    --qualifier "${ALIAS_NAME}" \
    --statement-id "FunctionURLAllowPublicAccess-${ALIAS_NAME}" \
    --action lambda:InvokeFunctionUrl \
    --principal "*" \
    --function-url-auth-type NONE \
    --region "${REGION}" >/dev/null 2>&1 || true

  aws lambda add-permission \
    --function-name "${FUNCTION_NAME}" \
    --qualifier "${ALIAS_NAME}" \
    --statement-id "FunctionURLAllowPublicInvoke-${ALIAS_NAME}" \
    --action lambda:InvokeFunction \
    --principal "*" \
    --invoked-via-function-url \
    --region "${REGION}" >/dev/null 2>&1 || true
}

deploy_lambda() {
  local role_arn env_file
  role_arn="$(resolve_role_arn)"
  if [[ -z "${role_arn}" ]]; then
    echo "Unable to resolve Lambda role. Set LAMBDA_ROLE_ARN or ensure ${SOURCE_FUNCTION_NAME} exists." >&2
    exit 1
  fi

  # ENC-ISS-258 Bug 1 fix: source missing Cognito vars from live Lambda if it exists.
  preflight_merge_live_env_vars

  # ENC-ISS-258 Bug 2 fix: BSD mktemp (macOS) only substitutes X characters at
  # the end of the template. The prior `/tmp/${FN}-env-XXXXXX.json` pattern
  # left a literal `XXXXXX.json` file on disk, causing `mkstemp: File exists`
  # on subsequent runs. PID-based naming plus a trap on EXIT is portable and
  # self-cleaning across macOS BSD and GNU coreutils.
  env_file="/tmp/${FUNCTION_NAME}-env-$$.json"
  # ENC-ISS-267: env_file is local to deploy_lambda(); the EXIT trap fires at
  # shell-exit after main() returns, where env_file is out of scope. Use
  # ${env_file:-} so `rm -f ""` is a safe no-op under `set -u`.
  trap 'rm -f "${env_file:-}"' EXIT

  if [[ -z "${COGNITO_USER_POOL_ID}" ]]; then
    echo "Refusing deploy with empty COGNITO_USER_POOL_ID for ${FUNCTION_NAME}." >&2
    exit 1
  fi
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
  COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID}" \
  COGNITO_REGION="${COGNITO_REGION}" \
  COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID}" \
  COGNITO_CLIENT_SECRET="${COGNITO_CLIENT_SECRET}" \
  COGNITO_DOMAIN="${COGNITO_DOMAIN}" \
  CUSTOM_DOMAIN="${CUSTOM_DOMAIN}" \
  build_environment_payload "${env_file}"

  # Env-conditional: gamma=arm64/py3.12, prod=x86_64/py3.11
  local arch_flag="x86_64" runtime_flag="python3.11"
  if [ -n "${ENVIRONMENT_SUFFIX:-}" ]; then
    arch_flag="arm64"; runtime_flag="python3.12"
  fi

  if function_exists; then
    log "[START] updating Lambda code: ${FUNCTION_NAME}"
    # ENC-TSK-E19: verify package arch matches Lambda runtime before upload
    E19_REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
    E19_EXPECTED_ARCH="x86_64"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && E19_EXPECTED_ARCH="arm64"
    python3 "${E19_REPO_ROOT}/tools/verify_lambda_package_arch.py" \
      --package "${ZIP_FILE}" \
      --expected-arch "${E19_EXPECTED_ARCH}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --zip-file "fileb://${ZIP_FILE}" \
      --architectures "${arch_flag}" >/dev/null
    aws lambda wait function-updated-v2 \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}"

    log "[START] updating Lambda configuration: ${FUNCTION_NAME}"
    aws lambda update-function-configuration \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --role "${role_arn}" \
      --handler "server.lambda_handler" \
      --runtime "${runtime_flag}" \
      --timeout 30 \
      --memory-size 512 \
      --environment "file://${env_file}" >/dev/null
  else
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${runtime_flag}" \
      --architectures "${arch_flag}" \
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

  # ENC-TSK-B83: Publish version + alias + provisioned concurrency
  publish_version_and_alias

  log "[END] Lambda ready: ${FUNCTION_NAME}"
}

deploy_gamma_twin() {
  # ENC-TSK-F74 / ENC-ISS-279: Opt-in gamma upsert. Keeps the out-of-band
  # enceladus-mcp-code-gamma Lambda reachable from a code-managed deploy path
  # after the prod twin succeeds. Triggered by `--include-gamma` arg or
  # `DEPLOY_MCP_CODE_GAMMA=1` env.
  log "[START] gamma twin upsert: enceladus-mcp-code-gamma"
  (
    export FUNCTION_NAME="enceladus-mcp-code-gamma"
    export SOURCE_FUNCTION_NAME="devops-coordination-api-gamma"
    export ENVIRONMENT_SUFFIX="-gamma"
    export ZIP_FILE="/tmp/${FUNCTION_NAME}.zip"
    package_lambda
    deploy_lambda
    rm -f "${ZIP_FILE}"
  )
  log "[END] gamma twin upsert complete"
}

main() {
  local include_gamma=0
  for arg in "$@"; do
    [[ "${arg}" == "--include-gamma" ]] && include_gamma=1
  done
  [[ "${DEPLOY_MCP_CODE_GAMMA:-0}" == "1" ]] && include_gamma=1

  log "[START] Deploying ${FUNCTION_NAME}"
  package_lambda
  deploy_lambda
  rm -f "${ZIP_FILE}"
  log "[SUCCESS] ${FUNCTION_NAME} deployed"

  if [[ "${include_gamma}" == "1" ]]; then
    deploy_gamma_twin
  fi
}

main "$@"
