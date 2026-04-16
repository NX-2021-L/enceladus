#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# deploy.sh — Deploy tracker_mutation Lambda (devops-tracker-mutation-api)
#
# Manages: Lambda code, environment variables, API Gateway routes.
# Full CRUD API for the Enceladus project tracker.
#
# Related: ENC-TSK-564 (Phase 2a)
# ---------------------------------------------------------------------------

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"

REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
source "${REPO_ROOT}/tools/lambda_artifact_helper.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-tracker-mutation-api${ENVIRONMENT_SUFFIX}}"
API_ID="${API_ID:-8nkzqkmxqc}"

# Cognito config
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"

# Internal API key (resolved from env or existing Lambda config)
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
COORDINATION_INTERNAL_API_KEY_PREVIOUS="${COORDINATION_INTERNAL_API_KEY_PREVIOUS:-}"
COORDINATION_INTERNAL_API_KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES:-}"
COORDINATION_API_FUNCTION_NAME="${COORDINATION_API_FUNCTION_NAME:-devops-coordination-api${ENVIRONMENT_SUFFIX}}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

resolve_internal_api_key() {
  local coord_env_json
  coord_env_json="$(aws lambda get-function-configuration \
    --function-name "${COORDINATION_API_FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null || echo '{}')"
  if [[ "${coord_env_json}" == "None" || -z "${coord_env_json}" ]]; then
    coord_env_json='{}'
  fi
  if [[ -n "${COORDINATION_INTERNAL_API_KEY}" ]]; then
    printf '%s' "${COORDINATION_INTERNAL_API_KEY}"
    return
  fi
  local coordination_key
  coordination_key="$(COORD_ENV_JSON="${coord_env_json}" python3 - <<'PY'
import json, os
env = json.loads(os.environ.get("COORD_ENV_JSON", "{}"))
if not isinstance(env, dict):
    env = {}
for name in (
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY",
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
    "COORDINATION_INTERNAL_API_KEY",
):
    value = str(env.get(name, "")).strip()
    if value:
        print(value)
        break
PY
)"
  if [[ "${coordination_key}" != "None" && -n "${coordination_key}" ]]; then
    printf '%s' "${coordination_key}"
    return
  fi
  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" == "None" || -z "${existing}" ]]; then
    existing=""
  fi
  printf '%s' "${existing}"
}

resolve_internal_api_keys_csv() {
  local primary_key="$1"
  local coord_env_json
  coord_env_json="$(aws lambda get-function-configuration \
    --function-name "${COORDINATION_API_FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null || echo '{}')"
  if [[ "${coord_env_json}" == "None" || -z "${coord_env_json}" ]]; then
    coord_env_json='{}'
  fi
  COORD_ENV_JSON="${coord_env_json}" PRIMARY_KEY="${primary_key}" python3 - <<'PY'
import json, os
env = json.loads(os.environ.get("COORD_ENV_JSON", "{}"))
if not isinstance(env, dict):
    env = {}
seen = set()
items = []
def add(raw):
    for part in str(raw or "").split(","):
        key = part.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        items.append(key)
add(env.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS", ""))
add(env.get("ENCELADUS_COORDINATION_INTERNAL_API_KEYS", ""))
add(env.get("COORDINATION_INTERNAL_API_KEYS", ""))
add(env.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEY", ""))
add(env.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", ""))
add(env.get("COORDINATION_INTERNAL_API_KEY", ""))
add(env.get("ENCELADUS_COORDINATION_API_INTERNAL_API_KEY_PREVIOUS", ""))
add(env.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY_PREVIOUS", ""))
add(env.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", ""))
add(os.environ.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", ""))
add(os.environ.get("PRIMARY_KEY", ""))
print(",".join(items))
PY
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
  cp "${SCRIPT_DIR}/transition_type_matrix.py" "${build_dir}/"

  # NOTE: PyJWT is provided by the enceladus-shared Lambda layer (shared_layer/deploy.sh).
  # Do NOT bundle dependencies here - cross-platform binary compatibility issues.

  (
    cd "${build_dir}"
    zip -qr "${zip_path}" .
  )
  rm -rf "${build_dir}"
  echo "${zip_path}"
}

deploy_lambda() {
  local zip_path="$1"

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

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  log "[END] Lambda updated: ${FUNCTION_NAME}"
}

ensure_env_vars() {
  log "[START] Setting Lambda environment variables"

  local effective_key
  effective_key="$(resolve_internal_api_key)"
  local effective_keys_csv
  effective_keys_csv="$(resolve_internal_api_keys_csv "${effective_key}")"
  if [[ -z "${effective_key}" && -z "${effective_keys_csv}" ]]; then
    log "[ERROR] refusing deploy with empty internal auth key set for ${FUNCTION_NAME}"
    exit 1
  fi

  local env_json existing_env_json
  existing_env_json="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null || echo '{}')"
  [[ "${existing_env_json}" == "None" || -z "${existing_env_json}" ]] && existing_env_json='{}'

  local dynamodb_table="devops-project-tracker${ENVIRONMENT_SUFFIX}"
  local projects_table="projects${ENVIRONMENT_SUFFIX}"

  env_json="$(EXISTING_ENV_JSON="${existing_env_json}" \
    COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID}" \
    COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID}" \
    DYNAMODB_REGION="${REGION}" \
    DYNAMODB_TABLE="${dynamodb_table}" \
    PROJECTS_TABLE="${projects_table}" \
    EFFECTIVE_KEY="${effective_key}" \
    EFFECTIVE_KEY_PREVIOUS="${COORDINATION_INTERNAL_API_KEY_PREVIOUS}" \
    EFFECTIVE_KEYS_CSV="${effective_keys_csv}" \
    KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES}" \
    python3 - <<'PY'
import json
import os

env = json.loads(os.environ.get("EXISTING_ENV_JSON", "{}"))
if not isinstance(env, dict):
    env = {}

effective_key = (os.environ.get("EFFECTIVE_KEY", "") or "").strip() or str(
    env.get("COORDINATION_INTERNAL_API_KEY", "")
).strip()
effective_prev = (os.environ.get("EFFECTIVE_KEY_PREVIOUS", "") or "").strip() or str(
    env.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", "")
).strip()
effective_keys = (os.environ.get("EFFECTIVE_KEYS_CSV", "") or "").strip() or str(
    env.get("COORDINATION_INTERNAL_API_KEYS", "")
).strip()
effective_scopes = (os.environ.get("KEY_SCOPES", "") or "").strip() or str(
    env.get("COORDINATION_INTERNAL_API_KEY_SCOPES", "")
).strip()

env.update(
    {
        "COGNITO_USER_POOL_ID": os.environ.get("COGNITO_USER_POOL_ID", "us-east-1_b2D0V3E1k"),
        "COGNITO_CLIENT_ID": os.environ.get("COGNITO_CLIENT_ID", "6q607dk3liirhtecgps7hifmlk"),
        "DYNAMODB_TABLE": os.environ.get("DYNAMODB_TABLE", "devops-project-tracker"),
        "DYNAMODB_REGION": os.environ.get("DYNAMODB_REGION", "us-west-2"),
        "PROJECTS_TABLE": os.environ.get("PROJECTS_TABLE", "projects"),
        "COORDINATION_INTERNAL_API_KEY": effective_key,
        "COORDINATION_INTERNAL_API_KEY_PREVIOUS": effective_prev,
        "ENCELADUS_COORDINATION_INTERNAL_API_KEY": effective_key,
        "ENCELADUS_COORDINATION_INTERNAL_API_KEY_PREVIOUS": effective_prev,
        "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY": effective_key,
        "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY_PREVIOUS": effective_prev,
        "COORDINATION_INTERNAL_API_KEYS": effective_keys,
        "ENCELADUS_COORDINATION_INTERNAL_API_KEYS": effective_keys,
        "ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS": effective_keys,
        "COORDINATION_INTERNAL_API_KEY_SCOPES": effective_scopes,
        "CORS_ORIGIN": "https://jreese.net",
        "ENABLE_LESSON_PRIMITIVE": "true",
    }
)

print(json.dumps({"Variables": env}, separators=(",", ":")))
PY
)"

  aws lambda update-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --environment "${env_json}" >/dev/null

  aws lambda wait function-updated-v2 \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  if [[ -n "${effective_key}" ]]; then
    log "[OK] COORDINATION_INTERNAL_API_KEY set"
  else
    log "[WARN] COORDINATION_INTERNAL_API_KEY empty — internal-key auth disabled"
  fi
  log "[END] Environment variables configured"
}

ensure_api_routes() {
  local target_arn integration_id
  target_arn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"

  # Find existing integration
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
    # Existing PWA routes
    "PATCH /api/v1/tracker/{projectId}/{recordType}/{recordId}"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}"
    # New CRUD routes (Phase 2a)
    "GET /api/v1/tracker/pending-updates"
    "GET /api/v1/tracker/{projectId}"
    "GET /api/v1/tracker/{projectId}/{recordType}/{recordId}"
    "POST /api/v1/tracker/{projectId}/{recordType}"
    "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/log"
    "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout"
    "DELETE /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout"
    "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/acceptance-evidence"
    # ENC-FTR-052: Lesson extend sub-resource
    "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/extend"
    # ENC-FTR-049: Typed relationship edge routes
    "GET /api/v1/tracker/{projectId}/relationship"
    "DELETE /api/v1/tracker/{projectId}/relationship"
    "OPTIONS /api/v1/tracker/{projectId}/relationship"
    # OPTIONS for new routes
    "OPTIONS /api/v1/tracker/pending-updates"
    "OPTIONS /api/v1/tracker/{projectId}"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/log"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/acceptance-evidence"
    "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/extend"
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
      existing_route_keys="${existing_route_keys}"$'\n'"${route_key}"
    else
      log "[OK] route exists: ${route_key}"
    fi
  done

  # Ensure Lambda invoke permission for API Gateway
  local stmt_id
  stmt_id="allow-apigw-${API_ID}-tracker-crud"
  if aws lambda add-permission \
    --region "${REGION}" \
    --function-name "${FUNCTION_NAME}" \
    --statement-id "${stmt_id}" \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/tracker/*" >/dev/null 2>&1; then
    log "[OK] lambda invoke permission added"
  else
    log "[OK] lambda invoke permission already present"
  fi

  # Deploy API changes
  aws apigatewayv2 create-deployment \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --description "Deploy tracker CRUD routes $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null || true

  log "[END] API routes ready"
}

main() {
  log "=========================================="
  log "Deploying tracker_mutation Lambda"
  log "=========================================="

  log ""
  log "--- Packaging ---"
  local zip_path
  zip_path="$(package_lambda)"
  log "[OK] Package: ${zip_path}"

  log ""
  log "--- Deploying Code ---"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"

  log ""
  log "--- Configuring Env Vars ---"
  ensure_env_vars

  log ""
  log "--- Configuring API Routes ---"
  if [[ -z "${ENVIRONMENT_SUFFIX}" ]]; then
    ensure_api_routes
  else
    log "[SKIP] API route configuration skipped for suffixed environment (${ENVIRONMENT_SUFFIX})"
  fi

  log ""
  log "=========================================="
  log "[SUCCESS] tracker_mutation Lambda deployed"
  log "=========================================="
}

main "$@"
