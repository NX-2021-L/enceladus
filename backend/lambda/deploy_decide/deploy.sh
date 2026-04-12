#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"

# ---------------------------------------------------------------------------
# deploy.sh — Deploy deploy_decide Lambda (GMF DOC-63420302EF65)
# Cognito-only auth for production deployment governance decisions.
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-deploy-decide${ENVIRONMENT_SUFFIX}}"

DEPLOY_TABLE="${DEPLOY_TABLE:-devops-deployment-manager${ENVIRONMENT_SUFFIX}}"
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"
CORS_ORIGIN="${CORS_ORIGIN:-https://jreese.net}"
GITHUB_APP_ID="${GITHUB_APP_ID:-}"
GITHUB_INSTALLATION_ID="${GITHUB_INSTALLATION_ID:-}"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# ---------------------------------------------------------------------------
# Resolve GitHub App config from coordination-api if not set
# ---------------------------------------------------------------------------
resolve_github_config() {
  # ENC-ISS-204: Read existing Lambda env vars first to avoid clearing CFN-set values.
  # Priority: shell env > existing Lambda config > coordination-api fallback
  if [[ -z "${GITHUB_APP_ID}" ]]; then
    GITHUB_APP_ID="$(aws lambda get-function-configuration \
      --function-name "${FUNCTION_NAME}" --region "${REGION}" \
      --query 'Environment.Variables.GITHUB_APP_ID' --output text 2>/dev/null || true)"
    [[ "${GITHUB_APP_ID}" == "None" ]] && GITHUB_APP_ID=""
  fi
  if [[ -z "${GITHUB_INSTALLATION_ID}" ]]; then
    GITHUB_INSTALLATION_ID="$(aws lambda get-function-configuration \
      --function-name "${FUNCTION_NAME}" --region "${REGION}" \
      --query 'Environment.Variables.GITHUB_INSTALLATION_ID' --output text 2>/dev/null || true)"
    [[ "${GITHUB_INSTALLATION_ID}" == "None" ]] && GITHUB_INSTALLATION_ID=""
  fi
  # Fallback to coordination-api if still empty (first deploy before CFN sets values)
  local coord_fn="devops-coordination-api${ENVIRONMENT_SUFFIX}"
  if [[ -z "${GITHUB_APP_ID}" ]]; then
    GITHUB_APP_ID="$(aws lambda get-function-configuration \
      --function-name "${coord_fn}" --region "${REGION}" \
      --query 'Environment.Variables.GITHUB_APP_ID' --output text 2>/dev/null || true)"
    [[ "${GITHUB_APP_ID}" == "None" ]] && GITHUB_APP_ID=""
  fi
  if [[ -z "${GITHUB_INSTALLATION_ID}" ]]; then
    GITHUB_INSTALLATION_ID="$(aws lambda get-function-configuration \
      --function-name "${coord_fn}" --region "${REGION}" \
      --query 'Environment.Variables.GITHUB_INSTALLATION_ID' --output text 2>/dev/null || true)"
    [[ "${GITHUB_INSTALLATION_ID}" == "None" ]] && GITHUB_INSTALLATION_ID=""
  fi
  log "GitHub App ID: ${GITHUB_APP_ID:-NOT SET}"
  log "GitHub Installation ID: ${GITHUB_INSTALLATION_ID:-NOT SET}"
}

# ---------------------------------------------------------------------------
# Package Lambda
# ---------------------------------------------------------------------------
package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
    # v3 production lock: x86_64 / py3.11 unless targeting gamma (ENC-PLN-019)
    local pip_platform pip_pyver pip_abi
    if [ -n "${ENVIRONMENT_SUFFIX:-}" ]; then
      pip_platform="manylinux2014_aarch64"; pip_pyver="3.12"; pip_abi="cp312"
    else
      pip_platform="manylinux2014_x86_64"; pip_pyver="3.11"; pip_abi="cp311"
    fi
    python3 -m pip install \
      --quiet --upgrade \
      -r "${SCRIPT_DIR}/requirements.txt" \
      --platform "${pip_platform}" \
      --implementation cp \
      --python-version "${pip_pyver}" \
      --abi "${pip_abi}" \
      --only-binary=:all: \
      -t "${build_dir}" >/dev/null
  fi

  (cd "${build_dir}" && zip -qr "${zip_path}" .)
  rm -rf "${build_dir}"
  echo "${zip_path}"
}

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
main() {
  log "Deploying ${FUNCTION_NAME} (suffix='${ENVIRONMENT_SUFFIX}')"

  resolve_github_config

  log "Packaging Lambda..."
  local zip_path
  zip_path="$(package_lambda)"
  log "Package: ${zip_path} ($(du -h "${zip_path}" | cut -f1))"

  log "Updating Lambda code..."
  aws lambda update-function-code \
    --function-name "${FUNCTION_NAME}" \
    --zip-file "fileb://${zip_path}" \
    --region "${REGION}" >/dev/null

  log "Waiting for update..."
  aws lambda wait function-updated \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  log "Updating environment variables..."
  aws lambda update-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --environment "Variables={
      DEPLOY_TABLE=${DEPLOY_TABLE},
      DEPLOY_REGION=${REGION},
      COGNITO_USER_POOL_ID=${COGNITO_USER_POOL_ID},
      COGNITO_CLIENT_ID=${COGNITO_CLIENT_ID},
      CORS_ORIGIN=${CORS_ORIGIN},
      GITHUB_APP_ID=${GITHUB_APP_ID},
      GITHUB_INSTALLATION_ID=${GITHUB_INSTALLATION_ID},
      GITHUB_PRIVATE_KEY_SECRET=devops/github-app/private-key,
      ALLOWED_REPOS=NX-2021-L/enceladus,
      GAMMA_INTEGRATION_BRANCH=v4/main
    }" >/dev/null

  aws lambda wait function-updated \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}"

  log "[SUCCESS] ${FUNCTION_NAME} deployed"
  rm -f "${zip_path}"
}

main "$@"
