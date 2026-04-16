#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
source "${REPO_ROOT}/tools/lambda_artifact_helper.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-enceladus-neo4j-backup${ENVIRONMENT_SUFFIX}}"
ROLE_NAME="${ROLE_NAME:-enceladus-neo4j-backup-lambda-role${ENVIRONMENT_SUFFIX}}"
S3_BUCKET="${S3_BUCKET:-jreese-net}"
S3_PREFIX="${S3_PREFIX:-neo4j-backups/}"
NEO4J_SECRET_NAME="${NEO4J_SECRET_NAME:-enceladus/neo4j/auradb-credentials}"

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

  log "[INFO] Attaching inline policy"
  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "neo4j-backup-policy${ENVIRONMENT_SUFFIX}" \
    --policy-document "{
      \"Version\": \"2012-10-17\",
      \"Statement\": [
        {
          \"Sid\": \"CloudWatchLogs\",
          \"Effect\": \"Allow\",
          \"Action\": [\"logs:CreateLogGroup\", \"logs:CreateLogStream\", \"logs:PutLogEvents\"],
          \"Resource\": \"arn:aws:logs:${REGION}:${ACCOUNT_ID}:*\"
        },
        {
          \"Sid\": \"SecretsManagerNeo4j\",
          \"Effect\": \"Allow\",
          \"Action\": [\"secretsmanager:GetSecretValue\"],
          \"Resource\": \"arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:${NEO4J_SECRET_NAME}*\"
        },
        {
          \"Sid\": \"S3BackupWrite\",
          \"Effect\": \"Allow\",
          \"Action\": [\"s3:PutObject\"],
          \"Resource\": \"arn:aws:s3:::${S3_BUCKET}/${S3_PREFIX}*\"
        }
      ]
    }" \
    --region "${REGION}" >/dev/null
}

package_lambda() {
  local build_dir zip_path pip_platform pip_pyver pip_abi
  build_dir="$(mktemp -d /tmp/deploy-${FUNCTION_NAME}-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"
  # ENC-TSK-E27: try S3 artifact first
  local resolved_zip
  if resolved_zip="$(resolve_artifact "${FUNCTION_NAME}" "${zip_path}")"; then
    echo "${resolved_zip}"
    return 0
  fi


  # Environment-conditional: prod=x86_64/py3.11, gamma=arm64/py3.12
  if [ -n "${ENVIRONMENT_SUFFIX:-}" ]; then
    pip_platform="manylinux2014_aarch64"; pip_pyver="3.12"; pip_abi="cp312"
  else
    pip_platform="manylinux2014_x86_64"; pip_pyver="3.11"; pip_abi="cp311"
  fi

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"

  python3 -m pip install \
    --quiet --upgrade \
    --platform "${pip_platform}" \
    --implementation cp --python-version "${pip_pyver}" --abi "${pip_abi}" \
    --only-binary=:all: \
    -r "${SCRIPT_DIR}/requirements.txt" \
    -t "${build_dir}" >/dev/null

  (cd "${build_dir}" && zip -qr "${zip_path}" .)
  rm -rf "${build_dir}"
  echo "${zip_path}"
}

deploy_lambda() {
  local zip_path="$1"
  local role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] Updating existing function ${FUNCTION_NAME}"
    local arch_flag="x86_64" runtime_flag="python3.11"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && arch_flag="arm64" && runtime_flag="python3.12"
    # ENC-TSK-E19: verify package arch matches Lambda runtime before upload
    E19_REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null)}"
    E19_EXPECTED_ARCH="x86_64"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && E19_EXPECTED_ARCH="arm64"
    python3 "${E19_REPO_ROOT}/tools/verify_lambda_package_arch.py" \
      --package "${zip_path}" \
      --expected-arch "${E19_EXPECTED_ARCH}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --zip-file "fileb://${zip_path}" \
      --region "${REGION}" --architectures "${arch_flag}" >/dev/null
    aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
    aws lambda update-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${runtime_flag}" \
      --handler lambda_function.lambda_handler \
      --role "${role_arn}" \
      --timeout 300 \
      --memory-size 512 \
      --environment "Variables={NEO4J_SECRET_NAME=${NEO4J_SECRET_NAME},S3_BUCKET=${S3_BUCKET},S3_PREFIX=${S3_PREFIX},SECRETS_REGION=${REGION}}" \
      --region "${REGION}" >/dev/null
  else
    log "[INFO] Creating new function ${FUNCTION_NAME}"
    aws lambda create-function \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${runtime_flag}" \
      --architectures "${arch_flag}" \
      --handler lambda_function.lambda_handler \
      --role "${role_arn}" \
      --zip-file "fileb://${zip_path}" \
      --timeout 300 \
      --memory-size 512 \
      --environment "Variables={NEO4J_SECRET_NAME=${NEO4J_SECRET_NAME},S3_BUCKET=${S3_BUCKET},S3_PREFIX=${S3_PREFIX},SECRETS_REGION=${REGION}}" \
      --region "${REGION}" >/dev/null
  fi
  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}" 2>/dev/null || true
  log "[SUCCESS] Lambda ${FUNCTION_NAME} deployed"
}

main() {
  log "=========================================="
  log "Deploying Neo4j backup Lambda"
  log "=========================================="

  ensure_role
  local zip_path
  zip_path="$(package_lambda)"
  deploy_lambda "${zip_path}"
  rm -f "${zip_path}"

  log "=========================================="
  log "[SUCCESS] Neo4j backup Lambda deployed"
  log "=========================================="
}

main "$@"
