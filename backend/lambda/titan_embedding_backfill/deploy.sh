#!/usr/bin/env bash
# ENC-TSK-B91 — devops-titan-embedding-backfill Lambda deploy script.
#
# Mirrors the deploy conventions used by devops-graph-sync and
# enceladus-neo4j-backup (environment-conditional arch: prod=x86_64/py3.11,
# gamma=arm64/py3.12). See backend/lambda/graph_sync/deploy.sh for the
# canonical pattern this script follows.
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-titan-embedding-backfill${ENVIRONMENT_SUFFIX}}"
ROLE_NAME="${ROLE_NAME:-devops-titan-embedding-backfill-lambda-role${ENVIRONMENT_SUFFIX}}"
NEO4J_SECRET_NAME="${NEO4J_SECRET_NAME:-enceladus/neo4j/auradb-credentials}"
TRACKER_TABLE="${TRACKER_TABLE:-devops-project-tracker}"
DOCUMENTS_TABLE="${DOCUMENTS_TABLE:-documents}"
BEDROCK_MODEL_ID="${BEDROCK_MODEL_ID:-amazon.titan-embed-text-v2:0}"

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

# ---------------------------------------------------------------------------
# IAM role
# ---------------------------------------------------------------------------

ensure_role() {
  if aws iam get-role --role-name "${ROLE_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] IAM role exists: ${ROLE_NAME}"
  else
    log "[INFO] Creating IAM role: ${ROLE_NAME}"
    aws iam create-role \
      --role-name "${ROLE_NAME}" \
      --assume-role-policy-document '{
        "Version":"2012-10-17",
        "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
      }' \
      --region "${REGION}" >/dev/null
    sleep 10
  fi

  log "[INFO] Attaching inline policy to ${ROLE_NAME}"
  local policy_file
  policy_file="$(mktemp /tmp/titan-embed-backfill-policy-XXXXXX.json)"
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
      "Sid": "SecretsManagerNeo4j",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:${NEO4J_SECRET_NAME}*"
    },
    {
      "Sid": "BedrockTitanEmbedV2Invoke",
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel"],
      "Resource": "arn:aws:bedrock:${REGION}::foundation-model/${BEDROCK_MODEL_ID}"
    },
    {
      "Sid": "DynamoDBReadTracker",
      "Effect": "Allow",
      "Action": ["dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem", "dynamodb:BatchGetItem"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TRACKER_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TRACKER_TABLE}/index/*",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DOCUMENTS_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DOCUMENTS_TABLE}/index/*"
      ]
    }
  ]
}
POLICY
  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "titan-embed-backfill-inline${ENVIRONMENT_SUFFIX}" \
    --policy-document "file://${policy_file}" \
    --region "${REGION}" >/dev/null
  rm -f "${policy_file}"
}

# ---------------------------------------------------------------------------
# Package
# ---------------------------------------------------------------------------

package_lambda() {
  local build_dir zip_path pip_platform pip_pyver pip_abi
  build_dir="$(mktemp -d /tmp/titan-embed-backfill-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  # Environment-conditional: prod=x86_64/py3.11, gamma=arm64/py3.12
  if [ -n "${ENVIRONMENT_SUFFIX:-}" ]; then
    pip_platform="manylinux2014_aarch64"; pip_pyver="3.12"; pip_abi="cp312"
  else
    pip_platform="manylinux2014_x86_64"; pip_pyver="3.11"; pip_abi="cp311"
  fi

  cp "${SCRIPT_DIR}/lambda_function.py" "${build_dir}/"
  # Bundle the CANONICAL embedding helper from graph_sync (ENC-TSK-B94).
  # Copying it into this build dir guarantees the batch backfill and the
  # incremental graph_sync stream path share the same text-extraction,
  # hashing, and Bedrock invoke contracts. Any contract change must
  # happen upstream in backend/lambda/graph_sync/embedding.py.
  cp "${REPO_ROOT}/backend/lambda/graph_sync/embedding.py" \
     "${build_dir}/embedding.py"

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

# ---------------------------------------------------------------------------
# Lambda create / update
# ---------------------------------------------------------------------------

ensure_lambda() {
  local zip_path role_arn env_file
  zip_path="$(package_lambda)"
  role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

  local arch_flag="x86_64" runtime_flag="python3.11"
  [ -n "${ENVIRONMENT_SUFFIX:-}" ] && arch_flag="arm64" && runtime_flag="python3.12"

  env_file="$(mktemp /tmp/${FUNCTION_NAME}-env-XXXXXX.json)"
  cat > "${env_file}" <<ENV_JSON
{
  "Variables": {
    "NEO4J_SECRET_NAME": "${NEO4J_SECRET_NAME}",
    "SECRETS_REGION": "${REGION}",
    "DDB_REGION": "${REGION}",
    "BEDROCK_REGION": "${REGION}",
    "TRACKER_TABLE": "${TRACKER_TABLE}",
    "DOCUMENTS_TABLE": "${DOCUMENTS_TABLE}"
  }
}
ENV_JSON

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[INFO] Updating existing Lambda: ${FUNCTION_NAME}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --zip-file "fileb://${zip_path}" \
      --architectures "${arch_flag}" \
      --region "${REGION}" >/dev/null
    aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
    aws lambda update-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${runtime_flag}" \
      --handler lambda_function.lambda_handler \
      --role "${role_arn}" \
      --timeout 900 \
      --memory-size 1024 \
      --environment "file://${env_file}" \
      --region "${REGION}" >/dev/null
  else
    log "[INFO] Creating new Lambda: ${FUNCTION_NAME}"
    aws lambda create-function \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${runtime_flag}" \
      --architectures "${arch_flag}" \
      --handler lambda_function.lambda_handler \
      --role "${role_arn}" \
      --zip-file "fileb://${zip_path}" \
      --timeout 900 \
      --memory-size 1024 \
      --environment "file://${env_file}" \
      --region "${REGION}" >/dev/null
  fi

  rm -f "${env_file}"
  rm -f "${zip_path}"
  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}" 2>/dev/null || true
  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}" 2>/dev/null || true
  log "[SUCCESS] Lambda deployed: ${FUNCTION_NAME}"
}

main() {
  log "=========================================="
  log "Deploying ${FUNCTION_NAME}"
  log "=========================================="
  ensure_role
  ensure_lambda
  log "[SUCCESS] titan-embedding-backfill deploy complete"
}

main "$@"
