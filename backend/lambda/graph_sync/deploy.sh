#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT_SUFFIX="${ENVIRONMENT_SUFFIX:-}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-graph-sync${ENVIRONMENT_SUFFIX}}"
ROLE_NAME="${ROLE_NAME:-devops-graph-sync-lambda-role${ENVIRONMENT_SUFFIX}}"
SQS_QUEUE_NAME="devops-graph-sync-queue${ENVIRONMENT_SUFFIX}.fifo"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

ensure_role() {
  if ! aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
    log "[START] creating IAM role ${ROLE_NAME}"
    aws iam create-role \
      --role-name "${ROLE_NAME}" \
      --assume-role-policy-document '{
        "Version":"2012-10-17",
        "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
      }' >/dev/null
    log "[END] created IAM role ${ROLE_NAME}"
    sleep 5
  else
    log "[OK] IAM role exists: ${ROLE_NAME}"
  fi

  log "[START] updating IAM inline policy for ${ROLE_NAME}"
  local policy_file
  policy_file="$(mktemp /tmp/graph-sync-policy-XXXXXX.json)"
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
      "Resource": "arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:enceladus/neo4j/auradb-credentials*"
    },
    {
      "Sid": "SQSGraphSyncQueue",
      "Effect": "Allow",
      "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
      "Resource": "arn:aws:sqs:${REGION}:${ACCOUNT_ID}:${SQS_QUEUE_NAME}"
    },
    {
      "Sid": "BedrockTitanV2InvokeModel",
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel"],
      "Resource": [
        "arn:aws:bedrock:${REGION}::foundation-model/amazon.titan-embed-text-v2:0"
      ]
    }
  ]
}
POLICY
  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "devops-graph-sync-inline" \
    --policy-document "file://${policy_file}" >/dev/null
  rm -f "${policy_file}"
  log "[END] IAM inline policy updated"
}

package_lambda() {
  local build_dir zip_path pip_platform pip_pyver pip_abi
  build_dir="$(mktemp -d /tmp/graph-sync-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  # Environment-conditional: prod=x86_64/py3.11, gamma=arm64/py3.12
  if [ -n "${ENVIRONMENT_SUFFIX:-}" ]; then
    pip_platform="manylinux2014_aarch64"; pip_pyver="3.12"; pip_abi="cp312"
  else
    pip_platform="manylinux2014_x86_64"; pip_pyver="3.11"; pip_abi="cp311"
  fi

  cp "${ROOT_DIR}/lambda_function.py" "${build_dir}/"
  # ENC-TSK-B94: colocated Titan V2 embedding helpers imported by
  # lambda_function.py. Must be packaged alongside the handler module.
  cp "${ROOT_DIR}/embedding.py" "${build_dir}/"

  python3 -m pip install \
    --quiet \
    --upgrade \
    --platform "${pip_platform}" \
    --implementation cp \
    --python-version "${pip_pyver}" \
    --abi "${pip_abi}" \
    --only-binary=:all: \
    -r "${ROOT_DIR}/requirements.txt" \
    -t "${build_dir}" >/dev/null

  (
    cd "${build_dir}"
    zip -qr "${zip_path}" .
  )

  rm -rf "${build_dir}"
  echo "${zip_path}"
}

ensure_lambda() {
  local zip_path role_arn env_file
  zip_path="$(package_lambda)"
  role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[START] updating Lambda code: ${FUNCTION_NAME}"
    local arch_flag="x86_64"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && arch_flag="arm64"
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
      --architectures "${arch_flag}" \
      --zip-file "fileb://${zip_path}" >/dev/null
  else
    local runtime="python3.11" arch="x86_64"
    [ -n "${ENVIRONMENT_SUFFIX:-}" ] && runtime="python3.12" && arch="arm64"
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime "${runtime}" \
      --architectures "${arch}" \
      --handler lambda_function.handler \
      --role "${role_arn}" \
      --timeout 60 \
      --memory-size 256 \
      --zip-file "fileb://${zip_path}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"

  env_file="$(mktemp /tmp/${FUNCTION_NAME}-env-XXXXXX.json)"
  cat > "${env_file}" <<ENV_JSON
{
  "Variables": {
    "NEO4J_SECRET_NAME": "enceladus/neo4j/auradb-credentials",
    "SECRETS_REGION": "${REGION}"
  }
}
ENV_JSON

  local cfg_attempt=1 cfg_max=6 cfg_sleep=10
  while :; do
    if aws lambda update-function-configuration \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --role "${role_arn}" \
      --timeout 60 \
      --memory-size 256 \
      --environment "file://${env_file}" >/dev/null; then
      break
    fi
    if [[ "${cfg_attempt}" -ge "${cfg_max}" ]]; then
      echo "[ERROR] update-function-configuration failed after ${cfg_attempt} attempts" >&2
      rm -f "${env_file}"
      return 1
    fi
    log "[WARNING] update-function-configuration conflict; retrying in ${cfg_sleep}s (attempt ${cfg_attempt}/${cfg_max})"
    sleep "${cfg_sleep}"
    aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}" || true
    cfg_attempt=$((cfg_attempt + 1))
  done
  rm -f "${env_file}"

  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  log "[END] Lambda ready: ${FUNCTION_NAME}"
}

main() {
  ensure_role
  ensure_lambda
  log "[SUCCESS] graph-sync deploy complete"
}

main "$@"
