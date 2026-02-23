#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
API_ID="${API_ID:-8nkzqkmxqc}"
FUNCTION_NAME="${FUNCTION_NAME:-devops-coordination-api}"
ROLE_NAME="${ROLE_NAME:-devops-coordination-api-lambda-role}"
TABLE_NAME="${TABLE_NAME:-coordination-requests}"
TRACKER_TABLE="${TRACKER_TABLE:-devops-project-tracker}"
PROJECTS_TABLE="${PROJECTS_TABLE:-projects}"
HOST_V2_INSTANCE_ID="${HOST_V2_INSTANCE_ID:-i-0523f94e99ec15a1e}"
HOST_V2_ENCELADUS_MCP_INSTALLER="${HOST_V2_ENCELADUS_MCP_INSTALLER:-tools/enceladus-mcp-server/install_profile.sh}"
HOST_V2_MCP_PROFILE_PATH="${HOST_V2_MCP_PROFILE_PATH:-.claude/mcp.json}"
HOST_V2_MCP_MARKER_PATH="${HOST_V2_MCP_MARKER_PATH:-.cache/enceladus/mcp-profile-installed-v1.json}"
HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS="${HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS:-4}"
HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS="${HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS:-2,5,10}"
HOST_V2_MCP_BOOTSTRAP_SCRIPT="${HOST_V2_MCP_BOOTSTRAP_SCRIPT:-tools/enceladus-mcp-server/host_v2_first_bootstrap.sh}"
HOST_V2_FLEET_LAUNCH_TEMPLATE_ID="${HOST_V2_FLEET_LAUNCH_TEMPLATE_ID:-}"
HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION="${HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION:-\$Default}"
HOST_V2_FLEET_USER_DATA_TEMPLATE="${HOST_V2_FLEET_USER_DATA_TEMPLATE:-tools/enceladus-mcp-server/host_v2_user_data_template.sh}"
ENCELADUS_MCP_SERVER_PATH="${ENCELADUS_MCP_SERVER_PATH:-tools/enceladus-mcp-server/server.py}"
S3_BUCKET="${S3_BUCKET:-jreese-net}"
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
SECRETS_REGION="${SECRETS_REGION:-us-west-2}"
OPENAI_API_KEY_SECRET_ID="${OPENAI_API_KEY_SECRET_ID:-devops/coordination/openai/api-key}"
ANTHROPIC_API_KEY_SECRET_ID="${ANTHROPIC_API_KEY_SECRET_ID:-devops/coordination/anthropic/api-key}"
ENABLE_CLAUDE_HEADLESS="${ENABLE_CLAUDE_HEADLESS:-true}"
DEBOUNCE_WINDOW_SECONDS="${DEBOUNCE_WINDOW_SECONDS:-180}"
DISPATCH_LOCK_BUFFER_SECONDS="${DISPATCH_LOCK_BUFFER_SECONDS:-60}"
DEAD_LETTER_TIMEOUT_MULTIPLIER="${DEAD_LETTER_TIMEOUT_MULTIPLIER:-2}"
DEAD_LETTER_SNS_TOPIC_ARN="${DEAD_LETTER_SNS_TOPIC_ARN:-}"
MCP_SERVER_LOG_GROUP="${MCP_SERVER_LOG_GROUP:-/enceladus/mcp/server}"
WORKER_RUNTIME_LOG_GROUP="${WORKER_RUNTIME_LOG_GROUP:-/enceladus/coordination/worker-runtime}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-90}"
BEDROCK_AGENT_ROLE_ARN="${BEDROCK_AGENT_ROLE_ARN:-arn:aws:iam::${ACCOUNT_ID}:role/enceladus-bedrock-agent-execution-role}"
BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN="${BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN:-arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:enceladus-bedrock-agent-actions}"
BEDROCK_AGENT_DEFAULT_MODEL="${BEDROCK_AGENT_DEFAULT_MODEL:-anthropic.claude-3-5-sonnet-20241022-v2:0}"
BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS="${BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS:-120}"
BEDROCK_AGENT_CLEANUP="${BEDROCK_AGENT_CLEANUP:-true}"
BEDROCK_AGENT_REGION="${BEDROCK_AGENT_REGION:-${REGION}}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

ensure_table() {
  if aws dynamodb describe-table --table-name "${TABLE_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] DynamoDB table exists: ${TABLE_NAME}"
    return
  fi

  log "[START] creating DynamoDB table ${TABLE_NAME}"
  aws dynamodb create-table \
    --region "${REGION}" \
    --table-name "${TABLE_NAME}" \
    --billing-mode PAY_PER_REQUEST \
    --attribute-definitions \
      AttributeName=request_id,AttributeType=S \
      AttributeName=project_id,AttributeType=S \
      AttributeName=updated_epoch,AttributeType=N \
      AttributeName=idempotency_key,AttributeType=S \
      AttributeName=created_epoch,AttributeType=N \
    --key-schema \
      AttributeName=request_id,KeyType=HASH \
    --global-secondary-indexes \
      '[
        {
          "IndexName": "project-updated-index",
          "KeySchema": [
            {"AttributeName": "project_id", "KeyType": "HASH"},
            {"AttributeName": "updated_epoch", "KeyType": "RANGE"}
          ],
          "Projection": {"ProjectionType": "ALL"}
        },
        {
          "IndexName": "idempotency-key-index",
          "KeySchema": [
            {"AttributeName": "idempotency_key", "KeyType": "HASH"},
            {"AttributeName": "created_epoch", "KeyType": "RANGE"}
          ],
          "Projection": {"ProjectionType": "ALL"}
        }
      ]'

  aws dynamodb wait table-exists --table-name "${TABLE_NAME}" --region "${REGION}"
  log "[END] DynamoDB table created: ${TABLE_NAME}"
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
  policy_file="$(mktemp /tmp/devops-coordination-policy-XXXXXX.json)"
  cat > "${policy_file}" <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": [
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:/aws/lambda/${FUNCTION_NAME}*",
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${MCP_SERVER_LOG_GROUP}*",
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${WORKER_RUNTIME_LOG_GROUP}*"
      ]
    },
    {
      "Sid": "CoordinationTableAccess",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TABLE_NAME}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TABLE_NAME}/index/*"
      ]
    },
    {
      "Sid": "TrackerTableAccess",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TRACKER_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${TRACKER_TABLE}/index/*"
      ]
    },
    {
      "Sid": "ProjectsTableRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${PROJECTS_TABLE}"
    },
    {
      "Sid": "SSMDispatch",
      "Effect": "Allow",
      "Action": ["ssm:SendCommand", "ssm:GetCommandInvocation", "ssm:ListCommands", "ssm:ListCommandInvocations"],
      "Resource": "*"
    },
    {
      "Sid": "EC2Describe",
      "Effect": "Allow",
      "Action": ["ec2:DescribeInstances"],
      "Resource": "*"
    },
    {
      "Sid": "ProviderSecretsRead",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": "arn:aws:secretsmanager:${SECRETS_REGION}:${ACCOUNT_ID}:secret:devops/coordination/*"
    },
    {
      "Sid": "BedrockAgentLifecycle",
      "Effect": "Allow",
      "Action": [
        "bedrock:CreateAgent",
        "bedrock:GetAgent",
        "bedrock:DeleteAgent",
        "bedrock:PrepareAgent",
        "bedrock:CreateAgentActionGroup",
        "bedrock:GetAgentActionGroup",
        "bedrock:DeleteAgentActionGroup",
        "bedrock:CreateAgentAlias",
        "bedrock:GetAgentAlias",
        "bedrock:DeleteAgentAlias",
        "bedrock:AssociateAgentKnowledgeBase",
        "bedrock:DisassociateAgentKnowledgeBase"
      ],
      "Resource": "arn:aws:bedrock:${REGION}:${ACCOUNT_ID}:agent/*"
    },
    {
      "Sid": "BedrockAgentInvoke",
      "Effect": "Allow",
      "Action": ["bedrock:InvokeAgent"],
      "Resource": "arn:aws:bedrock:${REGION}:${ACCOUNT_ID}:agent-alias/*"
    },
    {
      "Sid": "BedrockPassAgentRole",
      "Effect": "Allow",
      "Action": ["iam:PassRole"],
      "Resource": "${BEDROCK_AGENT_ROLE_ARN}",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "bedrock.amazonaws.com"
        }
      }
    }
  ]
}
POLICY
  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "devops-coordination-api-inline" \
    --policy-document "file://${policy_file}" >/dev/null
  rm -f "${policy_file}"
  log "[END] IAM inline policy updated"
}

ensure_observability_log_groups() {
  local groups=(
    "/aws/lambda/${FUNCTION_NAME}"
    "${MCP_SERVER_LOG_GROUP}"
    "${WORKER_RUNTIME_LOG_GROUP}"
  )
  for group in "${groups[@]}"; do
    if aws logs describe-log-groups --region "${REGION}" --log-group-name-prefix "${group}" --query "logGroups[?logGroupName=='${group}'].logGroupName | [0]" --output text | grep -qx "${group}"; then
      log "[OK] log group exists: ${group}"
    else
      log "[START] creating log group ${group}"
      aws logs create-log-group --region "${REGION}" --log-group-name "${group}" >/dev/null || true
      log "[END] created log group ${group}"
    fi
    aws logs put-retention-policy \
      --region "${REGION}" \
      --log-group-name "${group}" \
      --retention-in-days "${LOG_RETENTION_DAYS}" >/dev/null || true
    log "[OK] retention ${LOG_RETENTION_DAYS}d set for ${group}"
  done
}

resolve_internal_api_key() {
  if [[ -n "${COORDINATION_INTERNAL_API_KEY}" ]]; then
    printf '%s' "${COORDINATION_INTERNAL_API_KEY}"
    return
  fi

  local existing
  existing="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY' \
    --output text 2>/dev/null || true)"
  if [[ "${existing}" == "None" ]]; then
    existing=""
  fi
  printf '%s' "${existing}"
}

package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/devops-coordination-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"

  cp "${ROOT_DIR}/lambda_function.py" "${build_dir}/"
  cp "${ROOT_DIR}/mcp_client.py" "${build_dir}/"

  python3 -m pip install \
    --quiet \
    --upgrade \
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
  local zip_path role_arn effective_internal_key env_file
  zip_path="$(package_lambda)"
  role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

  if aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    log "[START] updating Lambda code: ${FUNCTION_NAME}"
    aws lambda update-function-code \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --zip-file "fileb://${zip_path}" >/dev/null
  else
    log "[START] creating Lambda function: ${FUNCTION_NAME}"
    aws lambda create-function \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --runtime python3.11 \
      --handler lambda_function.lambda_handler \
      --role "${role_arn}" \
      --timeout 120 \
      --memory-size 512 \
      --zip-file "fileb://${zip_path}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"

  effective_internal_key="$(resolve_internal_api_key)"
  if [[ -z "${effective_internal_key}" ]]; then
    log "[WARNING] COORDINATION_INTERNAL_API_KEY resolved empty; internal-key auth will be disabled."
  fi

  env_file="$(mktemp /tmp/${FUNCTION_NAME}-env-XXXXXX)"
  TABLE_NAME="${TABLE_NAME}" \
  TRACKER_TABLE="${TRACKER_TABLE}" \
  PROJECTS_TABLE="${PROJECTS_TABLE}" \
  REGION="${REGION}" \
  SECRETS_REGION="${SECRETS_REGION}" \
  OPENAI_API_KEY_SECRET_ID="${OPENAI_API_KEY_SECRET_ID}" \
  ANTHROPIC_API_KEY_SECRET_ID="${ANTHROPIC_API_KEY_SECRET_ID}" \
  ENABLE_CLAUDE_HEADLESS="${ENABLE_CLAUDE_HEADLESS}" \
  HOST_V2_INSTANCE_ID="${HOST_V2_INSTANCE_ID}" \
  HOST_V2_ENCELADUS_MCP_INSTALLER="${HOST_V2_ENCELADUS_MCP_INSTALLER}" \
  HOST_V2_MCP_PROFILE_PATH="${HOST_V2_MCP_PROFILE_PATH}" \
  HOST_V2_MCP_MARKER_PATH="${HOST_V2_MCP_MARKER_PATH}" \
  HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS="${HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS}" \
  HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS="${HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS}" \
  HOST_V2_MCP_BOOTSTRAP_SCRIPT="${HOST_V2_MCP_BOOTSTRAP_SCRIPT}" \
  HOST_V2_FLEET_LAUNCH_TEMPLATE_ID="${HOST_V2_FLEET_LAUNCH_TEMPLATE_ID}" \
  HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION="${HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION}" \
  HOST_V2_FLEET_USER_DATA_TEMPLATE="${HOST_V2_FLEET_USER_DATA_TEMPLATE}" \
  ENCELADUS_MCP_SERVER_PATH="${ENCELADUS_MCP_SERVER_PATH}" \
  DEBOUNCE_WINDOW_SECONDS="${DEBOUNCE_WINDOW_SECONDS}" \
  DISPATCH_LOCK_BUFFER_SECONDS="${DISPATCH_LOCK_BUFFER_SECONDS}" \
  DEAD_LETTER_TIMEOUT_MULTIPLIER="${DEAD_LETTER_TIMEOUT_MULTIPLIER}" \
  DEAD_LETTER_SNS_TOPIC_ARN="${DEAD_LETTER_SNS_TOPIC_ARN}" \
  MCP_SERVER_LOG_GROUP="${MCP_SERVER_LOG_GROUP}" \
  WORKER_RUNTIME_LOG_GROUP="${WORKER_RUNTIME_LOG_GROUP}" \
  BEDROCK_AGENT_ROLE_ARN="${BEDROCK_AGENT_ROLE_ARN}" \
  BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN="${BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN}" \
  BEDROCK_AGENT_DEFAULT_MODEL="${BEDROCK_AGENT_DEFAULT_MODEL}" \
  BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS="${BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS}" \
  BEDROCK_AGENT_CLEANUP="${BEDROCK_AGENT_CLEANUP}" \
  BEDROCK_AGENT_REGION="${BEDROCK_AGENT_REGION}" \
  FUNCTION_NAME="${FUNCTION_NAME}" \
  EFFECTIVE_INTERNAL_KEY="${effective_internal_key}" \
  python3 - "${env_file}" <<'PY'
import json
import os
import sys

path = sys.argv[1]
env_vars = {
    "COORDINATION_TABLE": os.environ["TABLE_NAME"],
    "TRACKER_TABLE": os.environ["TRACKER_TABLE"],
    "PROJECTS_TABLE": os.environ["PROJECTS_TABLE"],
    "DYNAMODB_REGION": os.environ["REGION"],
    "SSM_REGION": os.environ["REGION"],
    "SECRETS_REGION": os.environ["SECRETS_REGION"],
    "OPENAI_API_KEY_SECRET_ID": os.environ["OPENAI_API_KEY_SECRET_ID"],
    "ANTHROPIC_API_KEY_SECRET_ID": os.environ["ANTHROPIC_API_KEY_SECRET_ID"],
    "ENABLE_CLAUDE_HEADLESS": os.environ["ENABLE_CLAUDE_HEADLESS"],
    "COGNITO_USER_POOL_ID": "us-east-1_b2D0V3E1k",
    "COGNITO_CLIENT_ID": "6q607dk3liirhtecgps7hifmlk",
    "COORDINATION_INTERNAL_API_KEY": os.environ.get("EFFECTIVE_INTERNAL_KEY", ""),
    "HOST_V2_INSTANCE_ID": os.environ["HOST_V2_INSTANCE_ID"],
    "HOST_V2_ENCELADUS_MCP_INSTALLER": os.environ["HOST_V2_ENCELADUS_MCP_INSTALLER"],
    "HOST_V2_MCP_PROFILE_PATH": os.environ["HOST_V2_MCP_PROFILE_PATH"],
    "HOST_V2_MCP_MARKER_PATH": os.environ["HOST_V2_MCP_MARKER_PATH"],
    "HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS": os.environ["HOST_V2_MCP_BOOTSTRAP_MAX_ATTEMPTS"],
    "HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS": os.environ["HOST_V2_MCP_BOOTSTRAP_RETRY_BACKOFF_SECONDS"],
    "HOST_V2_MCP_BOOTSTRAP_SCRIPT": os.environ["HOST_V2_MCP_BOOTSTRAP_SCRIPT"],
    "HOST_V2_FLEET_LAUNCH_TEMPLATE_ID": os.environ["HOST_V2_FLEET_LAUNCH_TEMPLATE_ID"],
    "HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION": os.environ["HOST_V2_FLEET_LAUNCH_TEMPLATE_VERSION"],
    "HOST_V2_FLEET_USER_DATA_TEMPLATE": os.environ["HOST_V2_FLEET_USER_DATA_TEMPLATE"],
    "ENCELADUS_MCP_SERVER_PATH": os.environ["ENCELADUS_MCP_SERVER_PATH"],
    "HOST_V2_PROJECT": "devops",
    "HOST_V2_WORK_ROOT": "/home/ec2-user/claude-code-dev",
    "HOST_V2_AWS_PROFILE": "ec2-role",
    "CORS_ORIGIN": "https://jreese.net",
    "DEBOUNCE_WINDOW_SECONDS": os.environ["DEBOUNCE_WINDOW_SECONDS"],
    "DISPATCH_LOCK_BUFFER_SECONDS": os.environ["DISPATCH_LOCK_BUFFER_SECONDS"],
    "DEAD_LETTER_TIMEOUT_MULTIPLIER": os.environ["DEAD_LETTER_TIMEOUT_MULTIPLIER"],
    "DEAD_LETTER_SNS_TOPIC_ARN": os.environ["DEAD_LETTER_SNS_TOPIC_ARN"],
    "COORDINATION_GSI_IDEMPOTENCY": "idempotency-key-index",
    "MCP_SERVER_LOG_GROUP": os.environ["MCP_SERVER_LOG_GROUP"],
    "WORKER_RUNTIME_LOG_GROUP": os.environ["WORKER_RUNTIME_LOG_GROUP"],
    "MCP_AUDIT_CALLER_IDENTITY": os.environ["FUNCTION_NAME"],
    "BEDROCK_AGENT_ROLE_ARN": os.environ["BEDROCK_AGENT_ROLE_ARN"],
    "BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN": os.environ["BEDROCK_AGENT_ACTION_GROUP_LAMBDA_ARN"],
    "BEDROCK_AGENT_DEFAULT_MODEL": os.environ["BEDROCK_AGENT_DEFAULT_MODEL"],
    "BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS": os.environ["BEDROCK_AGENT_CREATION_TIMEOUT_SECONDS"],
    "BEDROCK_AGENT_CLEANUP": os.environ["BEDROCK_AGENT_CLEANUP"],
    "BEDROCK_AGENT_REGION": os.environ["BEDROCK_AGENT_REGION"],
}
with open(path, "w", encoding="utf-8") as f:
    json.dump({"Variables": env_vars}, f)
PY

  aws lambda update-function-configuration \
    --region "${REGION}" \
    --function-name "${FUNCTION_NAME}" \
    --role "${role_arn}" \
    --timeout 120 \
    --memory-size 512 \
    --environment "file://${env_file}" >/dev/null
  rm -f "${env_file}"

  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  log "[END] Lambda ready: ${FUNCTION_NAME}"
}

ensure_api_integration_and_routes() {
  local integration_id target_arn
  target_arn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"

  integration_id="$(aws apigatewayv2 get-integrations \
    --region "${REGION}" \
    --api-id "${API_ID}" \
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
    "POST /api/v1/coordination/requests"
    "GET /api/v1/coordination/requests/{requestId}"
    "POST /api/v1/coordination/requests/{requestId}/dispatch"
    "POST /api/v1/coordination/requests/{requestId}/callback"
    "GET /api/v1/coordination/capabilities"
    "OPTIONS /api/v1/coordination/requests"
    "OPTIONS /api/v1/coordination/requests/{requestId}"
    "OPTIONS /api/v1/coordination/requests/{requestId}/dispatch"
    "OPTIONS /api/v1/coordination/requests/{requestId}/callback"
    "OPTIONS /api/v1/coordination/capabilities"
  )

  for route_key in "${routes[@]}"; do
    local existing
    existing="$(aws apigatewayv2 get-routes \
      --region "${REGION}" \
      --api-id "${API_ID}" \
      --query "Items[?RouteKey=='${route_key}'].RouteId | [0]" \
      --output text)"

    if [[ -z "${existing}" || "${existing}" == "None" ]]; then
      log "[START] creating route: ${route_key}"
      aws apigatewayv2 create-route \
        --region "${REGION}" \
        --api-id "${API_ID}" \
        --route-key "${route_key}" \
        --target "integrations/${integration_id}" >/dev/null
      log "[END] route created: ${route_key}"
    else
      log "[OK] route exists: ${route_key}"
    fi
  done

  local stmt_id
  stmt_id="allow-apigw-${API_ID}-${FUNCTION_NAME}"
  if aws lambda add-permission \
    --region "${REGION}" \
    --function-name "${FUNCTION_NAME}" \
    --statement-id "${stmt_id}" \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/coordination/*" >/dev/null 2>&1; then
    log "[OK] lambda invoke permission added"
  else
    log "[OK] lambda invoke permission already present"
  fi

  aws apigatewayv2 create-deployment \
    --region "${REGION}" \
    --api-id "${API_ID}" \
    --description "Deploy ${FUNCTION_NAME} $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null || true

  log "[END] API routes and permissions ready"
}

smoke_hint() {
  cat <<EOF

[INFO] Smoke-test hint:
curl -sS -X GET 'https://jreese.net/api/v1/coordination/capabilities' --cookie 'enceladus_id_token=<token>'
EOF
}

main() {
  ensure_table
  ensure_role
  ensure_lambda
  ensure_observability_log_groups
  ensure_api_integration_and_routes
  smoke_hint
  log "[SUCCESS] coordination API deploy complete"
}

main "$@"
