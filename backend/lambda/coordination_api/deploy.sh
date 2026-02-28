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
GOVERNANCE_POLICIES_TABLE="${GOVERNANCE_POLICIES_TABLE:-governance-policies}"
GOVERNANCE_DICTIONARY_POLICY_ID="${GOVERNANCE_DICTIONARY_POLICY_ID:-governance_data_dictionary}"
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
HOST_V2_FLEET_ENABLED="${HOST_V2_FLEET_ENABLED:-true}"
HOST_V2_FLEET_FALLBACK_TO_STATIC="${HOST_V2_FLEET_FALLBACK_TO_STATIC:-true}"
HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES="${HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES:-3}"
HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS="${HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS:-420}"
HOST_V2_FLEET_READINESS_POLL_SECONDS="${HOST_V2_FLEET_READINESS_POLL_SECONDS:-15}"
HOST_V2_FLEET_INSTANCE_TTL_SECONDS="${HOST_V2_FLEET_INSTANCE_TTL_SECONDS:-3600}"
HOST_V2_FLEET_SWEEP_ON_DISPATCH="${HOST_V2_FLEET_SWEEP_ON_DISPATCH:-true}"
HOST_V2_FLEET_SWEEP_GRACE_SECONDS="${HOST_V2_FLEET_SWEEP_GRACE_SECONDS:-300}"
HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL="${HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL:-true}"
HOST_V2_FLEET_TAG_MANAGED_BY_VALUE="${HOST_V2_FLEET_TAG_MANAGED_BY_VALUE:-enceladus-coordination}"
HOST_V2_FLEET_NAME_PREFIX="${HOST_V2_FLEET_NAME_PREFIX:-enceladus-host-v2-fleet}"
HOST_V2_FLEET_PASSROLE_ARN="${HOST_V2_FLEET_PASSROLE_ARN:-arn:aws:iam::${ACCOUNT_ID}:role/*}"
ENCELADUS_MCP_SERVER_PATH="${ENCELADUS_MCP_SERVER_PATH:-server.py}"
S3_BUCKET="${S3_BUCKET:-jreese-net}"
COORDINATION_INTERNAL_API_KEY="${COORDINATION_INTERNAL_API_KEY:-}"
COORDINATION_INTERNAL_API_KEY_PREVIOUS="${COORDINATION_INTERNAL_API_KEY_PREVIOUS:-}"
COORDINATION_INTERNAL_API_KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES:-}"
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
COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID:-us-east-1_b2D0V3E1k}"
COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID:-6q607dk3liirhtecgps7hifmlk}"
COGNITO_REGION="${COGNITO_REGION:-us-east-1}"
TERMINAL_COGNITO_SECRET_ID="${TERMINAL_COGNITO_SECRET_ID:-devops/coordination/cognito/terminal-agent}"
TERMINAL_COGNITO_USERNAME="${TERMINAL_COGNITO_USERNAME:-terminal-agent}"

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
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:DescribeTable"],
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
      "Sid": "GovernancePoliciesReadWrite",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:DescribeTable"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${GOVERNANCE_POLICIES_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${GOVERNANCE_POLICIES_TABLE}/index/*"
      ]
    },
    {
      "Sid": "DocumentsTableRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/documents",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/documents/index/*"
      ]
    },
    {
      "Sid": "GovernanceAndReferenceS3Read",
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::${S3_BUCKET}"
    },
    {
      "Sid": "GovernanceAndReferenceS3Get",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}/governance/*",
        "arn:aws:s3:::${S3_BUCKET}/projects/*",
        "arn:aws:s3:::${S3_BUCKET}/mobile/v1/reference/*"
      ]
    },
    {
      "Sid": "GovernanceS3Write",
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}/governance/live/*",
        "arn:aws:s3:::${S3_BUCKET}/governance/history/*"
      ]
    },
    {
      "Sid": "S3HeadBucket",
      "Effect": "Allow",
      "Action": ["s3:HeadBucket", "s3:GetBucketLocation"],
      "Resource": "arn:aws:s3:::${S3_BUCKET}"
    },
    {
      "Sid": "SSMDispatch",
      "Effect": "Allow",
      "Action": [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:ListCommands",
        "ssm:ListCommandInvocations",
        "ssm:DescribeInstanceInformation"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2FleetDispatch",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "ec2:CreateTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ProviderSecretsRead",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": "arn:aws:secretsmanager:${SECRETS_REGION}:${ACCOUNT_ID}:secret:devops/coordination/*"
    },
    {
      "Sid": "CognitoTerminalAuth",
      "Effect": "Allow",
      "Action": ["cognito-idp:InitiateAuth"],
      "Resource": "arn:aws:cognito-idp:${COGNITO_REGION}:${ACCOUNT_ID}:userpool/${COGNITO_USER_POOL_ID}"
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
    },
    {
      "Sid": "FleetHostPassRole",
      "Effect": "Allow",
      "Action": ["iam:PassRole"],
      "Resource": "${HOST_V2_FLEET_PASSROLE_ARN}",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "ec2.amazonaws.com"
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

resolve_internal_api_keys_csv() {
  local primary_key="$1"
  local previous_key="$2"
  local existing_csv
  existing_csv="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEYS' \
    --output text 2>/dev/null || true)"
  if [[ "${existing_csv}" == "None" || -z "${existing_csv}" ]]; then
    existing_csv=""
  fi
  PRIMARY_KEY="${primary_key}" PREVIOUS_KEY="${previous_key}" EXISTING_CSV="${existing_csv}" python3 - <<'PY'
import os

seen = set()
items = []

def add(raw):
    for part in str(raw or "").split(","):
        key = part.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        items.append(key)

add(os.environ.get("PRIMARY_KEY", ""))
add(os.environ.get("PREVIOUS_KEY", ""))
add(os.environ.get("EXISTING_CSV", ""))
print(",".join(items))
PY
}

ensure_terminal_cognito_credentials() {
  log "[START] ensuring terminal Cognito credentials"

  # Check if Secrets Manager secret already exists
  if aws secretsmanager describe-secret \
    --secret-id "${TERMINAL_COGNITO_SECRET_ID}" \
    --region "${SECRETS_REGION}" >/dev/null 2>&1; then
    log "[OK] Secrets Manager secret exists: ${TERMINAL_COGNITO_SECRET_ID}"
    return
  fi

  log "[INFO] Secret ${TERMINAL_COGNITO_SECRET_ID} not found — provisioning"

  # Ensure Cognito client allows USER_PASSWORD_AUTH
  local current_flows
  current_flows="$(aws cognito-idp describe-user-pool-client \
    --user-pool-id "${COGNITO_USER_POOL_ID}" \
    --client-id "${COGNITO_CLIENT_ID}" \
    --region "${COGNITO_REGION}" \
    --query 'UserPoolClient.ExplicitAuthFlows' \
    --output text 2>/dev/null || true)"

  if ! echo "${current_flows}" | grep -q "ALLOW_USER_PASSWORD_AUTH"; then
    log "[START] enabling ALLOW_USER_PASSWORD_AUTH on Cognito client"
    # update-user-pool-client is a replace operation — must preserve all existing settings
    POOL="${COGNITO_USER_POOL_ID}" CLIENT="${COGNITO_CLIENT_ID}" CREGION="${COGNITO_REGION}" python3 -c "
import boto3, os
client = boto3.client('cognito-idp', region_name=os.environ['CREGION'])
desc = client.describe_user_pool_client(
    UserPoolId=os.environ['POOL'], ClientId=os.environ['CLIENT']
)['UserPoolClient']
flows = set(desc.get('ExplicitAuthFlows', []))
flows.add('ALLOW_USER_PASSWORD_AUTH')
flows.add('ALLOW_REFRESH_TOKEN_AUTH')
# Build update kwargs preserving all existing settings
kwargs = {
    'UserPoolId': desc['UserPoolId'],
    'ClientId': desc['ClientId'],
    'ExplicitAuthFlows': sorted(flows),
}
# Preserve fields that reset to defaults if omitted
for key in [
    'ClientName', 'RefreshTokenValidity', 'AccessTokenValidity',
    'IdTokenValidity', 'TokenValidityUnits', 'ReadAttributes',
    'WriteAttributes', 'SupportedIdentityProviders',
    'CallbackURLs', 'LogoutURLs', 'DefaultRedirectURI',
    'AllowedOAuthFlows', 'AllowedOAuthScopes',
    'AllowedOAuthFlowsUserPoolClient', 'PreventUserExistenceErrors',
    'EnableTokenRevocation', 'EnablePropagateAdditionalUserContextData',
    'AuthSessionValidity',
]:
    if key in desc and desc[key] is not None:
        kwargs[key] = desc[key]
client.update_user_pool_client(**kwargs)
print('OK')
" >/dev/null
    log "[OK] Cognito client auth flows updated"
  else
    log "[OK] Cognito client already allows USER_PASSWORD_AUTH"
  fi

  # Generate secure random password
  local password
  password="$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"

  # Create Cognito user (idempotent — skip if exists)
  if aws cognito-idp admin-get-user \
    --user-pool-id "${COGNITO_USER_POOL_ID}" \
    --username "${TERMINAL_COGNITO_USERNAME}" \
    --region "${COGNITO_REGION}" >/dev/null 2>&1; then
    log "[INFO] Cognito user ${TERMINAL_COGNITO_USERNAME} already exists — resetting password"
  else
    log "[START] creating Cognito user ${TERMINAL_COGNITO_USERNAME}"
    aws cognito-idp admin-create-user \
      --user-pool-id "${COGNITO_USER_POOL_ID}" \
      --username "${TERMINAL_COGNITO_USERNAME}" \
      --user-attributes Name=email,Value="terminal-agent@enceladus.internal" Name=email_verified,Value=true \
      --message-action SUPPRESS \
      --region "${COGNITO_REGION}" >/dev/null
    log "[OK] Cognito user created"
  fi

  # Set permanent password (use env var to avoid shell interpolation issues)
  COGNITO_PASS="${password}" aws cognito-idp admin-set-user-password \
    --user-pool-id "${COGNITO_USER_POOL_ID}" \
    --username "${TERMINAL_COGNITO_USERNAME}" \
    --password "${password}" \
    --permanent \
    --region "${COGNITO_REGION}" >/dev/null
  log "[OK] Cognito user password set"

  # Create Secrets Manager secret (use Python to build JSON safely)
  local secret_json
  secret_json="$(CUSER="${TERMINAL_COGNITO_USERNAME}" CPASS="${password}" CCLIENT="${COGNITO_CLIENT_ID}" python3 -c "
import json, os
print(json.dumps({
    'username': os.environ['CUSER'],
    'password': os.environ['CPASS'],
    'client_id': os.environ['CCLIENT'],
    'auth_flow': 'USER_PASSWORD_AUTH'
}, separators=(',', ':')))
")"
  aws secretsmanager create-secret \
    --name "${TERMINAL_COGNITO_SECRET_ID}" \
    --secret-string "${secret_json}" \
    --region "${SECRETS_REGION}" \
    --description "Terminal agent Cognito credentials for coordination API" >/dev/null
  log "[OK] Secrets Manager secret created: ${TERMINAL_COGNITO_SECRET_ID}"
  log "[END] terminal Cognito credentials provisioned"
}

package_lambda() {
  local build_dir zip_path
  build_dir="$(mktemp -d /tmp/devops-coordination-build-XXXXXX)"
  zip_path="/tmp/${FUNCTION_NAME}.zip"
  local mcp_server_src="" mcp_dispatch_src=""

  for candidate in \
    "${ROOT_DIR}/../../../tools/enceladus-mcp-server/server.py" \
    "${ROOT_DIR}/../../../../tools/enceladus-mcp-server/server.py" \
    "/Users/jreese/agents-dev/projects/enceladus/repo/tools/enceladus-mcp-server/server.py" \
    "/Users/jreese/agents-dev/tools/enceladus-mcp-server/server.py"; do
    if [[ -f "${candidate}" ]]; then
      mcp_server_src="${candidate}"
      break
    fi
  done

  for candidate in \
    "${ROOT_DIR}/../../../tools/enceladus-mcp-server/dispatch_plan_generator.py" \
    "${ROOT_DIR}/../../../../tools/enceladus-mcp-server/dispatch_plan_generator.py" \
    "/Users/jreese/agents-dev/projects/enceladus/repo/tools/enceladus-mcp-server/dispatch_plan_generator.py" \
    "/Users/jreese/agents-dev/tools/enceladus-mcp-server/dispatch_plan_generator.py"; do
    if [[ -f "${candidate}" ]]; then
      mcp_dispatch_src="${candidate}"
      break
    fi
  done

  if [[ -z "${mcp_server_src}" || -z "${mcp_dispatch_src}" ]]; then
    echo "[ERROR] Unable to locate canonical Enceladus MCP runtime sources for packaging." >&2
    exit 1
  fi

  find "${ROOT_DIR}" -maxdepth 1 -type f -name '*.py' ! -name 'test_*' -exec cp {} "${build_dir}/" \;
  if [[ -f "${ROOT_DIR}/governance_data_dictionary.json" ]]; then
    cp "${ROOT_DIR}/governance_data_dictionary.json" "${build_dir}/governance_data_dictionary.json"
  fi
  cp "${mcp_server_src}" "${build_dir}/server.py"
  cp "${mcp_dispatch_src}" "${build_dir}/dispatch_plan_generator.py"

  python3 -m pip install \
    --quiet \
    --upgrade \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python-version 3.11 \
    --abi cp311 \
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
  local zip_path role_arn effective_internal_key effective_internal_key_previous effective_internal_keys env_file existing_env_json
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

  # Ensure all pending Lambda code updates have settled before we push configuration.
  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"

  effective_internal_key="$(resolve_internal_api_key)"
  effective_internal_key_previous="${COORDINATION_INTERNAL_API_KEY_PREVIOUS}"
  if [[ -z "${effective_internal_key_previous}" ]]; then
    effective_internal_key_previous="$(aws lambda get-function-configuration \
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --query 'Environment.Variables.COORDINATION_INTERNAL_API_KEY_PREVIOUS' \
      --output text 2>/dev/null || true)"
    [[ "${effective_internal_key_previous}" == "None" ]] && effective_internal_key_previous=""
  fi
  effective_internal_keys="$(resolve_internal_api_keys_csv "${effective_internal_key}" "${effective_internal_key_previous}")"
  if [[ -z "${effective_internal_key}" ]]; then
    log "[WARNING] COORDINATION_INTERNAL_API_KEY resolved empty; internal-key auth will be disabled."
  fi
  if [[ -z "${effective_internal_key}" && -z "${effective_internal_keys}" ]]; then
    log "[ERROR] refusing deploy with empty internal auth key set for ${FUNCTION_NAME}"
    exit 1
  fi
  existing_env_json="$(aws lambda get-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --query 'Environment.Variables' \
    --output json 2>/dev/null || echo '{}')"
  [[ "${existing_env_json}" == "None" || -z "${existing_env_json}" ]] && existing_env_json='{}'

  env_file="$(mktemp /tmp/${FUNCTION_NAME}-env-XXXXXX)"
  TABLE_NAME="${TABLE_NAME}" \
  TRACKER_TABLE="${TRACKER_TABLE}" \
  PROJECTS_TABLE="${PROJECTS_TABLE}" \
  GOVERNANCE_POLICIES_TABLE="${GOVERNANCE_POLICIES_TABLE}" \
  GOVERNANCE_DICTIONARY_POLICY_ID="${GOVERNANCE_DICTIONARY_POLICY_ID}" \
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
  HOST_V2_FLEET_ENABLED="${HOST_V2_FLEET_ENABLED}" \
  HOST_V2_FLEET_FALLBACK_TO_STATIC="${HOST_V2_FLEET_FALLBACK_TO_STATIC}" \
  HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES="${HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES}" \
  HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS="${HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS}" \
  HOST_V2_FLEET_READINESS_POLL_SECONDS="${HOST_V2_FLEET_READINESS_POLL_SECONDS}" \
  HOST_V2_FLEET_INSTANCE_TTL_SECONDS="${HOST_V2_FLEET_INSTANCE_TTL_SECONDS}" \
  HOST_V2_FLEET_SWEEP_ON_DISPATCH="${HOST_V2_FLEET_SWEEP_ON_DISPATCH}" \
  HOST_V2_FLEET_SWEEP_GRACE_SECONDS="${HOST_V2_FLEET_SWEEP_GRACE_SECONDS}" \
  HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL="${HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL}" \
  HOST_V2_FLEET_TAG_MANAGED_BY_VALUE="${HOST_V2_FLEET_TAG_MANAGED_BY_VALUE}" \
  HOST_V2_FLEET_NAME_PREFIX="${HOST_V2_FLEET_NAME_PREFIX}" \
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
  EXISTING_ENV_JSON="${existing_env_json}" \
  EFFECTIVE_INTERNAL_KEY="${effective_internal_key}" \
  EFFECTIVE_INTERNAL_KEY_PREVIOUS="${effective_internal_key_previous}" \
  EFFECTIVE_INTERNAL_KEYS="${effective_internal_keys}" \
  EFFECTIVE_INTERNAL_KEY_SCOPES="${COORDINATION_INTERNAL_API_KEY_SCOPES}" \
  COGNITO_USER_POOL_ID="${COGNITO_USER_POOL_ID}" \
  COGNITO_CLIENT_ID="${COGNITO_CLIENT_ID}" \
  COGNITO_REGION="${COGNITO_REGION}" \
  TERMINAL_COGNITO_SECRET_ID="${TERMINAL_COGNITO_SECRET_ID}" \
  python3 - "${env_file}" <<'PY'
import json
import os
import sys

path = sys.argv[1]
existing_env = json.loads(os.environ.get("EXISTING_ENV_JSON", "{}"))
if not isinstance(existing_env, dict):
    existing_env = {}
effective_key = (os.environ.get("EFFECTIVE_INTERNAL_KEY", "") or "").strip() or str(
    existing_env.get("COORDINATION_INTERNAL_API_KEY", "")
).strip()
effective_prev = (os.environ.get("EFFECTIVE_INTERNAL_KEY_PREVIOUS", "") or "").strip() or str(
    existing_env.get("COORDINATION_INTERNAL_API_KEY_PREVIOUS", "")
).strip()
effective_keys = (os.environ.get("EFFECTIVE_INTERNAL_KEYS", "") or "").strip() or str(
    existing_env.get("COORDINATION_INTERNAL_API_KEYS", "")
).strip()
effective_scopes = (os.environ.get("EFFECTIVE_INTERNAL_KEY_SCOPES", "") or "").strip() or str(
    existing_env.get("COORDINATION_INTERNAL_API_KEY_SCOPES", "")
).strip()
env_vars = {
    "COORDINATION_TABLE": os.environ["TABLE_NAME"],
    "TRACKER_TABLE": os.environ["TRACKER_TABLE"],
    "PROJECTS_TABLE": os.environ["PROJECTS_TABLE"],
    "GOVERNANCE_POLICIES_TABLE": os.environ["GOVERNANCE_POLICIES_TABLE"],
    "GOVERNANCE_DICTIONARY_POLICY_ID": os.environ["GOVERNANCE_DICTIONARY_POLICY_ID"],
    "DYNAMODB_REGION": os.environ["REGION"],
    "SSM_REGION": os.environ["REGION"],
    "SECRETS_REGION": os.environ["SECRETS_REGION"],
    "OPENAI_API_KEY_SECRET_ID": os.environ["OPENAI_API_KEY_SECRET_ID"],
    "ANTHROPIC_API_KEY_SECRET_ID": os.environ["ANTHROPIC_API_KEY_SECRET_ID"],
    "ENABLE_CLAUDE_HEADLESS": os.environ["ENABLE_CLAUDE_HEADLESS"],
    "COGNITO_USER_POOL_ID": os.environ["COGNITO_USER_POOL_ID"],
    "COGNITO_CLIENT_ID": os.environ["COGNITO_CLIENT_ID"],
    "COGNITO_REGION": os.environ.get("COGNITO_REGION", ""),
    "TERMINAL_COGNITO_SECRET_ID": os.environ.get("TERMINAL_COGNITO_SECRET_ID", ""),
    "COORDINATION_INTERNAL_API_KEY": effective_key,
    "COORDINATION_INTERNAL_API_KEY_PREVIOUS": effective_prev,
    "COORDINATION_INTERNAL_API_KEYS": effective_keys,
    "COORDINATION_INTERNAL_API_KEY_SCOPES": effective_scopes,
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY": effective_key,
    "ENCELADUS_COORDINATION_INTERNAL_API_KEY_PREVIOUS": effective_prev,
    "ENCELADUS_COORDINATION_INTERNAL_API_KEYS": effective_keys,
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY": effective_key,
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEY_PREVIOUS": effective_prev,
    "ENCELADUS_COORDINATION_API_INTERNAL_API_KEYS": effective_keys,
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
    "HOST_V2_FLEET_ENABLED": os.environ["HOST_V2_FLEET_ENABLED"],
    "HOST_V2_FLEET_FALLBACK_TO_STATIC": os.environ["HOST_V2_FLEET_FALLBACK_TO_STATIC"],
    "HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES": os.environ["HOST_V2_FLEET_MAX_ACTIVE_DISPATCHES"],
    "HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS": os.environ["HOST_V2_FLEET_READINESS_TIMEOUT_SECONDS"],
    "HOST_V2_FLEET_READINESS_POLL_SECONDS": os.environ["HOST_V2_FLEET_READINESS_POLL_SECONDS"],
    "HOST_V2_FLEET_INSTANCE_TTL_SECONDS": os.environ["HOST_V2_FLEET_INSTANCE_TTL_SECONDS"],
    "HOST_V2_FLEET_SWEEP_ON_DISPATCH": os.environ["HOST_V2_FLEET_SWEEP_ON_DISPATCH"],
    "HOST_V2_FLEET_SWEEP_GRACE_SECONDS": os.environ["HOST_V2_FLEET_SWEEP_GRACE_SECONDS"],
    "HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL": os.environ["HOST_V2_FLEET_AUTO_TERMINATE_ON_TERMINAL"],
    "HOST_V2_FLEET_TAG_MANAGED_BY_VALUE": os.environ["HOST_V2_FLEET_TAG_MANAGED_BY_VALUE"],
    "HOST_V2_FLEET_NAME_PREFIX": os.environ["HOST_V2_FLEET_NAME_PREFIX"],
    "ENCELADUS_MCP_SERVER_PATH": os.environ["ENCELADUS_MCP_SERVER_PATH"],
    "HOST_V2_PROJECT": "devops",
    "HOST_V2_WORK_ROOT": "/home/ec2-user/claude-code-dev",
    "HOST_V2_AWS_PROFILE": "ec2-role",
    "CORS_ORIGIN": "https://jreese.net",
    "S3_BUCKET": "jreese-net",
    "S3_GOVERNANCE_PREFIX": "governance/live",
    "S3_GOVERNANCE_HISTORY_PREFIX": "governance/history",
    "DOCUMENTS_TABLE": "documents",
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
existing_env.update({k: v for k, v in env_vars.items() if v is not None})
with open(path, "w", encoding="utf-8") as f:
    json.dump({"Variables": existing_env}, f)
PY

  local cfg_attempt cfg_max cfg_sleep
  cfg_attempt=1
  cfg_max=6
  cfg_sleep=10
  while :; do
    if aws lambda update-function-configuration \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --role "${role_arn}" \
      --timeout 120 \
      --memory-size 512 \
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

sync_governance_dictionary() {
  local dictionary_path
  dictionary_path="${ROOT_DIR}/governance_data_dictionary.json"
  if [[ ! -f "${dictionary_path}" ]]; then
    log "[WARNING] governance_data_dictionary.json not found; skipping dictionary sync"
    return 0
  fi

  GOVERNANCE_POLICIES_TABLE="${GOVERNANCE_POLICIES_TABLE}" \
  GOVERNANCE_DICTIONARY_POLICY_ID="${GOVERNANCE_DICTIONARY_POLICY_ID}" \
  DICTIONARY_PATH="${dictionary_path}" \
  REGION="${REGION}" \
  python3 - <<'PY'
import datetime
import hashlib
import json
import os

import boto3
from botocore.exceptions import ClientError

table = os.environ["GOVERNANCE_POLICIES_TABLE"]
policy_id = os.environ["GOVERNANCE_DICTIONARY_POLICY_ID"]
path = os.environ["DICTIONARY_PATH"]
region = os.environ["REGION"]

with open(path, "r", encoding="utf-8") as f:
    payload = json.load(f)

payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

ddb = boto3.client("dynamodb", region_name=region)
try:
    desc = ddb.describe_table(TableName=table)
except ClientError as exc:
    code = str(exc.response.get("Error", {}).get("Code", ""))
    if code in {"AccessDeniedException", "AccessDenied", "UnauthorizedOperation"}:
        print(
            "[WARNING] skipping governance dictionary sync due to insufficient IAM "
            f"permissions for table '{table}': {code}"
        )
        raise SystemExit(0)
    raise
key_schema = [entry["AttributeName"] for entry in desc["Table"]["KeySchema"]]

item = {
    "policy_id": {"S": policy_id},
    "status": {"S": "active"},
    "policy_type": {"S": "data_dictionary"},
    "dictionary_json": {"S": payload_json},
    "dictionary_hash": {"S": payload_hash},
    "updated_at": {"S": now},
    "write_source": {"S": "coordination_api_deploy"},
}

for key in key_schema:
    if key in item:
        continue
    if key == "scope":
        item[key] = {"S": "governance"}
    elif key == "record_id":
        item[key] = {"S": f"policy#{policy_id}"}
    elif key.endswith("_id"):
        item[key] = {"S": policy_id}
    else:
        item[key] = {"S": "default"}

try:
    ddb.put_item(TableName=table, Item=item)
except ClientError as exc:
    code = str(exc.response.get("Error", {}).get("Code", ""))
    if code in {"AccessDeniedException", "AccessDenied", "UnauthorizedOperation"}:
        print(
            "[WARNING] unable to write governance dictionary policy due to IAM "
            f"permissions on table '{table}': {code}"
        )
        raise SystemExit(0)
    raise
print(f"[INFO] synced governance dictionary policy_id={policy_id} hash={payload_hash}")
PY
}

ensure_api_integration_and_routes() {
  local integration_id target_arn
  target_arn="arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${FUNCTION_NAME}"

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
    # Existing coordination routes
    "POST /api/v1/coordination/requests"
    "GET /api/v1/coordination/requests/{requestId}"
    "POST /api/v1/coordination/requests/{requestId}/dispatch"
    "POST /api/v1/coordination/requests/{requestId}/callback"
    "GET /api/v1/coordination/mcp"
    "POST /api/v1/coordination/mcp"
    "GET /api/v1/coordination/capabilities"
    "OPTIONS /api/v1/coordination/mcp"
    "OPTIONS /api/v1/coordination/requests"
    "OPTIONS /api/v1/coordination/requests/{requestId}"
    "OPTIONS /api/v1/coordination/requests/{requestId}/dispatch"
    "OPTIONS /api/v1/coordination/requests/{requestId}/callback"
    "OPTIONS /api/v1/coordination/capabilities"
    # Phase 2b: Governance routes
    "GET /api/v1/governance/hash"
    "GET /api/v1/governance/dictionary"
    "PUT /api/v1/governance/{fileName}"
    "OPTIONS /api/v1/governance/hash"
    "OPTIONS /api/v1/governance/dictionary"
    "OPTIONS /api/v1/governance/{fileName}"
    # Phase 2b: Projects routes (read-only, via coordination API)
    "GET /api/v1/coordination/projects"
    "GET /api/v1/coordination/projects/{projectId}"
    "OPTIONS /api/v1/coordination/projects"
    "OPTIONS /api/v1/coordination/projects/{projectId}"
    # Unified auth token management routes
    "GET /api/v1/coordination/auth/tokens"
    "POST /api/v1/coordination/auth/tokens"
    "DELETE /api/v1/coordination/auth/tokens/{tokenId}"
    "PATCH /api/v1/coordination/auth/permissions/{tokenId}"
    "POST /api/v1/coordination/auth/cognito/session"
    "GET /api/v1/coordination/auth/oauth-clients"
    "POST /api/v1/coordination/auth/oauth-clients"
    "PATCH /api/v1/coordination/auth/oauth-clients/{clientId}/usage"
    "OPTIONS /api/v1/coordination/auth/tokens"
    "OPTIONS /api/v1/coordination/auth/tokens/{tokenId}"
    "OPTIONS /api/v1/coordination/auth/permissions/{tokenId}"
    "OPTIONS /api/v1/coordination/auth/cognito/session"
    "OPTIONS /api/v1/coordination/auth/oauth-clients"
    "OPTIONS /api/v1/coordination/auth/oauth-clients/{clientId}/usage"
    # Phase 2b: Health route
    "GET /api/v1/health"
    "OPTIONS /api/v1/health"
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

  # Lambda invoke permissions for each route prefix
  local permissions=(
    "allow-apigw-${API_ID}-${FUNCTION_NAME}:arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/coordination/*"
    "allow-apigw-${API_ID}-governance:arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/governance/*"
    "allow-apigw-${API_ID}-health:arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/api/v1/health"
  )
  for perm in "${permissions[@]}"; do
    local stmt_id="${perm%%:*}"
    local source_arn="${perm#*:}"
    if aws lambda add-permission \
      --region "${REGION}" \
      --function-name "${FUNCTION_NAME}" \
      --statement-id "${stmt_id}" \
      --action lambda:InvokeFunction \
      --principal apigateway.amazonaws.com \
      --source-arn "${source_arn}" >/dev/null 2>&1; then
      log "[OK] lambda invoke permission added: ${stmt_id}"
    else
      log "[OK] lambda invoke permission already present: ${stmt_id}"
    fi
  done

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
  ensure_terminal_cognito_credentials || log "[WARNING] terminal Cognito credential provisioning failed (non-fatal). Manual setup may be required — see ENC-ISS-076."
  sync_governance_dictionary
  ensure_observability_log_groups
  ensure_api_integration_and_routes
  smoke_hint
  log "[SUCCESS] coordination API deploy complete"
}

main "$@"
