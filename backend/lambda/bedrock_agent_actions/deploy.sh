#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"

FUNCTION_NAME="${FUNCTION_NAME:-enceladus-bedrock-agent-actions}"
ROLE_NAME="${ROLE_NAME:-enceladus-bedrock-actions-lambda-role}"
POLICY_NAME="${POLICY_NAME:-enceladus-bedrock-actions-inline}"

TRACKER_TABLE="${TRACKER_TABLE:-devops-project-tracker}"
PROJECTS_TABLE="${PROJECTS_TABLE:-projects}"
DOCUMENTS_TABLE="${DOCUMENTS_TABLE:-documents}"
DEPLOY_TABLE="${DEPLOY_TABLE:-devops-deployment-manager}"
COORDINATION_TABLE="${COORDINATION_TABLE:-coordination-requests}"
GOVERNANCE_POLICIES_TABLE="${GOVERNANCE_POLICIES_TABLE:-governance-policies}"
AGENT_COMPLIANCE_TABLE="${AGENT_COMPLIANCE_TABLE:-agent-compliance-violations}"
DOCUMENT_STORAGE_POLICY_ID="${DOCUMENT_STORAGE_POLICY_ID:-document_storage_cloud_only}"
COMPLIANCE_ENFORCEMENT_DEFAULT="${COMPLIANCE_ENFORCEMENT_DEFAULT:-enforce}"
S3_BUCKET="${S3_BUCKET:-jreese-net}"
S3_DOC_PREFIX="${S3_DOC_PREFIX:-agent-documents}"
S3_REFERENCE_PREFIX="${S3_REFERENCE_PREFIX:-reference}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

ensure_role() {
  if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
    log "[OK] IAM role exists: ${ROLE_NAME}"
  else
    log "[START] creating IAM role: ${ROLE_NAME}"
    aws iam create-role \
      --role-name "${ROLE_NAME}" \
      --assume-role-policy-document '{
        "Version":"2012-10-17",
        "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
      }' >/dev/null
    log "[END] IAM role created: ${ROLE_NAME}"
    sleep 5
  fi

  local policy_file
  policy_file="$(mktemp /tmp/bedrock-actions-policy-XXXXXX.json)"
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
      "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
      "Resource": "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${PROJECTS_TABLE}"
    },
    {
      "Sid": "DocumentsTableRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DOCUMENTS_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DOCUMENTS_TABLE}/index/*"
      ]
    },
    {
      "Sid": "CoordinationTableRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${COORDINATION_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${COORDINATION_TABLE}/index/*"
      ]
    },
    {
      "Sid": "DeploymentTableRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query"],
      "Resource": "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DEPLOY_TABLE}"
    },
    {
      "Sid": "GovernancePoliciesRead",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
      "Resource": [
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${GOVERNANCE_POLICIES_TABLE}",
        "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${GOVERNANCE_POLICIES_TABLE}/index/*"
      ]
    },
    {
      "Sid": "ComplianceTableWrite",
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem"],
      "Resource": "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${AGENT_COMPLIANCE_TABLE}"
    },
    {
      "Sid": "S3ReadAccess",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}",
        "arn:aws:s3:::${S3_BUCKET}/${S3_DOC_PREFIX}/*",
        "arn:aws:s3:::${S3_BUCKET}/${S3_REFERENCE_PREFIX}/*"
      ]
    }
  ]
}
POLICY

  log "[START] updating IAM inline policy ${POLICY_NAME} on ${ROLE_NAME}"
  aws iam put-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-name "${POLICY_NAME}" \
    --policy-document "file://${policy_file}" >/dev/null
  rm -f "${policy_file}"
  log "[END] IAM inline policy updated"
}

package_lambda() {
  local zip_path
  zip_path="/tmp/${FUNCTION_NAME}.zip"
  (
    cd "${ROOT_DIR}"
    zip -qj "${zip_path}" lambda_function.py
  )
  echo "${zip_path}"
}

ensure_function() {
  local zip_path role_arn env_file
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
      --function-name "${FUNCTION_NAME}" \
      --region "${REGION}" \
      --runtime python3.11 \
      --handler lambda_function.handler \
      --role "${role_arn}" \
      --timeout 30 \
      --memory-size 256 \
      --zip-file "fileb://${zip_path}" >/dev/null
  fi

  aws lambda wait function-active-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"

  env_file="$(mktemp /tmp/${FUNCTION_NAME}-env-XXXXXX)"
  TRACKER_TABLE="${TRACKER_TABLE}" \
  PROJECTS_TABLE="${PROJECTS_TABLE}" \
  DOCUMENTS_TABLE="${DOCUMENTS_TABLE}" \
  DEPLOY_TABLE="${DEPLOY_TABLE}" \
  GOVERNANCE_POLICIES_TABLE="${GOVERNANCE_POLICIES_TABLE}" \
  AGENT_COMPLIANCE_TABLE="${AGENT_COMPLIANCE_TABLE}" \
  DOCUMENT_STORAGE_POLICY_ID="${DOCUMENT_STORAGE_POLICY_ID}" \
  COMPLIANCE_ENFORCEMENT_DEFAULT="${COMPLIANCE_ENFORCEMENT_DEFAULT}" \
  DYNAMODB_REGION="${REGION}" \
  S3_BUCKET="${S3_BUCKET}" \
  python3 - "${env_file}" <<'PY'
import json
import os
import sys

path = sys.argv[1]
env_vars = {
    "TRACKER_TABLE": os.environ["TRACKER_TABLE"],
    "PROJECTS_TABLE": os.environ["PROJECTS_TABLE"],
    "DOCUMENTS_TABLE": os.environ["DOCUMENTS_TABLE"],
    "DEPLOY_TABLE": os.environ["DEPLOY_TABLE"],
    "GOVERNANCE_POLICIES_TABLE": os.environ["GOVERNANCE_POLICIES_TABLE"],
    "AGENT_COMPLIANCE_TABLE": os.environ["AGENT_COMPLIANCE_TABLE"],
    "DOCUMENT_STORAGE_POLICY_ID": os.environ["DOCUMENT_STORAGE_POLICY_ID"],
    "COMPLIANCE_ENFORCEMENT_DEFAULT": os.environ["COMPLIANCE_ENFORCEMENT_DEFAULT"],
    "DYNAMODB_REGION": os.environ["DYNAMODB_REGION"],
    "S3_BUCKET": os.environ["S3_BUCKET"],
}
with open(path, "w", encoding="utf-8") as f:
    json.dump({"Variables": env_vars}, f)
PY

  log "[START] updating Lambda configuration: ${FUNCTION_NAME}"
  aws lambda update-function-configuration \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --handler lambda_function.handler \
    --role "${role_arn}" \
    --timeout 30 \
    --memory-size 256 \
    --environment "file://${env_file}" >/dev/null
  rm -f "${env_file}"

  aws lambda wait function-updated-v2 --function-name "${FUNCTION_NAME}" --region "${REGION}"
  log "[END] Lambda ready: ${FUNCTION_NAME}"
}

ensure_bedrock_permission() {
  local statement_id
  statement_id="allow-bedrock-invoke"
  if aws lambda add-permission \
    --function-name "${FUNCTION_NAME}" \
    --region "${REGION}" \
    --statement-id "${statement_id}" \
    --action "lambda:InvokeFunction" \
    --principal "bedrock.amazonaws.com" >/dev/null 2>&1; then
    log "[OK] Added Bedrock invoke permission"
  else
    log "[OK] Bedrock invoke permission already exists"
  fi
}

main() {
  ensure_role
  ensure_function
  ensure_bedrock_permission
  log "[SUCCESS] Bedrock action Lambda deploy complete"
}

main "$@"
