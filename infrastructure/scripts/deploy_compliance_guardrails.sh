#!/usr/bin/env bash
set -euo pipefail

REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-356364570033}"
GOVERNANCE_POLICIES_TABLE="${GOVERNANCE_POLICIES_TABLE:-governance-policies}"
AGENT_COMPLIANCE_TABLE="${AGENT_COMPLIANCE_TABLE:-agent-compliance-violations}"
DOCUMENT_STORAGE_POLICY_ID="${DOCUMENT_STORAGE_POLICY_ID:-document_storage_cloud_only}"
DASHBOARD_NAME="${DASHBOARD_NAME:-Enceladus-Agent-Compliance}"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

ensure_governance_policies_table() {
  if aws dynamodb describe-table --table-name "${GOVERNANCE_POLICIES_TABLE}" --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] table exists: ${GOVERNANCE_POLICIES_TABLE}"
    return
  fi

  log "[START] creating table: ${GOVERNANCE_POLICIES_TABLE}"
  aws dynamodb create-table \
    --region "${REGION}" \
    --table-name "${GOVERNANCE_POLICIES_TABLE}" \
    --billing-mode PAY_PER_REQUEST \
    --attribute-definitions AttributeName=policy_id,AttributeType=S \
    --key-schema AttributeName=policy_id,KeyType=HASH >/dev/null

  aws dynamodb wait table-exists --table-name "${GOVERNANCE_POLICIES_TABLE}" --region "${REGION}"
  log "[END] table created: ${GOVERNANCE_POLICIES_TABLE}"
}

ensure_agent_compliance_table() {
  if aws dynamodb describe-table --table-name "${AGENT_COMPLIANCE_TABLE}" --region "${REGION}" >/dev/null 2>&1; then
    log "[OK] table exists: ${AGENT_COMPLIANCE_TABLE}"
    return
  fi

  log "[START] creating table: ${AGENT_COMPLIANCE_TABLE}"
  aws dynamodb create-table \
    --region "${REGION}" \
    --table-name "${AGENT_COMPLIANCE_TABLE}" \
    --billing-mode PAY_PER_REQUEST \
    --attribute-definitions \
      AttributeName=violation_id,AttributeType=S \
      AttributeName=policy_id,AttributeType=S \
      AttributeName=event_epoch,AttributeType=N \
      AttributeName=provider,AttributeType=S \
    --key-schema \
      AttributeName=violation_id,KeyType=HASH \
    --global-secondary-indexes \
      '[
        {
          "IndexName":"policy-timestamp-index",
          "KeySchema":[
            {"AttributeName":"policy_id","KeyType":"HASH"},
            {"AttributeName":"event_epoch","KeyType":"RANGE"}
          ],
          "Projection":{"ProjectionType":"ALL"}
        },
        {
          "IndexName":"provider-timestamp-index",
          "KeySchema":[
            {"AttributeName":"provider","KeyType":"HASH"},
            {"AttributeName":"event_epoch","KeyType":"RANGE"}
          ],
          "Projection":{"ProjectionType":"ALL"}
        }
      ]' >/dev/null

  aws dynamodb wait table-exists --table-name "${AGENT_COMPLIANCE_TABLE}" --region "${REGION}"
  log "[END] table created: ${AGENT_COMPLIANCE_TABLE}"
}

seed_document_storage_policy() {
  local now epoch item_file
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  epoch="$(date -u +%s)"
  item_file="$(mktemp /tmp/governance-policy-item-XXXXXX.json)"

  cat > "${item_file}" <<JSON
{
  "policy_id": {"S": "${DOCUMENT_STORAGE_POLICY_ID}"},
  "policy_name": {"S": "Document Storage Cloud-Only"},
  "status": {"S": "active"},
  "enforcement_mode": {"S": "enforce"},
  "description": {"S": "Documents must be persisted to Enceladus docstore/governance paths. Local filesystem persistence is prohibited."},
  "allowed_targets": {"L": [{"S": "docstore_api"}, {"S": "governance_s3"}, {"S": "mcp_validator"}, {"S": "bedrock_action"}]},
  "provider_enforcement": {
    "M": {
      "openai_codex": {"S": "check_document_policy + mcp write gate"},
      "claude_agent_sdk": {"S": "check_document_policy + mcp write gate"},
      "aws_bedrock_agent": {"S": "action-group policy validator"},
      "custom_agent": {"S": "mcp check_document_policy contract"}
    }
  },
  "version": {"N": "1"},
  "updated_at": {"S": "${now}"},
  "updated_epoch": {"N": "${epoch}"}
}
JSON

  aws dynamodb put-item \
    --region "${REGION}" \
    --table-name "${GOVERNANCE_POLICIES_TABLE}" \
    --item "file://${item_file}" >/dev/null

  rm -f "${item_file}"
  log "[OK] seeded policy '${DOCUMENT_STORAGE_POLICY_ID}' in ${GOVERNANCE_POLICIES_TABLE}"
}

deploy_dashboard() {
  local dashboard_file
  dashboard_file="$(mktemp /tmp/agent-compliance-dashboard-XXXXXX.json)"

  cat > "${dashboard_file}" <<JSON
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "title": "Agent Compliance Table Activity",
        "view": "timeSeries",
        "stacked": false,
        "region": "${REGION}",
        "metrics": [
          ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", "${AGENT_COMPLIANCE_TABLE}"],
          [".", "ConsumedReadCapacityUnits", ".", "."],
          [".", "SuccessfulRequestLatency", ".", "."],
          [".", "UserErrors", ".", "."]
        ],
        "stat": "Sum",
        "period": 300
      }
    },
    {
      "type": "metric",
      "x": 12,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "title": "Governance Policies Table Activity",
        "view": "timeSeries",
        "stacked": false,
        "region": "${REGION}",
        "metrics": [
          ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", "${GOVERNANCE_POLICIES_TABLE}"],
          [".", "ConsumedReadCapacityUnits", ".", "."],
          [".", "SuccessfulRequestLatency", ".", "."],
          [".", "UserErrors", ".", "."]
        ],
        "stat": "Sum",
        "period": 300
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 6,
      "width": 12,
      "height": 6,
      "properties": {
        "title": "Coordination + Bedrock Action Lambda Health",
        "view": "timeSeries",
        "stacked": false,
        "region": "${REGION}",
        "metrics": [
          ["AWS/Lambda", "Errors", "FunctionName", "devops-coordination-api"],
          [".", "Errors", "FunctionName", "enceladus-bedrock-agent-actions"],
          [".", "Invocations", "FunctionName", "devops-coordination-api"],
          [".", "Invocations", "FunctionName", "enceladus-bedrock-agent-actions"]
        ],
        "stat": "Sum",
        "period": 300
      }
    },
    {
      "type": "metric",
      "x": 12,
      "y": 6,
      "width": 12,
      "height": 6,
      "properties": {
        "title": "Compliance Table Throttle/Failure Signals",
        "view": "timeSeries",
        "stacked": false,
        "region": "${REGION}",
        "metrics": [
          ["AWS/DynamoDB", "ThrottledRequests", "TableName", "${AGENT_COMPLIANCE_TABLE}"],
          [".", "SystemErrors", ".", "."]
        ],
        "stat": "Sum",
        "period": 300
      }
    }
  ]
}
JSON

  aws cloudwatch put-dashboard \
    --region "${REGION}" \
    --dashboard-name "${DASHBOARD_NAME}" \
    --dashboard-body "file://${dashboard_file}" >/dev/null

  rm -f "${dashboard_file}"
  log "[OK] dashboard updated: ${DASHBOARD_NAME}"
}

main() {
  ensure_governance_policies_table
  ensure_agent_compliance_table
  seed_document_storage_policy
  deploy_dashboard
  log "[SUCCESS] compliance guardrails infrastructure deployed"
}

main "$@"
