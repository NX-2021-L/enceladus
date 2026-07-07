#!/usr/bin/env python3
"""
ENC-FTR-041 / ENC-FTR-042: Seed the component registry for all managed projects.

Usage:
    python3 tools/seed-component-registry.py [--dry-run] [--base-url URL] [--api-key KEY]
        [--assistant-key KEY] [--direct-apigw-base URL]

Environment variables (can be set instead of flags):
    ENCELADUS_COORDINATION_INTERNAL_API_KEY  — internal API key
    COORDINATION_API_BASE                    — base URL (default: https://jreese.net/api/v1/coordination)
    CHECKOUT_ASSISTANT_KEY                   — checkout-service-assistant key (allows setting
                                               non-default transition_type at create time)
    COORDINATION_DIRECT_APIGW_BASE           — direct APIGW URL used for assistant-key calls
                                               (bypasses CloudFront header stripping);
                                               default: https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/coordination

Auth note for non-default transition_type:
    Creating a component with a non-default transition_type (anything other than
    "github_pr_deploy") requires either Cognito auth (PWA session) or the checkout-service-
    assistant key (--assistant-key / CHECKOUT_ASSISTANT_KEY). If neither is provided, the
    script creates the component with the default "github_pr_deploy" type and emits a warning
    that a manual PATCH via the PWA is needed to set the correct type.

    The assistant-key PATCH must be sent to the direct APIGW URL (not CloudFront) because
    CloudFront strips custom headers before reaching the Lambda backend.

The script is idempotent: it GETs each component first. If the existing record has the same
transition_type as the seed entry it is skipped. If the type differs, a warning is emitted
and the record is left unchanged.

ENC-TSK-F50 / ENC-ISS-270 update (2026-04-19): every entry below now also carries a
``required_transition_type`` field, matched to the governance-intent decisions in
DOC-240A67973B13 (AC-1 review). ``required_transition_type`` is the field that
checkout_service reads for strictness enforcement post-F50 — ``transition_type`` is
retained for back-compat documentation. For all current components in this manifest
the two fields carry the same value, but that equivalence is a deliberate governance
output, not a blind copy. The coordination API create handler rejects any POST missing
``required_transition_type`` with HTTP 400 (F50/AC-6 strict mode).

Components seeded:
    Enceladus project (ENC-FTR-041):
        comp-checkout-service      enceladus  lambda          github_pr_deploy
        comp-coordination-api      enceladus  lambda          github_pr_deploy
        comp-tracker-mutation      enceladus  lambda          github_pr_deploy
        comp-enceladus-mcp-server  enceladus  library         github_pr_deploy
        comp-enceladus-pwa         enceladus  frontend        web_deploy          (needs assistant-key)
        comp-cloudformation-data   enceladus  infrastructure  no_code             (needs assistant-key)
        comp-cloudformation-app    enceladus  infrastructure  no_code             (needs assistant-key)

    Harrisonfamily project:
        comp-harrisonfamily-site   harrisonfamily  frontend  web_deploy           (needs assistant-key)

    MOD project (vagamod.io):
        comp-mod-web               mod  frontend        github_pr_deploy
        comp-mod-api               mod  lambda          github_pr_deploy
        comp-mod-infra             mod  infrastructure  github_pr_deploy
        comp-mod-keycloak          mod  external        no_code                  (needs assistant-key)

    DevOps project (ENC-FTR-042):
        comp-devops-governance     devops  workflow  no_code                     (needs assistant-key)

    jreesewebops project (ENC-FTR-042):
        comp-jwo-web-infra         jreesewebops  infrastructure  no_code         (needs assistant-key)

    jreeseGPT project (ENC-FTR-042):
        comp-jgp-platform          jreeseGPT  external  no_code                  (needs assistant-key)

    jobapps project (ENC-FTR-042):
        comp-jap-jds-platform      jobapps  external  no_code                    (needs assistant-key)

    intelligent-scraper-generator project (ENC-FTR-042):
        comp-isg-toolkit           intelligent-scraper-generator  library  no_code  (needs assistant-key)

    property160c1 project (ENC-FTR-042):
        comp-prp-planning          property160c1  workflow  no_code              (needs assistant-key)

    agentharmony project (ENC-FTR-042):
        comp-agh-governance        agentharmony  workflow  no_code               (needs assistant-key)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

KNOWN_COMPONENTS = [
    # ── Enceladus ────────────────────────────────────────────────────────────
    {
        "component_id": "comp-checkout-service",
        "component_name": "Checkout Service Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus checkout service Lambda — sole authorized caller for task status transitions and worklog appends.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:lambda:us-west-2:{account}:function:enceladus-checkout-service-gamma",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "backend/lambda/checkout_service",
        "source_paths": {
            "primary": "backend/lambda/checkout_service/lambda_function.py",
            "directory": "backend/lambda/checkout_service/",
            "workflow": ".github/workflows/lambda-checkout-service-deploy.yml",
            "related": ["backend/lambda/shared_layer/"],
            "architecture_sections": ["4.17"],
        },
        "deploy_targets": ["checkout_service"],
        # ENC-TSK-L05 AC-1 (ENC-TSK-E68/PLN-031 Ph3 hardening fields).
        # Role enceladus-checkout-service-role${EnvironmentSuffix} is deliberately
        # NOT CFN-managed (02-compute.yaml:493-506 -- agent identity has an explicit
        # IAM deny on iam:GetRole/ListRolePolicies, so the live policy document
        # cannot be read). Actions below are derived from the actual boto3 calls
        # in backend/lambda/checkout_service/lambda_function.py (dynamodb get_item/
        # put_item/update_item/scan calls + secretsmanager get_secret_value for the
        # GitHub App private key), not from a CFN Policy document.
        "required_iam_actions": [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:Scan",
            "secretsmanager:GetSecretValue",
        ],
        # _deploy.yml (Gen2 shared pipeline) is the only production-equivalent
        # deploy path; it references exactly two secrets for every Lambda
        # component it deploys (no per-component secret gating -- confirmed no
        # matrix/strategy block, single `deploy` job, ThreadPoolExecutor fan-out).
        "required_env_secrets": ["DM_GITHUB_READ_TOKEN", "COORDINATION_INTERNAL_API_KEY"],
        # infrastructure/cloudformation/03-api.yaml: two Integrations target this
        # function (CheckoutServiceIntegration lines 811-818 for the newer /plan/*
        # routes; CheckoutApiIntegration lines 927-937, adopted out-of-band via
        # ENC-TSK-J13 IMPORT, whose comment notes "live traffic uses this one" for
        # the /task/* routes). Both integrations target the same live Lambda, so
        # both route sets are declared here.
        "required_apigw_routes": [
            "POST /api/v1/checkout/{project}/plan/{planId}/checkout",
            "DELETE /api/v1/checkout/{project}/plan/{planId}/checkout",
            "POST /api/v1/checkout/{project}/plan/{planId}/advance",
            "POST /api/v1/checkout/{project}/plan/{planId}/log",
            "GET /api/v1/checkout/{project}/plan/{planId}/status",
            "DELETE /api/v1/checkout/{project}/task/{taskId}/checkout",
            "GET /api/v1/checkout/validate/commit-complete/{cciId}",
            "GET /api/v1/checkout/{project}/task/{taskId}/status",
            "POST /api/v1/checkout/{project}/task/{taskId}/advance",
            "POST /api/v1/checkout/{project}/task/{taskId}/checkout",
            "POST /api/v1/checkout/{project}/task/{taskId}/log",
        ],
        "required_cfn_resources": ["CheckoutServiceFunction", "CheckoutServiceIntegration", "CheckoutApiIntegration"],
        "required_lambda_env_vars": [
            "CHECKOUT_TOKENS_REGION",
            "CHECKOUT_TOKENS_TABLE",
            "COORDINATION_INTERNAL_API_KEY",
            "ENCELADUS_COORDINATION_INTERNAL_API_KEY",
            "GITHUB_PRIVATE_KEY_SECRET",
            "GITHUB_APP_ID",
            "GITHUB_INSTALLATION_ID",
            "GITHUB_TOKEN",
            "COGNITO_USER_POOL_ID",
            "COGNITO_CLIENT_ID",
            "CORS_ORIGIN",
            "TRACKER_API_BASE",
        ],
    },
    {
        "component_id": "comp-lifecycle-service",
        "component_name": "Lifecycle Service Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus Lifecycle Service Lambda (B63 Phase 2A / ENC-TSK-H46) — authoritative owner of transition_type_matrix validation, STRICTNESS_RANK enforcement, subtask gates, and the per-cell gate_class taxonomy (ENC-FTR-111 scaffold). Synchronously invoked by tracker_mutation behind the enable_lifecycle_service_extraction feature flag (fail-closed).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:lambda:us-west-2:{account}:function:enceladus-lifecycle-service-gamma",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "backend/lambda/lifecycle_service",
        "source_paths": {
            "primary": "backend/lambda/lifecycle_service/lambda_function.py",
            "directory": "backend/lambda/lifecycle_service/",
            "workflow": ".github/workflows/_deploy.yml",
            "deploy_script": "backend/lambda/lifecycle_service/deploy.sh",
            "related": [
                "backend/lambda/lifecycle_service/transition_type_matrix.py",
                "backend/lambda/shared_layer/",
            ],
            "architecture_sections": ["4.17"],
        },
        "deploy_targets": ["lifecycle_service"],
        # ENC-TSK-L05 AC-1. Role LifecycleServiceRole is CFN-managed
        # (02-compute.yaml:3749-3799, RoleName enceladus-lifecycle-service-lambda-role).
        # Single inline policy grants read-only DynamoDB access (tracker,
        # component-registry, projects tables) -- this service validates
        # transitions, it does not invoke other Lambdas or publish events.
        "required_iam_actions": [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "xray:PutTraceSegments",
            "xray:PutTelemetryRecords",
            "dynamodb:GetItem",
            "dynamodb:Query",
        ],
        "required_env_secrets": ["DM_GITHUB_READ_TOKEN", "COORDINATION_INTERNAL_API_KEY"],
        # No API Gateway Integration targets this function anywhere in
        # 03-api.yaml -- it is invoked synchronously by tracker_mutation via
        # lambda:InvokeFunction (TrackerMutationRole's invoke-lifecycle-service
        # policy), never over HTTP. Empty is correct, not an oversight.
        "required_apigw_routes": [],
        "required_cfn_resources": ["LifecycleServiceFunction", "LifecycleServiceRole"],
        "required_lambda_env_vars": [
            "DYNAMODB_TABLE",
            "DYNAMODB_REGION",
            "COMPONENTS_TABLE",
            "PROJECTS_TABLE",
        ],
    },
    {
        "component_id": "comp-scoring-service",
        "component_name": "Scoring Service Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus Scoring Service Lambda (B63 Phase 2B / ENC-TSK-H47) — standalone, SNS-triggered async owner of lesson constitutional scoring (pillar_composite + resonance_score, ENC-FTR-054) and the lesson scoring_status: pending -> scored lifecycle. Subscribes to the enceladus-lesson-scoring SNS topic; tracker_mutation publishes to it behind the enable_scoring_service_extraction feature flag (best-effort; idempotent conditional write-back for at-least-once delivery).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:lambda:us-west-2:{account}:function:enceladus-scoring-service-gamma",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "backend/lambda/scoring_service",
        "source_paths": {
            "primary": "backend/lambda/scoring_service/lambda_function.py",
            "directory": "backend/lambda/scoring_service/",
            "workflow": ".github/workflows/_deploy.yml",
            "deploy_script": "backend/lambda/scoring_service/deploy.sh",
            "related": [
                "backend/lambda/tracker_mutation/lambda_function.py",
                "backend/lambda/shared_layer/",
            ],
            "architecture_sections": ["4.17"],
        },
        "deploy_targets": ["scoring_service"],
        # ENC-TSK-L05 AC-1. Role ScoringServiceRole is CFN-managed
        # (02-compute.yaml:3805-3841, RoleName enceladus-scoring-service-lambda-role).
        # Pure SNS-triggered DynamoDB writer (lesson pillar_composite/resonance_score
        # write-back on the tracker table) -- no other AWS API calls.
        "required_iam_actions": [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "xray:PutTraceSegments",
            "xray:PutTelemetryRecords",
            "dynamodb:GetItem",
            "dynamodb:UpdateItem",
        ],
        "required_env_secrets": ["DM_GITHUB_READ_TOKEN", "COORDINATION_INTERNAL_API_KEY"],
        # No API Gateway Integration targets this function -- it subscribes to
        # the enceladus-lesson-scoring SNS topic (ScoringServiceSubscription /
        # ScoringServiceSnsPermission, 02-compute.yaml:603-617) and is never
        # invoked over HTTP. Empty is correct, not an oversight.
        "required_apigw_routes": [],
        "required_cfn_resources": [
            "ScoringServiceFunction",
            "ScoringServiceRole",
            "ScoringServiceSubscription",
            "ScoringServiceSnsPermission",
        ],
        "required_lambda_env_vars": ["DYNAMODB_TABLE", "DYNAMODB_REGION"],
    },
    {
        "component_id": "comp-id-service",
        "component_name": "ID Service Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus ID Service Lambda (B63 Phase 2 AC-6 / ENC-TSK-L06) — sole authority for record-ID allocation (dedicated enceladus-id-counters table, IAM-isolated from tracker_mutation), the idempotency-key contract (client-supplied idempotency_key returns the same record_id on retry), and HMAC-SHA256 item_id_provenance signing. Also owns the per-caller trust-score violation counter for ID_BOUNDARY_VIOLATION rejections. Synchronously invoked (RequestResponse, fail-closed) by tracker_mutation behind the enable_id_service_extraction feature flag; the violation counter is invoked fire-and-forget (Event).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:lambda:us-west-2:{account}:function:enceladus-id-service-gamma",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "backend/lambda/id_service",
        "source_paths": {
            "primary": "backend/lambda/id_service/lambda_function.py",
            "directory": "backend/lambda/id_service/",
            "workflow": ".github/workflows/_deploy.yml",
            "deploy_script": "backend/lambda/id_service/deploy.sh",
            "related": [
                "backend/lambda/tracker_mutation/lambda_function.py",
                "backend/lambda/graph_sync/lambda_function.py",
                "backend/lambda/shared_layer/",
            ],
            "architecture_sections": ["4.17"],
        },
        "deploy_targets": ["id_service"],
        # ENC-TSK-L05 AC-1 hardening fields. Role IdServiceRole is CFN-managed
        # (02-compute.yaml IdServiceRole) -- exclusive owner of the dedicated
        # enceladus-id-counters table (AC-0 isolation), read/write on
        # enceladus-id-idempotency + enceladus-id-violations, read-only Query
        # fallback on the shared tracker table (_max_existing_number cold-start
        # seed), and GetSecretValue scoped to its own HMAC signing secret.
        "required_iam_actions": [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "xray:PutTraceSegments",
            "xray:PutTelemetryRecords",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:Query",
            "secretsmanager:GetSecretValue",
        ],
        "required_env_secrets": ["DM_GITHUB_READ_TOKEN", "COORDINATION_INTERNAL_API_KEY"],
        # No API Gateway Integration targets this function -- it is invoked
        # synchronously (RequestResponse, allocate) and fire-and-forget (Event,
        # record_violation) by tracker_mutation via lambda:InvokeFunction
        # (TrackerMutationRole's invoke-id-service policy), never over HTTP.
        # Empty is correct, not an oversight.
        "required_apigw_routes": [],
        "required_cfn_resources": [
            "IdServiceFunction",
            "IdServiceRole",
            "IdServiceHmacSecret",
            "IdCountersTable",
            "IdIdempotencyTable",
            "IdViolationsTable",
        ],
        "required_lambda_env_vars": [
            "DYNAMODB_TABLE",
            "DYNAMODB_REGION",
            "ID_COUNTERS_TABLE",
            "IDEMPOTENCY_TABLE",
            "VIOLATIONS_TABLE",
            "HMAC_SECRET_ARN",
            "VIOLATION_THRESHOLD",
        ],
    },
    {
        "component_id": "comp-coordination-api",
        "component_name": "Coordination API Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus coordination API Lambda — coordination mode, governance routes, projects, documents, components.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:lambda:us-west-2:{account}:function:enceladus-coordination-api-gamma",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "backend/lambda/coordination_api",
        "source_paths": {
            "primary": "backend/lambda/coordination_api/lambda_function.py",
            "directory": "backend/lambda/coordination_api/",
            "workflow": ".github/workflows/api-mcp-backend-deploy.yml",
            "deploy_script": "backend/lambda/coordination_api/deploy.sh",
            "related": [
                "backend/lambda/coordination_api/governance_data_dictionary.json",
                "backend/lambda/coordination_api/config.py",
            ],
            "architecture_sections": ["4.2", "5.1"],
        },
        "deploy_targets": ["coordination_api"],
        # ENC-TSK-L05 AC-1. Role CoordinationApiRole is CFN-managed
        # (02-compute.yaml:3302-3620, RoleName devops-coordination-api-lambda-role).
        # Deduped action set across its Bedrock-dispatch + inline + AppConfig
        # policies (this is the largest role in the stack -- coordination mode,
        # governance, host-provisioning (EC2/SSM), Bedrock agent management, and
        # Cognito client management all live in this one Lambda).
        "required_iam_actions": [
            "bedrock:InvokeAgent",
            "lambda:InvokeFunction",
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "xray:PutTraceSegments",
            "xray:PutTelemetryRecords",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:DescribeTable",
            "dynamodb:DeleteItem",
            "s3:ListBucket",
            "s3:GetObject",
            "s3:PutObject",
            "s3:HeadBucket",
            "s3:GetBucketLocation",
            "ssm:SendCommand",
            "ssm:GetCommandInvocation",
            "ssm:ListCommands",
            "ssm:ListCommandInvocations",
            "ssm:DescribeInstanceInformation",
            "ec2:DescribeInstances",
            "ec2:DescribeLaunchTemplates",
            "ec2:DescribeLaunchTemplateVersions",
            "ec2:RunInstances",
            "ec2:TerminateInstances",
            "ec2:CreateTags",
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret",
            "sns:Publish",
            "cognito-idp:InitiateAuth",
            "cognito-idp:CreateUserPoolClient",
            "cognito-idp:DeleteUserPoolClient",
            "cognito-idp:DescribeUserPoolClient",
            "cognito-idp:UpdateUserPoolClient",
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
            "bedrock:DisassociateAgentKnowledgeBase",
            "iam:PassRole",
            "appconfig:GetConfiguration",
            "appconfig:GetLatestConfiguration",
            "appconfig:StartConfigurationSession",
        ],
        "required_env_secrets": ["DM_GITHUB_READ_TOKEN", "COORDINATION_INTERNAL_API_KEY"],
        # infrastructure/cloudformation/03-api.yaml: CoordinationApiIntegration
        # (lines 78-86) backs ~111 Route resources (many IsProduction/IsGamma
        # twins of the same RouteKey). Deduped distinct RouteKeys below.
        "required_apigw_routes": [
            "POST /api/v1/coordination/requests",
            "GET /api/v1/coordination/requests/{requestId}",
            "POST /api/v1/coordination/requests/{requestId}/dispatch",
            "POST /api/v1/coordination/requests/{requestId}/callback",
            "POST /api/v1/cursor/webhook",
            "GET /api/v1/coordination/capabilities",
            "GET /api/v1/coordination/mcp",
            "POST /api/v1/coordination/mcp",
            "GET /api/v1/coordination/components",
            "POST /api/v1/coordination/components",
            "GET /api/v1/coordination/agents/sessions",
            "GET /api/v1/coordination/agents/types",
            "GET /api/v1/coordination/components/{componentId}",
            "PATCH /api/v1/coordination/components/{componentId}",
            "DELETE /api/v1/coordination/components/{componentId}",
            "POST /api/v1/coordination/components/{componentId}/add_edge",
            "POST /api/v1/coordination/components/{componentId}/remove_edge",
            "POST /api/v1/coordination/components/{componentId}/deprecate",
            "POST /api/v1/coordination/components/{componentId}/restore",
            "POST /api/v1/coordination/components/{componentId}/revert",
            "POST /api/v1/coordination/sessions/{sessionId}/message",
            "DELETE /api/v1/coordination/auth/oauth-clients/{clientId}",
            "DELETE /api/v1/coordination/auth/tokens/{tokenId}",
            "GET /api/v1/coordination/auth/oauth-clients",
            "GET /api/v1/coordination/auth/tokens",
            "GET /api/v1/coordination/projects",
            "GET /api/v1/coordination/projects/{projectId}",
            "GET /api/v1/governance/dictionary",
            "GET /api/v1/governance/hash",
            "GET /api/v1/governance/{fileName+}",
            "GET /api/v1/health",
            "OPTIONS /api/v1/coordination/auth/cognito/session",
            "OPTIONS /api/v1/coordination/auth/oauth-clients",
            "OPTIONS /api/v1/coordination/auth/oauth-clients/{clientId}",
            "OPTIONS /api/v1/coordination/auth/oauth-clients/{clientId}/permissions",
            "OPTIONS /api/v1/coordination/auth/oauth-clients/{clientId}/usage",
            "OPTIONS /api/v1/coordination/auth/permissions/{tokenId}",
            "OPTIONS /api/v1/coordination/auth/tokens",
            "OPTIONS /api/v1/coordination/auth/tokens/{tokenId}",
            "OPTIONS /api/v1/coordination/capabilities",
            "OPTIONS /api/v1/coordination/mcp",
            "OPTIONS /api/v1/coordination/projects",
            "OPTIONS /api/v1/coordination/projects/{projectId}",
            "OPTIONS /api/v1/coordination/requests",
            "OPTIONS /api/v1/coordination/requests/{requestId}",
            "OPTIONS /api/v1/coordination/requests/{requestId}/callback",
            "OPTIONS /api/v1/coordination/requests/{requestId}/dispatch",
            "PATCH /api/v1/coordination/auth/oauth-clients/{clientId}/permissions",
            "PATCH /api/v1/coordination/auth/oauth-clients/{clientId}/usage",
            "PATCH /api/v1/coordination/auth/permissions/{tokenId}",
            "POST /api/v1/coordination/auth/cognito/session",
            "POST /api/v1/coordination/auth/oauth-clients",
            "POST /api/v1/coordination/auth/tokens",
            "POST /api/v1/coordination/components/propose",
            "POST /api/v1/coordination/components/{componentId}/advance",
            "POST /api/v1/coordination/components/{componentId}/approve",
            "POST /api/v1/coordination/components/{componentId}/cloudwatch_event",
            "POST /api/v1/coordination/components/{componentId}/reject",
            "PUT /api/v1/governance/{fileName+}",
            "POST /api/v1/coordination/lesson-candidates/{documentId}/approve",
            "POST /api/v1/coordination/lesson-candidates/{documentId}/reject",
            "GET /api/v1/coordination/escalations",
            "GET /api/v1/coordination/escalations/watch",
            "POST /api/v1/coordination/escalations/{projectId}/{escalationId}/approve",
            "POST /api/v1/coordination/escalations/{projectId}/{escalationId}/deny",
        ],
        "required_cfn_resources": [
            "CoordinationApiFunction",
            "CoordinationApiRole",
            "CoordinationBatchPollerRule",
            "CoordinationBatchPollerPermission",
            "AgentSessionIdleSweepSchedule",
            "AgentSessionIdleSweepPermission",
            "AgentSessionUnclaimSweepSchedule",
            "AgentSessionUnclaimSweepPermission",
            "IntentClassifierTrainingSchedule",
            "IntentClassifierTrainingPermission",
        ],
        "required_lambda_env_vars": [
            "COORDINATION_INTERNAL_API_KEY",
            "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
            "COGNITO_USER_POOL_ID",
            "COGNITO_CLIENT_ID",
            "COORDINATION_TABLE",
            "TRACKER_TABLE",
            "RELATIONSHIPS_TABLE",
            "PROJECTS_TABLE",
            "DOCUMENTS_TABLE",
            "DYNAMODB_REGION",
            "SSM_REGION",
            "SECRETS_REGION",
            "CORS_ORIGIN",
            "ENCELADUS_MCP_INTERFACE_MODE",
            "DOCUMENT_API_LAMBDA_NAME",
            "TRACKER_MUTATION_LAMBDA_NAME",
            "CURSOR_WEBHOOK_SECRET",
            "COMPONENTS_TABLE",
            "GOVERNANCE_POLICIES_TABLE",
            "AUTH_TOKENS_TABLE",
            "GOVERNANCE_VERSION_TABLE",
            "AGENT_SESSIONS_TABLE",
            "AGENT_TYPES_TABLE",
            "AGENT_CREDENTIALS_TABLE",
            "AGENT_SESSIONS_IDLE_SWEEP_ENABLED",
            "AGENT_SESSIONS_IDLE_THRESHOLD_SECONDS",
            "AGENT_SESSIONS_UNCLAIM_SWEEP_ENABLED",
            "AGENT_SESSIONS_UNCLAIM_TTL_MINUTES",
            "CHECKOUT_TOKENS_TABLE",
            "AWS_APPCONFIG_EXTENSION_POLL_INTERVAL_SECONDS",
            "APPCONFIG_APPLICATION",
            "APPCONFIG_ENVIRONMENT",
            "APPCONFIG_CONFIGURATION",
            "TRAINING_HARD_DISABLED",
            "INTENT_TRAINING_BUCKET",
            "INTENT_TRAINING_PREFIX",
        ],
    },
    {
        "component_id": "comp-tracker-mutation",
        "component_name": "Tracker Mutation Lambda",
        "project_id": "enceladus",
        "category": "lambda",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus tracker mutation Lambda — handles all tracker record writes (create, set, log, etc.).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:lambda:us-west-2:{account}:function:enceladus-tracker-mutation-gamma",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "backend/lambda/tracker_mutation",
        "source_paths": {
            "primary": "backend/lambda/tracker_mutation/lambda_function.py",
            "directory": "backend/lambda/tracker_mutation/",
            "workflow": ".github/workflows/lambda-tracker-mutation-api-deploy.yml",
            "deploy_script": "backend/lambda/tracker_mutation/deploy.sh",
            "related": ["backend/lambda/shared_layer/"],
            "architecture_sections": ["4.1", "5.1"],
        },
        "deploy_targets": ["tracker_mutation"],
        # ENC-TSK-L05 AC-1. Role TrackerMutationRole is CFN-managed
        # (02-compute.yaml:3621-3745, RoleName devops-tracker-mutation-lambda-role).
        # Deduped across its tracker-dynamodb, projects-read, eventbridge-put-events,
        # AppConfig, invoke-lifecycle-service, and publish-lesson-scoring policies.
        "required_iam_actions": [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:DescribeTable",
            "events:PutEvents",
            "appconfig:GetConfiguration",
            "appconfig:GetLatestConfiguration",
            "appconfig:StartConfigurationSession",
            "lambda:InvokeFunction",
            "sns:Publish",
        ],
        "required_env_secrets": ["DM_GITHUB_READ_TOKEN", "COORDINATION_INTERNAL_API_KEY"],
        # infrastructure/cloudformation/03-api.yaml: TrackerMutationIntegration
        # (lines 87-94) plus a gamma-only TrackerMutationGammaLiveIntegration
        # (lines 405-414, :live-alias-qualified, adopted for the gamma dedup/
        # escalation surfaces). Deduped distinct RouteKeys across both.
        "required_apigw_routes": [
            "PATCH /{projectId}/{recordType}/{recordId}",
            "PATCH /api/v1/tracker/{projectId}/{recordType}/{recordId}",
            "DELETE /api/v1/tracker/{projectId}/relationship",
            "DELETE /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout",
            "GET /api/v1/tracker/pending-updates",
            "GET /api/v1/tracker/{projectId}",
            "GET /api/v1/tracker/{projectId}/relationship",
            "GET /api/v1/tracker/{projectId}/{recordType}/{recordId}",
            "OPTIONS /api/v1/tracker/pending-updates",
            "OPTIONS /api/v1/tracker/{projectId}",
            "OPTIONS /api/v1/tracker/{projectId}/relationship",
            "OPTIONS /api/v1/tracker/{projectId}/{recordType}",
            "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}",
            "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/acceptance-evidence",
            "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout",
            "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/extend",
            "OPTIONS /api/v1/tracker/{projectId}/{recordType}/{recordId}/log",
            "OPTIONS /{projectId}/{recordType}/{recordId}",
            "POST /api/v1/tracker/{projectId}/{recordType}",
            "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/acceptance-evidence",
            "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/checkout",
            "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/extend",
            "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/log",
            "POST /api/v1/tracker/{projectId}/{recordType}/{recordId}/apply",
            "POST /api/v1/tracker/{projectId}/dedup-review",
        ],
        "required_cfn_resources": ["TrackerMutationFunction", "TrackerMutationRole"],
        "required_lambda_env_vars": [
            "COORDINATION_INTERNAL_API_KEY",
            "COORDINATION_INTERNAL_API_KEY_PREVIOUS",
            "COGNITO_USER_POOL_ID",
            "COGNITO_CLIENT_ID",
            "DYNAMODB_TABLE",
            "RELATIONSHIPS_TABLE",
            "DYNAMODB_REGION",
            "PROJECTS_TABLE",
            "AWS_APPCONFIG_EXTENSION_POLL_INTERVAL_SECONDS",
            "APPCONFIG_APPLICATION",
            "APPCONFIG_ENVIRONMENT",
            "APPCONFIG_CONFIGURATION",
            "LIFECYCLE_SERVICE_FUNCTION",
            "LESSON_SCORING_TOPIC_ARN",
            "ESCALATION_ALERTS_TOPIC_ARN",
            "ENABLE_LESSON_PRIMITIVE",
        ],
    },
    {
        "component_id": "comp-enceladus-mcp-server",
        "component_name": "MCP Server (server.py)",
        "project_id": "enceladus",
        "category": "library",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus MCP server (tools/enceladus-mcp-server/server.py) — exposed to Claude agents via MCP protocol. [AC-4/T1] Single MCP umbrella owning the shared server.py; the enceladus-mcp-code + enceladus-mcp-streamable dual-deployment decomposition (server_core.py + entry shims) is known debt deferred to ENC-FTR-094.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:lambda:us-west-2:{account}:function:enceladus-mcp-code-gamma",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "tools/enceladus-mcp-server/server.py",
        "source_paths": {
            "primary": "tools/enceladus-mcp-server/server.py",
            "directory": "tools/enceladus-mcp-server/",
            "related": ["tools/enceladus-mcp-server/install_profile.sh"],
            "architecture_sections": ["8.1"],
        },
        # ENC-TSK-L05 AC-1. This is a `library` component (server.py source), not
        # a standalone deploy unit -- it has no `deploy_targets` entry (unlike the
        # 5 lambda-category components above) and is architecturally different
        # from them: the gamma runtime (EnceladusMcpCodeGammaFunction,
        # 02-compute.yaml:6393-6501) is CFN-managed but Condition:IsProduction
        # (created BY the prod stack, not gamma's own stack) and reuses the
        # borrowed role devops-coordination-api-lambda-role-gamma rather than a
        # role scoped to this component. The prod runtime (plain enceladus-mcp-code,
        # no -gamma suffix) has NO CFN Function resource anywhere in the repo --
        # it is entirely out-of-band/unmanaged and only appears as a literal ARN
        # string in another component's (McpStreamingGatewayRole-adjacent
        # DeployParityValidatorRole) IAM policy. Given this component owns neither
        # a dedicated CFN-managed role nor a dedicated CFN Function resource of
        # its own, all five fields are considered and left empty rather than
        # attributing another component's borrowed/shared infrastructure to this
        # one -- forcing values here would misrepresent drift-audit ownership.
        "required_iam_actions": [],
        "required_env_secrets": ["DM_GITHUB_READ_TOKEN", "COORDINATION_INTERNAL_API_KEY"],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    # ENC-TSK-L05 AC-2 (T2): PWA decomposition — 03-api.yaml is already API-Gateway-only and the CDN already lives in 07-ui-cdn.yaml, so no file split; supersedes the former single comp-enceladus-pwa.
    {
        "component_id": "comp-enceladus-pwa-frontend",
        "component_name": "Enceladus PWA Frontend (React SPA)",
        "project_id": "enceladus",
        "category": "frontend",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:s3:::jreese-net-pwa-artifacts",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "frontend/ui/src",
        "description": "Enceladus PWA React single-page app source; built and published to the artifacts S3 bucket fronted by the CloudFront distribution (comp-enceladus-pwa-cdn).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-pwa-cdn",
        "component_name": "Enceladus PWA CloudFront Distribution",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudfront::{account}:distribution/{dist-id}",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/07-ui-cdn.yaml",
        "description": "CloudFront distribution + edge config that serves the Enceladus PWA (provisioned by 07-ui-cdn.yaml).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-api-gateway",
        "component_name": "Enceladus HTTP API Gateway",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:apigateway:us-west-2::/restapis/{api-id}",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/03-api.yaml",
        "description": "Enceladus HTTP API Gateway (routes + integrations) provisioned by 03-api.yaml.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-cloudformation-data",
        "component_name": "CloudFormation Data Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus data CloudFormation stack (01-data.yaml) — DynamoDB tables, S3 buckets, etc. Updated by product lead via elevated IAM role.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-data-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/01-data.yaml",
        "source_paths": {
            "primary": "infrastructure/cloudformation/01-data.yaml",
            "directory": "infrastructure/cloudformation/",
            "architecture_sections": ["3.1", "3.2", "3.3"],
        },
        # ENC-TSK-L05 AC-1. Infra-umbrella component -- this IS the entire
        # 01-data.yaml template (no other component claims sub-resources within
        # it), so listing its full logical-resource set is meaningful (unlike
        # comp-cloudformation-app below, where 5 of ~35 Functions already have
        # their own dedicated components). Deploy path: cloudformation-compute-
        # stack-deploy.yml (data-stack change-set step; job-level
        # AWS_CLOUDFORMATION_ROLE_TO_ASSUME secret, environment v3-prod/v4-gamma).
        # required_iam_actions left empty: AWS_CLOUDFORMATION_ROLE_TO_ASSUME
        # resolves to an externally-managed IAM role (GitHub secret, not a
        # repo-declared CFN role) -- this agent's IAM identity is denied
        # iam:GetRole/ListRolePolicies (per ENC-TSK-564), and no in-repo source
        # enumerates that role's policy document, so this is a considered
        # empty, not an oversight.
        "required_iam_actions": [],
        "required_env_secrets": ["AWS_CLOUDFORMATION_ROLE_TO_ASSUME"],
        "required_apigw_routes": [],
        "required_cfn_resources": [
            "CoordinationRequestsTable",
            "TrackerTable",
            "RelationshipsTable",
            "ProjectsTable",
            "DocumentsTable",
            "DriftTelemetryTable",
            "StigmergicTraceTable",
            "DeploymentManagerTable",
            "GovernancePoliciesTable",
            "ComponentRegistryTable",
            "AgentComplianceViolationsTable",
            "DeployQueue",
            "FeedPublishQueue",
            "GraphSyncQueue",
            "GraphSyncDLQ",
            "SearchIndexQueue",
            "SearchIndexDLQ",
            "ConvergenceTelemetryQueue",
            "ConvergenceTelemetryDLQ",
            "CoordinationDeadLetterTopic",
            "FeedAlertsTopic",
            "ParquetReadyTopic",
            "ProjectJsonSyncTopic",
            "ComponentRegistryEventsTopic",
            "LessonScoringTopic",
            "AgentSessionsTable",
            "AgentTypesTable",
            "AgentCredentialsTable",
            "UserPreferencesTable",
            "GovernanceVersionTable",
            "PercolationTelemetryTable",
            "ConvergenceTelemetryTable",
        ],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-cloudformation-app",
        "component_name": "CloudFormation App Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Enceladus compute/app CloudFormation stack (02-compute.yaml) — Lambda functions, API Gateway, EventBridge rules, etc. Updated by product lead via elevated IAM role.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-compute-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/02-compute.yaml",
        "source_paths": {
            "primary": "infrastructure/cloudformation/02-compute.yaml",
            "directory": "infrastructure/cloudformation/",
            "related": ["infrastructure/lambda_workflow_manifest.json"],
            "architecture_sections": ["2.1", "4.0"],
        },
        # ENC-TSK-L05 AC-1. Unlike comp-cloudformation-data, this umbrella's
        # template (02-compute.yaml) already has 5 of its ~35 Lambda Functions
        # registered as their OWN dedicated components (comp-checkout-service,
        # comp-lifecycle-service, comp-scoring-service, comp-coordination-api,
        # comp-tracker-mutation), each carrying its own required_cfn_resources
        # now. Enumerating this umbrella's required_cfn_resources would mean
        # either re-listing resources already owned/tracked by those dedicated
        # components (double-booking drift ownership) or dumping the remaining
        # ~30 unrelated Functions/Roles/EventBridge rules into a field with no
        # scoping logic -- that re-scoping is explicitly ENC-TSK-L05 AC-4 (T4a,
        # umbrella-per-CFn-file registration), which is out of scope for this
        # AC-1-only pass and remains blocked on the same H-SCHEMA prerequisite
        # as AC2-AC6. Left empty and considered, not force-filled, to avoid
        # preempting AC-4's proper scoping decision.
        "required_iam_actions": [],
        "required_env_secrets": [
            "AWS_CLOUDFORMATION_ROLE_TO_ASSUME",
            "COORDINATION_INTERNAL_API_KEY",
            "ENCELADUS_COGNITO_CLIENT_SECRET",
            "CURSOR_WEBHOOK_SECRET",
        ],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    # ── Enceladus AC-3 external + AC-4 CFN umbrellas + AC-6 governance-doc umbrella ──
    {
        "component_id": "comp-enceladus-neo4j",
        "component_name": "Enceladus Neo4j AuraDB",
        "project_id": "enceladus",
        "category": "external",
        "transition_type": "code",
        "required_transition_type": "external_deploy",
        "component_address": "neo4j+s://{instance-id}.databases.neo4j.io",
        "component_address_class": "neo4j_auradb",
        "component_class": "external",
        "component_repo_dir": "infrastructure/external/neo4j-auradb.yaml",
        "description": "Neo4j AuraDB graph substrate (managed externally; connection config + secret refs declared in infrastructure/external/neo4j-auradb.yaml). Changes tracked via external_deploy_evidence.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": ["NEO4J_URI", "NEO4J_PASSWORD"],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-github-roles",
        "component_name": "Enceladus CloudFormation GitHub Roles Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-github-roles-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/04-github-roles.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 04-github-roles.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-monitoring",
        "component_name": "Enceladus CloudFormation Monitoring Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-monitoring-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/05-monitoring.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 05-monitoring.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-appsync-events",
        "component_name": "Enceladus CloudFormation AppSync Events Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-appsync-events-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/06-appsync-events.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 06-appsync-events.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-feature-flags",
        "component_name": "Enceladus CloudFormation Feature Flags Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-feature-flags-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/06-feature-flags.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 06-feature-flags.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-codedeploy",
        "component_name": "Enceladus CloudFormation CodeDeploy Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-codedeploy-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/07-codedeploy.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 07-codedeploy.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-agent-auth",
        "component_name": "Enceladus CloudFormation Agent Auth Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-agent-auth-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/08-agent-auth.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 08-agent-auth.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-lambda-artifacts",
        "component_name": "Enceladus CloudFormation Lambda Artifacts Staging Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-lambda-artifacts-staging-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/08-lambda-artifacts-staging.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 08-lambda-artifacts-staging.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-appconfig-governance",
        "component_name": "Enceladus CloudFormation AppConfig Governance Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-appconfig-governance-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/09-appconfig-governance.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 09-appconfig-governance.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-enceladus-cfn-opensearch",
        "component_name": "Enceladus CloudFormation OpenSearch Node Stack",
        "project_id": "enceladus",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "component_address": "arn:aws:cloudformation:us-west-2:{account}:stack/enceladus-opensearch-node-gamma/*",
        "component_address_class": "aws_arn",
        "component_class": "physical",
        "component_repo_dir": "infrastructure/cloudformation/10-opensearch-node.yaml",
        "description": "Enceladus CloudFormation umbrella component owning 10-opensearch-node.yaml (T4a umbrella-per-CFN-file; finer per-resource split tracked by ENC-FTR-093).",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    {
        "component_id": "comp-umbrella-governance-documentation",
        "component_name": "Governance Documentation Umbrella",
        "project_id": "enceladus",
        "category": "workflow",
        "transition_type": "code",
        "required_transition_type": "documentation",
        "component_address": "meta:comp-umbrella-governance-documentation",
        "component_address_class": "meta",
        "component_class": "meta",
        "component_repo_dir": "meta:comp-umbrella-governance-documentation",
        "description": "Meta governance-documentation umbrella (v3 rename of the legacy comp-umbrella-no-code). Governance-only; tasks close against it with documentation_evidence.",
        "github_repo": "NX-2021-L/enceladus",
        "status": "active",
        "required_iam_actions": [],
        "required_env_secrets": [],
        "required_apigw_routes": [],
        "required_cfn_resources": [],
        "required_lambda_env_vars": [],
    },
    # ── Harrisonfamily ───────────────────────────────────────────────────────
    {
        "component_id": "comp-harrisonfamily-site",
        "component_name": "Harrison Family Site",
        "project_id": "harrisonfamily",
        "category": "frontend",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Harrison Family static site — Eleventy + 11ty deployed to CloudFront/S3.",
        "github_repo": "me-jreese/harrisonfamily",
        "status": "active",
        "source_paths": {
            "primary": "repo/11ty/.eleventy.js",
            "directory": "repo/11ty/",
            "related": ["workspace/11ty-dev/", "repo/11ty/js/", "repo/11ty/_data/"],
        },
    },
    # ── MOD (vagamod.io) ─────────────────────────────────────────────────────
    {
        "component_id": "comp-mod-web",
        "component_name": "MOD Next.js Frontend (vagamod.io)",
        "project_id": "mod",
        "category": "frontend",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "MOD Next.js/SST frontend app — deployed via GitHub Actions sst deploy to CloudFront/Lambda@Edge.",
        "github_repo": "NX-2021-L/mod",
        "status": "active",
    },
    {
        "component_id": "comp-mod-api",
        "component_name": "MOD Lambda API Handlers",
        "project_id": "mod",
        "category": "lambda",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "MOD Lambda API handlers (objects, custody, users, comments, search, QR) — deployed via GitHub Actions sst deploy.",
        "github_repo": "NX-2021-L/mod",
        "status": "active",
    },
    {
        "component_id": "comp-mod-infra",
        "component_name": "MOD SST Infrastructure (DynamoDB + CloudFormation)",
        "project_id": "mod",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "MOD SST v3 infrastructure stack — DynamoDB tables, IAM roles, CloudFront, API Gateway; deployed via GitHub Actions sst deploy.",
        "github_repo": "NX-2021-L/mod",
        "status": "active",
    },
    {
        "component_id": "comp-mod-keycloak",
        "component_name": "MOD Keycloak Auth (Lightsail)",
        "project_id": "mod",
        "category": "external",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "MOD Keycloak identity provider on AWS Lightsail (auth.vagamod.io) — admin-managed via Lightsail console and SSH. No GitHub Actions pipeline.",
        "github_repo": "NX-2021-L/mod",
        "status": "active",
    },
    # ── DevOps (ENC-FTR-042) ─────────────────────────────────────────────────
    {
        "component_id": "comp-devops-governance",
        "component_name": "DevOps Governance & Deployment Config",
        "project_id": "devops",
        "category": "workflow",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "DevOps governance policies (agents.md, data dictionary), deployment configs, and agent SOPs in S3. Updated via MCP governance_update.",
        "status": "active",
        "source_paths": {
            "primary": "governance://agents.md",
            "related": [
                "tools/seed-component-registry.py",
                "backend/lambda/coordination_api/governance_data_dictionary.json",
            ],
        },
    },
    # ── jreesewebops (ENC-FTR-042) ───────────────────────────────────────────
    {
        "component_id": "comp-jwo-web-infra",
        "component_name": "Web Infrastructure (CloudFront/S3/Cloudflare/Lightsail)",
        "project_id": "jreesewebops",
        "category": "infrastructure",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Unified web infrastructure for jreese.net, jree.se, go.thepup.io — CloudFront distributions, S3 origins, Cloudflare Workers/DNS, Lightsail instances. Admin-managed via consoles.",
        "status": "active",
    },
    # ── jreeseGPT (ENC-FTR-042) ──────────────────────────────────────────────
    {
        "component_id": "comp-jgp-platform",
        "component_name": "jreeseGPT AI Platform",
        "project_id": "jreeseGPT",
        "category": "external",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "AI recruiter assistant — corpus ingestion, embeddings, Bedrock/Lambda APIs, scheduling workflows. Development stage.",
        "status": "active",
    },
    # ── jobapps (ENC-FTR-042) ────────────────────────────────────────────────
    {
        "component_id": "comp-jap-jds-platform",
        "component_name": "Job Discovery System (JDS)",
        "project_id": "jobapps",
        "category": "external",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "JDS scraper runners, configuration playbooks, ChromeDriver hardening, and analytics. Development stage.",
        "status": "active",
    },
    # ── intelligent-scraper-generator (ENC-FTR-042) ──────────────────────────
    {
        "component_id": "comp-isg-toolkit",
        "component_name": "Intelligent Scraper Generator",
        "project_id": "intelligent-scraper-generator",
        "category": "library",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "LLM-assisted toolkit for analyzing employer career sites and generating scraper/playbook scaffolding. Child of jobapps JDS pipeline.",
        "status": "active",
    },
    # ── property160c1 (ENC-FTR-042) ──────────────────────────────────────────
    {
        "component_id": "comp-prp-planning",
        "component_name": "Property 160C1 Planning",
        "project_id": "property160c1",
        "category": "workflow",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Property 160C1 project planning and requirements artifacts. Planning stage.",
        "status": "active",
    },
    # ── agentharmony (ENC-FTR-042) ───────────────────────────────────────────
    {
        "component_id": "comp-agh-governance",
        "component_name": "Agent Harmony Governance & Templates",
        "project_id": "agentharmony",
        "category": "workflow",
        "transition_type": "code",
        "required_transition_type": "code",
        "description": "Agent documentation standards, templates (bootstrap-session.sh, codex-auto.sh), and operational tooling inherited by all downstream projects.",
        "status": "active",
    },
]

# ENC-TSK-L05 AC2-6 / ENC-TSK-L77: v3 component policy enum default is "code".
# Legacy default was "github_pr_deploy" (pre-DOC-157A790F9E8B). All enceladus
# manifest entries now carry transition_type="code", so no assistant-key /
# Cognito gate is tripped for the automated create path (the create handler
# only gates a NON-"code" transition_type).
_DEFAULT_TRANSITION_TYPE = "code"


def _api_request(
    base_url: str,
    api_key: str,
    method: str,
    path: str,
    payload: dict | None = None,
    extra_headers: dict | None = None,
) -> tuple[int, dict]:
    url = f"{base_url.rstrip('/')}{path}"
    body = json.dumps(payload).encode() if payload is not None else None
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "X-Coordination-Internal-Key": api_key,
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        try:
            err_body = json.loads(body_bytes)
        except Exception:
            err_body = {"raw": body_bytes.decode(errors="replace")}
        return exc.code, err_body


def seed(
    base_url: str,
    api_key: str,
    dry_run: bool,
    assistant_key: str = "",
    direct_apigw_base: str = "",
) -> None:
    ok_count = 0
    skip_count = 0
    err_count = 0
    needs_manual_patch: list[tuple[str, str]] = []  # (component_id, target_transition_type)

    for comp in KNOWN_COMPONENTS:
        cid = comp["component_id"]
        target_type = comp["transition_type"]
        print(f"\n[{cid}] ({target_type})", end="")

        if dry_run:
            print(" — DRY RUN, skipping")
            continue

        # Check if already exists
        status, existing = _api_request(base_url, api_key, "GET", f"/components/{cid}")
        if status == 200:
            # ENC-TSK-L05 AC2-6: the seed is the deploy-applied backfill surface.
            # The legacy skip-on-exists behavior could never populate the new v3
            # schema fields onto the 10 pre-existing enceladus components (this is
            # exactly the gap AC-1's separate backfill tool hit, then couldn't run
            # for lack of a live write path). For enceladus components we now
            # UPSERT the four v3 identity fields, the migrated
            # required_transition_type, and the five ENC-TSK-E68 capability fields
            # via PATCH /components/{id}. Non-enceladus components keep the
            # conservative skip so this seed never overwrites another project's
            # governance state.
            if comp.get("project_id") != "enceladus":
                print(" — exists (non-enceladus), skipping")
                skip_count += 1
                continue
            patch_fields = {
                k: comp[k]
                for k in (
                    "component_address",
                    "component_address_class",
                    "component_class",
                    "component_repo_dir",
                    "required_transition_type",
                    "required_iam_actions",
                    "required_env_secrets",
                    "required_apigw_routes",
                    "required_cfn_resources",
                    "required_lambda_env_vars",
                    "description",
                    "category",
                )
                if k in comp
            }
            pstatus, presult = _api_request(
                base_url, api_key, "PATCH", f"/components/{cid}", patch_fields
            )
            if pstatus in (200, 204):
                print(" — UPSERTED v3 identity + capability fields ✓")
                ok_count += 1
            else:
                print(
                    f" — PATCH ERROR {pstatus}: {presult.get('error', presult)} "
                    "(if this is an auth gate on required_transition_type, re-run "
                    "with a Cognito/assistant credential)"
                )
                err_count += 1
            continue

        # Non-default transition_type requires assistant key or Cognito.
        # Without those: create with default type, record for manual follow-up.
        needs_type_auth = target_type != _DEFAULT_TRANSITION_TYPE

        if needs_type_auth and not assistant_key:
            create_payload = {k: v for k, v in comp.items() if k != "transition_type"}
            status, result = _api_request(base_url, api_key, "POST", "/components", create_payload)
            if status == 201:
                print(
                    f" — CREATED with default type (github_pr_deploy); "
                    f"⚠️  MANUAL PATCH needed → transition_type={target_type} (via PWA or --assistant-key)"
                )
                needs_manual_patch.append((cid, target_type))
                ok_count += 1
            elif status == 409:
                print(f" — 409 Conflict (already exists), skipping")
                skip_count += 1
            else:
                print(f" — ERROR {status}: {result.get('error', result)}")
                err_count += 1
            continue

        # Build create payload; use assistant key + direct APIGW for non-default types
        create_payload = dict(comp)
        if needs_type_auth and assistant_key:
            extra = {"X-Checkout-Assistant-Key": assistant_key}
            create_base = (direct_apigw_base or base_url).rstrip("/")
            status, result = _api_request(
                create_base, api_key, "POST", "/components", create_payload, extra
            )
        else:
            status, result = _api_request(base_url, api_key, "POST", "/components", create_payload)

        if status == 201:
            print(f" — CREATED ✓")
            ok_count += 1
        elif status == 409:
            print(f" — 409 Conflict (already exists), skipping")
            skip_count += 1
        else:
            print(f" — ERROR {status}: {result.get('error', result)}")
            err_count += 1

    print(f"\n\n=== Seed complete ===")
    print(f"Created:  {ok_count}")
    print(f"Skipped:  {skip_count}")
    print(f"Errors:   {err_count}")
    if needs_manual_patch:
        print(f"\n⚠️  {len(needs_manual_patch)} component(s) created with wrong transition_type — manual PATCH needed:")
        for cid, tt in needs_manual_patch:
            print(f"   {cid}  →  {tt}")
        print(
            "\n   Fix options:\n"
            "   1. Open jreese.net/components, find the component, click Edit, set Transition Type.\n"
            "   2. Re-run with: CHECKOUT_ASSISTANT_KEY=<key> python3 tools/seed-component-registry.py\n"
            "      (script will SKIP existing correct-type entries; only patch mismatches need manual fix)"
        )
    if err_count:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed Enceladus component registry (ENC-FTR-041)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be done without making API calls",
    )
    parser.add_argument("--base-url", default=None, help="Coordination API base URL")
    parser.add_argument("--api-key", default=None, help="Internal API key")
    parser.add_argument(
        "--assistant-key", default=None,
        help=(
            "Checkout-service-assistant key (X-Checkout-Assistant-Key). "
            "Allows setting non-default transition_type at create time without Cognito. "
            "Env var: CHECKOUT_ASSISTANT_KEY"
        ),
    )
    parser.add_argument(
        "--direct-apigw-base", default=None,
        help=(
            "Direct API Gateway base URL for assistant-key requests (bypasses CloudFront). "
            "Env var: COORDINATION_DIRECT_APIGW_BASE. "
            "Default: https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/coordination"
        ),
    )
    args = parser.parse_args()

    base_url = (
        args.base_url
        or os.environ.get("COORDINATION_API_BASE", "")
        or "https://jreese.net/api/v1/coordination"
    )
    api_key = (
        args.api_key
        or os.environ.get("ENCELADUS_COORDINATION_INTERNAL_API_KEY", "")
        or os.environ.get("COORDINATION_INTERNAL_API_KEY", "")
    )
    assistant_key = args.assistant_key or os.environ.get("CHECKOUT_ASSISTANT_KEY", "")
    direct_apigw_base = (
        args.direct_apigw_base
        or os.environ.get("COORDINATION_DIRECT_APIGW_BASE", "")
        or "https://8nkzqkmxqc.execute-api.us-west-2.amazonaws.com/api/v1/coordination"
    )

    if not api_key and not args.dry_run:
        print(
            "ERROR: --api-key or ENCELADUS_COORDINATION_INTERNAL_API_KEY env var is required",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Base URL:      {base_url}")
    print(f"Direct APIGW:  {direct_apigw_base}")
    print(f"Dry run:       {args.dry_run}")
    print(f"Assistant key: {'set' if assistant_key else 'not set — non-default types will default to github_pr_deploy'}")
    print(f"Components:    {len(KNOWN_COMPONENTS)}")

    seed(
        base_url,
        api_key,
        dry_run=args.dry_run,
        assistant_key=assistant_key,
        direct_apigw_base=direct_apigw_base,
    )


if __name__ == "__main__":
    main()
