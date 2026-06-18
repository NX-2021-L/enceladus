# ENC-TSK-G95 — CFN vs Live IAM action-level diff (2026-06-17)

Supersedes DOC-FBD770A9483B. Source: live dump under product-lead (io-dev-admin).

- roles compared: 25
- roles with live actions MISSING from CFN (drift): 10
- roles that are CFN placeholders (no inline Policies): 0
- roles in CFN but not live (deploy would create): ['devops-deploy-parity-validator-role']

## CoordinationApiRole  (devops-coordination-api-lambda-role) — HAS_CFN_POLICIES
  - **ACTIONS MISSING IN CFN (live-only):** ['lambda:invokefunction']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## TrackerMutationRole  (devops-tracker-mutation-lambda-role) — HAS_CFN_POLICIES
  - live attached managed policies: ['arn:aws:iam::356364570033:policy/devops-tracker-dynamodb-policy', 'arn:aws:iam::356364570033:policy/projects-read-policy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## DocumentApiRole  (devops-document-api-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## ProjectServiceRole  (devops-project-service-lambda-role) — HAS_CFN_POLICIES
  - **ACTIONS MISSING IN CFN (live-only):** ['s3:deleteobject', 's3:putobject']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## FeedQueryRole  (devops-feed-query-lambda-role) — HAS_CFN_POLICIES
  - live attached managed policies: ['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole']
  - **ACTIONS MISSING IN CFN (live-only):** ['dynamodb:getitem', 'dynamodb:query', 'dynamodb:scan']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## CoordinationMonitorRole  (devops-coordination-monitor-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## DeployIntakeRole  (devops-deploy-intake-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## DeployOrchestratorRole  (devops-deploy-orchestrator-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## DeployFinalizeRole  (devops-deploy-finalize-lambda-role) — HAS_CFN_POLICIES
  - **ACTIONS MISSING IN CFN (live-only):** ['dynamodb:getitem', 'dynamodb:putitem', 'dynamodb:query', 'dynamodb:scan', 'dynamodb:updateitem', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:putobject']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## DeployDecideRole  (devops-deploy-decide-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## DeployParityValidatorRole  (devops-deploy-parity-validator-role) — CFN_ONLY_NOT_LIVE
  - Declared in CFN but does not exist live -> deploy CREATES role (ISS-252: iam:CreateRole).

## ReferenceSearchRole  (devops-reference-search-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## FeedPublisherRole  (devops-feed-publisher-lambda-role) — HAS_CFN_POLICIES
  - live attached managed policies: ['arn:aws:iam::356364570033:policy/projects-read-policy']
  - **ACTIONS MISSING IN CFN (live-only):** ['cloudfront:createinvalidation', 'dynamodb:getitem', 'dynamodb:query', 'dynamodb:scan', 'events:putevents', 's3:getobject', 's3:putobject', 'sns:publish']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## GovernanceAuditRole  (enceladus-governance-audit-role) — HAS_CFN_POLICIES
  - live attached managed policies: ['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole']
  - **ACTIONS MISSING IN CFN (live-only):** ['sns:publish']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## DocPrepRole  (devops-doc-prep-lambda-role) — HAS_CFN_POLICIES
  - **ACTIONS MISSING IN CFN (live-only):** ['dynamodb:getitem', 'dynamodb:query', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:getobject']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## BedrockActionsRole  (enceladus-bedrock-actions-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## ChangelogApiRole  (devops-changelog-api-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## AuthRefreshRole  (auth-refresh-lambda-role) — HAS_CFN_POLICIES
  - live attached managed policies: ['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole']
  - **ACTIONS MISSING IN CFN (live-only):** ['cognito-idp:initiateauth']
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## FeedPipeRole  (devops-feed-pipe-role) — HAS_CFN_POLICIES
  - **ACTIONS MISSING IN CFN (live-only):** ['sqs:getqueueattributes']

## GraphSyncRole  (devops-graph-sync-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## GraphQueryApiRole  (devops-graph-query-api-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## Neo4jBackupRole  (enceladus-neo4j-backup-lambda-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## GraphHealthMetricsRole  (enceladus-graph-health-metrics-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

## GraphPipeRole  (devops-graph-pipe-role) — HAS_CFN_POLICIES
  - **ACTIONS MISSING IN CFN (live-only):** ['sqs:getqueueattributes']

## EnvDriftAuditorRole  (devops-env-drift-auditor-role) — HAS_CFN_POLICIES
  - actions in CFN but not live (benign add on deploy): ['appconfig:getconfiguration', 'appconfig:getlatestconfiguration', 'appconfig:startconfigurationsession']

