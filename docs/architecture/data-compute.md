# Enceladus Architecture: Data & Compute Layer

> Sections 2-5 extracted from ARCHITECTURE.md (ENC-TSK-819).
> For navigation, see [docs/ARCHITECTURE.md](../ARCHITECTURE.md).

---

# SECTION 2 — SYSTEM ARCHITECTURE DIAGRAM

## [SECTION 2.1] High-Level Architecture

```
                        +------------------+
                        |   CloudFront     |
                        |  E2BOQXCW1TA6Y4  |
                        +--------+---------+
                                 |
                    +------------+------------+
                    |            |            |
               /enceladus   /mobile/v1   /api/v1/*
                    |            |            |
               +----+----+  +---+---+  +-----+------+
               | S3 PWA  |  | S3    |  | API Gateway |
               | Assets  |  | Feeds |  | HTTP API    |
               +---------+  +-------+  +-----+------+
                                              |
              +-------+-------+-------+-------+-------+
              |       |       |       |       |       |
         tracker  document  project  feed   deploy  github
         mutation   api     service  query  intake  integration
              |       |       |       |       |       |
              +-------+---+---+-------+       |       |
                          |                   |       |
                   +------+------+      +-----+----+  |
                   | DynamoDB    |      | SQS FIFO |  |
                   | Tables (7)  |      | Queues   |  |
                   +------+------+      +-----+----+  |
                          |                   |       |
                   +------+------+      +-----+------+|
                   | DynamoDB    |      | deploy     ||
                   | Streams     |      | orchestrator|
                   +------+------+      +-----+------+|
                          |                   |       |
                   +------+------+      +-----+----+ |
                   | EventBridge |      | CodeBuild| |
                   | Pipes       |      +----------+ |
                   +------+------+                   |
                          |                    +-----+------+
                   +------+------+             | GitHub API |
                   | feed        |             | (App auth) |
                   | publisher   |             +------------+
                   +------+------+
                          |
                   +------+------+
                   | S3 Feeds +  |
                   | CloudFront  |
                   | Invalidation|
                   +-------------+
```

## [SECTION 2.2] Data Flow Diagram

```
USER (PWA) --[HTTPS]--> CloudFront --[Lambda@Edge auth]--> API Gateway
                                                                |
  Reads:  GET /mobile/v1/*.json  --> S3 (cached feeds)          |
  Writes: PATCH /api/v1/tracker  --> tracker_mutation Lambda    |
                                          |                     |
                                    DynamoDB write              |
                                          |                     |
                                    DynamoDB Stream             |
                                          |                     |
                                    EventBridge Pipe            |
                                          |                     |
                                    SQS FIFO (debounce)         |
                                          |                     |
                                    feed_publisher Lambda       |
                                          |                     |
                                    S3 feed + CloudFront invalidation
                                          |
                                    SNS -> Glue Crawler -> Parquet -> Analytics

AGENT (MCP) --[stdio]--> MCP Server --[HTTPS]--> API Gateway --> Lambda APIs
                              |
                        DynamoDB (reads)
                        S3 (reads)
                        HTTP API (writes via Lambda)
```

---

# SECTION 3 — DATA LAYER

## [SECTION 3.1] DynamoDB Tables

All tables use PAY_PER_REQUEST billing and are in us-west-2.

### coordination-requests

Core table for agent coordination request lifecycle.

| Attribute | Type | Role |
|-----------|------|------|
| `request_id` | S | HASH key |

**GSIs:**
| GSI Name | HASH | RANGE | Projection |
|----------|------|-------|------------|
| `project-updated-index` | `project_id` | `updated_epoch` | ALL |
| `idempotency-index` | `idempotency_key` | `created_epoch` | ALL |

**Stream:** None
**Deletion Protection:** Yes

---

### devops-project-tracker

Core tracker table powering all project tracking across the portfolio.

| Attribute | Type | Role |
|-----------|------|------|
| `project_id` | S | HASH key |
| `record_id` | S | RANGE key (format: `{type}#{human_id}`, e.g. `task#ENC-TSK-086`) |

**GSIs:**
| GSI Name | HASH | RANGE | Projection |
|----------|------|-------|------------|
| `type-updated-index` | `record_type` | `updated_at` | ALL |
| `project-type-index` | `project_id` | `record_type` | ALL |

**Stream:** NEW_AND_OLD_IMAGES (powers feed pipeline + governance audit)
**Deletion Protection:** Yes
**Consumers:** tracker_mutation, feed_publisher, governance_audit, feed_query, bedrock_agent_actions, coordination_api, deploy_finalize

---

### projects

Project metadata registry.

| Attribute | Type | Role |
|-----------|------|------|
| `project_id` | S | HASH key |

**GSIs:**
| GSI Name | HASH | RANGE | Projection |
|----------|------|-------|------------|
| `prefix-index` | `prefix` | — | ALL |

**Stream:** None
**Deletion Protection:** Yes
**Key Fields:** project_id, prefix (3-char uppercase), summary, status, parent, repo, days_since_active

---

### documents

Agent documentation metadata (content stored in S3).

| Attribute | Type | Role |
|-----------|------|------|
| `document_id` | S | HASH key (format: `DOC-{12-char-hex}`) |

**GSIs:**
| GSI Name | HASH | RANGE | Projection |
|----------|------|-------|------------|
| `project-updated-index` | `project_id` | `updated_at` | ALL |

**Stream:** NEW_AND_OLD_IMAGES (powers documents-to-feed EventBridge Pipe)
**Deletion Protection:** Yes
**S3 Content:** `s3://jreese-net/agent-documents/{project_id}/{document_id}.md`

---

### devops-deployment-manager

Deployment lifecycle state machine.

| Attribute | Type | Role |
|-----------|------|------|
| `project_id` | S | HASH key |
| `record_id` | S | RANGE key |

**GSIs:**
| GSI Name | HASH | RANGE | Projection |
|----------|------|-------|------------|
| `record-type-index` | `project_id` | `record_type` | ALL |

**Stream:** None
**Record Types:** `request` (pending deploy), `spec` (deployment spec), `state` (ACTIVE/PAUSED)

---

### governance-policies

Governance rule definitions for agent compliance enforcement.

| Attribute | Type | Role |
|-----------|------|------|
| `policy_id` | S | HASH key |

**Stream:** None

---

### agent-compliance-violations

Audit trail for agent policy violations.

| Attribute | Type | Role |
|-----------|------|------|
| `violation_id` | S | HASH key |

**GSIs:**
| GSI Name | HASH | RANGE | Projection |
|----------|------|-------|------------|
| `provider-timestamp-index` | `provider` | `event_epoch` | ALL |
| `policy-timestamp-index` | `policy_id` | `event_epoch` | ALL |

**Stream:** None

---

## [SECTION 3.2] SQS Queues

### devops-deploy-queue.fifo

| Property | Value |
|----------|-------|
| Type | FIFO |
| VisibilityTimeout | 180s (debounce window) |
| MessageRetentionPeriod | 86400s (24h) |
| ContentBasedDeduplication | true |
| Encryption | SQS-managed SSE |
| Producer | deploy_intake Lambda |
| Consumer | deploy_orchestrator Lambda (batch size 1) |

### devops-feed-publish-queue.fifo

| Property | Value |
|----------|-------|
| Type | FIFO |
| VisibilityTimeout | 900s (5-min debounce per project) |
| MessageRetentionPeriod | 86400s (24h) |
| ContentBasedDeduplication | true |
| Encryption | SQS-managed SSE |
| Producer | EventBridge Pipes (from DynamoDB Streams) |
| Consumer | feed_publisher Lambda (batch size 10) |
| MessageGroupId | `project_id` (per-project ordering) |
| DeduplicationId | `record_id` or `document_id` |

---

## [SECTION 3.3] S3 Buckets and Prefixes

**Primary Bucket:** `jreese-net` (us-west-2)

| Prefix | Purpose | Writers | Readers |
|--------|---------|---------|---------|
| `mobile/v1/` | Mobile feed JSONs (tasks, issues, features, documents, projects) | feed_publisher | PWA (via CloudFront) |
| `mobile/v1/reference/` | Project reference markdown files | project_service | reference_search, PWA |
| `agent-documents/` | Agent-generated documents | document_api | document_api, MCP server |
| `agent-documents/{project_id}/` | Per-project document content | document_api | document_api |
| `governance/live/` | Active governance files | governance_update MCP | MCP server, coordination_api |
| `governance/history/` | Archived governance versions | governance_update MCP | (audit trail) |
| `deploy-config/` | Deployment configuration | deploy_orchestrator | deploy_orchestrator |
| `deploy-config/devops/deploy.json` | Semver state for deployment | deploy_orchestrator | deploy_orchestrator |

**Analytics Bucket:** `devops-agentcli-compute`

| Prefix | Purpose |
|--------|---------|
| `projects/sync-stage/` | Staged JSON exports from feed_publisher |
| `projects/sync/` | Parquet files from json_to_parquet_transformer |

---

## [SECTION 3.4] EventBridge Rules and Pipes

### EventBridge Rules

| Rule | Pattern/Schedule | Target | Purpose |
|------|-----------------|--------|---------|
| `devops-coordination-batch-poller` | `rate(5 minutes)` | coordination_api | Poll coordination requests for state transitions |
| `devops-deploy-codebuild-finalize` | CodeBuild state change (SUCCEEDED/FAILED) for `devops-ui-deploy-builder` | deploy_finalize | Finalize UI deployments |
| `on-project-json-sync` | Custom event `devops.json-sync` / `project-json-sync` | json_to_parquet_transformer | Trigger analytics pipeline |

### EventBridge Pipes

| Pipe | Source | Filter | Target | GroupId | DedupeId |
|------|--------|--------|--------|---------|----------|
| `devops-tracker-to-feed-queue` | devops-project-tracker stream (LATEST) | `record_type != "reference"` | devops-feed-publish-queue.fifo | `project_id` | `record_id` |
| `devops-documents-to-feed-queue` | documents table stream (LATEST) | `eventName IN [INSERT, MODIFY]` | devops-feed-publish-queue.fifo | `project_id` | `document_id` |

---

## [SECTION 3.5] SNS Topics

| Topic | Purpose | Publishers | Subscribers |
|-------|---------|-----------|-------------|
| `coordination-dead-letter` | Dead-letter for coordination failures | coordination_api | (alerts) |
| `devops-feed-alerts` | Feed publication alerts | feed_publisher | (alerts) |
| `devops-json-parquet-ready` | Parquet transform notifications | json_to_parquet_transformer | glue_crawler_launcher |
| `devops-project-json-sync` | Cross-sync trigger + governance anomaly alerts | feed_publisher, governance_audit | json_to_parquet_transformer, glue_crawler_launcher |

---

# SECTION 4 — COMPUTE LAYER (LAMBDA FUNCTIONS)

## [SECTION 4.1] tracker_mutation

Primary API for tracker record lifecycle (tasks, issues, features).

| Property | Value |
|----------|-------|
| **Function Name** | `devops-tracker-mutation-api` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 10s |
| **Trigger** | API Gateway (PATCH, GET, POST, DELETE, OPTIONS) |
| **Layer** | enceladus-shared:2 |
| **Source** | `backend/lambda/tracker_mutation/lambda_function.py` |

**API Routes:**
```
GET    /api/v1/tracker/pending-updates
GET    /api/v1/tracker/{project}
GET    /api/v1/tracker/{project}/{type}/{id}
POST   /api/v1/tracker/{project}/{type}
PATCH  /api/v1/tracker/{project}/{type}/{id}
POST   /api/v1/tracker/{project}/{type}/{id}/log
POST   /api/v1/tracker/{project}/{type}/{id}/checkout
DELETE /api/v1/tracker/{project}/{type}/{id}/checkout
POST   /api/v1/tracker/{project}/{type}/{id}/acceptance-evidence
OPTIONS *
```

**DynamoDB Tables:** `devops-project-tracker` (primary), `projects` (lookups)
**Auth:** Cognito JWT (`enceladus_id_token` cookie) OR `X-Coordination-Internal-Key`
**Key Schema:** `(project_id, {type}#{human_id})` e.g. `(enceladus, task#ENC-TSK-086)`
**ID Allocation:** Atomic counter `COUNTER-{type}` with retry loop (max 10)
**EventBridge:** Emits `tracker.record.reopened` events
**Write Source:** Tags all mutations with `write_source.channel` (mcp_server, tracker_cli, mutation_api, feed_publisher)
**Relationships:** Bidirectional best-effort updates on related/parent fields

---

## [SECTION 4.2] project_service

Centralized project creation, listing, and retrieval.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-project-service` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 30s |
| **Source** | `backend/lambda/project_service/lambda_function.py` |

**API Routes:**
```
POST   /api/v1/projects
GET    /api/v1/projects
GET    /api/v1/projects/{projectName}
OPTIONS /api/v1/projects*
```

**Auth:** Cognito JWT only
**Validations:** name `^[a-z][a-z0-9_-]*$`, prefix `^[A-Z]{3}$`, summary 1-500 chars
**Creation Flow:** Validate -> check uniqueness -> check prefix -> verify parent -> create projects entry -> create tracker reference row -> upload S3 reference template -> return
**Rollback:** Multi-step on failure (deletes previously created entries)

---

## [SECTION 4.3] document_api

Document CRUD with S3 storage and DynamoDB metadata.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-document-api` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 30s |
| **Source** | `backend/lambda/document_api/lambda_function.py` |

**API Routes:**
```
PUT    /api/v1/documents
GET    /api/v1/documents/{documentId}
GET    /api/v1/documents?project={id}
PATCH  /api/v1/documents/{documentId}
GET    /api/v1/documents/search?<params>
OPTIONS /api/v1/documents*
```

**Auth:** Cognito JWT OR `X-Coordination-Internal-Key`
**S3 Storage:** `s3://jreese-net/agent-documents/{project_id}/{document_id}.md`
**Features:** Markdown compliance scoring (0-100, warn-only), content hash (SHA256) tracking, keyword indexing
**Search:** By project_id, keyword, related tracker ID, title substring

---

## [SECTION 4.4] reference_search

Search project reference documents stored in S3.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-reference-search` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 10s |
| **Source** | `backend/lambda/reference_search/lambda_function.py` |

**API Routes:**
```
GET    /api/v1/reference/search?project=X&query=Y[&regex=true&section=Z&max_results=20&context_lines=2]
OPTIONS /api/v1/reference/*
```

**Auth:** Cognito JWT
**S3 Path:** `s3://jreese-net/mobile/v1/reference/{project_id}.md`
**Output:** Matched snippets with line numbers, section context, surrounding lines

---

## [SECTION 4.5] deploy_intake

Deployment submission, state management, status, and history.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-deploy-intake` |
| **Runtime** | Python 3.11 |
| **Memory** | 512 MB |
| **Timeout** | 120s |
| **Source** | `backend/lambda/deploy_intake/lambda_function.py` |

**API Routes:**
```
POST   /api/v1/deploy/submit
GET    /api/v1/deploy/state/{projectId}
PATCH  /api/v1/deploy/state/{projectId}
GET    /api/v1/deploy/status/{specId}
GET    /api/v1/deploy/history/{projectId}
OPTIONS /api/v1/deploy/*
```

**Auth:** Cognito JWT OR `X-Coordination-Internal-Key`
**SQS:** Writes to `devops-deploy-queue.fifo` (60s debounce)
**Deployment Types:** github_public_static, github_private_sst, github_public_workers, github_private_workers, lambda_update, lambda_layer, container_template, glue_crawler_update, glue_job_update, eventbridge_rule, s3_asset_sync, cloudfront_config, step_function_update
**Change Types:** patch, minor, major

---

## [SECTION 4.6] deploy_orchestrator

SQS FIFO-triggered deployment orchestration.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-deploy-orchestrator` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 120s |
| **Trigger** | SQS (`devops-deploy-queue.fifo`, batch size 1) |
| **Source** | `backend/lambda/deploy_orchestrator/lambda_function.py` |

**UI Deployments:** Resolve semver -> write spec -> start CodeBuild (`devops-ui-deploy-builder`)
**Non-UI Deployments:** Validate service-group -> write `queued_non_ui` spec
**Config:** `s3://jreese-net/deploy-config/` for semver state

---

## [SECTION 4.7] deploy_finalize

EventBridge-triggered post-deployment finalization.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-deploy-finalize` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 120s |
| **Trigger** | EventBridge (CodeBuild state change) |
| **Source** | `backend/lambda/deploy_finalize/lambda_function.py` |

**On SUCCESS:** Update spec -> create audit record -> write `[DEPLOYMENT]` worklog entries -> confirm requests
**On FAILURE:** Update spec -> reset requests to `pending` for retry

---

## [SECTION 4.8] feed_publisher

Event-driven mobile feed publisher. Debounced via SQS FIFO.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-feed-publisher` |
| **Runtime** | Python 3.11 |
| **Memory** | 512 MB |
| **Timeout** | 600s |
| **Trigger** | SQS (`devops-feed-publish-queue.fifo`, batch size 10) |
| **Source** | `backend/lambda/feed_publisher/lambda_function.py` |

**Pipeline:** DynamoDB Streams -> EventBridge Pipes -> SQS FIFO (5-min debounce) -> This Lambda -> S3 feeds -> CloudFront invalidation -> SNS signal -> EventBridge events
**S3 Output:** `s3://jreese-net/mobile/v1/{feedname}.json` (per-project feeds)
**CloudFront:** Invalidates `E2BOQXCW1TA6Y4` after upload
**Cache-Control:** `max-age=0, s-maxage=300, must-revalidate`
**Analytics:** Writes JSON to `devops-agentcli-compute` bucket

---

## [SECTION 4.9] feed_query

Feed read API with subscription lifecycle management.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-feed-query-api` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 15s |
| **Source** | `backend/lambda/feed_query/lambda_function.py` |

**API Routes:**
```
GET     /api/v1/feed
POST    /api/v1/feed/subscriptions
GET     /api/v1/feed/subscriptions/{subscriptionId}
DELETE  /api/v1/feed/subscriptions/{subscriptionId}
OPTIONS /api/v1/feed*
```

**Auth:** Cognito JWT
**Tables:** devops-project-tracker, feed-subscriptions, coordination-requests, projects
**Subscriptions:** Scope (project, record IDs, types, status, updated_since), delivery (poll/push), duration 1-10080 min

---

## [SECTION 4.10] auth_refresh

Cognito token refresh endpoint.

| Property | Value |
|----------|-------|
| **Function Name** | `auth-refresh` |
| **Runtime** | Python 3.11 |
| **Memory** | 128 MB |
| **Timeout** | 10s |
| **Source** | `backend/lambda/auth_refresh/lambda_function.py` |

**Route:** `POST /api/v1/auth/refresh`
**Flow:** Extract `enceladus_refresh_token` cookie -> Cognito `REFRESH_TOKEN_AUTH` -> Return new ID token as HttpOnly cookie + session timestamp cookie
**Cookies Set:** `enceladus_id_token` (HttpOnly, Secure, SameSite=None, 3600s), session timestamp (JS-readable)

---

## [SECTION 4.11] auth_edge

CloudFront Lambda@Edge for request-time JWT validation.

| Property | Value |
|----------|-------|
| **Function Name** | `enceladus-auth-edge` |
| **Runtime** | nodejs18.x |
| **Memory** | 128 MB |
| **Timeout** | 5s |
| **Region** | us-east-1 (Lambda@Edge requirement) |
| **Source** | `backend/lambda/auth_edge/` |

**Trigger:** CloudFront viewer-request on `/enceladus*` and `/mobile/v1/*`
**Behavior:** Validates `enceladus_id_token` JWT; redirects to Cognito login on expiry

---

## [SECTION 4.12] governance_audit

DynamoDB Streams-triggered write-source anomaly detector.

| Property | Value |
|----------|-------|
| **Function Name** | `enceladus-governance-audit` |
| **Runtime** | Python 3.11 |
| **Memory** | 128 MB |
| **Timeout** | 30s |
| **Trigger** | DynamoDB Stream (devops-project-tracker, batch 25, window 30s) |
| **Source** | `backend/lambda/governance_audit/lambda_function.py` |

**Known Write Channels:** mcp_server, tracker_cli, mutation_api, feed_publisher
**Alerts via SNS:** MISSING_WRITE_SOURCE, EMPTY_WRITE_SOURCE, UNKNOWN_CHANNEL

---

## [SECTION 4.13] coordination_monitor_api

Read-only API for coordination request status dashboard.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-coordination-monitor-api` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 30s |
| **Source** | `backend/lambda/coordination_monitor_api/lambda_function.py` |

**Route:** `GET /api/v1/coordination/monitor`
**Auth:** Cognito JWT
**Pagination:** limit (default 50, max 200), offset
**Security:** Redacts `callback_token` from responses

---

## [SECTION 4.14] github_integration

GitHub App issue creation + bidirectional webhook sync (ENC-FTR-021).

| Property | Value |
|----------|-------|
| **Function Name** | `devops-github-integration` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 30s |
| **Source** | `backend/lambda/github_integration/lambda_function.py` |

**API Routes:**
```
POST   /api/v1/github/issues
POST   /api/v1/github/webhook
GET    /api/v1/github/projects
POST   /api/v1/github/projects/sync
OPTIONS /api/v1/github/*
```

**Auth:** Cognito JWT OR `X-Coordination-Internal-Key`
**GitHub App Config:**
- App ID: env `GITHUB_APP_ID`
- Installation ID: env `GITHUB_INSTALLATION_ID`
- Private Key: Secrets Manager `devops/github-app/private-key`
- Webhook Secret: Secrets Manager `devops/github-app/webhook-secret`
- Allowed Repos: `NX-2021-L/enceladus`

**Webhook:** HMAC-SHA256 signature validation (X-Hub-Signature-256)
**Record ID Parsing:** `^([A-Z]{3})-([A-Z]{2,3})-(\d{3,})$` -> project prefix + type

---

## [SECTION 4.15] doc_prep

Pre-deployment document preparation hook.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-doc-prep` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 30s |
| **Source** | `backend/lambda/doc_prep/lambda_function.py` |

**Route:** `POST /api/v1/doc-prep/{projectName}` (AWS_IAM auth)
**Purpose:** Fetches primary project docs from S3 for deployment hooks

---

## [SECTION 4.16] glue_crawler_launcher

SNS-triggered Glue crawler with cadence guard.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-glue-crawler-launcher` |
| **Runtime** | Python 3.11 |
| **Memory** | 128 MB |
| **Timeout** | 3s |
| **Trigger** | SNS (from feed_publisher or json_to_parquet_transformer) |
| **Source** | `backend/lambda/glue_crawler_launcher/handler.py` |

**Cadence Guard:** MIN_CRAWL_INTERVAL_SECONDS = 7200 (2h)
**Crawler Map:** `{features: features-sync, tasks: tasks-sync, issues: issues-sync}`

---

## [SECTION 4.17] json_to_parquet_transformer

EventBridge-triggered JSON to Parquet conversion for analytics.

| Property | Value |
|----------|-------|
| **Function Name** | `devops-json-to-parquet-transformer` |
| **Runtime** | Python 3.11 |
| **Memory** | 128 MB |
| **Timeout** | 3s |
| **Trigger** | EventBridge rule `on-project-json-sync` |
| **Source** | `backend/lambda/json_to_parquet_transformer/handler.py` |
| **Layers** | devops-json-to-parquet-pyarrow:3, devops-json-to-parquet-numpy:2 |

**Input:** EventBridge event with project, log_type, stage_prefix
**Output:** `s3://devops-agentcli-compute/projects/sync/{log_type}/project={project}/ingest_ts={YYYYMMDDHHMM}/`
**Compression:** Snappy (PyArrow)

---

## [SECTION 4.18] bedrock_agent_actions

Bedrock Agent action group executor for agent tool use.

| Property | Value |
|----------|-------|
| **Function Name** | `enceladus-bedrock-agent-actions` |
| **Runtime** | Python 3.11 |
| **Memory** | 256 MB |
| **Timeout** | 30s |
| **Trigger** | Bedrock agent action group |
| **Source** | `backend/lambda/bedrock_agent_actions/lambda_function.py` |

**Supported Actions:** GET/POST/PUT for tracker records, projects, documents, deployment state
**Tables:** devops-project-tracker, projects, documents, devops-deployment-manager, governance-policies, agent-compliance-violations

---

## [SECTION 4.19] coordination_api

Core agent coordination platform. Largest Lambda (~8000 lines).

| Property | Value |
|----------|-------|
| **Function Name** | `devops-coordination-api` |
| **Runtime** | Python 3.11 |
| **Memory** | 512 MB |
| **Timeout** | 120s |
| **Source** | `backend/lambda/coordination_api/lambda_function.py` |

**API Routes:**
```
POST   /api/v1/coordination/requests
GET    /api/v1/coordination/requests/{requestId}
POST   /api/v1/coordination/requests/{requestId}/dispatch
POST   /api/v1/coordination/requests/{requestId}/callback
GET    /api/v1/coordination/capabilities
GET    /api/v1/coordination/mcp
POST   /api/v1/coordination/mcp
```

**Auth:** Cognito JWT OR `X-Coordination-Internal-Key`
**Providers:** openai_codex, claude_agent_sdk, aws_native, aws_bedrock_agent
**Co-Located Modules:** auth.py, tracker_ops.py, persistence.py, config.py, project_utils.py, handlers.py
**Environment Variables:** 51 (includes Anthropic/OpenAI API keys via Secrets Manager)

---

## [SECTION 4.20] shared_layer

Lambda layer providing shared utilities across all Python Lambdas.

| Property | Value |
|----------|-------|
| **Layer Name** | `enceladus-shared` |
| **Version** | 2 |
| **Path** | `backend/lambda/shared_layer/` |

**Contents:**
| Module | Purpose |
|--------|---------|
| `python/enceladus_shared/auth.py` | JWT validation with 1-hour JWKS cache |
| `python/enceladus_shared/aws_clients.py` | Boto3 client factories (module-level singletons) |
| `python/enceladus_shared/http_utils.py` | HTTP response helpers (CORS headers, error envelopes) |
| `python/enceladus_shared/serialization.py` | DynamoDB type serialization/deserialization |

---

## [SECTION 4.21] Cross-Cutting Lambda Patterns

### Authentication Pattern
- **Primary:** Cognito JWT (RS256) via `enceladus_id_token` cookie with 1-hour JWKS cache
- **Secondary:** `X-Coordination-Internal-Key` header for service-to-service calls
- **Edge:** Lambda@Edge (nodejs18.x) for CloudFront request-time validation
- **Token Refresh:** Dedicated Lambda (`auth-refresh`) with refresh_token cookie flow

### DynamoDB Patterns
- Module-level singleton clients (reused across warm invocations)
- `botocore.config.Config(retries={'max_attempts': 3, 'mode': 'standard'})`
- Both low-level (S/N/BOOL/M/L/SS) and boto3 TypeDeserializer patterns
- Pagination via ExclusiveStartKey

### Error Handling
- Response envelope: `{success, error, error_envelope: {code, message, retryable, details}}`
- HTTP codes: 400 (validation), 401 (auth), 404 (not found), 409 (conflict), 500 (server)

### CORS
- Origin: `https://jreese.net` (hardcoded)
- Credentials: `true`
- Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
- Headers: Content-Type, Cookie, X-Coordination-Internal-Key

---

# SECTION 5 — API LAYER

## [SECTION 5.1] API Gateway HTTP API

| Property | Value |
|----------|-------|
| **API Name** | `devops-tracker-api` |
| **Type** | HTTP (v2) |
| **Stage** | `$default` (auto-deploy) |
| **CORS Origin** | `https://jreese.net` |
| **CORS Credentials** | true |
| **Integration Type** | AWS_PROXY (Lambda, Payload Format 2.0) |

## [SECTION 5.2] API Route Reference Table

| Method | Route | Lambda | Auth |
|--------|-------|--------|------|
| POST | `/api/v1/coordination/requests` | coordination_api | JWT/Key |
| GET | `/api/v1/coordination/requests/{requestId}` | coordination_api | JWT/Key |
| POST | `/api/v1/coordination/requests/{requestId}/dispatch` | coordination_api | JWT/Key |
| POST | `/api/v1/coordination/requests/{requestId}/callback` | coordination_api | JWT/Key |
| GET | `/api/v1/coordination/capabilities` | coordination_api | JWT/Key |
| GET/POST | `/api/v1/coordination/mcp` | coordination_api | JWT/Key |
| GET | `/api/v1/coordination/monitor` | coordination_monitor_api | JWT |
| PATCH | `/api/v1/tracker/{projectId}/{recordType}/{recordId}` | tracker_mutation | JWT/Key |
| GET | `/api/v1/tracker/pending-updates` | tracker_mutation | JWT/Key |
| GET | `/api/v1/tracker/{project}` | tracker_mutation | JWT/Key |
| GET | `/api/v1/tracker/{project}/{type}/{id}` | tracker_mutation | JWT/Key |
| POST | `/api/v1/tracker/{project}/{type}` | tracker_mutation | JWT/Key |
| GET | `/api/v1/documents` | document_api | JWT/Key |
| GET | `/api/v1/documents/{documentId}` | document_api | JWT/Key |
| GET | `/api/v1/documents/search` | document_api | JWT/Key |
| PUT | `/api/v1/documents` | document_api | JWT/Key |
| PATCH | `/api/v1/documents/{documentId}` | document_api | JWT/Key |
| GET | `/api/v1/projects` | project_service | JWT |
| GET | `/api/v1/projects/{projectName}` | project_service | JWT |
| POST | `/api/v1/projects` | project_service | JWT |
| GET | `/api/v1/feed` | feed_query | JWT |
| POST | `/api/v1/deploy/submit` | deploy_intake | JWT/Key |
| GET | `/api/v1/deploy/state/{projectId}` | deploy_intake | JWT/Key |
| PATCH | `/api/v1/deploy/state/{projectId}` | deploy_intake | JWT/Key |
| GET | `/api/v1/deploy/status/{specId}` | deploy_intake | JWT/Key |
| GET | `/api/v1/deploy/history/{projectId}` | deploy_intake | JWT/Key |
| GET | `/api/v1/reference/search` | reference_search | JWT |
| POST | `/api/v1/doc-prep/{projectName}` | doc_prep | IAM |
| POST | `/api/v1/auth/refresh` | auth_refresh | Cookie |
| POST | `/api/v1/github/issues` | github_integration | JWT/Key |
| POST | `/api/v1/github/webhook` | github_integration | HMAC |
| GET | `/api/v1/github/projects` | github_integration | JWT/Key |
| POST | `/api/v1/github/projects/sync` | github_integration | JWT/Key |

---
