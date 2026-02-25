# Enceladus Platform Architecture Reference

## Document Metadata
- **Version**: 1.0.0
- **Generated**: 2026-02-25T15:20:00Z
- **Governance Hash**: 86099402327ca237c67bf5e2c21805a24958d306b97f7908cd84923f62940944
- **Canonical Locations**: Enceladus docstore (DOC-*) + `repo/docs/ARCHITECTURE.md`
- **Sync Policy**: GitHub-primary. Repo changes trigger docstore update via GitHub Actions.

---

## How to Use This Document (Token Optimization Guide)

**This document is ~3000 lines. Do NOT read it end-to-end.**

### Navigation Strategy for Agents

1. **Quick Lookup** — Use the Component Index (Section 0.2) to find the section number for any named component, then jump directly to that section.
2. **Keyword Search** — Use the Keyword Index (Section 15) to map any term to its section(s).
3. **Section Markers** — Every section starts with `[SECTION X.Y]` for grep/search: `grep "\[SECTION 4.3\]" ARCHITECTURE.md`
4. **Section Abstracts** — The first line after each heading is a one-line summary. Read it to decide if the section is relevant before reading further.
5. **Table of Contents** — Section 0.1 lists every section with a one-line description.

### When to Read Which Section

| You need to know about... | Read section(s) |
|---------------------------|-----------------|
| DynamoDB tables, keys, GSIs | 3.1 |
| A specific Lambda function | 4.x (see Component Index) |
| API routes and endpoints | 5.1 |
| Authentication flow | 6.1-6.4 |
| Frontend pages and components | 7.x |
| CI/CD and deployment | 9.x |
| MCP server tools | 8.1-8.3 |
| S3 buckets and prefixes | 3.3 |
| SQS queues | 3.2 |
| EventBridge rules and pipes | 3.4 |
| IAM and security model | 6.5 |
| CloudFront CDN config | 10.1 |
| Feed publishing pipeline | 11.1 |
| Deployment orchestration pipeline | 11.2 |
| Analytics/Parquet pipeline | 11.3 |
| GitHub integration | 4.14, 9.2 |
| Governance and compliance | 12.x |
| Frontend state management | 7.4 |
| PWA and service worker | 7.7 |
| Environment variables (all) | 13.x |

---

## 0.1 Table of Contents

### Section 0 — Navigation
- 0.1 Table of Contents *(this section)*
- 0.2 Component Index — Alphabetical lookup of every named component to its section

### Section 1 — Executive Summary
- 1.1 Platform Overview — What Enceladus is and what it does
- 1.2 Technology Stack Summary — Languages, frameworks, services at a glance
- 1.3 Resource Counts — Quantitative summary of all infrastructure

### Section 2 — System Architecture Diagram
- 2.1 High-Level Architecture — Request flow from user to data stores
- 2.2 Data Flow Diagram — How data moves between components

### Section 3 — Data Layer
- 3.1 DynamoDB Tables — All 7 tables with key schemas, GSIs, streams, billing
- 3.2 SQS Queues — All FIFO queues with config
- 3.3 S3 Buckets and Prefixes — All storage locations and their purposes
- 3.4 EventBridge Rules and Pipes — All event routing
- 3.5 SNS Topics — All notification channels

### Section 4 — Compute Layer (Lambda Functions)
- 4.1 tracker_mutation — Tracker CRUD API (tasks/issues/features)
- 4.2 project_service — Project lifecycle manager
- 4.3 document_api — Document upload, retrieval, search
- 4.4 reference_search — Project reference document search
- 4.5 deploy_intake — Deployment submission and state management
- 4.6 deploy_orchestrator — SQS-triggered deployment orchestration
- 4.7 deploy_finalize — EventBridge-triggered deployment finalization
- 4.8 feed_publisher — Event-driven mobile feed publisher
- 4.9 feed_query — Feed read and subscription lifecycle
- 4.10 auth_refresh — Cognito token refresh
- 4.11 auth_edge — CloudFront Lambda@Edge authentication
- 4.12 governance_audit — Write-source anomaly detector
- 4.13 coordination_monitor_api — Coordination request monitor
- 4.14 github_integration — GitHub issue operations and webhook handling
- 4.15 doc_prep — Document preparation for deployment
- 4.16 glue_crawler_launcher — Glue crawler orchestration
- 4.17 json_to_parquet_transformer — JSON to Parquet conversion
- 4.18 bedrock_agent_actions — Bedrock agent action group executor
- 4.19 coordination_api — Agent coordination platform (core)
- 4.20 shared_layer — Lambda layer with shared utilities
- 4.21 Cross-Cutting Lambda Patterns — Auth, DynamoDB, S3, error handling, CORS

### Section 5 — API Layer
- 5.1 API Gateway HTTP API — All routes, integrations, CORS
- 5.2 API Route Reference Table — Complete route-to-Lambda mapping
- 5.3 Request/Response Patterns — Envelope formats, pagination, error codes

### Section 6 — Authentication & Security
- 6.1 Cognito Configuration — User pool, client, OAuth settings
- 6.2 JWT Validation — RS256, JWKS caching, cookie extraction
- 6.3 Service-to-Service Auth — X-Coordination-Internal-Key header
- 6.4 Auth Cookie Architecture — Cookie names, attributes, lifecycle
- 6.5 IAM Security Model — Three-role model, agent CLI restrictions
- 6.6 Secrets Manager — All stored secrets

### Section 7 — Frontend (PWA)
- 7.1 Framework and Build Configuration — React, Vite, TypeScript, Tailwind
- 7.2 Pages and Routes — All routes with component mapping
- 7.3 API Client Layer — All fetch functions, retry logic, error handling
- 7.4 State Management — React Query, React Context, local state
- 7.5 Custom Hooks — All 13 hooks with signatures and behavior
- 7.6 Components Reference — All 60+ components organized by category
- 7.7 PWA Configuration — Service worker, manifest, offline support
- 7.8 Environment Variables — All VITE_* variables
- 7.9 Styling — Tailwind config, color scheme, responsive approach

### Section 8 — MCP Server
- 8.1 Server Architecture — Async Python, stdio transport, lazy imports
- 8.2 MCP Tools Reference — All 35 tools by category
- 8.3 MCP Configuration — Environment variables, table defaults
- 8.4 Governance Resolution — S3 paths, caching, hash computation

### Section 9 — CI/CD and Deployment
- 9.1 GitHub Actions Workflows — All 5 workflows with triggers and jobs
- 9.2 Lambda Deploy Scripts — Per-function deploy.sh pattern
- 9.3 Parity Audit — Nightly validation of repo-to-live parity
- 9.4 Secrets Guardrail — TruffleHog scanning

### Section 10 — CDN and Distribution
- 10.1 CloudFront Distribution — Behaviors, origins, cache policies

### Section 11 — Event-Driven Pipelines
- 11.1 Feed Publishing Pipeline — DynamoDB Streams to S3 feeds
- 11.2 Deployment Orchestration Pipeline — Intake to CodeBuild to finalization
- 11.3 Analytics Pipeline — JSON to Parquet to Glue

### Section 12 — Governance and Compliance
- 12.1 Governance Files — S3 structure, URI scheme, current files
- 12.2 Write-Source Attribution — Mutation tracking across all write paths
- 12.3 Governance Hash — Optimistic concurrency control

### Section 13 — Environment Variable Reference
- 13.1 Lambda Environment Variables — Per-function env var tables
- 13.2 Frontend Environment Variables — VITE_* build-time variables
- 13.3 MCP Server Environment Variables — Table names, S3 paths
- 13.4 Cognito Constants — Hardcoded auth parameters

### Section 14 — Repository Structure
- 14.1 Directory Layout — Complete tree with purposes
- 14.2 Key File Inventory — Critical files with line counts

### Section 15 — Keyword Index
- Alphabetical mapping of terms to section numbers

---

## 0.2 Component Index

Alphabetical lookup. Find a component name, get its primary section.

| Component | Section | One-Line Description |
|-----------|---------|---------------------|
| agent-compliance-violations (table) | 3.1 | DynamoDB table for policy violation audit trail |
| AnimatedList | 7.6 | React component for enter/exit list animations |
| API Gateway HTTP API | 5.1 | HTTP API `devops-tracker-api` routing all `/api/v1/*` |
| AppShell | 7.6 | React layout: Header + Outlet + BottomNav |
| auth-refresh (Lambda) | 4.10 | Cognito token refresh endpoint |
| auth_edge (Lambda) | 4.11 | CloudFront Lambda@Edge JWT validation |
| bedrock_agent_actions (Lambda) | 4.18 | Bedrock agent action group executor |
| BottomNav | 7.6 | React tab bar navigation |
| CloudFront Distribution | 10.1 | CDN `E2BOQXCW1TA6Y4` at jreese.net |
| Cognito User Pool | 6.1 | `us-east-1_b2D0V3E1k` with OAuth |
| coordination-requests (table) | 3.1 | DynamoDB table for coordination request state |
| coordination_api (Lambda) | 4.19 | Core agent coordination platform |
| coordination_monitor_api (Lambda) | 4.13 | Read-only coordination status API |
| CoordinationPage | 7.2 | React page for agent coordination list |
| DashboardPage | 7.2 | React overview page with stat cards |
| deploy_finalize (Lambda) | 4.7 | Post-CodeBuild deployment finalization |
| deploy_intake (Lambda) | 4.5 | Deployment submission API |
| deploy_orchestrator (Lambda) | 4.6 | SQS-triggered deployment orchestration |
| devops-deploy-queue.fifo (SQS) | 3.2 | FIFO queue for deployment pipeline |
| devops-deployment-manager (table) | 3.1 | DynamoDB table for deployment lifecycle |
| devops-feed-publish-queue.fifo (SQS) | 3.2 | FIFO queue for feed publishing |
| devops-project-tracker (table) | 3.1 | Core tracker table for all projects |
| doc_prep (Lambda) | 4.15 | Pre-deployment document preparation |
| document_api (Lambda) | 4.3 | Document CRUD with S3 storage |
| documents (table) | 3.1 | DynamoDB table for document metadata |
| DocumentsListPage | 7.2 | React page listing all documents |
| enceladus-mcp-server | 8.1 | MCP server with 35 tools |
| enceladus-shared (Layer) | 4.20 | Lambda layer: JWT, auth, AWS clients |
| FeedPage | 7.2 | React unified feed with live polling |
| feed_publisher (Lambda) | 4.8 | Event-driven S3 feed publisher |
| feed_query (Lambda) | 4.9 | Feed read API with subscriptions |
| FilterBar | 7.6 | React multi-select toggle filter |
| github_integration (Lambda) | 4.14 | GitHub App issue creation + webhooks |
| GitHubOverlay | 7.6 | React modal for GitHub issue linking |
| glue_crawler_launcher (Lambda) | 4.16 | Glue crawler trigger with cadence guard |
| governance-policies (table) | 3.1 | DynamoDB table for governance rules |
| governance_audit (Lambda) | 4.12 | Write-source anomaly detector |
| Header | 7.6 | React app header component |
| json_to_parquet_transformer (Lambda) | 4.17 | JSON to Parquet analytics conversion |
| MarkdownRenderer | 7.6 | React markdown rendering component |
| project_service (Lambda) | 4.2 | Project lifecycle management |
| projects (table) | 3.1 | DynamoDB table for project metadata |
| ProjectDetailPage | 7.2 | React page with project tabs |
| reference_search (Lambda) | 4.4 | S3 reference document search |
| ScrollSentinel | 7.6 | React IntersectionObserver infinite scroll |
| SessionExpiredOverlay | 7.6 | React session refresh prompt |
| shared_layer | 4.20 | Lambda layer with shared utilities |
| StatusChip | 7.6 | React status badge component |
| TaskDetailPage | 7.2 | React task detail with mutations |
| tracker_mutation (Lambda) | 4.1 | Core tracker CRUD API |
| useDocuments | 7.5 | React hook for document data |
| useFeed | 7.5 | React hook for unified feed |
| useFilterState | 7.5 | React hook for generic filter state |
| useInfiniteList | 7.5 | React hook for pagination |
| useProjects | 7.5 | React hook for project data |
| useRecordMutation | 7.5 | React hook for tracker mutations |
| useSessionLifecycle | 7.5 | React hook for session revalidation |
| useSessionTimer | 7.5 | React hook for session timeout |
| useTasks | 7.5 | React hook for task data |

---

# SECTION 1 — EXECUTIVE SUMMARY

## [SECTION 1.1] Platform Overview

Enceladus is a serverless AWS platform for agent coordination, project tracking, document management, and deployment orchestration.

**Core capabilities:**
- **Mobile-First PWA** — React 19 + Vite 7 dashboard at `https://jreese.net/enceladus`
- **Coordination API + MCP** — Multi-agent dispatch with deterministic completion contracts
- **Tracker Mutation API** — REST API for task/issue/feature lifecycle (Cognito JWT auth)
- **Document Store** — S3-backed markdown storage with DynamoDB metadata
- **Feed Pipeline** — DynamoDB Streams to S3 feeds via EventBridge + SQS + CloudFront
- **Deployment Manager** — Automated build/deploy with CodeBuild + semver
- **GitHub Integration** — Bidirectional issue sync via GitHub App (ENC-FTR-021)
- **Analytics Pipeline** — JSON to Parquet for Glue/Trino/Superset

**Production URL:** `https://jreese.net/enceladus`
**API Base:** `https://jreese.net/api/v1/`
**AWS Region:** us-west-2 (primary), us-east-1 (auth edge only)
**Monthly Cost:** ~$30-40

## [SECTION 1.2] Technology Stack Summary

| Layer | Technologies |
|-------|-------------|
| **Frontend** | React 19.2.0, TypeScript 5.9.3, Vite 7.3.1, Tailwind CSS 4.1.18, TanStack React Query 5.90, React Router 7.13, react-window 2.2.7, vite-plugin-pwa 1.2.0 |
| **Backend** | Python 3.11, AWS Lambda (19 functions), API Gateway HTTP API v2 |
| **Data** | DynamoDB (7 tables, PAY_PER_REQUEST), S3 (jreese-net bucket) |
| **Auth** | AWS Cognito (RS256 JWT), Lambda@Edge, service-to-service key |
| **Messaging** | SQS FIFO (2 queues), SNS (4 topics), EventBridge (3 rules, 2 pipes) |
| **CDN** | CloudFront (E2BOQXCW1TA6Y4) |
| **CI/CD** | GitHub Actions (5 workflows), CodeBuild, per-Lambda deploy.sh |
| **Analytics** | PyArrow (Parquet), AWS Glue crawlers, EventBridge |
| **AI/Agents** | MCP server (35 tools), Bedrock Agent, Anthropic API, OpenAI API |

## [SECTION 1.3] Resource Counts

| Resource | Count |
|----------|-------|
| Lambda Functions | 19 (18 us-west-2 + 1 us-east-1) |
| DynamoDB Tables | 7 |
| SQS FIFO Queues | 2 |
| SNS Topics | 4 |
| API Gateway HTTP APIs | 1 |
| API Routes | 30+ |
| EventBridge Rules | 3 |
| EventBridge Pipes | 2 |
| CloudFront Distributions | 1 |
| Lambda Layers | 1 (enceladus-shared) |
| GitHub Actions Workflows | 5 |
| CloudFormation Stacks | 3 |
| MCP Tools | 35 |
| Frontend Pages | 15 |
| Frontend Components | 60+ |
| Custom React Hooks | 13 |
| Frontend API Modules | 7 |

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

# SECTION 6 — AUTHENTICATION & SECURITY

## [SECTION 6.1] Cognito Configuration

| Property | Value |
|----------|-------|
| **User Pool ID** | `us-east-1_b2D0V3E1k` |
| **User Pool Name** | `enceladus-status-users` |
| **Client ID** | `6q607dk3liirhtecgps7hifmlk` |
| **Domain** | `enceladus-status-356364570033.auth.us-east-1.amazoncognito.com` |
| **Region** | us-east-1 |
| **Scopes** | openid, email, profile |
| **Redirect URI** | `https://jreese.net/enceladus/callback` |
| **Token Signing** | RS256 |
| **Token Expiration** | 1 hour |

## [SECTION 6.2] JWT Validation

All API Lambdas validate JWT from cookies using the shared layer auth module:
1. Extract `enceladus_id_token` from `headers.cookie` AND `event.cookies` (API Gateway v2)
2. Fetch JWKS from `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_b2D0V3E1k/.well-known/jwks.json`
3. Cache JWKS for 1 hour (module-level singleton)
4. Verify RS256 signature, expiration, audience, issuer
5. Return decoded token payload on success, 401 on failure

**Critical Note:** Both `headers.cookie` AND `event.cookies` must be checked. API Gateway v2 provides cookies in both locations depending on request format.

## [SECTION 6.3] Service-to-Service Auth

| Header | Value Source | Used By |
|--------|-------------|---------|
| `X-Coordination-Internal-Key` | Environment variable `COORDINATION_INTERNAL_API_KEY` | MCP server -> Lambda APIs |

This bypasses Cognito JWT validation for internal service calls.

## [SECTION 6.4] Auth Cookie Architecture

| Cookie | HttpOnly | Secure | SameSite | Max-Age | Purpose |
|--------|----------|--------|----------|---------|---------|
| `enceladus_id_token` | Yes | Yes | None | 3600 | JWT for API authentication |
| `enceladus_refresh_token` | Yes | Yes | Lax | 86400 | Cognito refresh token |
| `enceladus_session_at` | No | Yes | None | 3600 | Session timestamp (JS-readable) |

## [SECTION 6.5] IAM Security Model

Three-role model (ENC-TSK-564):

| Role | Purpose | Allowed | Denied |
|------|---------|---------|--------|
| `enceladus-agent-cli` | Local agent sessions | STS, CloudWatch reads, Lambda inspect, S3 reads, doc/deploy table reads, SQS SendMessage | All DynamoDB writes, tracker/projects reads, S3 writes, Lambda mutations, IAM, STS AssumeRole |
| CI backend deploy | GitHub Actions backend | Lambda update, S3 write, CloudFormation | (scoped to backend resources) |
| CI frontend deploy | GitHub Actions UI | S3 write, CloudFront invalidation | (scoped to frontend resources) |

**Critical:** Agent sessions MUST use MCP tools for all mutations. Direct DynamoDB/S3 writes are IAM-denied.

## [SECTION 6.6] Secrets Manager

| Secret | Purpose | Used By |
|--------|---------|---------|
| `devops/github-app/private-key` | GitHub App RS256 private key | github_integration Lambda |
| `devops/github-app/webhook-secret` | GitHub webhook HMAC secret | github_integration Lambda |
| Anthropic API key | Claude API access | coordination_api Lambda |
| OpenAI API key | Codex API access | coordination_api Lambda |

---

# SECTION 7 — FRONTEND (PWA)

## [SECTION 7.1] Framework and Build Configuration

| Property | Value |
|----------|-------|
| **Framework** | React 19.2.0 |
| **Language** | TypeScript 5.9.3 (strict mode) |
| **Build Tool** | Vite 7.3.1 |
| **Styling** | Tailwind CSS 4.1.18 (via @tailwindcss/vite) |
| **State** | TanStack React Query 5.90.21 + React Context |
| **Routing** | React Router DOM 7.13.0 |
| **Testing** | Vitest 4.0.18 + React Testing Library |
| **PWA Plugin** | vite-plugin-pwa 1.2.0 |
| **Markdown** | react-markdown 10.1.0 + react-syntax-highlighter 16.1.0 |
| **Virtualization** | react-window 2.2.7 |
| **Base Path** | `/enceladus/` |
| **Source** | `frontend/ui/src/` |
| **Build Output** | `frontend/ui/dist/` |

**Manual Chunks (Vite):** react-core, react-router, query, markdown, virtualized, routes, shell

## [SECTION 7.2] Pages and Routes

| Path | Component | Description |
|------|-----------|-------------|
| `/` | DashboardPage | Stat cards + top projects |
| `/projects` | ProjectsListPage | All projects |
| `/projects/create` | CreateProjectPage | New project form |
| `/projects/:projectId` | ProjectDetailPage | Tabs: Tasks/Issues/Features |
| `/projects/:projectId/reference` | ProjectReferencePage | Markdown reference doc |
| `/feed` | FeedPage | Unified feed with live polling (3s) |
| `/tasks/:taskId` | TaskDetailPage | Task detail + mutations |
| `/issues/:issueId` | IssueDetailPage | Issue detail |
| `/features/:featureId` | FeatureDetailPage | Feature detail |
| `/documents` | DocumentsListPage | All documents |
| `/documents/:documentId(/:slug)` | DocumentDetailPage | Document content |
| `/coordination` | CoordinationPage | Coordination requests |
| `/coordination/:requestId` | CoordinationDetailPage | Request detail |

## [SECTION 7.3] API Client Layer

**Base URLs (configurable via VITE_* env vars):**
- Feed: `/mobile/v1` (S3 CDN)
- Mutation: `/api/v1/tracker`
- General: `/api/v1`
- GitHub: `/api/v1/github`

**Retry Pattern (mutations):** 3-cycle with 10s abort timeout. On 401, calls `refreshCredentials()` before retry. Client errors (4xx) throw immediately. Server errors (5xx) retry.

**Feed Functions:** fetchProjects, fetchTasks, fetchIssues, fetchFeatures, fetchDocumentsFeed, fetchLiveFeed (single observer), fetchProjectReference
**Mutation Functions:** closeRecord, reopenRecord, submitNote, setField
**Auth Functions:** refreshCredentials (POST /api/v1/auth/refresh)
**Document Functions:** fetchDocumentsByProject, fetchDocument, searchDocuments
**GitHub Functions:** createGitHubIssue (2-cycle retry, 15s timeout)
**Coordination Functions:** fetchCoordinationList, fetchCoordinationRequest

## [SECTION 7.4] State Management

**React Context (Auth):**
- `AuthStateContext` / `AuthStateProvider` in `lib/authState.tsx`
- State: `authStatus` (authenticated/expired/logged-out), `sessionExpiresAt`
- Session duration: 60 minutes
- Storage: `enceladus:session_last_active` in localStorage

**TanStack React Query:**
- staleTime: 2 min
- gcTime: 30 min
- retry: 2 times (except SessionExpiredError)
- refetchOnWindowFocus: true
- refetchOnReconnect: true

## [SECTION 7.5] Custom Hooks

| Hook | Purpose | Key Behavior |
|------|---------|-------------|
| `useSessionLifecycle()` | Revalidates session on resume | Probes after 10+ min idle; refreshes credentials on 401 |
| `useSessionTimer()` | Polls for session expiry | Checks localStorage every 15s; debounced 30s activity tracking |
| `useProjects()` | Project data | Returns projects array + generatedAt timestamp |
| `useTasks(filters?)` | Task data | Client-side filtering/sorting on feed data |
| `useIssues(filters?)` | Issue data | Same pattern with severity filtering |
| `useFeatures(filters?)` | Feature data | Same pattern |
| `useFeed(filters?, options?)` | Unified feed | Merges tasks+issues+features; single live observer; 3s polling |
| `useDocuments(filters?)` | Document data | S3 feed polling (15s interval); de-dupe by ID |
| `useCoordinationList(filters?)` | Coordination list | 3s polling; stable array refs |
| `useCoordinationDetail(requestId)` | Coordination detail | 3s polling; enabled when ID exists |
| `useProjectReference(projectId)` | Reference markdown | 5-min staleTime; 1 retry |
| `useRecordMutation()` | Tracker mutations | Optimistic close/reopen; rollback on error; 15s invalidation debounce |
| `useInfiniteList(items, pageSize)` | Pagination | IntersectionObserver; 200px root margin; 20 items/page |
| `useFilterState<T>(initial)` | Filter state | toggleArrayFilter, setFilter, clearFilters |

## [SECTION 7.6] Components Reference

**Layout (3):** AppShell, Header, BottomNav

**Cards/Rows (7):** TaskRow, IssueRow, FeatureRow, FeedRow, DocumentRow, CoordinationRow, ProjectCard

**Badges (7):** StatusChip, PriorityBadge, SeverityBadge, GitHubLinkBadge, FreshnessBadge, ActiveSessionBadge, CoordinationFlagBadge, CoordinationStateBadge

**Data Display (5):** HistoryFeed, RelatedItems, ParentRecord, ChildRecords, RecentItemsDisplay

**Interactive (5):** FilterBar, SortPicker, SearchInput, GitHubOverlay, NoteOverlay

**Content (3):** MarkdownRenderer, CodeBlock, LinkedText

**Utility (5):** AnimatedList, ScrollSentinel, LoadingState, ErrorState, EmptyState

**Auth (2):** SessionExpiredOverlay, LoggedOutScreen

## [SECTION 7.7] PWA Configuration

- **Service Worker:** Manual registration in main.tsx; scope `/enceladus/`; `updateViaCache: 'none'`
- **Workbox:** Static asset caching (`*.{js,css,html,ico,png,svg,woff2}`)
- **Offline:** Static assets only; feeds require network auth
- **Manifest:** "Project Status" / "ProjStatus"; standalone display; dark theme (#0f172a)
- **Icons:** 192x192, 512x512, 512x512 maskable

## [SECTION 7.8] Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VITE_FEED_BASE_URL` | `/mobile/v1` | S3 feed CDN path |
| `VITE_MUTATION_BASE_URL` | `/api/v1/tracker` | Tracker mutation API |
| `VITE_API_BASE_URL` | `/api/v1` | General API base |
| `VITE_GITHUB_API_BASE_URL` | `/api/v1/github` | GitHub integration API |

## [SECTION 7.9] Styling

- **Framework:** Tailwind CSS 4.1.18 (utility-first, no custom CSS files)
- **Theme:** Dark mode (slate-900 bg, slate-100 text)
- **Colors:** blue (primary), emerald (completed), rose (closed), amber (in-progress), purple (planned)
- **Priorities:** red (P0), orange (P1), yellow (P2), slate (P3)
- **Responsive:** Mobile-first, no breakpoints (mobile-optimized PWA)

---

# SECTION 8 — MCP SERVER

## [SECTION 8.1] Server Architecture

| Property | Value |
|----------|-------|
| **File** | `tools/enceladus-mcp-server/server.py` (~4400 lines) |
| **Transport** | stdio (MCP protocol) |
| **Language** | Async Python |
| **AWS Access** | Lazy boto3 import; supports provider sessions without AWS CLI |
| **SSL** | Custom CA bundle handling for macOS (falls back to certifi) |

## [SECTION 8.2] MCP Tools Reference

**Project Management (2):** projects_list, projects_get
**Tracker CRUD (7):** tracker_get, tracker_list, tracker_pending_updates, tracker_set, tracker_log, tracker_create, tracker_set_acceptance_evidence
**Documents (6):** documents_get, documents_list, documents_put, documents_patch, documents_search, check_document_policy
**Governance (2):** governance_hash, governance_update
**Deployments (8):** deploy_submit, deploy_state_get, deploy_state_set, deploy_pending_requests, deploy_history, deploy_history_list, deploy_status, deploy_status_get, deploy_trigger
**Coordination (4):** coordination_capabilities, coordination_request_get, dispatch_plan_generate, dispatch_plan_dry_run
**Search (1):** reference_search
**GitHub (3):** github_create_issue, github_projects_list, github_projects_sync
**System (1):** connection_health

## [SECTION 8.3] MCP Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `ENCELADUS_TRACKER_TABLE` | `devops-project-tracker` | Tracker DynamoDB table |
| `ENCELADUS_PROJECTS_TABLE` | `projects` | Projects DynamoDB table |
| `ENCELADUS_DOCUMENTS_TABLE` | `documents` | Documents DynamoDB table |

## [SECTION 8.4] Governance Resolution

- **Live files:** `s3://jreese-net/governance/live/`
- **History:** `s3://jreese-net/governance/history/`
- **URI scheme:** `governance://agents.md` -> `governance/live/agents.md`
- **Hash:** SHA-256 of all loaded governance files (optimistic concurrency for writes)

---

# SECTION 9 — CI/CD AND DEPLOYMENT

## [SECTION 9.1] GitHub Actions Workflows

### api-mcp-backend-deploy.yml
**Trigger:** Push to `backend/lambda/coordination_api/**` or `tools/enceladus-mcp-server/**`; workflow_dispatch
**Action:** Runs `backend/lambda/coordination_api/deploy.sh`
**Auth:** OIDC role (`AWS_BACKEND_ROLE_TO_ASSUME`)

### github-integration-deploy.yml
**Trigger:** Push to `backend/lambda/github_integration/**`; workflow_dispatch
**Action:** Runs `backend/lambda/github_integration/deploy.sh`
**Auth:** OIDC role; passes GH_APP_ID, GH_INSTALLATION_ID secrets

### ui-backend-deploy.yml
**Trigger:** Push to `frontend/ui/**`; workflow_dispatch with change_type/summary/related_ids
**Action:** `python tools/submit_backend_ui_deploy.py` -> deployment-manager -> SQS -> orchestrator -> CodeBuild
**Auth:** OIDC with static key fallback

### nightly-parity-audit.yml
**Trigger:** Scheduled daily 09:25 UTC; workflow_dispatch
**Action:** `python tools/parity_audit.py --output-dir infrastructure/parity/out --fail-on-drift`
**Artifacts:** resource_inventory.json, lambda_parity.json, summary.md (14-day retention)

### secrets-guardrail.yml
**Trigger:** PR, push to main, daily 08:17 UTC; workflow_dispatch
**Action:** TruffleHog scan of repo history + filesystem; optional remote GitHub scan

## [SECTION 9.2] Lambda Deploy Scripts

Each Lambda has `backend/lambda/{function_name}/deploy.sh` that:
1. Packages Lambda code (pip install --platform manylinux2014_x86_64)
2. Uploads to S3
3. Updates Lambda function via AWS CLI
4. Validates deployment

**Critical:** Never build Lambda packages on macOS. Use `--platform manylinux2014_x86_64 --only-binary=:all:` for compiled dependencies.

## [SECTION 9.3] Parity Audit

**Tool:** `tools/parity_audit.py` (23,689 bytes)
**Purpose:** Validates live Lambda SHA256 matches repo source
**Output:** `infrastructure/parity/out/` (resource_inventory.json, lambda_parity.json, summary.md)
**Manifests:** `infrastructure/lambda-manifests/*.json` (19 files)

## [SECTION 9.4] Secrets Guardrail

**Tool:** TruffleHog via `tools/secrets_guard.sh`
**Protections:** GitHub repo secret scanning + push protection, CI gate, local pre-push hook
**Install:** `./tools/install_git_hooks.sh`

---

# SECTION 10 — CDN AND DISTRIBUTION

## [SECTION 10.1] CloudFront Distribution

| Property | Value |
|----------|-------|
| **Distribution ID** | `E2BOQXCW1TA6Y4` |
| **Domain** | `jreese.net` |
| **Origins** | S3 (jreese-net bucket) |

**Behaviors:**
| Path | Origin | Auth | Cache |
|------|--------|------|-------|
| `/enceladus*` | S3 PWA assets | Lambda@Edge (auth_edge) | Standard caching |
| `/mobile/v1/*` | S3 feeds | Lambda@Edge (auth_edge) | s-maxage=300 |
| `/api/v1/*` | API Gateway | Pass-through | No cache |

---

# SECTION 11 — EVENT-DRIVEN PIPELINES

## [SECTION 11.1] Feed Publishing Pipeline

```
devops-project-tracker (DynamoDB Stream, NEW_AND_OLD_IMAGES)
  -> EventBridge Pipe (devops-tracker-to-feed-queue, filter: record_type != "reference")
  -> devops-feed-publish-queue.fifo (5-min visibility = debounce, GroupId: project_id)
  -> feed_publisher Lambda (batch 10, 600s timeout)
  -> S3 feeds (mobile/v1/*.json) + CloudFront invalidation
  -> SNS (devops-project-json-sync) + EventBridge events

documents (DynamoDB Stream, NEW_AND_OLD_IMAGES)
  -> EventBridge Pipe (devops-documents-to-feed-queue, filter: INSERT/MODIFY)
  -> devops-feed-publish-queue.fifo (GroupId: project_id, DedupeId: document_id)
  -> feed_publisher Lambda (same as above)
```

## [SECTION 11.2] Deployment Orchestration Pipeline

```
deploy_intake Lambda (POST /api/v1/deploy/submit)
  -> devops-deployment-manager (DynamoDB, request record)
  -> devops-deploy-queue.fifo (180s visibility = debounce)
  -> deploy_orchestrator Lambda (batch 1)
  -> CodeBuild (devops-ui-deploy-builder) [UI only]
  -> EventBridge (CodeBuild state change: SUCCEEDED/FAILED)
  -> deploy_finalize Lambda
  -> DynamoDB (spec status update + tracker worklog)
```

## [SECTION 11.3] Analytics Pipeline

```
feed_publisher Lambda
  -> S3 staged JSON (devops-agentcli-compute/projects/sync-stage/)
  -> EventBridge event (devops.json-sync / project-json-sync)
  -> json_to_parquet_transformer Lambda
  -> S3 Parquet (devops-agentcli-compute/projects/sync/{log_type}/...)
  -> SNS (devops-json-parquet-ready)
  -> glue_crawler_launcher Lambda (2h cadence guard)
  -> Glue Crawlers (features-sync, tasks-sync, issues-sync)
```

---

# SECTION 12 — GOVERNANCE AND COMPLIANCE

## [SECTION 12.1] Governance Files

**S3 Location:** `s3://jreese-net/governance/live/`
**URI Scheme:** `governance://agents.md` -> `governance/live/agents.md`
**History:** `s3://jreese-net/governance/history/` (auto-archived on update)

**Current Files:** agents.md, agents/agents-reference-project-tracking.md, agents/agents-reference-markdown.md, agent-schema.json, agent-manifest.json, dispatch-heuristics.md, guide-numbering.md, yaml_structure.yaml

## [SECTION 12.2] Write-Source Attribution

All mutations to devops-project-tracker include `write_source` attribute:
| Channel | Source |
|---------|--------|
| `mcp_server` | MCP tool writes (governed, audited) |
| `tracker_cli` | Human-supervised CLI writes |
| `mutation_api` | Cognito-authenticated PWA writes |
| `feed_publisher` | Automated pipeline writes |

governance_audit Lambda detects: MISSING_WRITE_SOURCE, EMPTY_WRITE_SOURCE, UNKNOWN_CHANNEL

## [SECTION 12.3] Governance Hash

SHA-256 hash of all loaded governance files. Required for all MCP write operations as optimistic concurrency control. Computed by MCP server on startup and via `governance_hash()` tool.

---

# SECTION 13 — ENVIRONMENT VARIABLE REFERENCE

## [SECTION 13.1] Lambda Environment Variables (Key Functions)

**coordination_api (51 vars):** Cognito pool/client, Bedrock agent/alias/action-group IDs, Anthropic/OpenAI API key ARNs, all DynamoDB table names, S3 bucket/prefix, SQS queue URLs, SNS topic ARNs, COORDINATION_INTERNAL_API_KEY

**tracker_mutation:** COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID, TRACKER_TABLE_NAME, PROJECTS_TABLE_NAME, CORS_ORIGIN

**feed_publisher:** TRACKER_TABLE_NAME, DOCUMENTS_TABLE_NAME, PROJECTS_TABLE_NAME, S3_BUCKET, S3_PREFIX, CLOUDFRONT_DISTRIBUTION_ID, SNS_TOPIC_ARN, ANALYTICS_BUCKET, DRY_RUN

**deploy_intake:** DEPLOY_TABLE, PROJECTS_TABLE, SQS_QUEUE_URL, DOC_PREP_FUNCTION_NAME

## [SECTION 13.2] Frontend Environment Variables

See Section 7.8.

## [SECTION 13.3] MCP Server Environment Variables

See Section 8.3.

## [SECTION 13.4] Cognito Constants

See Section 6.1.

---

# SECTION 14 — REPOSITORY STRUCTURE

## [SECTION 14.1] Directory Layout

```
/Users/jreese/enceladus/repo/
+-- .github/workflows/          # 5 GitHub Actions workflows
+-- .githooks/                  # Local pre-push hook
+-- backend/
|   +-- lambda/
|   |   +-- auth_edge/          # Lambda@Edge (nodejs18.x)
|   |   +-- auth_refresh/       # Token refresh (Python)
|   |   +-- bedrock_agent_actions/  # Bedrock action group
|   |   +-- coordination_api/   # Core coordination (~8000 lines)
|   |   +-- coordination_monitor_api/
|   |   +-- deploy_finalize/
|   |   +-- deploy_intake/
|   |   +-- deploy_orchestrator/
|   |   +-- doc_prep/
|   |   +-- document_api/
|   |   +-- feed_publisher/
|   |   +-- feed_query/
|   |   +-- github_integration/ # ENC-FTR-021
|   |   +-- glue_crawler_launcher/
|   |   +-- governance_audit/
|   |   +-- json_to_parquet_transformer/
|   |   +-- project_service/
|   |   +-- reference_search/
|   |   +-- shared_layer/       # Lambda layer
|   |   +-- tracker_mutation/
+-- frontend/ui/
|   +-- src/
|   |   +-- api/                # 7 API client modules
|   |   +-- components/         # 60+ components (cards/, layout/, shared/)
|   |   +-- hooks/              # 13 custom hooks
|   |   +-- lib/                # Utilities (auth, routes, query client)
|   |   +-- pages/              # 15 page components
|   |   +-- types/              # TypeScript interfaces
|   +-- dist/                   # Build output
|   +-- public/                 # Static assets
+-- infrastructure/
|   +-- cloudformation/         # 3 CFn templates (01-data, 02-compute, 03-api)
|   +-- lambda-manifests/       # 19 per-function metadata JSON
|   +-- parity/                 # Nightly audit output
+-- tools/
|   +-- enceladus-mcp-server/   # MCP server (~4400 lines) + briefings
|   +-- parity_audit.py         # Nightly parity check
|   +-- submit_backend_ui_deploy.py
|   +-- secrets_guard.sh
|   +-- sync_non_ui_sources.sh
```

---

# SECTION 15 — KEYWORD INDEX

| Keyword | Section(s) |
|---------|-----------|
| acceptance criteria | 4.1, 12.1 |
| agent-compliance-violations | 3.1, 4.18 |
| analytics | 11.3, 4.16, 4.17 |
| API Gateway | 5.1, 5.2 |
| API routes | 5.2 |
| auth cookie | 6.4 |
| auth edge | 4.11, 6.2 |
| auth refresh | 4.10, 6.4 |
| Bedrock | 4.18 |
| cache control | 4.8, 10.1 |
| CloudFormation | 3.x (all), 14.1 |
| CloudFront | 10.1, 4.8 |
| CodeBuild | 4.6, 11.2 |
| Cognito | 6.1, 6.2, 6.4 |
| coordination | 4.19, 4.13, 8.2 |
| CORS | 4.21, 5.1 |
| dark mode | 7.9 |
| debounce | 3.2, 4.8, 4.6 |
| deploy | 4.5, 4.6, 4.7, 9.x, 11.2 |
| dispatch | 4.19, 8.2 |
| document store | 4.3, 3.1, 3.3 |
| DynamoDB | 3.1 |
| DynamoDB Streams | 3.1, 3.4, 11.1 |
| environment variables | 13.x |
| EventBridge | 3.4 |
| feed | 4.8, 4.9, 11.1 |
| filter | 7.5 (useFilterState) |
| GitHub Actions | 9.1 |
| GitHub App | 4.14, 6.6 |
| GitHub integration | 4.14, 9.1 |
| Glue | 4.16, 11.3 |
| governance | 8.4, 12.x |
| governance hash | 12.3, 8.4 |
| GSI | 3.1 |
| HMAC | 4.14 |
| hooks (React) | 7.5 |
| IAM | 6.5 |
| infinite scroll | 7.5 (useInfiniteList) |
| JWT | 6.2, 4.11 |
| Lambda | 4.x (all) |
| Lambda@Edge | 4.11 |
| Lambda layer | 4.20 |
| macOS build | 9.2 |
| MCP | 8.x |
| mutations | 7.3, 7.5 (useRecordMutation) |
| optimistic update | 7.5 |
| pagination | 5.3, 7.5 |
| Parquet | 4.17, 11.3 |
| parity audit | 9.3 |
| PWA | 7.7 |
| React Query | 7.4 |
| reference search | 4.4 |
| retry | 7.3 |
| S3 | 3.3 |
| secrets | 6.6, 9.4 |
| service worker | 7.7 |
| session | 6.4, 7.4, 7.5 |
| SNS | 3.5 |
| SQS | 3.2 |
| Tailwind | 7.9 |
| tracker | 4.1, 3.1 |
| Vite | 7.1 |
| webhook | 4.14 |
| write source | 12.2, 4.12 |
| X-Coordination-Internal-Key | 6.3 |

---

# Document Sync Policy

## Canonical Locations
1. **Repository (primary):** `repo/docs/ARCHITECTURE.md`
2. **Docstore (mirror):** Enceladus docstore document (DOC-*)

## Update Triggers
- Any code change to `backend/`, `frontend/`, `infrastructure/`, or `tools/` that modifies component behavior, API routes, DynamoDB schemas, environment variables, or deployment configuration.
- New Lambda functions, removed Lambda functions, or Lambda configuration changes.
- New or modified GitHub Actions workflows.
- Frontend route changes, new pages, or new components.

## Sync Mechanism
GitHub-primary model:
1. Developer/agent updates `repo/docs/ARCHITECTURE.md` in the repository
2. GitHub Actions workflow detects changes to `docs/ARCHITECTURE.md`
3. Workflow calls `documents_patch` via deployment API to update the docstore mirror
4. Docstore version stays in sync with the repo version

## Future Automation (Recommended)
Add to `.github/workflows/`:
```yaml
name: sync-architecture-doc
on:
  push:
    branches: [main]
    paths: ['docs/ARCHITECTURE.md']
jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Sync to docstore
        run: python tools/sync_architecture_doc.py
```
