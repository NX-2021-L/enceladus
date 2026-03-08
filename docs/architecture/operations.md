# Enceladus Architecture: Operations & Infrastructure

> Sections 9-15 extracted from ARCHITECTURE.md (ENC-TSK-819).
> For navigation, see [docs/ARCHITECTURE.md](../ARCHITECTURE.md).

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
