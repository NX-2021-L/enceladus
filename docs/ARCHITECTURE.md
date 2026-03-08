# Enceladus Platform Architecture Reference

## Document Metadata
- **Version**: 2.0.0
- **Updated**: 2026-03-08
- **Split**: ENC-TSK-819 (token optimization)
- **Canonical Locations**: Enceladus docstore (DOC-*) + `repo/docs/ARCHITECTURE.md`
- **Sync Policy**: GitHub-primary. Repo changes trigger docstore update via GitHub Actions.

---

## How to Navigate This Reference

**This index is ~200 lines. Full content lives in 3 domain files.**

| You need to know about... | Read this file | Section(s) |
|---------------------------|---------------|------------|
| System architecture diagrams | [data-compute.md](architecture/data-compute.md) | 2.1-2.2 |
| DynamoDB tables, SQS, S3, EventBridge | [data-compute.md](architecture/data-compute.md) | 3.1-3.5 |
| A specific Lambda function | [data-compute.md](architecture/data-compute.md) | 4.x (see Component Index) |
| API routes and endpoints | [data-compute.md](architecture/data-compute.md) | 5.1-5.2 |
| Authentication / Cognito / JWT | [security-frontend.md](architecture/security-frontend.md) | 6.1-6.6 |
| IAM security model | [security-frontend.md](architecture/security-frontend.md) | 6.5 |
| Frontend pages, hooks, components | [security-frontend.md](architecture/security-frontend.md) | 7.1-7.9 |
| MCP server tools | [security-frontend.md](architecture/security-frontend.md) | 8.1-8.4 |
| CI/CD and deployment | [operations.md](architecture/operations.md) | 9.1-9.4 |
| CloudFront CDN config | [operations.md](architecture/operations.md) | 10.1 |
| Event-driven pipelines | [operations.md](architecture/operations.md) | 11.1-11.3 |
| Governance and compliance | [operations.md](architecture/operations.md) | 12.1-12.3 |
| Environment variables | [operations.md](architecture/operations.md) | 13.x |
| Repository structure | [operations.md](architecture/operations.md) | 14.1 |
| Keyword index | [operations.md](architecture/operations.md) | 15 |

### For Agents: Fastest Path
1. Query the **component registry** via `get_code_map(project_id)` for source_paths first.
2. Use the **Component Index** below to find the right section number.
3. Use `reference_search(project_id, query="[SECTION X.Y]")` to read specific sections.

---

## Component Index

Alphabetical lookup. Find a component name, get its section and file.

| Component | File | Section | Description |
|-----------|------|---------|-------------|
| agent-compliance-violations (table) | data-compute | 3.1 | Policy violation audit trail |
| API Gateway HTTP API | data-compute | 5.1 | HTTP API routing all `/api/v1/*` |
| AppShell | security-frontend | 7.6 | React layout: Header + Outlet + BottomNav |
| auth-refresh (Lambda) | data-compute | 4.10 | Cognito token refresh endpoint |
| auth_edge (Lambda) | data-compute | 4.11 | CloudFront Lambda@Edge JWT validation |
| bedrock_agent_actions (Lambda) | data-compute | 4.18 | Bedrock agent action group executor |
| CloudFront Distribution | operations | 10.1 | CDN `E2BOQXCW1TA6Y4` at jreese.net |
| Cognito User Pool | security-frontend | 6.1 | `us-east-1_b2D0V3E1k` with OAuth |
| coordination-requests (table) | data-compute | 3.1 | Coordination request state |
| coordination_api (Lambda) | data-compute | 4.19 | Core agent coordination platform |
| coordination_monitor_api (Lambda) | data-compute | 4.13 | Read-only coordination status API |
| deploy_finalize (Lambda) | data-compute | 4.7 | Post-CodeBuild finalization |
| deploy_intake (Lambda) | data-compute | 4.5 | Deployment submission API |
| deploy_orchestrator (Lambda) | data-compute | 4.6 | SQS-triggered deployment |
| devops-deploy-queue.fifo (SQS) | data-compute | 3.2 | FIFO queue for deployment pipeline |
| devops-deployment-manager (table) | data-compute | 3.1 | Deployment lifecycle |
| devops-feed-publish-queue.fifo (SQS) | data-compute | 3.2 | FIFO queue for feed publishing |
| devops-project-tracker (table) | data-compute | 3.1 | Core tracker table |
| doc_prep (Lambda) | data-compute | 4.15 | Pre-deployment document preparation |
| document_api (Lambda) | data-compute | 4.3 | Document CRUD with S3 |
| documents (table) | data-compute | 3.1 | Document metadata |
| enceladus-mcp-server | security-frontend | 8.1 | MCP server with 35+ tools |
| enceladus-shared (Layer) | data-compute | 4.20 | Lambda layer: JWT, auth, AWS clients |
| feed_publisher (Lambda) | data-compute | 4.8 | Event-driven S3 feed publisher |
| feed_query (Lambda) | data-compute | 4.9 | Feed read API with subscriptions |
| github_integration (Lambda) | data-compute | 4.14 | GitHub App issues + webhooks |
| glue_crawler_launcher (Lambda) | data-compute | 4.16 | Glue crawler trigger |
| governance-policies (table) | data-compute | 3.1 | Governance rules |
| governance_audit (Lambda) | data-compute | 4.12 | Write-source anomaly detector |
| json_to_parquet_transformer (Lambda) | data-compute | 4.17 | JSON to Parquet analytics |
| project_service (Lambda) | data-compute | 4.2 | Project lifecycle management |
| projects (table) | data-compute | 3.1 | Project metadata |
| reference_search (Lambda) | data-compute | 4.4 | S3 reference document search |
| tracker_mutation (Lambda) | data-compute | 4.1 | Core tracker CRUD API |

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
| **AI/Agents** | MCP server (35+ tools), Bedrock Agent, Anthropic API, OpenAI API |

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
| MCP Tools | 35+ |
| Frontend Pages | 15 |
| Frontend Components | 60+ |
| Custom React Hooks | 13 |
| Frontend API Modules | 7 |

---

## File Structure

```
docs/
  ARCHITECTURE.md              <- This index file (~200 lines)
  architecture/
    data-compute.md            <- Sections 2-5: diagrams, data layer, Lambda functions, API routes
    security-frontend.md       <- Sections 6-8: auth/security, PWA, MCP server
    operations.md              <- Sections 9-15: CI/CD, CDN, pipelines, governance, env vars, repo structure
```
