# Codebase Map

This reference routes each major capability of Enceladus to the directories and files that implement it. It exists so a reader can move from "what the system does" to "where that is in the code" in one hop. Paths are relative to the repository root.

For the system described component by component, see the [architecture reference](../ARCHITECTURE.md). For the governed tool API, see the [MCP tool surface](mcp-tool-surface.md).

## Component inventory

| Directory | Contents |
|---|---|
| `backend/lambda/` | Python AWS Lambda functions (one directory per function) |
| `backend/lambda/shared_layer/` | Shared Python layer (`enceladus_shared`) — auth, feature flags, common helpers |
| `tools/enceladus-mcp-server/` | The MCP server and its supporting modules |
| `tools/` | Deployment, parity-audit, drift-detection, and verification scripts |
| `frontend/ui/` | React 19 + TypeScript + Vite progressive web app |
| `infrastructure/cloudformation/` | CloudFormation templates (data, compute, API, roles, monitoring) |
| `infrastructure/lambda-manifests/` | Per-function deployment manifests |
| `infrastructure/parity/` | Parity-audit mappings and generated output |
| `.github/workflows/` | CI/CD workflows |
| `.githooks/` | Local git hooks |
| `docs/` | Documentation (this tree) |
| `tests/` | Integration and end-to-end test suites |

## Capability → code

| Capability | Description | Key paths | Open first |
|---|---|---|---|
| **Governed tracker / ontology** | CRUD and deterministic status transitions for tracker records (task, issue, feature, plan, lesson), with write-source attribution and validation. | `backend/lambda/tracker_mutation/lambda_function.py`, `…/transition_type_matrix.py`; `infrastructure/cloudformation/01-data.yaml` (table definitions) | `backend/lambda/tracker_mutation/lambda_function.py` |
| **Checkout lifecycle state machine** | Per-task checkout tokens that serialize work and gate status advancement on commit-SHA and PR-merge evidence. | `backend/lambda/checkout_service/lambda_function.py`, `…/transition_type_matrix.py` | `backend/lambda/checkout_service/lambda_function.py` |
| **MCP code-mode server** | Exposes the governed resources to agent sessions through a compact tool surface; validates governance hashes for writes. | `tools/enceladus-mcp-server/server.py`; supporting `manifest_projection.py`, `handoff_mandate.py`, `dispatch_plan_generator.py` | `tools/enceladus-mcp-server/server.py` |
| **Coordination API / dispatch** | HTTP bridge and state machine for coordination requests; decomposes outcomes into tracker artifacts before dispatch. | `backend/lambda/coordination_api/lambda_function.py` | `backend/lambda/coordination_api/lambda_function.py` |
| **Hybrid retrieval** | Fuses keyword, graph, and vector signals via Reciprocal Rank Fusion for record and reference search. | `backend/lambda/reference_search/lambda_function.py`, `backend/lambda/graph_query_api/lambda_function.py`; MCP wrappers in `tools/enceladus-mcp-server/server.py` (`_search`, `_tracker_graphsearch`, `get_compact_context`) | `backend/lambda/graph_query_api/lambda_function.py` |
| **Graph projection / Neo4j** | Streaming projection of tracker records and typed edges into Neo4j; Titan embeddings; MENTIONS auto-extraction. | `backend/lambda/graph_sync/lambda_function.py`, `…/embedding.py`, `…/mentions_extraction.py`; `backend/lambda/graph_health_metrics/`, `backend/lambda/neo4j_backup/`; `tools/neo4j-migrations/` | `backend/lambda/graph_sync/lambda_function.py` |
| **Deploy pipeline & gates** | Intake → debounce → orchestrate → finalize deployment flow, with parity and coverage gates and feature-flagged rollouts. | `backend/lambda/deploy_intake/`, `deploy_orchestrator/`, `deploy_finalize/`, `deploy_parity_validator/`, `deploy_decide/`; `tools/parity_audit.py`, `tools/verify_lambda_workflow_coverage.py`; `infrastructure/cloudformation/07-codedeploy.yaml` | `backend/lambda/deploy_intake/lambda_function.py` |
| **Governance dictionary & validation** | Governance file registry, governance-hash concurrency control, and write-source audit. | `backend/lambda/coordination_api/governance_data_dictionary.json`; `backend/lambda/governance_audit/lambda_function.py`; `tools/enceladus-mcp-server/server.py` (`_governance_*`); `.github/workflows/governance-dictionary-guard.yml` | `backend/lambda/governance_audit/lambda_function.py` |
| **Feed pipeline** | Event-driven publication of per-project JSON feeds to S3/CloudFront, with an analytics fan-out. | `backend/lambda/feed_publisher/lambda_function.py`; `backend/lambda/json_to_parquet_transformer/`, `backend/lambda/glue_crawler_launcher/`; `infrastructure/cloudformation/02-compute.yaml` | `backend/lambda/feed_publisher/lambda_function.py` |
| **PWA frontend** | Mobile-first React PWA: pages, components, API clients, and data hooks for the full tracker surface. | `frontend/ui/src/pages/`, `…/components/`, `…/api/`, `…/hooks/`, `…/lib/authState.tsx` | `frontend/ui/src/pages/DashboardPage.tsx` |
| **Authentication (Cognito / JWT)** | Cognito user pool, Lambda@Edge JWT validation, token refresh, and shared-layer JWKS verification. | `backend/lambda/auth_edge/`, `backend/lambda/auth_refresh/`, `backend/lambda/shared_layer/enceladus_shared/auth.py`; `frontend/ui/src/lib/authState.tsx`; `infrastructure/cloudformation/03-api.yaml` | `backend/lambda/shared_layer/enceladus_shared/auth.py` |
| **GitHub integration** | Webhook ingestion, commit/PR validation for the checkout gate, and GitHub issue/project sync. | `backend/lambda/github_integration/lambda_function.py`; `backend/lambda/checkout_service/lambda_function.py` (commit/PR validation); `tools/enceladus-mcp-server/server.py` (`_github_*`); `infrastructure/cloudformation/04-github-roles.yaml` | `backend/lambda/github_integration/lambda_function.py` |

## Notes

- Function directories under `backend/lambda/` each contain a `lambda_function.py` entry point and, where applicable, a `deploy.sh`, tests, and supporting modules.
- The CloudFormation stacks are numbered by layer: `01-data`, `02-compute`, `03-api`, `04-github-roles`, and higher-numbered stacks for monitoring, feature flags, and CodeDeploy.
- Function counts and directory contents evolve; treat this map as a routing index, not an inventory of record. Where a path here and the [architecture reference](../ARCHITECTURE.md) disagree, the code is authoritative.
