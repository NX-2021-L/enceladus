# Backend

Enceladus API backend source mirror.

## Scope

This folder contains Lambda-based API components sourced from the canonical DevOps Enceladus backend paths:

- `lambda/coordination_api`
- `lambda/coordination_monitor_api`
- `lambda/dispatch_orchestrator`
- `lambda/bedrock_agent_actions`
- `lambda/document_api`
- `lambda/project_service`
- `lambda/reference_search`
- `lambda/tracker_mutation`
- `lambda/deploy_intake`
- `lambda/deploy_finalize`
- `lambda/deploy_orchestrator`
- `lambda/doc_prep`
- `lambda/feed_publisher`
- `lambda/glue_crawler_launcher`
- `lambda/json_to_parquet_transformer`
- `lambda/auth_refresh`
- `lambda/auth_edge`
- `lambda/governance_audit`

## Deployment Policy

- UI deployment remains managed by `.github/workflows/ui-backend-deploy.yml`.
- API + MCP runtime deployment is managed by `.github/workflows/api-mcp-backend-deploy.yml`,
  which executes `backend/lambda/coordination_api/deploy.sh`.
- Non-UI requests routed through deployment-manager (`queued_non_ui`) are not the canonical
  execution path for API/MCP runtime updates in this repo.

## Baseline Notes

See `backend/SOURCE_BASELINE_2026-02-21.md` for the initial cloud/local parity review captured during migration.
See `backend/API_MCP_DEPLOY_PROCESS.md` for the current API+MCP deployment runbook.
