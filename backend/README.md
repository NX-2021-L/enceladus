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

- This repo currently enables GitHub Actions deployment for UI only.
- API code in this folder is source-managed in GitHub, but non-UI auto-deploy is intentionally not enabled.

## Baseline Notes

See `backend/SOURCE_BASELINE_2026-02-21.md` for the initial cloud/local parity review captured during migration.
