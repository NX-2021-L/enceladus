# API Source Baseline (2026-02-21)

Migration objective: move Enceladus API source into `projects/enceladus/repo` while keeping non-UI deployment disabled in GitHub Actions.

## Canonical Source Directories Imported

- `projects/devops/tools/lambda/coordination_api`
- `projects/devops/tools/lambda/coordination_monitor_api`
- `projects/devops/tools/lambda/dispatch_orchestrator`
- `projects/devops/tools/lambda/bedrock_agent_actions`
- `projects/devops/tools/lambda/document_api`
- `projects/devops/tools/lambda/project_service`
- `projects/devops/tools/lambda/reference_search`
- `projects/devops/tools/lambda/tracker_mutation`
- `projects/devops/tools/lambda/deploy_intake`

## Cloud Parity Check Summary

Compared deployed Lambda `lambda_function.py` in `us-west-2` against local source files.

`MATCH`:

- `devops-coordination-monitor-api`
- `devops-project-service`
- `devops-reference-search`
- `devops-tracker-mutation-api`
- `enceladus-bedrock-agent-actions`

`DIFF`:

- `devops-coordination-api`
- `devops-document-api`
- `devops-deploy-intake`

Local files for `DIFF` entries had newer local mtimes than currently deployed functions at migration time, so this repo import used local canonical source from `projects/devops/tools/lambda/*`.

## Update (2026-02-24)

`ENC-TSK-325` established a production-safe API+MCP deployment process without relying on the non-UI deployment-manager executor path:

- Added `.github/workflows/api-mcp-backend-deploy.yml` to deploy `devops-coordination-api` from `main` when API/MCP runtime sources change.
- Codified runbook in `backend/API_MCP_DEPLOY_PROCESS.md`.
- Updated backend deployment policy references in `backend/README.md`.
