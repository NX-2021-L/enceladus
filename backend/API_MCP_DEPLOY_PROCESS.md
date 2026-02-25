# API + MCP Deployment Process

This runbook defines the supported deployment process for Enceladus API and MCP runtime changes in `NX-2021-L/enceladus`.

## Scope

- `backend/lambda/coordination_api/**`
- `tools/enceladus-mcp-server/**`

These paths are deployed together because the coordination API package embeds the MCP server runtime (`server.py` and `dispatch_plan_generator.py`) during build.

## Why This Process Exists

The backend deployment-manager pipeline currently executes UI deployments through CodeBuild. Non-UI requests are validated and queued as `queued_non_ui`, but there is no downstream non-UI executor in this repository. Because of that, API/MCP deployments must use the direct coordination API deploy script.

## Canonical Automation

- Workflow: `.github/workflows/api-mcp-backend-deploy.yml`
- Job action: runs `backend/lambda/coordination_api/deploy.sh`
- Trigger:
  - push to `main` touching scoped paths
  - manual `workflow_dispatch`

## Manual Execution (local)

```bash
cd /path/to/enceladus/repo
chmod +x backend/lambda/coordination_api/deploy.sh
backend/lambda/coordination_api/deploy.sh
```

Required environment:

- AWS credentials with permission to update Lambda, API Gateway, IAM, CloudWatch Logs, DynamoDB.
- Region defaults to `us-west-2` unless `REGION` is overridden.

Optional environment:

- `COORDINATION_INTERNAL_API_KEY` to force key rotation/update during deploy.

## Validation Requirements

After each deployment, confirm:

1. `devops-coordination-api` Lambda reports `State=Active` and `LastUpdateStatus=Successful`.
2. API Gateway integration/routes remain present for `/api/v1/coordination/*`.
3. Capability endpoint responds through production path (authenticated smoke test where required).

The GitHub workflow enforces item (1) directly using `aws lambda get-function-configuration`.

## Governance / Compliance Notes

- Do not submit API/MCP changes through the UI deployment-manager request flow as a substitute for runtime deployment.
- Document deployment evidence (commit, function last-modified timestamp, validation outcome) in tracker worklogs for affected tasks.
- Keep this runbook referenced from governance guidance so future agent sessions use this process by default.
