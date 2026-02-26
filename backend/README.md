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

## ⚠️ CRITICAL: Lambda Dependency Build Requirements

**All Lambda functions with requirements.txt must use the shared layer (`backend/lambda/shared_layer/`).**

Never bundle compiled dependencies directly in Lambda function packages. macOS-built binaries are incompatible with Lambda's Linux runtime.

### Building Lambda Packages

Use platform-specific targeting:
```bash
pip install \
  --platform manylinux2014_x86_64 \
  --only-binary=:all: \
  -r requirements.txt \
  -t lambda_build_dir
```

### Shared Layer Deployment
```bash
cd backend/lambda/shared_layer
./deploy.sh --attach-all  # Attach to all Enceladus Lambdas
```

### Cookie Parsing Requirement

All auth-checking Lambda functions MUST parse cookies from BOTH sources:
- `headers.cookie` (standard HTTP)
- `event.cookies` (API Gateway v2)

Failure to parse both causes auth failures with modern API Gateway versions (see DVP-ISS-071).

See `JWT_AUTHENTICATION_FORENSICS.md` for complete prevention framework.

## Deployment Policy

- UI deployment remains managed by `.github/workflows/ui-backend-deploy.yml`.
- API + MCP runtime deployment is managed by `.github/workflows/api-mcp-backend-deploy.yml`,
  which executes `backend/lambda/coordination_api/deploy.sh`.
- Every production Lambda declared in `infrastructure/cloudformation/02-compute.yaml`
  must have a mapped workflow entry in `infrastructure/lambda_workflow_manifest.json`.
- Dedicated Lambda deploy workflows are under `.github/workflows/lambda-*-deploy.yml`
  and use `.github/workflows/lambda-deploy-reusable.yml`.
- Workflow coverage is enforced by `.github/workflows/lambda-workflow-coverage-guard.yml`
  running `tools/verify_lambda_workflow_coverage.py` on PRs and pushes.
- Non-UI requests routed through deployment-manager (`queued_non_ui`) are not the canonical
  execution path for API/MCP runtime updates in this repo.

## New Lambda Process

When adding a new production Lambda:

1. Add the Lambda definition to `infrastructure/cloudformation/02-compute.yaml`.
2. Add a matching entry in `infrastructure/lambda_workflow_manifest.json`.
3. Add a deploy workflow file under `.github/workflows/lambda-*-deploy.yml` mapped to
   either a dedicated `deploy.sh` or the reusable generic package path.
4. Run `python tools/verify_lambda_workflow_coverage.py` locally before opening a PR.

The coverage guard will fail CI if any production Lambda lacks workflow mapping.

## Baseline Notes

See `backend/SOURCE_BASELINE_2026-02-21.md` for the initial cloud/local parity review captured during migration.
See `backend/API_MCP_DEPLOY_PROCESS.md` for the current API+MCP deployment runbook.
