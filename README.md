# Enceladus

Monorepo shell for Enceladus components:

- `api/` - backend API service (placeholder)
- `ui/` - web UI (PWA source migrated)
- `mcp-server/` - MCP server service (placeholder)

## Status

This initial setup only includes the UI codebase. API and MCP server directories are intentionally empty placeholders.

## UI Deployment Integration

The UI deployment now integrates with the backend Deployment Manager using GitHub Actions.

- Workflow: `.github/workflows/ui-backend-deploy.yml`
- Submit script: `scripts/submit_backend_ui_deploy.py`
- Trigger conditions:
  - Push to `main` with changes under `ui/**`
  - Manual `workflow_dispatch`

### Required Repository Secrets

- `AWS_ROLE_TO_ASSUME` (recommended OIDC path), or
- `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`)

### Backend Target

The workflow submits deployment requests to the existing backend pipeline for project `devops`:

- DynamoDB table: `devops-deployment-manager`
- Queue: `devops-deploy-queue.fifo`
- Deploy config location: `s3://jreese-net/deploy-config/devops/deploy.json`

### Manual Local Dry Run

```bash
cd /Users/jreese/Dropbox/claude-code-dev/projects/enceladus/repo
python3 scripts/submit_backend_ui_deploy.py \
  --project-id devops \
  --summary "Dry run validation from local" \
  --related-ids "DVP-TSK-421" \
  --dry-run
```
