# Enceladus

Monorepo for Enceladus components:

- `api/` - backend API source (Lambda services, source mirror)
- `ui/` - web UI (PWA source + active GitHub Actions deployment flow)
- `mcp-server/` - Enceladus MCP server source (source mirror) + native MCP briefing templates (`mcp-server/briefings/`)

## Status

API and MCP source files are now stored in this repo so the full Enceladus codebase is available in GitHub.

Important deployment boundary:

- UI: auto-deploy enabled through GitHub Actions + backend deployment manager.
- API/MCP: source-only in this repo; no GitHub Actions auto-deploy is configured for non-UI components.

## UI Deployment Integration

The UI deployment now integrates with the backend Deployment Manager using GitHub Actions.

- Workflow: `.github/workflows/ui-backend-deploy.yml`
- Submit script: `scripts/submit_backend_ui_deploy.py`
- Trigger conditions:
  - Push to `main` with changes under `ui/**`
  - Manual `workflow_dispatch`

Non-UI paths (`api/**`, `mcp-server/**`) do not trigger this workflow.

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

## Source Sync (API/MCP)

To refresh API/MCP source mirrors from the canonical DevOps tool directories:

```bash
cd /Users/jreese/Dropbox/claude-code-dev/projects/enceladus/repo
./scripts/sync_non_ui_sources.sh
```

## Secrets Guardrails

Secrets protection is now enforced at multiple layers:

- GitHub repository settings:
  - Secret scanning: enabled
  - Push protection: enabled
- CI gate:
  - Workflow: `.github/workflows/secrets-guardrail.yml`
  - Runs on PRs and pushes to `main`
  - Scans git history + filesystem for secrets
  - Scheduled daily scan also checks the public GitHub repo URL
- Local pre-push hook (recommended):
  - Hook file: `.githooks/pre-push`
  - Install once per clone:

```bash
cd /Users/jreese/Dropbox/claude-code-dev/projects/enceladus/repo
./scripts/install_git_hooks.sh
```

Run the guard scans manually at any time:

```bash
cd /Users/jreese/Dropbox/claude-code-dev/projects/enceladus/repo
./scripts/secrets_guard.sh
```
