# Repository operations

Reference for the continuous-integration workflows, guard checks, and maintenance scripts that build, deploy, and protect this repository. Paths are relative to the repository root. This page describes the machinery; for the reasoning behind the API boundary it enforces, see [About the MCP API boundary](../explanation/about-the-mcp-api-boundary.md).

## Deployment boundary

Different parts of the repository deploy through different paths.

| Source area | Deployment path |
|---|---|
| `frontend/ui/**` | Auto-deploys via GitHub Actions through the backend Deployment Manager (`ui-backend-deploy.yml`). |
| `backend/lambda/**` | Each production Lambda deploys via its dedicated `lambda-*-deploy.yml` workflow. Coverage is tracked in `infrastructure/lambda_workflow_manifest.json` and enforced by `lambda-workflow-coverage-guard.yml`. |
| `tools/enceladus-mcp-server/**` | The MCP server Lambda; not on the UI auto-deploy path. |
| `infrastructure/cloudformation/03-api.yaml` | Deploys via `cloudformation-api-stack-deploy.yml` to stack `enceladus-api` using a privileged OIDC role. |

## UI deployment

- Workflow: `.github/workflows/ui-backend-deploy.yml`
- Submit script: `tools/submit_backend_ui_deploy.py`
- Triggers: push to `main` touching `frontend/ui/**`, or manual `workflow_dispatch`.
- Target: deployment requests are submitted to the `devops` project pipeline (DynamoDB table `devops-deployment-manager`, queue `devops-deploy-queue.fifo`, config `s3://jreese-net/deploy-config/devops/deploy.json`).
- Required repository secrets: `AWS_ROLE_TO_ASSUME` (OIDC), or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`).

A local dry run:

```bash
python3 tools/submit_backend_ui_deploy.py \
  --project-id devops \
  --summary "Dry run validation from local" \
  --related-ids "DVP-TSK-421" \
  --dry-run
```

## Source sync

API and MCP source mirrors are refreshed from the canonical tool directories:

```bash
./tools/sync_non_ui_sources.sh
```

## Parity audit

A nightly audit validates that live Lambda code hashes match the repository manifest.

- Workflow: `.github/workflows/nightly-parity-audit.yml`
- Script: `tools/parity_audit.py`
- Inputs: `infrastructure/parity/lambda_function_map.json`, `infrastructure/lambda-manifests/*.json`

Manual run:

```bash
python3 tools/parity_audit.py --output-dir infrastructure/parity/out
```

## Secrets guardrails

Secrets protection is enforced at three layers:

- **GitHub repository settings** — secret scanning and push protection enabled.
- **CI gate** — `.github/workflows/secrets-guardrail.yml` runs on pull requests and pushes to `main`, scanning git history and the filesystem; a scheduled daily scan also checks the public repository URL.
- **Local pre-push hook** — `.githooks/pre-push`, installed once per clone with `./tools/install_git_hooks.sh`.

Run the guard scan manually at any time:

```bash
./tools/secrets_guard.sh
```

## MCP API boundary guard

MCP tool handlers must access business data through Enceladus service APIs rather than reading or writing DynamoDB directly.

- CI guard: `.github/workflows/mcp-api-boundary-guard.yml`
- Guard script: `tools/check_mcp_api_boundary.py`
- Rationale: [About the MCP API boundary](../explanation/about-the-mcp-api-boundary.md)

## Architecture documentation sync

Changes to `docs/ARCHITECTURE.md` on `main` are synchronized to the Enceladus docstore.

- Workflow: `.github/workflows/sync-architecture-doc.yml` (triggers on `docs/ARCHITECTURE.md`)
- Script: `tools/sync_architecture_doc.py`

> Because this sync is keyed to the exact path `docs/ARCHITECTURE.md`, that file and its `docs/architecture/` domain files are kept at the repository's documentation root rather than relocated under `docs/reference/`.
