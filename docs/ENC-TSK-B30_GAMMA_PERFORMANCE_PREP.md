# ENC-TSK-B30 Gamma Performance Prep

**Project**: enceladus
**Related**: ENC-TSK-B30, ENC-TSK-B60, ENC-TSK-B61, ENC-FTR-062
**Created**: 2026-04-03
**Author**: Codex

## Scope

Dispatch H asked for investigation plus IaC prep only. This branch captures the
production Lambda baseline on 2026-04-03 and stages only the changes that are
safe to prepare before gamma is confirmed operational.

Raw inventory: `infrastructure/lambda-live-inventory-2026-04-03-enc-tsk-b30.json`

## Production Baseline

- 19-function baseline confirmed from `infrastructure/lambda_workflow_manifest.json` plus `enceladus-checkout-service`
- Runtime split: 18 functions on `python3.11`, 1 function on `python3.12`
- Architecture split: all 19 functions on `x86_64`
- SnapStart: `Off` on all 19 baseline functions
- SQS-triggered Lambdas: `devops-deploy-orchestrator`, `devops-feed-publisher`, `devops-graph-sync`
- Checkout companion: `enceladus-checkout-service-auto` is also `python3.12` on `x86_64`
- MCP functions: `enceladus-mcp-code` and `enceladus-mcp-streamable` are already `python3.12` on `arm64`, but neither has aliases or provisioned concurrency configured

## Safe Prep Staged Here

- Move the compute CloudFormation template baseline from `python3.11` / `x86_64` to `python3.12` / `arm64`
- Update checkout deploy flow so future deploys do not recreate checkout Lambdas on `x86_64`
- Keep MCP deploy flows pinned to `arm64` on both create and update paths

## Blockers Found

### ReportBatchItemFailures is not config-only

All three SQS consumers currently return success payloads but do not emit the
partial batch response shape (`batchItemFailures`). Enabling
`FunctionResponseTypes: [ReportBatchItemFailures]` without handler changes is
unsafe because failed records can be treated as successfully processed.

- `backend/lambda/deploy_orchestrator/lambda_function.py`
- `backend/lambda/feed_publisher/lambda_function.py`
- `backend/lambda/graph_sync/lambda_function.py`

### SnapStart needs versioned deploy flow

SnapStart only applies to published versions. Most current Lambda deploy paths
still update `$LATEST` directly, so adding a template property alone would not
make SnapStart live on gamma.

- `infrastructure/cloudformation/02-compute.yaml`
- `backend/lambda/*/deploy.sh`

### MCP provisioned concurrency needs alias-qualified routing

Provisioned concurrency applies to a version or alias, not the unqualified
function. The MCP deploy scripts currently manage Function URLs on the base
function name and there are no aliases in production, so alias creation plus
invoke-path routing is required before provisioned concurrency helps cold
starts.

- `backend/lambda/mcp_code/deploy.sh`
- `backend/lambda/mcp_streamable/deploy.sh`

## Recommended Follow-On Before Gamma Apply

1. Add partial batch response support to the three SQS handlers, then enable
   `ReportBatchItemFailures` on their event source mappings.
2. Introduce a version-and-alias deploy path for the functions that should use
   SnapStart.
3. Introduce an alias-qualified MCP invoke path, then attach provisioned
   concurrency to that alias.
4. Re-run the live inventory against gamma after `ENC-TSK-B60` closes.

## Neo4j Backup Investigation

### Current State

- `ENC-TSK-934` confirms the current AuraDB instance was resumed from pause and
  the projection pipeline recovered without a backfill
- `tools/backfill_graph.py` already exists to rebuild the graph from
  DynamoDB source records
- Governed tracker totals on 2026-04-03 are approximately:
  - tasks: 1172
  - issues: 159
  - features: 62
  - lessons: 17
  - plans: 10
- That is roughly 1420 primary governed records before typed relationship
  items and project nodes

### Backup Conclusion

I found evidence that AuraDB exposes automated backup/snapshot operations via
the Aura platform and API, but I did not find evidence of a native direct S3
export target for AuraDB Free. The practical Enceladus approach is therefore:

1. Schedule a backup worker outside the request path.
2. Call the Aura control plane to create or fetch the latest restore snapshot.
3. Download the snapshot artifact locally.
4. Upload the artifact to S3 with retention metadata.
5. Periodically test restore the snapshot into a disposable target.

### Rebuild Estimate

`tools/backfill_graph.py` performs a full scan of `devops-project-tracker` and
then executes a node pass plus an edge-reconciliation pass. At the current
governed record volume, a conservative estimate is that a full rebuild should
fit inside the `< 15 minutes` gate for `ENC-TSK-B61`, likely in the `5-10`
minute range. This is an inference from the current corpus size and the
existing sequential backfill design, not a measured benchmark.
