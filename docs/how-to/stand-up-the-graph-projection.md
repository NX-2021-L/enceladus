# How to stand up the graph projection

This guide walks you through bringing the Enceladus graph index online from a
cold or partially-populated state: confirming the Neo4j instance and its
credentials, seeding the node-and-edge projection from the tracker, and creating
and verifying the GDS standing projection used by anchored hybrid retrieval.

It assumes you are comfortable with AWS (Lambda, Secrets Manager, EventBridge,
CloudFormation) and with Neo4j/Cypher. It does **not** explain *why* the graph
is shaped the way it is — for the design rationale (derived read-only index,
typed edges, hybrid retrieval signals) see
[The v4 graph and hybrid retrieval](../explanation/v4-graph-and-hybrid-retrieval.md).

The graph is a **read-only derived index**: DynamoDB is the source of truth, and
graph unavailability never blocks tracker mutations. Standing it up is therefore
a recovery/bootstrap operation, not a data-migration one — you are always
re-projecting state that already exists in DynamoDB.

## Before you begin

You will need:

- AWS credentials that can read Secrets Manager, invoke the graph Lambdas, and
  read the tracker/documents DynamoDB tables. The backfill and migration paths
  in this guide are run with `AWS_PROFILE=product-lead` (the agent-CLI profile
  cannot read the tracker table or write the graph secret).
- The `neo4j` Python driver and `boto3` available locally if you run
  `tools/backfill_graph.py` directly.
- Region `us-west-2` (the default for every tool referenced here).

This guide targets the **production** graph unless noted. The shared AuraDB
instance backs both the prod `devops-graph-sync` Lambda and the gamma
`devops-graph-sync-gamma` Lambda; gamma uses a separate AuraDB, and its compute
deploy is currently blocked, so the standing-projection feature is dormant on
gamma. Run destructive steps with care and confirm a recent backup first (see
[Back up and restore Neo4j](./back-up-and-restore-neo4j.md)).

## 1. Confirm the Neo4j instance and connection secrets

Both graph Lambdas resolve their credentials from a single Secrets Manager
secret. The secret ID is supplied by the `NEO4J_SECRET_NAME` environment
variable and defaults to `enceladus/neo4j/auradb-credentials`
(see `backend/lambda/graph_sync/lambda_function.py`, where the default is
declared and the driver is built). In CloudFormation the value is environment-
suffixed — `enceladus/neo4j/auradb-credentials${EnvironmentSuffix}` — in
`infrastructure/cloudformation/02-compute.yaml` on both `GraphSyncFunction` and
`GraphQueryApiFunction`.

The secret is a JSON document with exactly these keys, consumed by
`_get_neo4j_driver()` in both Lambdas:

- `NEO4J_URI`
- `NEO4J_USERNAME` (defaults to `neo4j` if absent)
- `NEO4J_PASSWORD`

Confirm the secret exists and is well-formed. Do **not** print the password
value into shared logs:

```bash
AWS_PROFILE=product-lead aws secretsmanager get-secret-value \
  --secret-id enceladus/neo4j/auradb-credentials \
  --region us-west-2 \
  --query 'SecretString' --output text \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('keys:', sorted(d))"
```

You should see `keys: ['NEO4J_PASSWORD', 'NEO4J_URI', 'NEO4J_USERNAME']`.

> The Neo4j AuraDB instance itself (Free tier, on-demand) is provisioned in the
> Neo4j Aura console, not by this repo's CloudFormation. If the secret is
> missing or the instance has been paused/recycled, restore the instance and
> repopulate the secret from the Aura console before continuing — there are no
> credential values committed to this repository, by design.

Apply the vector-index schema migration if this is a fresh instance. The
migration is idempotent (`IF NOT EXISTS`), so re-running against an instance
that already has the indexes is a no-op:

```bash
AWS_PROFILE=product-lead \
NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials \
python3 tools/backfill_graph.py --region us-west-2 \
  --run-migration tools/neo4j-migrations/001-hnsw-vector-indexes-governed-records.cypher
```

Verify the six per-label HNSW indexes (`governed_task_embedding`, … ,
`governed_document_embedding`) are present:

```bash
AWS_PROFILE=product-lead \
NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials \
python3 tools/backfill_graph.py --region us-west-2 --verify-vector-indexes
```

See `tools/neo4j-migrations/README.md` and the migration file's header comment
for the full index contract (dimensions = 256, similarity = cosine).

## 2. Seed and sync nodes and edges

Once the instance and secret are confirmed, populate the graph. There are two
paths: the live streaming path (which keeps it in sync going forward) and a
one-shot backfill (which seeds it from current DynamoDB state).

### 2a. Confirm the live streaming path is wired

Ongoing sync flows from the tracker through an EventBridge Pipe to a FIFO queue
into the `graph_sync` Lambda:

```
DynamoDB Streams -> EventBridge Pipe -> SQS FIFO -> graph_sync -> MERGE/DELETE (Neo4j)
```

The implementing resources are all in
`infrastructure/cloudformation/02-compute.yaml`:

- `TrackerToGraphPipe` (`AWS::Pipes::Pipe`) — sources the tracker DynamoDB
  Stream (`StartingPosition: LATEST`, filtering out `record_type: reference`)
  and targets the graph-sync FIFO queue, with `MessageGroupId` set to the
  record's `project_id`.
- `DocumentsToGraphPipe` — the parallel pipe for the documents table, targeting
  the same queue.
- `GraphSyncSqsTrigger` (`AWS::Lambda::EventSourceMapping`) — wires the FIFO
  queue to `GraphSyncFunction` (`devops-graph-sync`).

Inside the Lambda, `backend/lambda/graph_sync/lambda_function.py` performs
`MERGE` on `INSERT`/`MODIFY` events and `DETACH DELETE` on `REMOVE`, projecting
`Task`/`Issue`/`Feature`/`Plan` (plus `Lesson`/`Document`/`Generation`) nodes and
the typed edges (`CHILD_OF`, `BLOCKS`, `RELATES_TO`/`RELATED_TO`, `DUPLICATES`,
`DEPENDS_ON`, `MENTIONS`, and the rest registered in
`RELATIONSHIP_TYPE_TO_EDGE_LABEL`). Because the Lambda returns success even when
Neo4j is unavailable (to avoid an infinite SQS retry), a graph outage degrades
sync silently rather than blocking the tracker — which is exactly why an
explicit backfill exists.

Confirm the pipes are running and the event-source mapping is enabled:

```bash
AWS_PROFILE=product-lead aws pipes describe-pipe \
  --name devops-tracker-to-graph-sync-queue --region us-west-2 \
  --query 'CurrentState'
```

A healthy pipe reports `RUNNING`.

### 2b. Backfill from DynamoDB (one-shot seed)

To seed a cold graph — or to repair drift after an outage — re-project the
entire corpus from DynamoDB with `tools/backfill_graph.py`. This is the same
tool the restore procedure uses; it scans the tracker and documents tables and
replays every entity and relationship record through the projection logic.

Preview first with `--dry-run` (scans only, no writes):

```bash
AWS_PROFILE=product-lead \
NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials \
python3 tools/backfill_graph.py --region us-west-2 --dry-run
```

Then run the backfill. Estimated time is roughly 5–10 minutes for the current
corpus size. Add `--wipe-existing` only if you want a clean rebuild (it
`DETACH DELETE`s the whole graph first):

```bash
AWS_PROFILE=product-lead \
NEO4J_SECRET_NAME=enceladus/neo4j/auradb-credentials \
python3 tools/backfill_graph.py --region us-west-2
```

For the full backup/restore context — including the daily S3 snapshot Lambda and
when a wipe-and-replay is the right call — see
[Back up and restore Neo4j](./back-up-and-restore-neo4j.md).

## 3. Create and refresh the GDS standing projection

Anchored hybrid retrieval runs Personalized PageRank against a **standing**
named GDS projection rather than building a per-request projection (which is
slow on the on-demand Aura Graph Analytics compute plane). The projection is
named `gds_standing_enceladus`.

That name is assembled in `backend/lambda/graph_query_api/lambda_function.py`
(`_standing_projection_name()`) by joining the `GDS_STANDING_PROJECTION_PREFIX`
environment variable with the project id — `f"{prefix}_{project_id}"`,
lowercased with dashes turned into underscores. The prefix is set to
`gds_standing` (production only) in `infrastructure/cloudformation/02-compute.yaml`
on `GraphQueryApiFunction`, so `gds_standing` + `enceladus` →
`gds_standing_enceladus`. If `GDS_STANDING_PROJECTION_PREFIX` is unset (as on
gamma), the feature is off and the request path falls back to the per-query
projection — so confirming the env var is the first thing to check if the
projection never appears.

### 3a. Let the scheduled refresher build it

The projection is built and maintained **out of band** by a single writer, so it
is never projected from the request path. `02-compute.yaml` declares
`StandingProjectionRefreshSchedule` (an `AWS::Events::Rule`, production-only)
that fires every 30 minutes and invokes `GraphQueryApiFunction` with:

```json
{"action":"refresh_projection","project_ids":["enceladus"]}
```

`lambda_handler` detects that `action` (and scheduled-event shapes) ahead of the
HTTP routing and dispatches to `_handle_refresh_projection`, which calls
`_refresh_standing_projection` to drop any prior projection of the same name,
re-project the project's nodes and edges, and stamp a `GdsProjectionMeta` marker
carrying the last-refresh timestamp. On a freshly-deployed stack the projection
appears after the first scheduled fire.

### 3b. Trigger a refresh immediately

To build (or rebuild) the projection now instead of waiting for the schedule,
invoke the same Lambda directly with the same payload the EventBridge rule uses:

```bash
AWS_PROFILE=product-lead aws lambda invoke \
  --function-name devops-graph-query-api \
  --payload '{"action":"refresh_projection","project_ids":["enceladus"]}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/refresh-projection-result.json \
  --region us-west-2 && cat /tmp/refresh-projection-result.json
```

A successful refresh returns `{"ok": true, "results": [{"refreshed": true,
"graph_name": "gds_standing_enceladus", ...}]}` with the projected node and
relationship counts. The refresh is a graceful no-op (`refreshed: false`,
reason `GDS_STANDING_PROJECTION_PREFIX unset`) on any environment where the
prefix is not configured.

### 3c. Verify via `connection_health`

Confirm the projection exists and is not stale through the MCP health surface.
`connection_health()` returns a `graph_index` block sourced from the
graph_query_api `/health` endpoint, which includes a `graph_projection` object
populated by `_standing_projection_status` in
`backend/lambda/graph_query_api/lambda_function.py`. Call it from your governed
session:

```text
connection_health()
```

In the response, inspect `graph_index.graph_projection`. For a healthy standing
projection you should see:

- `configured: true` and `name: "gds_standing_enceladus"`
- `exists: true`
- `stale: false` — derived from `age_seconds` versus `max_age_seconds`
  (the default freshness budget is 3600s, comfortably above the 30-minute
  refresh cadence)
- a recent `last_refresh` timestamp

If `exists` is `false` or `stale` is `true`, trigger a manual refresh
(step 3b) and re-check. If `configured` is `false`, the function is missing the
`GDS_STANDING_PROJECTION_PREFIX` env var — confirm the latest `02-compute.yaml`
deploy landed on the function (the value is codified there specifically so a
compute deploy does not strip it).

> The `/health` graph signal probe (`signals.graph`) only checks that the GDS
> plugin is reachable (a cheap `CALL gds.list()`); it does **not** build a
> projection. Use the `graph_projection` block, not `signals.graph`, to judge
> whether the standing projection itself is present and fresh.

## Next steps

With nodes and edges seeded and the standing projection live and fresh, the
graph is ready to serve queries. To exercise traversal, neighbor, path, keyword,
and hybrid retrieval against it, see
[Exercise hybrid retrieval](./exercise-hybrid-retrieval.md).

For ongoing operational care — daily snapshots, restoring from DynamoDB, and
when to wipe-and-replay — see
[Back up and restore Neo4j](./back-up-and-restore-neo4j.md).
